#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/link_error.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <algorithm>
#include <chrono>
#include <exception>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace acpp::proxy::anytls::outbound {

// Shared by physical task completion and serialized-write failure. Keep this
// classification at session ownership, outside the framing codec.
inline ErrorCode SessionExceptionError(const std::exception_ptr& failure) noexcept {
    try { std::rethrow_exception(failure); }
    catch (const transport::LinkError& e) { return e.code(); }
    catch (const std::bad_alloc&) { return ErrorCode::RESOURCE_EXHAUSTED; }
    catch (const IoSystemError& e) { return MapAsioError(e.code()); }
    catch (...) { return ErrorCode::INTERNAL; }
}

// Worker-local physical-session ownership. A checkout is busy before any
// suspension; an unreturned checkout closes its session on every exit path.
// Each physical operation owns State and Session until its actual co_spawn
// completion. Retirement requests cancellation; it cannot destroy those roots
// while they are cleaning up. Neither roots nor timers borrow the Handler.
template<class Session>
class SessionPool : public memory::ThreadAllocated {
    using Clock = std::chrono::steady_clock;
    struct State;

    static_assert(noexcept(std::declval<Session&>().CloseAll(ErrorCode::CANCELLED)));
    static_assert(noexcept(std::declval<const Session&>().Available()));
    static_assert(noexcept(std::declval<const Session&>().IsClosed()));

    static void Close(const std::shared_ptr<Session>& session) noexcept {
        if (session) session->CloseAll(ErrorCode::CANCELLED);
    }

public:
    class Lease {
    public:
        Lease() = default;
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept = default;
        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                Discard();
                state_ = std::move(other.state_);
                session_ = std::move(other.session_);
            }
            return *this;
        }
        ~Lease() noexcept { Discard(); }

        [[nodiscard]] const std::shared_ptr<Session>& Get() const noexcept { return session_; }

        void Reuse() noexcept {
            if (state_ && session_) state_->Release(session_);
            session_.reset();
            state_.reset();
        }

    private:
        friend class SessionPool;
        Lease(std::shared_ptr<State> state, std::shared_ptr<Session> session) noexcept
            : state_(std::move(state)), session_(std::move(session)) {}
        void Discard() noexcept {
            if (state_ && session_) state_->Remove(session_);
            session_.reset();
            state_.reset();
        }
        std::shared_ptr<State> state_;
        std::shared_ptr<Session> session_;
    };

    SessionPool(net::io_context& io_context, Clock::duration check_interval,
                Clock::duration idle_timeout, size_t minimum_idle, std::string_view tag)
        : state_(memory::AllocateShared<State>(io_context, check_interval, idle_timeout,
                                         minimum_idle, tag)) {}
    SessionPool(const SessionPool&) = delete;
    SessionPool& operator=(const SessionPool&) = delete;
    ~SessionPool() noexcept { state_->Retire(); }

    template<class Accept>
    [[nodiscard]] Lease AcquireIf(Accept&& accept) {
        state_->CheckActive();
        state_->Prune();
        for (auto it = state_->entries.rbegin(); it != state_->entries.rend(); ++it) {
            if (it->idle_since && it->session->Available() && accept(*it->session)) {
                it->idle_since.reset();
                return Lease(state_, it->session);
            }
        }
        return {};
    }

    [[nodiscard]] Lease Acquire() {
        return AcquireIf([](const Session&) { return true; });
    }

    [[nodiscard]] Lease Adopt(std::shared_ptr<Session> session) {
        try {
            state_->CheckActive();
            if (!session || session->IsClosed()) {
                throw std::invalid_argument("cannot adopt a closed AnyTLS session");
            }
            state_->entries.push_back({session, std::nullopt});
            if (!state_->Valid()) state_->Schedule();
            state_->Start(session);
            return Lease(state_, std::move(session));
        } catch (...) {
            state_->Remove(session);
            throw;
        }
    }

private:
    struct State : std::enable_shared_from_this<State>, TimeoutEvent {
        struct Entry {
            std::shared_ptr<Session> session;
            std::optional<Clock::time_point> idle_since;
        };

        State(net::io_context& io_context, Clock::duration check, Clock::duration timeout,
              size_t minimum, std::string_view name)
            : io_context(io_context), scheduler(TimeoutScheduler::ForIoContext(io_context)),
              check_interval(check), idle_timeout(timeout),
              minimum_idle(minimum), tag(name) {
            if (check <= Clock::duration::zero() || timeout <= Clock::duration::zero()) {
                throw std::invalid_argument("AnyTLS session intervals must be positive");
            }
        }

        void CheckActive() const {
            if (failure) std::rethrow_exception(failure);
            if (retired) throw std::logic_error("AnyTLS session pool is retired");
        }

        void CancelTimer() noexcept {
            Cancel();
        }

        void Remove(const std::shared_ptr<Session>& session) noexcept {
            // Keep an owner while erasing the index, before cancellation can
            // notify logical requests or finish the physical operation.
            const auto closing = session;
            std::erase_if(entries, [&](const auto& entry) { return entry.session == session; });
            StopIfEmpty();
            Close(closing);
        }

        void Start(const std::shared_ptr<Session>& session) {
            net::co_spawn(io_context, session->Run(),
                net::bind_cancellation_slot(session->CancellationSlot(),
                    [owner = this->shared_from_this(), session](std::exception_ptr failure) {
                        ErrorCode error = ErrorCode::CONNECTION_CLOSED;
                        if (failure) {
                            error = SessionExceptionError(failure);
                        }
                        // A root that returned or threw must never remain
                        // reusable. CloseAll retains the first terminal cause.
                        session->CloseAll(error);
                        owner->Remove(session);
                        if (failure && error != ErrorCode::CANCELLED) {
                            try {
                                LOG_WARN("AnyTLS outbound '{}': physical session task failed: {}",
                                    owner->tag, ErrorCodeToString(error));
                            } catch (...) {}
                        }
                    }));
        }

        void Release(const std::shared_ptr<Session>& session) noexcept {
            auto it = std::find_if(entries.begin(), entries.end(),
                [&](const auto& entry) { return entry.session == session; });
            if (retired || it == entries.end() || !session->Available()) {
                Remove(session);
                return;
            }
            it->idle_since = Clock::now();
            // Keep most recently returned idle sessions at the back, without
            // allocating a second list or changing the ownership count.
            std::rotate(it, it + 1, entries.end());
        }

        void Prune() noexcept {
            const auto now = Clock::now();
            size_t retained_idle = 0;
            for (size_t i = entries.size(); i-- > 0;) {
                const auto& entry = entries[i];
                bool remove = entry.session->IsClosed();
                if (!remove && entry.idle_since) {
                    if (!entry.session->Available()) {
                        remove = true;
                    } else if (retained_idle >= minimum_idle &&
                               now - *entry.idle_since >= idle_timeout) {
                        remove = true;
                    } else {
                        ++retained_idle;
                    }
                }
                if (remove) {
                    const auto closing = entry.session;
                    entries.erase(entries.begin() + static_cast<std::ptrdiff_t>(i));
                    Close(closing);
                }
            }
            StopIfEmpty();
        }

        void StopIfEmpty() noexcept {
            if (!entries.empty()) return;
            CancelTimer();
            memory::ThreadLocalVector<Entry>{}.swap(entries);
        }

        void Schedule() {
            if (!scheduler.ScheduleAfter(
                    std::chrono::ceil<std::chrono::milliseconds>(check_interval), *this))
                throw IoSystemError(io_error::operation_aborted);
        }

        void OnTimeout() noexcept override {
            // Pruning can drop the last indexed session and notify its users.
            // Keep this event's owner alive until rescheduling has finished.
            const auto self = this->shared_from_this();
            if (retired) return;
            try {
                Prune();
                if (!entries.empty()) Schedule();
            } catch (...) {
                failure = std::current_exception();
                Retire();
                try {
                    LOG_ERROR("AnyTLS outbound '{}': idle session scheduler failed", tag);
                } catch (...) {}
            }
        }

        void Retire() noexcept {
            retired = true;
            CancelTimer();
            memory::ThreadLocalVector<Entry> closing;
            closing.swap(entries);
            for (const auto& entry : closing) Close(entry.session);
        }

        net::io_context& io_context;
        TimeoutScheduler& scheduler;
        const Clock::duration check_interval;
        const Clock::duration idle_timeout;
        const size_t minimum_idle;
        const memory::ThreadLocalString tag;
        memory::ThreadLocalVector<Entry> entries;
        bool retired = false;
        std::exception_ptr failure;
    };

    const std::shared_ptr<State> state_;
};

}  // namespace acpp::proxy::anytls::outbound
