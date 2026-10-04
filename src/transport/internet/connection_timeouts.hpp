#pragma once

#include "acppnode/common/error.hpp"
#include "acppnode/transport/phase_deadline.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <chrono>
#include <cstdint>
#include <new>
#include <optional>
#include <stdexcept>

namespace acpp::transport::internet::detail {

// Worker-thread-only aggregate deadlines for one connection. The scheduler
// callback borrows this object; destruction cancels its sole event token.
template<class Owner>
class ConnectionTimeouts {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    ConnectionTimeouts(net::io_context& io_context, Owner& owner)
        : scheduler_(TimeoutScheduler::ForIoContext(io_context)), owner_(owner) {}
    ConnectionTimeouts(const ConnectionTimeouts&) = delete;
    ConnectionTimeouts& operator=(const ConnectionTimeouts&) = delete;
    ~ConnectionTimeouts() noexcept { Stop(); }

    void SetIdleTimeout(std::chrono::seconds timeout) {
        if (stopped_) return;
        idle_enabled_ = timeout > std::chrono::seconds::zero();
        idle_timeout_ = idle_enabled_ ? timeout : std::chrono::seconds::zero();
        idle_expired_ = false;
        if (idle_enabled_) idle_deadline_ = Deadline(timeout);
        else idle_deadline_.reset();
        Reconcile();
    }

    void SetReadTimeout(std::chrono::seconds timeout) {
        if (stopped_) return;
        read_timeout_ = timeout > std::chrono::seconds::zero() ? timeout : std::chrono::seconds::zero();
        read_expired_ = false;
        if (read_pending_) read_deadline_ = MakeDeadline(read_timeout_);
        Reconcile();
    }

    void SetWriteTimeout(std::chrono::seconds timeout) {
        if (stopped_) return;
        write_timeout_ = timeout > std::chrono::seconds::zero() ? timeout : std::chrono::seconds::zero();
        write_expired_ = false;
        if (write_pending_) write_deadline_ = MakeDeadline(write_timeout_);
        Reconcile();
    }

    [[nodiscard]] PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        ClearPhaseDeadline();
        if (stopped_ || timeout <= std::chrono::seconds::zero()) return {};
        phase_deadline_ = Deadline(timeout);
        phase_expired_ = false;
        Reconcile();
        return {&flags_, kPhaseMask, &phase_generation_, phase_generation_};
    }

    void ClearPhaseDeadline() noexcept {
        ++phase_generation_;
        phase_deadline_.reset();
        phase_expired_ = false;
        UpdateFlags();
        ReconcileNoThrow();
    }

    [[nodiscard]] bool ConsumeIdleTimeout() noexcept { return Consume(idle_expired_); }
    [[nodiscard]] bool ConsumeReadTimeout() noexcept { return Consume(read_expired_); }
    [[nodiscard]] bool ConsumeWriteTimeout() noexcept { return Consume(write_expired_); }
    [[nodiscard]] bool ConsumePhaseDeadline() noexcept { return Consume(phase_expired_); }

    void BeginRead() {
        CheckCanBegin(read_pending_);
        read_pending_ = true;
        read_expired_ = false;
        read_deadline_ = MakeDeadline(read_timeout_);
        try { Reconcile(); }
        catch (...) { read_pending_ = false; read_deadline_.reset(); throw; }
    }
    void EndRead() noexcept { read_pending_ = false; read_deadline_.reset(); ReconcileNoThrow(); }

    void BeginWrite() {
        CheckCanBegin(write_pending_);
        write_pending_ = true;
        write_expired_ = false;
        write_deadline_ = MakeDeadline(write_timeout_);
        try { Reconcile(); }
        catch (...) { write_pending_ = false; write_deadline_.reset(); throw; }
    }
    void EndWrite() noexcept { write_pending_ = false; write_deadline_.reset(); ReconcileNoThrow(); }

    void TouchActivity() noexcept {
        if (stopped_ || !idle_enabled_) return;
        idle_deadline_ = Deadline(idle_timeout_);
        idle_expired_ = false;
        ReconcileNoThrow();
    }

    void Stop() noexcept {
        if (stopped_) return;
        stopped_ = true;
        idle_enabled_ = false;
        read_pending_ = write_pending_ = false;
        idle_deadline_.reset();
        read_deadline_.reset();
        write_deadline_.reset();
        phase_deadline_.reset();
        scheduler_.Cancel(token_);
        armed_deadline_.reset();
    }

private:
    static constexpr uint8_t kIdleMask = 1u << 0;
    static constexpr uint8_t kReadMask = 1u << 1;
    static constexpr uint8_t kWriteMask = 1u << 2;
    static constexpr uint8_t kPhaseMask = 1u << 3;

    static TimePoint Deadline(std::chrono::seconds timeout) noexcept {
        const auto now = Clock::now();
        const auto remaining = TimePoint::max() - now;
        if (timeout >= std::chrono::duration_cast<std::chrono::seconds>(remaining)) return TimePoint::max();
        return now + std::chrono::duration_cast<Clock::duration>(timeout);
    }
    static std::optional<TimePoint> MakeDeadline(std::chrono::seconds timeout) noexcept {
        if (timeout <= std::chrono::seconds::zero()) return std::nullopt;
        return Deadline(timeout);
    }
    static std::chrono::milliseconds DelayUntil(TimePoint deadline) noexcept {
        const auto now = Clock::now();
        if (deadline <= now) return std::chrono::milliseconds::zero();
        return std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
    }
    void CheckCanBegin(bool pending) const {
        if (stopped_) throw std::logic_error("connection timeouts stopped");
        if (pending) throw std::logic_error("connection permits one operation per direction");
    }
    bool Consume(bool& expired) noexcept {
        const bool result = expired;
        expired = false;
        UpdateFlags();
        return result;
    }
    void UpdateFlags() noexcept {
        flags_ = (idle_expired_ ? kIdleMask : 0) | (read_expired_ ? kReadMask : 0) |
                 (write_expired_ ? kWriteMask : 0) | (phase_expired_ ? kPhaseMask : 0);
    }
    [[nodiscard]] TimePoint Earliest() const noexcept {
        auto first = TimePoint::max();
        if (idle_deadline_ && *idle_deadline_ < first) first = *idle_deadline_;
        if (read_deadline_ && *read_deadline_ < first) first = *read_deadline_;
        if (write_deadline_ && *write_deadline_ < first) first = *write_deadline_;
        if (phase_deadline_ && *phase_deadline_ < first) first = *phase_deadline_;
        return first;
    }
    void Reconcile() {
        if (stopped_) return;
        const auto first = Earliest();
        if (first == TimePoint::max()) {
            scheduler_.Cancel(token_);
            armed_deadline_.reset();
            return;
        }
        // Earlier waits can safely wake later deadlines; avoid churn when idle
        // activity moves its deadline forward.
        if (token_.Valid() && armed_deadline_ && *armed_deadline_ <= first) return;
        scheduler_.Cancel(token_);
        armed_deadline_.reset();
        token_ = scheduler_.ScheduleAfter(DelayUntil(first), [this]() noexcept { OnWake(); });
        armed_deadline_ = first;
    }
    void ReconcileNoThrow() noexcept {
        try { Reconcile(); }
        catch (const std::bad_alloc&) { Fail(ErrorCode::RESOURCE_EXHAUSTED); }
        catch (...) { Fail(ErrorCode::INTERNAL); }
    }
    void OnWake() noexcept {
        token_.Reset();
        armed_deadline_.reset();
        if (stopped_) return;
        const auto now = Clock::now();
        if (idle_deadline_ && *idle_deadline_ <= now) idle_expired_ = true;
        if (read_deadline_ && *read_deadline_ <= now) read_expired_ = true;
        if (write_deadline_ && *write_deadline_ <= now) write_expired_ = true;
        if (phase_deadline_ && *phase_deadline_ <= now) phase_expired_ = true;
        UpdateFlags();
        if (idle_expired_ || read_expired_ || write_expired_ || phase_expired_) {
            Stop();
            owner_.OnTimeout(ErrorCode::CANCELLED);
            return;
        }
        ReconcileNoThrow();
    }
    void Fail(ErrorCode reason) noexcept {
        Stop();
        owner_.OnTimeout(reason);
    }

    TimeoutScheduler& scheduler_;
    Owner& owner_;
    TimeoutToken token_;
    std::optional<TimePoint> idle_deadline_, read_deadline_, write_deadline_, phase_deadline_;
    std::optional<TimePoint> armed_deadline_;
    std::chrono::seconds idle_timeout_{0}, read_timeout_{0}, write_timeout_{0};
    uint32_t phase_generation_ = 0;
    uint8_t flags_ = 0;
    bool idle_enabled_ = false, read_pending_ = false, write_pending_ = false, stopped_ = false;
    bool idle_expired_ = false, read_expired_ = false, write_expired_ = false, phase_expired_ = false;
};

}  // namespace acpp::transport::internet::detail
