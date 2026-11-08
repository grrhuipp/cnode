#pragma once

#include "app/dns/dns.hpp"
#include "common/allocator.hpp"
#include "common/container_util.hpp"
#include "../../common/awaitable_task_group.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>

#include <exception>
#include <memory>
#include <optional>
#include <string_view>

namespace app::dns {

// Executor-local service ownership: callers subscribe, never own the query.
// Retired generations remain counted until their query has actually unwound.
class InflightResolves {
    struct Pending {
        Pending(net::io_context& io_context, std::string_view name)
            : domain(name), completion(io_context) {}

        memory::ThreadLocalString domain;
        SignalChannel completion;
        std::optional<DnsResult> result;
        std::exception_ptr failure;
        transport::CancellationSource cancellation;
        size_t waiters = 0;
    };
    using PendingPtr = std::shared_ptr<Pending>;
    using Table = memory::ThreadLocalUnorderedMap<std::string_view, PendingPtr>;

    void Remove(Pending& pending) noexcept {
        const auto found = table_.find(std::string_view(pending.domain));
        if (found != table_.end() && found->second.get() == &pending) {
            table_.erase(found);
            MaybeShrinkHashContainer(table_, 8);
        }
    }

    struct Subscription {
        InflightResolves& owner;
        Pending& pending;
        ~Subscription() noexcept {
            if (--pending.waiters == 0 && !pending.result && !pending.failure) {
                // Unlink before cancellation: a new caller must start a fresh
                // generation, and late completion may not erase that entry.
                owner.Remove(pending);
                pending.cancellation.Stop();
            }
        }
    };

    template <typename Query>
    net::awaitable<void> Execute(PendingPtr pending, Query query) {
        DnsResult result;
        std::exception_ptr failure;
        try {
            result = co_await query(std::string_view(pending->domain));
        } catch (const IoSystemError& error) {
            if (error.code() == io_error::operation_aborted) {
                result.error = ErrorCode::CANCELLED;
            } else {
                failure = std::current_exception();
            }
        } catch (...) {
            failure = std::current_exception();
        }
        if (!pending->result) {
            if (failure) pending->failure = std::move(failure);
            else pending->result.emplace(std::move(result));
        }
        Remove(*pending);
        --active_;
        pending->completion.close();
    }

public:
    explicit InflightResolves(net::io_context& io_context, size_t capacity)
        : io_context_(io_context), capacity_(capacity), tasks_(io_context.get_executor()) {}
    InflightResolves(const InflightResolves&) = delete;
    InflightResolves& operator=(const InflightResolves&) = delete;

    void RequestStop() noexcept {
        if (stopping_) return;
        stopping_ = true;
        for (const auto& [domain, pending] : table_) {
            pending->result.emplace();
            pending->result->error = ErrorCode::CANCELLED;
            pending->completion.close();
        }
        tasks_.Tasks().Cancel();
    }

    net::awaitable<void> AsyncJoin() {
        RequestStop();
        co_await tasks_.AsyncJoin();
    }

    template <typename Query>
    net::awaitable<DnsResult> Run(std::string_view domain, Query query) {
        if (stopping_) {
            DnsResult cancelled;
            cancelled.error = ErrorCode::CANCELLED;
            co_return cancelled;
        }
        PendingPtr pending;
        if (const auto found = table_.find(domain); found != table_.end()) {
            pending = found->second;
        } else {
            if (active_ >= capacity_) {
                DnsResult rejected;
                rejected.error = ErrorCode::RESOURCE_EXHAUSTED;
                co_return rejected;
            }
            pending = memory::AllocateShared<Pending>(io_context_, domain);
            table_.emplace(std::string_view(pending->domain), pending);
            ++active_;
            try {
                tasks_.Tasks().Spawn(Execute(pending, std::move(query)), &pending->cancellation);
            } catch (...) {
                --active_;
                Remove(*pending);
                throw;
            }
        }
        ++pending->waiters;
        Subscription subscription{*this, *pending};
        if (!pending->result && !pending->failure) {
            (void)co_await pending->completion.async_receive(net::as_tuple(net::use_awaitable));
        }
        const auto cancellation = co_await net::this_coro::cancellation_state;
        if (cancellation.cancelled() == net::cancellation_type::none) {
            if (pending->failure) std::rethrow_exception(pending->failure);
            if (pending->result) co_return *pending->result;
        }
        DnsResult cancelled;
        cancelled.error = ErrorCode::CANCELLED;
        co_return cancelled;
    }

private:
    net::io_context& io_context_;
    Table table_;
    size_t capacity_;
    size_t active_ = 0;
    bool stopping_ = false;
    ResidentTaskGroup tasks_;
};

}  // namespace app::dns
