#pragma once

#include "acppnode/app/dns/dns.hpp"
#include "acppnode/common/allocator.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>

#include <memory>
#include <optional>
#include <string_view>
#include <type_traits>

namespace acpp::app::dns {

// All access, coroutine resumes and destruction belong to one Worker. A shared
// pending result owns the completion channel; no waiter pointers escape into
// the registry and cancellation removes only the cancelling receive operation.
class InflightResolves {
    struct Pending {
        Pending(net::io_context& io_context, std::string_view name)
            : domain(name), completion(io_context) {}

        memory::ThreadLocalString domain;
        SignalChannel completion;
        std::optional<DnsResult> result;
    };
    using PendingPtr = std::shared_ptr<Pending>;
    using Table = memory::ThreadLocalUnorderedMap<std::string_view, PendingPtr>;

    struct Completion {
        Table& table;
        Pending& pending;

        ~Completion() noexcept {
            table.erase(std::string_view(pending.domain));
            if (!pending.result) {
                static_assert(std::is_nothrow_default_constructible_v<DnsResult>);
                pending.result.emplace();
                pending.result->error = ErrorCode::DNS_RESOLVE_FAILED;
            }
            // Closing broadcasts to every outstanding receive. No result
            // copies or per-waiter allocations occur on the completion path.
            pending.completion.close();
        }
    };

public:
    explicit InflightResolves(net::io_context& io_context) : io_context_(io_context) {}
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
    }

    template <typename Query>
    net::awaitable<DnsResult> Run(std::string_view domain, Query query) {
        if (stopping_) {
            DnsResult cancelled;
            cancelled.error = ErrorCode::CANCELLED;
            co_return cancelled;
        }
        if (const auto found = table_.find(domain); found != table_.end()) {
            auto pending = found->second;
            (void)co_await pending->completion.async_receive(
                net::as_tuple(net::use_awaitable));
            if (pending->result) co_return *pending->result;

            DnsResult cancelled;
            cancelled.error = ErrorCode::CANCELLED;
            co_return cancelled;
        }

        auto pending = std::allocate_shared<Pending>(
            memory::ThreadLocalAllocator<Pending>{}, io_context_, domain);
        table_.emplace(std::string_view(pending->domain), pending);
        Completion completion{table_, *pending};

        // Move the authoritative result once. Any failure before this point
        // still removes the entry and signals subscribers through Completion.
        static_assert(std::is_nothrow_move_constructible_v<DnsResult>);
        try {
            auto result = co_await query();
            if (!stopping_) pending->result.emplace(std::move(result));
        } catch (const IoSystemError& error) {
            if (error.code() == io_error::operation_aborted) {
                pending->result.emplace();
                pending->result->error = ErrorCode::CANCELLED;
            }
            throw;
        }
        co_return *pending->result;
    }

private:
    net::io_context& io_context_;
    Table table_;
    bool stopping_ = false;
};

}  // namespace acpp::app::dns
