#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/byte_reader.hpp"
#include "common/clock.hpp"
#include "common/container_util.hpp"
#include "common/defaults.hpp"
#include "common/error.hpp"
#include "transport/internet/timeout_scheduler.hpp"
#include "../src/common/awaitable_task_group.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <bitset>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>
namespace app::dns {

class DNSWorker;

struct Config {
    std::vector<udp::endpoint> servers;
    uint32_t timeout_sec = 5;
    size_t cache_size = defaults::kDnsCacheSize;
    uint32_t min_ttl = 60;
    uint32_t max_ttl = 3600;
};

struct DnsCacheStats {
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t entries = 0;
    uint64_t capacity = 0;
};

struct DnsResult : ResultStatus {
    std::vector<net::ip::address> addresses;
    bool from_cache = false;
    uint32_t ttl = 60;

    [[nodiscard]] bool Ok() const noexcept {
        return ResultStatus::Ok() && !addresses.empty();
    }
};

// One bounded cache owned by the main/control DNS executor.
class DnsCache {
public:
    using NegativeEvent = void (*)(std::string_view domain, std::string_view reason,
                                  uint64_t hits, std::string_view event);
    explicit DnsCache(size_t max_size, uint32_t min_ttl, uint32_t max_ttl,
                      NegativeEvent negative_event = nullptr)
        : capacity_(max_size)
        , min_ttl_(std::min(min_ttl, max_ttl))
        , max_ttl_(std::max(min_ttl, max_ttl))
        , negative_event_(negative_event) {
        if (capacity_ > 0) entries_.reserve(capacity_);
    }

    ~DnsCache() {
        for (const auto& node : order_) {
            if (!node.entry.expired_negative) Report(node, "shutdown");
        }
    }

    DnsCache(const DnsCache&) = delete;
    DnsCache& operator=(const DnsCache&) = delete;

    std::optional<DnsResult> GetResult(std::string_view domain) {
        const auto found = entries_.find(domain);
        if (found == entries_.end()) {
            ++misses_;
            return std::nullopt;
        }
        const auto node = found->second;
        const auto now = steady_clock::now();
        if (now >= node->entry.expire_time) {
            if (std::holds_alternative<memory::ThreadLocalString>(node->entry.answer)) {
                // Keep only bounded recovery metadata, never serve an expired
                // answer. It shares the cache's eviction slots, not a second map.
                if (!node->entry.expired_negative) {
                    node->entry.expired_negative = true;
                    ++expired_negatives_;
                    Report(*node, "expired");
                }
                order_.splice(order_.end(), order_, node);
            } else {
                entries_.erase(found);
                order_.erase(node);
            }
            ++misses_;
            return std::nullopt;
        }

        DnsCacheEntry& entry = node->entry;
        DnsResult result;
        if (const auto* reason = std::get_if<memory::ThreadLocalString>(&entry.answer)) {
            result.error = ErrorCode::DNS_NO_RECORD;
            result.error_msg.assign(reason->data(), reason->size());
            if (entry.negative_hits != UINT64_MAX) ++entry.negative_hits;
        } else {
            const auto& addresses = std::get<memory::ThreadLocalVector<net::ip::address>>(entry.answer);
            result.addresses.assign(addresses.begin(), addresses.end());
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
            entry.expire_time - now);
        result.ttl = static_cast<uint32_t>(std::max<int64_t>(remaining.count(), 1));
        result.from_cache = true;
        ++hits_;
        return result;
    }

    void Store(std::string_view domain, const DnsResult& result) {
        if (capacity_ == 0 || (!result.Ok() && result.error != ErrorCode::DNS_NO_RECORD)) {
            return;
        }
        const auto existing = entries_.find(domain);
        // 零 TTL 地址只供本次查询使用，不受本地 TTL 下限延长，也不保留载荷。
        if (result.Ok() && result.ttl == 0) {
            if (existing != entries_.end()) {
                const auto node = existing->second;
                Report(*node, "recovered");
                if (node->entry.expired_negative) --expired_negatives_;
                entries_.erase(existing);
                order_.erase(node);
            }
            return;
        }

        DnsCacheEntry prepared;
        if (result.Ok()) {
            auto& addresses = std::get<memory::ThreadLocalVector<net::ip::address>>(prepared.answer);
            addresses.assign(result.addresses.begin(), result.addresses.end());
        } else {
            prepared.answer.emplace<memory::ThreadLocalString>(
                result.error_msg.data(), result.error_msg.size());
        }
        const uint32_t ttl = result.ttl == 0 ? 0 : std::clamp(result.ttl, min_ttl_, max_ttl_);
        prepared.expire_time = steady_clock::now() + std::chrono::seconds(ttl);

        if (existing != entries_.end()) {
            const auto node = existing->second;
            if (result.Ok() || !node->entry.expired_negative) {
                Report(*node, result.Ok() ? "recovered" : "refreshed");
            }
            if (node->entry.expired_negative) --expired_negatives_;
            std::destroy_at(&node->entry);
            std::construct_at(&node->entry, std::move(prepared));
            order_.splice(order_.begin(), order_, node);
            return;
        }

        // Stage both owners before eviction. If hash-node allocation fails, remove
        // the unindexed list node while all old entries and their views are intact.
        order_.emplace_front(domain, std::move(prepared));
        const auto node = order_.begin();
        try {
            entries_.emplace(std::string_view(node->domain), node);
        } catch (...) {
            order_.erase(node);
            throw;
        }

        // Insertion is the only growth path and adds one entry, so one eviction
        // restores the bound. Expired entries leave lazily on lookup; sweeping the
        // whole table here would make every insert into a full cache O(capacity).
        if (entries_.size() > capacity_) {
            const auto victim = std::prev(order_.end());
            if (!victim->entry.expired_negative) Report(*victim, "evicted");
            if (victim->entry.expired_negative) --expired_negatives_;
            entries_.erase(std::string_view(victim->domain));
            order_.erase(victim);
        }
    }

    DnsCacheStats GetStats() const {
        return DnsCacheStats{
            .hits = hits_,
            .misses = misses_,
            .entries = entries_.size() - expired_negatives_,
            .capacity = capacity_,
        };
    }
private:
    struct DnsCacheEntry {
        std::variant<memory::ThreadLocalVector<net::ip::address>,
                     memory::ThreadLocalString> answer;
        time_point expire_time;
        uint64_t negative_hits = 0;
        bool expired_negative = false;
    };
    struct CacheNode {
        memory::ThreadLocalString domain;
        DnsCacheEntry entry;

        CacheNode(std::string_view name, DnsCacheEntry value)
            : domain(name), entry(std::move(value)) {}
    };
    using NodeList = memory::ThreadLocalList<CacheNode>;
    void Report(const CacheNode& node, std::string_view event) const noexcept {
        const auto* reason = std::get_if<memory::ThreadLocalString>(&node.entry.answer);
        if (!negative_event_ || !reason) return;
        try {
            negative_event_(std::string_view(node.domain), std::string_view(*reason),
                            node.entry.negative_hits, event);
        } catch (...) {
            // Optional diagnostics must not invalidate cached answers or cleanup.
        }
    }

    // New and replaced entries move to the front. Read hits do not reorder.
    NodeList order_;
    memory::ThreadLocalUnorderedMap<std::string_view, NodeList::iterator> entries_;
    size_t capacity_;
    uint32_t min_ttl_;
    uint32_t max_ttl_;
    NegativeEvent negative_event_;
    size_t expired_negatives_ = 0;
    uint64_t hits_ = 0;
    uint64_t misses_ = 0;
};

// One connected UDP socket per upstream, owned exclusively by the DNS executor.
// Pending pointers borrow live Exchange frames; registration is removed before
// those frames can leave. No receive operation or timeout belongs to a caller.
class DatagramExchange : public std::enable_shared_from_this<DatagramExchange> {
public:
    struct Reply {
        std::array<uint8_t, 512> bytes{};
        size_t size = 0;
        IoErrorCode error;
    };

    DatagramExchange(net::io_context& io, udp::endpoint endpoint)
        : socket_(io), endpoint_(endpoint), scheduler_(TimeoutScheduler::ForIoContext(io)),
          joined_(io) {}

    void RequestStop() noexcept {
        if (stopping_) return;
        stopping_ = true;
        FailAll(io_error::operation_aborted);
        IoErrorCode ignored;
        socket_.close(ignored);
        NotifyJoined();
    }

    net::awaitable<void> AsyncJoin() {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        co_await net::this_coro::throw_if_cancelled(false);
        RequestStop();
        (void)co_await joined_.async_receive(net::as_tuple(net::use_awaitable));
    }

    net::awaitable<Reply> Exchange(std::span<uint8_t> query, std::chrono::seconds timeout) {
        // The caller owns query until completion, including cancellation unwind.
        auto owner = shared_from_this();
        Reply failure;
        if (stopping_) {
            failure.error = io_error::operation_aborted;
            co_return failure;
        }
        ActiveExchange active(*this);
        if (issued_ == 65536 && !pending_.empty()) {
            failure.error = io_error::no_buffer_space;
            co_return failure;
        }
        if (!socket_.is_open() || issued_ == 65536) {
            // Never recycle an ID on a live socket: a delayed reply could have
            // the same question. Bind the replacement while the old socket is
            // still open, ensuring a different source port, then retire it.
            udp::socket replacement(socket_.get_executor());
            replacement.open(endpoint_.protocol(), failure.error);
            if (!failure.error) replacement.connect(endpoint_, failure.error);
            // Sending a tiny datagram must never block the main/control loop.
            if (!failure.error) replacement.non_blocking(true, failure.error);
            if (failure.error) co_return failure;
            socket_ = std::move(replacement);
            ++generation_;
            used_ids_.reset();
            issued_ = 0;
        }
        uint16_t id;
        // Source ports now persist: unpredictable IDs are essential. Do not
        // replace this with a counter or a predictable general-purpose PRNG.
        if (RAND_bytes(reinterpret_cast<uint8_t*>(&id), sizeof(id)) != 1) {
            failure.error = io_error::fault;
            co_return failure;
        }
        while (used_ids_.test(id)) ++id;
        StoreU16BE(query.data(), id);
        Pending request(*this, id, query);
        pending_.emplace(id, &request);
        if (!scheduler_.ScheduleAfter(timeout, request)) {
            pending_.erase(id);
            failure.error = io_error::operation_aborted;
            co_return failure;
        }
        used_ids_.set(id);
        ++issued_;
        socket_.send(net::buffer(query.data(), query.size()), 0, failure.error);
        if (failure.error) {
            used_ids_.reset(id);
            --issued_;
            co_return failure;
        }
        Receive();
        (void)co_await request.completion.async_receive(net::as_tuple(net::use_awaitable));
        if (!request.reply.size && !request.reply.error) request.reply.error = io_error::operation_aborted;
        co_return std::move(request.reply);
    }

private:
    struct ActiveExchange {
        explicit ActiveExchange(DatagramExchange& owner) noexcept : owner(owner) {
            ++owner.active_;
        }
        ~ActiveExchange() {
            --owner.active_;
            owner.NotifyJoined();
        }
        DatagramExchange& owner;
    };

    void NotifyJoined() noexcept {
        if (stopping_ && active_ == 0 && !reading_) joined_.close();
    }

    struct Pending final : TimeoutEvent {
        Pending(DatagramExchange& owner, uint16_t id, std::span<const uint8_t> query)
            : owner(owner), id(id), query(query), completion(owner.socket_.get_executor()) {}
        ~Pending() {
            Cancel();
            const auto it = owner.pending_.find(id);
            if (it != owner.pending_.end() && it->second == this) owner.pending_.erase(it);
            owner.CancelIdleReceive();
        }
        DatagramExchange& owner;
        uint16_t id;
        std::span<const uint8_t> query;
        SignalChannel completion;
        void OnTimeout() override { owner.Complete(id, io_error::timed_out); }
        Reply reply;
    };

    // Match the echoed QNAME/QTYPE/QCLASS, not just the 16-bit transaction ID.
    // Support compressed names with bounded pointer traversal and ASCII folding.
    static bool Matches(std::span<const uint8_t> packet, std::span<const uint8_t> query) {
        if (packet.size() < 12 || (packet[2] & 0xf8) != 0x80 ||
            packet[4] != 0 || packet[5] != 1) return false;
        size_t pos = 12, expected = 12, after_name = 0;
        for (size_t steps = 0; steps < 256; ++steps) {
            if (pos >= packet.size() || expected >= query.size()) return false;
            const auto length = packet[pos++];
            if ((length & 0xc0) == 0xc0) {
                if (pos >= packet.size()) return false;
                const size_t ptr = ((static_cast<size_t>(length) & 0x3f) << 8) | packet[pos];
                ++pos;
                if (ptr < 12 || ptr >= pos - 2) return false;
                if (!after_name) after_name = pos;
                pos = ptr;
                continue;
            }
            if (length > 63 || length != query[expected++] ||
                pos + length > packet.size() || expected + length > query.size()) return false;
            if (length == 0) {
                if (after_name) pos = after_name;
                return pos + 4 <= packet.size() && expected + 4 == query.size() &&
                    std::equal(query.begin() + expected, query.end(), packet.begin() + pos);
            }
            auto lower = [](uint8_t c) { return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c; };
            for (size_t i = 0; i < length; ++i) {
                if (lower(packet[pos++]) != lower(query[expected++])) return false;
            }
        }
        return false;
    }

    void CancelIdleReceive() {
        if (reading_ && pending_.empty()) {
            IoErrorCode ignored;
            socket_.cancel(ignored);
        }
    }

    void Complete(uint16_t id, IoErrorCode error, size_t size = 0) {
        const auto it = pending_.find(id);
        if (it == pending_.end()) return;
        Pending& request = *it->second;
        pending_.erase(it);
        scheduler_.Cancel(request);
        request.reply.error = error;
        request.reply.size = size;
        if (size) std::copy_n(buffer_.begin(), size, request.reply.bytes.begin());
        request.completion.close();
        CancelIdleReceive();
    }

    void FailAll(IoErrorCode error) {
        while (!pending_.empty()) Complete(pending_.begin()->first, error);
    }

    void Receive() {
        if (stopping_ || reading_ || pending_.empty()) return;
        reading_ = true;
        try {
            socket_.async_receive(net::buffer(buffer_),
                [self = shared_from_this(), generation = generation_](IoErrorCode ec, size_t size) {
                    self->reading_ = false;
                    if (self->stopping_) {
                        self->NotifyJoined();
                        return;
                    }
                    if (generation != self->generation_) {
                        self->Receive();
                        return;
                    }
                    if (!ec && size >= 2) {
                        const uint16_t id = LoadU16BE(self->buffer_.data());
                        const auto it = self->pending_.find(id);
                        if (it != self->pending_.end() &&
                            Matches(std::span(self->buffer_.data(), size), it->second->query)) {
                            self->Complete(id, {}, size);
                        }
                    } else if (ec && ec != io_error::operation_aborted && ec != io_error::message_size) {
                        self->FailAll(ec);
                    }
                    // An idle cancellation can race a new registration. Re-arm
                    // only after the old receive has released the shared buffer.
                    self->Receive();
                });
        } catch (const std::bad_alloc&) {
            reading_ = false;
            FailAll(io_error::no_memory);
        } catch (...) {
            reading_ = false;
            FailAll(io_error::fault);
        }
    }

    udp::socket socket_;
    udp::endpoint endpoint_;
    TimeoutScheduler& scheduler_;
    SignalChannel joined_;
    memory::ThreadLocalUnorderedMap<uint16_t, Pending*> pending_;
    std::array<uint8_t, 512> buffer_{};
    std::bitset<65536> used_ids_;
    size_t issued_ = 0;
    uint64_t generation_ = 0;
    size_t active_ = 0;
    bool stopping_ = false;
    bool reading_ = false;
};

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
            if (pending->result) {
                co_return pending->waiters == 1
                    ? std::move(*pending->result)
                    : *pending->result;
            }
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

// The single owner of DNS sockets, cache, inflight queries and timers in
// production, on the main control Worker's io_context (no additional thread).
// Clients submit owned names through a bounded mailbox and only receive values;
// no live DNS state is exposed across threads.
class DNSWorker final {
public:
    DNSWorker(net::io_context& main_context,
              const Config& config, size_t mailbox_capacity);
    ~DNSWorker();

    DNSWorker(const DNSWorker&) = delete;
    DNSWorker& operator=(const DNSWorker&) = delete;

    net::awaitable<DnsResult> Resolve(std::string domain);
    net::awaitable<DnsCacheStats> GetCacheStats();

    // Main/control executor only. Both operations are idempotent. AsyncJoin
    // requests stop and waits for admitted requests and actual upstream I/O
    // completion; keep this owner and its executor alive until it returns.
    void RequestStop() noexcept;
    net::awaitable<void> AsyncJoin();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class DNS final {
public:
    // Client only: all resolution state and sockets belong to DNSWorker.
    explicit DNS(DNSWorker& worker) noexcept : worker_(worker) {}

    DNS(const DNS&) = delete;
    DNS& operator=(const DNS&) = delete;

    // Copies domain at task creation. The DNSWorker must outlive the task.
    net::awaitable<DnsResult> Resolve(std::string_view domain);

private:
    DNSWorker& worker_;
};

}  // namespace app::dns
