#pragma once

// DNSWorker 的私有实现：上游 socket、在途请求与缓存只属于主控执行器上的
// DNSWorker（src/app/dns.cpp）。只有 dns.cpp 与直接验证这些组件的测试包含本头。

#include "app/dns.hpp"
#include "common/allocator.hpp"
#include "common/ascii.hpp"
#include "common/awaitable_task_group.hpp"
#include "common/byte_reader.hpp"
#include "common/clock.hpp"
#include "transport/timeout_scheduler.hpp"
#include <asio/as_tuple.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/read.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <variant>
#include <list>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace app {

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
        , negative_event_(negative_event) {}

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
        const auto now = common::steady_clock::now();
        if (now >= node->entry.expire_time) {
            if (std::holds_alternative<std::string>(node->entry.answer)) {
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
        if (const auto* reason = std::get_if<std::string>(&entry.answer)) {
            result.error = common::ErrorCode::DNS_NO_RECORD;
            result.error_msg.assign(reason->data(), reason->size());
            if (entry.negative_hits != UINT64_MAX) ++entry.negative_hits;
        } else {
            const auto& addresses = std::get<std::vector<net::ip::address>>(entry.answer);
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
        if (capacity_ == 0 || (!result.Ok() && result.error != common::ErrorCode::DNS_NO_RECORD)) {
            return;
        }
        // RFC 2308 §5: a negative answer without a usable SOA (TTL 0) is not
        // cached. Any expired-negative metadata stays for a later "recovered".
        if (!result.Ok() && result.ttl == 0) return;
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

        common::CheckTestAllocationFault();
        DnsCacheEntry prepared;
        if (result.Ok()) {
            auto& addresses = prepared.answer.emplace<std::vector<net::ip::address>>();
            addresses.assign(result.addresses.begin(), result.addresses.end());
        } else {
            prepared.answer.emplace<std::string>(
                result.error_msg.data(), result.error_msg.size());
        }
        const uint32_t ttl = result.ttl == 0 ? 0 : std::clamp(result.ttl, min_ttl_, max_ttl_);
        prepared.expire_time = common::steady_clock::now() + std::chrono::seconds(ttl);

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
        DnsCacheEntry() = default;
        std::variant<std::vector<net::ip::address>,
                     std::string> answer;
        common::time_point expire_time;
        uint64_t negative_hits = 0;
        bool expired_negative = false;
    };
    struct CacheNode {
        std::string domain;
        DnsCacheEntry entry;

        CacheNode(std::string_view name, DnsCacheEntry value)
            : domain(name), entry(std::move(value)) {}
    };
    using NodeList = std::list<CacheNode>;
    void Report(const CacheNode& node, std::string_view event) const noexcept {
        const auto* reason = std::get_if<std::string>(&node.entry.answer);
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
    std::unordered_map<std::string_view, NodeList::iterator> entries_;
    size_t capacity_;
    uint32_t min_ttl_;
    uint32_t max_ttl_;
    NegativeEvent negative_event_;
    size_t expired_negatives_ = 0;
    uint64_t hits_ = 0;
    uint64_t misses_ = 0;
};

// RFC 6891 requester UDP payload size. 1232 follows DNS Flag Day 2020 / RFC 9715
// so answers avoid IP fragmentation; larger answers arrive with TC=1 and are
// re-queried over TCP (RFC 7766 §5).
inline constexpr size_t kDnsUdpPayloadSize = 1232;

// Upstream exchanges owned exclusively by the DNS executor: a fresh UDP socket
// per query and short-lived TCP retries for truncated answers. Each in-flight
// socket lives in its exchange frame and stays linked so RequestStop can close
// it; unlinking happens before that frame leaves.
class UpstreamExchange : public std::enable_shared_from_this<UpstreamExchange> {
public:
    struct Reply {
        std::vector<uint8_t> bytes;
        IoErrorCode error;
    };

    UpstreamExchange(net::io_context& io, udp::endpoint endpoint)
        : io_(io), endpoint_(endpoint), scheduler_(transport::TimeoutScheduler::ForIoContext(io)),
          joined_(io) {}

    void RequestStop() noexcept {
        if (stopping_) return;
        stopping_ = true;
        // Closing completes in-flight operations later; the lists stay intact.
        for (auto* exchange = datagrams_; exchange; exchange = exchange->next) exchange->Abort();
        for (auto* exchange = streams_; exchange; exchange = exchange->next) exchange->Abort();
        NotifyJoined();
    }

    net::awaitable<void> AsyncJoin() {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        co_await net::this_coro::throw_if_cancelled(false);
        RequestStop();
        (void)co_await joined_.async_receive(net::as_tuple(net::use_awaitable));
    }

    // RFC 5452 §9.2: every query gets its own connected socket, so the kernel
    // picks an unpredictable ephemeral source port and drops datagrams from any
    // other address; the random ID adds 16 bits. timeout is the remaining
    // budget, and a non-positive one fails at once. The caller owns query
    // until completion, including cancellation unwind.
    net::awaitable<Reply> ExchangeDatagram(std::span<uint8_t> query, std::chrono::milliseconds timeout) {
        auto owner = shared_from_this();
        Reply reply;
        if (stopping_) {
            reply.error = io_error::operation_aborted;
            co_return reply;
        }
        if (timeout <= std::chrono::milliseconds::zero()) {
            reply.error = io_error::timed_out;
            co_return reply;
        }
        ActiveExchange active(*this);
        common::CheckTestAllocationFault();
        InFlight<udp::socket> exchange(*this, datagrams_);
        exchange.socket.open(endpoint_.protocol(), reply.error);
        if (!reply.error) exchange.socket.connect(endpoint_, reply.error);
        // Reads after a readiness wait must never block the control loop.
        if (!reply.error) exchange.socket.non_blocking(true, reply.error);
        if (reply.error) co_return reply;
        uint16_t id;
        if (RAND_bytes(reinterpret_cast<uint8_t*>(&id), sizeof(id)) != 1) {
            reply.error = io_error::fault;
            co_return reply;
        }
        common::StoreU16BE(query.data(), id);
        if (!scheduler_.ScheduleAfter(timeout, exchange)) {
            reply.error = io_error::operation_aborted;
            co_return reply;
        }
        reply.error = co_await ExchangeOverDatagram(exchange.socket, query, reply.bytes);
        FinishReply(reply, exchange.timed_out);
        co_return reply;
    }

    // RFC 7766 §5: re-ask a truncated UDP question over TCP on the same
    // upstream. query already carries the ID of the truncated exchange; the
    // caller owns it until completion. One deadline bounds connect through the
    // last response byte.
    net::awaitable<Reply> ExchangeStream(std::span<const uint8_t> query, std::chrono::milliseconds timeout) {
        auto owner = shared_from_this();
        Reply reply;
        if (stopping_) {
            reply.error = io_error::operation_aborted;
            co_return reply;
        }
        if (timeout <= std::chrono::milliseconds::zero()) {
            reply.error = io_error::timed_out;
            co_return reply;
        }
        ActiveExchange active(*this);
        InFlight<tcp::socket> exchange(*this, streams_);
        if (!scheduler_.ScheduleAfter(timeout, exchange)) {
            reply.error = io_error::operation_aborted;
            co_return reply;
        }
        reply.error = co_await ExchangeOverStream(
            exchange.socket, tcp::endpoint(endpoint_.address(), endpoint_.port()), query, reply.bytes);
        FinishReply(reply, exchange.timed_out);
        co_return reply;
    }

    // RFC 6891 §7: a responder that does not implement EDNS answers FORMERR
    // or NOTIMP without echoing an OPT record. Callers retry once without OPT.
    [[nodiscard]] static bool RejectsEdns(std::span<const uint8_t> packet) noexcept {
        if (packet.size() < 12) return false;
        const uint8_t rcode = packet[3] & 0x0f;
        return (rcode == kRcodeFormatError || rcode == kRcodeNotImplemented) &&
               common::LoadU16BE(packet.data() + 10) == 0;
    }

    [[nodiscard]] static bool SkipWireName(std::span<const uint8_t> packet, size_t& offset) noexcept {
        size_t current_offset = offset;
        size_t next_offset = 0;
        size_t wire_len = 0;
        bool jumped = false;
        while (current_offset < packet.size()) {
            const uint8_t len = packet[current_offset];
            if (len == 0) {
                if (wire_len + 1 > 255) return false;
                offset = jumped ? next_offset : current_offset + 1;
                return true;
            }
            if ((len & 0xC0) == 0xC0) {
                if (current_offset + 1 >= packet.size()) return false;
                const size_t ptr = common::LoadU16BE(packet.data() + current_offset) & 0x3FFFu;
                if (ptr < 12 || ptr >= current_offset) return false;
                if (!jumped) {
                    next_offset = current_offset + 2;
                    jumped = true;
                }
                current_offset = ptr;
                continue;
            }
            if ((len & 0xC0) != 0) return false;
            if (packet.size() - current_offset <= static_cast<size_t>(len) + 1) return false;
            wire_len += static_cast<size_t>(len) + 1;
            if (wire_len >= 255) return false;
            current_offset += static_cast<size_t>(len) + 1;
        }
        return false;
    }
private:
    static constexpr uint8_t kRcodeFormatError = 1;
    static constexpr uint8_t kRcodeNotImplemented = 4;

    struct ActiveExchange {
        explicit ActiveExchange(UpstreamExchange& owner) noexcept : owner(owner) {
            ++owner.active_;
        }
        ~ActiveExchange() {
            --owner.active_;
            owner.NotifyJoined();
        }
        UpstreamExchange& owner;
    };

    void NotifyJoined() noexcept {
        if (stopping_ && active_ == 0) joined_.close();
    }

    template <typename Socket>
    struct InFlight final : transport::TimeoutEvent {
        InFlight(UpstreamExchange& owner, InFlight*& head)
            : head(head), socket(owner.io_), next(head) {
            if (next) next->prev = this;
            head = this;
        }
        ~InFlight() {
            Cancel();
            if (prev) prev->next = next; else head = next;
            if (next) next->prev = prev;
        }
        void Abort() noexcept {
            IoErrorCode ignored;
            socket.close(ignored);
        }
        void OnTimeout() override {
            timed_out = true;
            Abort();
        }
        InFlight*& head;
        Socket socket;
        InFlight* prev = nullptr;
        InFlight* next = nullptr;
        bool timed_out = false;
    };

    // A complete answer wins even if the deadline fired in the same turn.
    void FinishReply(Reply& reply, bool timed_out) const noexcept {
        if (!reply.error) return;
        if (timed_out) reply.error = io_error::timed_out;
        else if (stopping_) reply.error = io_error::operation_aborted;
        reply.bytes.clear();
    }

    // Waits for readability before sizing the buffer to the queued datagram
    // (Linux FIONREAD), one octet past the advertised payload so an oversized
    // reply stays detectable. Datagrams that do not answer this query are
    // dropped and the wait continues (RFC 5452 §9.1).
    static net::awaitable<IoErrorCode> ExchangeOverDatagram(
        udp::socket& socket, std::span<const uint8_t> query, std::vector<uint8_t>& response) {
        auto [send_error, sent] = co_await socket.async_send(
            net::buffer(query.data(), query.size()), net::as_tuple(net::use_awaitable));
        if (send_error) co_return send_error;
        for (;;) {
            auto [wait_error] = co_await socket.async_wait(
                udp::socket::wait_read, net::as_tuple(net::use_awaitable));
            if (wait_error) co_return wait_error;
            IoErrorCode error;
            const size_t queued = socket.available(error);
            if (error) co_return error;
            response.resize(std::clamp<size_t>(queued, 1, kDnsUdpPayloadSize + 1));
            const size_t size = socket.receive(net::buffer(response), 0, error);
            if (error == io_error::would_block) continue;
            // ICMP port unreachable surfaces here as connection_refused.
            if (error) co_return error;
            response.resize(size);
            if (size >= 2 && common::LoadU16BE(response.data()) == common::LoadU16BE(query.data()) &&
                (Matches(response, query) || RejectsEdnsWithoutQuestion(response, query))) {
                co_return IoErrorCode{};
            }
            response = {};  // Hold nothing across the next wait.
        }
    }

    static net::awaitable<IoErrorCode> ExchangeOverStream(
        tcp::socket& socket, tcp::endpoint endpoint,
        std::span<const uint8_t> query, std::vector<uint8_t>& response) {
        const auto bad_message = std::make_error_code(std::errc::bad_message);
        auto [connect_error] = co_await socket.async_connect(endpoint, net::as_tuple(net::use_awaitable));
        if (connect_error) co_return connect_error;
        // RFC 1035 §4.2.2: each TCP message carries a two-octet length prefix.
        std::array<uint8_t, 2> length{};
        common::StoreU16BE(length.data(), static_cast<uint16_t>(query.size()));
        const std::array<net::const_buffer, 2> request{
            net::buffer(length), net::buffer(query.data(), query.size())};
        auto [write_error, written] = co_await net::async_write(
            socket, request, net::as_tuple(net::use_awaitable));
        if (write_error) co_return write_error;
        auto [prefix_error, prefix_size] = co_await net::async_read(
            socket, net::buffer(length), net::as_tuple(net::use_awaitable));
        if (prefix_error) co_return prefix_error;
        const size_t expected = common::LoadU16BE(length.data());
        if (expected < 12) co_return bad_message;
        // Grow with bytes that actually arrived, never by the declared length.
        response.resize(std::min(expected, kDnsUdpPayloadSize));
        size_t received = 0;
        while (received < expected) {
            if (received == response.size()) response.resize(std::min(expected, response.size() * 2));
            auto [read_error, read] = co_await socket.async_read_some(
                net::buffer(response.data() + received, response.size() - received),
                net::as_tuple(net::use_awaitable));
            if (read_error) co_return read_error;
            received += read;
        }
        if (common::LoadU16BE(response.data()) != common::LoadU16BE(query.data()) ||
            !Matches(response, query)) {
            co_return bad_message;
        }
        co_return IoErrorCode{};
    }

    // RFC 1035 does not require an error reply to echo the question. Accept a
    // question-less rejection only for an EDNS query, and only to trigger the
    // plain retry: it carries no records for ParseResponse to trust.
    static bool RejectsEdnsWithoutQuestion(std::span<const uint8_t> packet,
                                           std::span<const uint8_t> query) noexcept {
        return packet.size() >= 12 && query.size() >= 12 && (packet[2] & 0xf8) == 0x80 &&
               common::LoadU16BE(query.data() + 10) == 1 &&
               common::LoadU16BE(packet.data() + 4) == 0 &&
               common::LoadU16BE(packet.data() + 6) == 0 &&
               common::LoadU16BE(packet.data() + 8) == 0 &&
               RejectsEdns(packet);
    }

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
                // An EDNS OPT record may follow the query's question.
                return pos + 4 <= packet.size() && expected + 4 <= query.size() &&
                    std::equal(query.begin() + expected, query.begin() + expected + 4,
                               packet.begin() + pos);
            }
            for (size_t i = 0; i < length; ++i) {
                if (common::ToLowerAscii(packet[pos++]) != common::ToLowerAscii(query[expected++])) return false;
            }
        }
        return false;
    }

    net::io_context& io_;
    udp::endpoint endpoint_;
    transport::TimeoutScheduler& scheduler_;
    common::SignalChannel joined_;
    InFlight<udp::socket>* datagrams_ = nullptr;
    InFlight<tcp::socket>* streams_ = nullptr;
    size_t active_ = 0;
    bool stopping_ = false;
};

// Executor-local service ownership: callers subscribe, never own the query.
// Retired generations remain counted until their query has actually unwound.
class InflightResolves {
    struct Pending {
        Pending(net::io_context& io_context, std::string_view name)
            : domain(name), completion(io_context) {}

        std::string domain;
        common::SignalChannel completion;
        std::optional<DnsResult> result;
        std::exception_ptr failure;
        transport::CancellationSource cancellation;
        size_t waiters = 0;
    };
    using PendingPtr = std::shared_ptr<Pending>;
    using Table = std::unordered_map<std::string_view, PendingPtr>;
    void Remove(Pending& pending) noexcept {
        const auto found = table_.find(std::string_view(pending.domain));
        if (found != table_.end() && found->second.get() == &pending) {
            table_.erase(found);
            common::MaybeShrinkHashContainer(table_, 8);
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
                result.error = common::ErrorCode::CANCELLED;
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
            pending->result->error = common::ErrorCode::CANCELLED;
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
            cancelled.error = common::ErrorCode::CANCELLED;
            co_return cancelled;
        }
        PendingPtr pending;
        if (const auto found = table_.find(domain); found != table_.end()) {
            pending = found->second;
        } else {
            if (active_ >= capacity_) {
                DnsResult rejected;
                rejected.error = common::ErrorCode::RESOURCE_EXHAUSTED;
                co_return rejected;
            }
            pending = std::make_shared<Pending>(io_context_, domain);
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
        cancelled.error = common::ErrorCode::CANCELLED;
        co_return cancelled;
    }

private:
    net::io_context& io_context_;
    Table table_;
    size_t capacity_;
    size_t active_ = 0;
    bool stopping_ = false;
    common::ResidentTaskGroup tasks_;
};

}  // namespace app
