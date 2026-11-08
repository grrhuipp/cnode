#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "transport/internet/timeout_scheduler.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <bitset>
#include <memory>
#include <openssl/rand.h>
#include <span>

namespace app::dns {

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
        query[0] = static_cast<uint8_t>(id >> 8);
        query[1] = static_cast<uint8_t>(id);
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
                        const uint16_t id = (self->buffer_[0] << 8) | self->buffer_[1];
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

} // namespace app::dns
