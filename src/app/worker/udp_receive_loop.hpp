#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "transport/internet/datagram_socket.hpp"

#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <type_traits>
#include <utility>

namespace detail {

class UdpReceiveBuffer final {
public:
    static constexpr size_t kMaxWireBytes = 65535;

    explicit UdpReceiveBuffer(memory::worker_memory& pool) noexcept
        : pool_(pool), large_(pool.resource()) {}

    void Release() noexcept {
        small_ = buf::BufferGuard{};
        if (large_.capacity() != 0) {
            memory::ByteVector empty{large_.get_allocator()};
            large_.swap(empty);
        }
    }

    [[nodiscard]] net::mutable_buffer Prepare(size_t available_bytes) {
        const size_t capacity = std::clamp<size_t>(
            available_bytes, 1, kMaxWireBytes);
        if (capacity <= buf::Buffer::kSize) {
            if (large_.capacity() != 0) {
                memory::ByteVector empty{large_.get_allocator()};
                large_.swap(empty);
            }
            if (!small_) {
                small_ = buf::BufferGuard{buf::Buffer::New(pool_)};
                if (!small_) {
                    return {};
                }
            }
            return net::buffer(small_->data, buf::Buffer::kSize);
        }

        small_ = buf::BufferGuard{};
        try {
            large_.resize(capacity);
        } catch (const std::bad_alloc&) {
            Release();
            return {};
        }
        return net::buffer(large_.data(), large_.size());
    }

    [[nodiscard]] std::span<const uint8_t> Data(size_t bytes) const noexcept {
        if (!large_.empty()) {
            return std::span<const uint8_t>(
                large_.data(), std::min(bytes, large_.size()));
        }
        if (small_) {
            return std::span<const uint8_t>(
                small_->data,
                std::min(bytes, static_cast<size_t>(buf::Buffer::kSize)));
        }
        return {};
    }

private:
    memory::worker_memory& pool_;
    buf::BufferGuard small_;
    memory::ByteVector large_;
};

}  // namespace detail
namespace worker_detail {

[[nodiscard]] inline bool IsTransientReceiveError(
    const IoErrorCode& error) noexcept {
    return error == io_error::would_block || error == io_error::try_again ||
        error == io_error::interrupted ||
        error == io_error::connection_refused ||
        error == io_error::connection_reset;
}

template <class IsOwned, class ProcessDatagram>
net::awaitable<void> RunUdpReceiveLoop(
    std::shared_ptr<udp::socket> socket,
    IsOwned is_owned,
    ProcessDatagram process_datagram,
    uint64_t& resource_drops,
    memory::worker_memory& pool) {
    static_assert(std::is_nothrow_invocable_r_v<
        bool, IsOwned&, const std::shared_ptr<udp::socket>&>);
    static_assert(std::is_same_v<std::invoke_result_t<
        ProcessDatagram&, const udp::endpoint&, std::span<const uint8_t>>, void>);
    static constexpr size_t kMaxReceiveBatch = 32;
    if (socket && socket->is_open() && !socket->non_blocking()) {
        IoErrorCode ignored;
        socket->non_blocking(true, ignored);
    }
    detail::UdpReceiveBuffer receive_buffer(pool);
    while (true) {
        receive_buffer.Release();
        if (!is_owned(socket)) {
            co_return;
        }

        auto [wait_error] = co_await socket->async_wait(
            udp::socket::wait_read, net::as_tuple(net::use_awaitable));
        if (!is_owned(socket)) {
            co_return;
        }
        if (wait_error) {
            if (IsTransientReceiveError(wait_error)) {
                continue;
            }
            throw IoSystemError(wait_error);
        }

        for (size_t drained = 0; drained < kMaxReceiveBatch; ++drained) {
            if (!is_owned(socket)) {
                receive_buffer.Release();
                co_return;
            }
            IoErrorCode probe_error;
            const size_t datagram_size =
                transport::internet::PeekDatagramSize(*socket, probe_error);
            if (probe_error) {
                if (probe_error == io_error::would_block ||
                    probe_error == io_error::try_again) {
                    break;
                }
                if (IsTransientReceiveError(probe_error)) {
                    continue;
                }
                throw IoSystemError(probe_error);
            }

            const auto storage = receive_buffer.Prepare(datagram_size);
            if (storage.size() == 0) {
                udp::endpoint discarded_peer;
                std::array<uint8_t, 1> discard_byte{};
                IoErrorCode discard_error;
                (void)socket->receive_from(
                    net::buffer(discard_byte), discarded_peer, 0, discard_error);
                if (discard_error == io_error::would_block ||
                    discard_error == io_error::try_again) {
                    break;
                }
                if (IsTransientReceiveError(discard_error)) {
                    continue;
                }
                if (discard_error && discard_error != io_error::message_size) {
                    throw IoSystemError(discard_error);
                }
                ++resource_drops;
                continue;
            }

            udp::endpoint peer;
            IoErrorCode receive_error;
            const size_t received_bytes = socket->receive_from(
                storage, peer, 0, receive_error);
            if (!is_owned(socket)) {
                receive_buffer.Release();
                co_return;
            }
            if (receive_error == io_error::would_block ||
                receive_error == io_error::try_again) {
                break;
            }
            if (receive_error == io_error::message_size) {
                ++resource_drops;
                continue;
            }
            if (receive_error) {
                if (IsTransientReceiveError(receive_error)) {
                    continue;
                }
                throw IoSystemError(receive_error);
            }
            if (received_bytes == 0) {
                continue;
            }

            const auto payload = receive_buffer.Data(received_bytes);
            try {
                process_datagram(peer, payload);
            } catch (const std::bad_alloc&) {
                ++resource_drops;
            }
        }
    }
}

}  // namespace worker_detail
