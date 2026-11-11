#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"
#include "transport/async_stream.hpp"

#include <asio/as_tuple.hpp>
#include <asio/buffer.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <type_traits>

namespace transport::internet {

struct ReceivedDatagram {
    udp::endpoint source;
    // A successful receive owns at least one buffer, including a zero-byte
    // datagram. Cancellation/close is reported as an error, never as EOF.
    buf::MultiBuffer payload;
};

class DatagramSocket final {
    struct Impl;

public:
    class ReadOperation final {
    public:
        ReadOperation(const ReadOperation&) = delete;
        ReadOperation& operator=(const ReadOperation&) = delete;
        ReadOperation(ReadOperation&&) = delete;
        ReadOperation& operator=(ReadOperation&&) = delete;
        ~ReadOperation() noexcept;

        [[nodiscard]] net::awaitable<ReceivedDatagram> Receive();
        [[nodiscard]] bool Cancelled() const noexcept;
        [[nodiscard]] common::ErrorCode CancellationReason() const noexcept;

    private:
        friend class DatagramSocket;
        friend struct DatagramSocket::Impl;
        explicit ReadOperation(Impl& impl);
        Impl* impl_;
        uint64_t generation_;
    };

    class WriteOperation final {
    public:
        WriteOperation(const WriteOperation&) = delete;
        WriteOperation& operator=(const WriteOperation&) = delete;
        WriteOperation(WriteOperation&&) = delete;
        WriteOperation& operator=(WriteOperation&&) = delete;
        ~WriteOperation() noexcept;

        [[nodiscard]] net::awaitable<void> SendTo(
            udp::endpoint destination, std::span<const net::const_buffer> buffers);
        [[nodiscard]] net::awaitable<void> SendTo(
            udp::endpoint destination, buf::MultiBuffer payload);
        [[nodiscard]] bool Cancelled() const noexcept;
        [[nodiscard]] common::ErrorCode CancellationReason() const noexcept;

    private:
        friend class DatagramSocket;
        friend struct DatagramSocket::Impl;
        explicit WriteOperation(Impl& impl);
        void CheckAvailable();

        Impl* impl_;
        uint64_t generation_;
        bool send_started_ = false;
    };

    DatagramSocket(net::io_context& io_context,
                   const net::ip::address& bind_address);
    ~DatagramSocket() noexcept;
    DatagramSocket(const DatagramSocket&) = delete;
    DatagramSocket& operator=(const DatagramSocket&) = delete;
    DatagramSocket(DatagramSocket&&) = delete;
    DatagramSocket& operator=(DatagramSocket&&) = delete;

    [[nodiscard]] ReadOperation StartRead();
    [[nodiscard]] WriteOperation StartWrite();

    void SetIdleTimeout(std::chrono::seconds timeout);
    void SetReadTimeout(std::chrono::seconds timeout);
    void SetWriteTimeout(std::chrono::seconds timeout);
    [[nodiscard]] PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout);
    void ClearPhaseDeadline() noexcept;
    [[nodiscard]] bool ConsumeIdleTimeout() noexcept;
    [[nodiscard]] bool ConsumeReadTimeout() noexcept;
    [[nodiscard]] bool ConsumeWriteTimeout() noexcept;
    [[nodiscard]] bool ConsumePhaseDeadline() noexcept;
    void TouchActivity() noexcept;

    [[nodiscard]] CancellationSource& Cancellation() noexcept;
    void Cancel() noexcept;
    void Close() noexcept;
    [[nodiscard]] bool IsIPv6() const noexcept;
    [[nodiscard]] udp::endpoint LocalEndpoint() const;
    [[nodiscard]] static std::size_t ActiveCount() noexcept;

private:
    std::unique_ptr<Impl> impl_;
};

// Length of the datagram at the head of `socket`'s receive queue, probed with a
// non-consuming recv(MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT); `error` is
// would_block when the queue is empty, and a pending socket error (e.g. an ICMP
// port unreachable) is reported and cleared like a receive would. Unlike
// FIONREAD (socket.available()), it tells an empty queue from a zero-length
// datagram, so a receive sized by it cannot truncate a datagram that arrived
// after the probe. The owning Worker is the socket's only reader, so the
// probed datagram is still the head at the following receive.
[[nodiscard]] std::size_t PeekDatagramSize(udp::socket& socket, IoErrorCode& error) noexcept;

// 共享 UDP 监听的收包暂存：等待可读时不持有缓冲；就绪后按探测长度借用一个
// Buffer，超过 Buffer 容量才改用连续存储。每轮等待前 Release() 归还。
class UdpReceiveBuffer final {
public:
    static constexpr std::size_t kMaxWireBytes = 65535;

    void Release() noexcept;
    // 返回空缓冲表示分配失败，调用方应丢弃队首数据报。
    [[nodiscard]] net::mutable_buffer Prepare(std::size_t available_bytes);
    [[nodiscard]] std::span<const uint8_t> Data(std::size_t bytes) const noexcept;

private:
    buf::BufferGuard small_;
    memory::ByteVector large_;
};

// 不终止监听的收包错误：队列暂空、被信号打断，以及 ICMP 回报的对端不可达/重置
// （无连接监听上它只属于某个对端，不代表本地 socket 故障）。
[[nodiscard]] bool IsTransientUdpReceiveError(const IoErrorCode& error) noexcept;

// 共享 UDP 监听 socket 的唯一收包循环（原生 UDP 入口与 QUIC 入口共用）。
// 每次可读至多同步排空 kMaxBatch 个数据报再让出事件循环；每个数据报先探测长度
// 再按需借用缓冲，借用失败或超长则丢弃队首并调用 |on_resource_drop|。
// |is_owned| 在每次挂起前后与每个数据报前重新检查，返回 false 即结束循环；
// |process_datagram| 同步消费借用视图，返回后视图失效，其抛出的 bad_alloc 计为
// 资源丢弃，其他异常与非瞬时 socket 错误一并结束循环并向上传播。
template <class IsOwned, class ProcessDatagram, class OnResourceDrop>
net::awaitable<void> RunUdpReceiveLoop(
    std::shared_ptr<udp::socket> socket,
    IsOwned is_owned,
    ProcessDatagram process_datagram,
    OnResourceDrop on_resource_drop) {
    static_assert(std::is_nothrow_invocable_r_v<
        bool, IsOwned&, const std::shared_ptr<udp::socket>&>);
    static_assert(std::is_same_v<std::invoke_result_t<
        ProcessDatagram&, const udp::endpoint&, std::span<const uint8_t>>, void>);
    static_assert(std::is_nothrow_invocable_v<OnResourceDrop&>);
    static constexpr std::size_t kMaxBatch = 32;
    if (socket && socket->is_open() && !socket->non_blocking()) {
        IoErrorCode ignored;
        socket->non_blocking(true, ignored);
    }
    UdpReceiveBuffer receive_buffer;
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
            if (IsTransientUdpReceiveError(wait_error)) {
                continue;
            }
            throw IoSystemError(wait_error);
        }

        for (std::size_t drained = 0; drained < kMaxBatch; ++drained) {
            if (!is_owned(socket)) {
                receive_buffer.Release();
                co_return;
            }
            IoErrorCode probe_error;
            const std::size_t datagram_size = PeekDatagramSize(*socket, probe_error);
            if (probe_error) {
                if (probe_error == io_error::would_block ||
                    probe_error == io_error::try_again) {
                    break;
                }
                if (IsTransientUdpReceiveError(probe_error)) {
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
                if (IsTransientUdpReceiveError(discard_error)) {
                    continue;
                }
                if (discard_error && discard_error != io_error::message_size) {
                    throw IoSystemError(discard_error);
                }
                on_resource_drop();
                continue;
            }

            udp::endpoint peer;
            IoErrorCode receive_error;
            const std::size_t received_bytes = socket->receive_from(
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
                on_resource_drop();
                continue;
            }
            if (receive_error) {
                if (IsTransientUdpReceiveError(receive_error)) {
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
                on_resource_drop();
            }
        }
    }
}

}  // namespace transport::internet
