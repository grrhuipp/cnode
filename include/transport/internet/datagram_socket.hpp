#pragma once

#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"
#include "transport/cancellation.hpp"
#include "transport/phase_deadline.hpp"

#include <asio/buffer.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

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
        [[nodiscard]] ErrorCode CancellationReason() const noexcept;

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
        [[nodiscard]] ErrorCode CancellationReason() const noexcept;

    private:
        friend class DatagramSocket;
        friend struct DatagramSocket::Impl;
        explicit WriteOperation(Impl& impl);
        void CheckAvailable();

        Impl* impl_;
        uint64_t generation_;
        bool send_started_ = false;
    };

    DatagramSocket(net::io_context& io_context, const net::ip::address& bind_address);
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
    // The dedicated association fd is retained across a passive domain handoff.
    [[nodiscard]] int NativeHandle() const noexcept;
    [[nodiscard]] udp::endpoint LocalEndpoint() const;
    [[nodiscard]] static std::size_t ActiveCount() noexcept;

private:
    std::unique_ptr<Impl> impl_;
};

}  // namespace transport::internet
