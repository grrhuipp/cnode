#pragma once

#include "common/allocator.hpp"
#include "common/target_address.hpp"
#include "transport/async_stream.hpp"
#include "transport/phase_deadline.hpp"
#include "app/session_group_executor.hpp"

#include <memory>
#include <span>

namespace transport::internet::hysteria {

// The QUIC connection behind every request stream and UDP session
// (quic_connection.hpp). Streams hold it weakly: a dispatched request may
// outlive the connection.
class Connection;

class QuicStreamState final : public memory::ThreadAllocated {
public:
    static constexpr size_t kMaxQueuedInputBytes = 512 * 1024;

    QuicStreamState(net::io_context& io_context, int64_t stream_id,
                    std::weak_ptr<Connection> owner);

    [[nodiscard]] int64_t Id() const noexcept { return stream_id_; }
    [[nodiscard]] net::io_context& IoContext() const noexcept { return domain_->Reactor(); }
    transport::CancellationSource& Cancellation() noexcept { return cancellation_; }
    [[nodiscard]] bool PushInput(std::span<const uint8_t> data, bool fin);
    // Bytes received but not yet read; the transport inspects a request
    // prefix here before deciding who reads the stream.
    [[nodiscard]] const buf::MultiBuffer& PendingInput() const noexcept { return input_; }
    void DiscardInput(size_t bytes) noexcept;
    void OnStreamClosed() noexcept;
    void RemoteReset() noexcept;
    void Cancel() noexcept;
    net::awaitable<size_t> Read(net::mutable_buffer buffer);
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer();
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload);
    void ShutdownWrite() noexcept;

    [[nodiscard]] bool Open() const noexcept { return !cancelled_; }

private:
    void AcknowledgeInput(size_t bytes) noexcept;
    void WakeReader() noexcept;

    std::shared_ptr<ExecutionDomain> domain_;
    int64_t stream_id_;
    std::weak_ptr<Connection> owner_;
    SignalChannel input_signal_;
    buf::MultiBuffer input_;
    bool input_done_ = false;
    bool write_done_ = false;
    bool cancelled_ = false;
    transport::CancellationSource cancellation_;
};

// One Hysteria TCP request stream handed to the inbound handler.
class QuicStream final : public AsyncStream {
public:
    // |state| must be non-null.
    explicit QuicStream(std::shared_ptr<QuicStreamState> state);
    ~QuicStream() noexcept override;
    transport::CancellationSource& Cancellation() noexcept override { return state_->Cancellation(); }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override;
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override;
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override;
    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override;
    void ShutdownWrite() override;
    void Cancel() noexcept override;
    void Close() override;
    [[nodiscard]] int NativeHandle() const override { return -1; }
    [[nodiscard]] bool IsOpen() const override;

protected:
    StreamPhaseDeadline* LogicalPhaseDeadline() noexcept override { return &deadline_; }

private:
    std::shared_ptr<QuicStreamState> state_;
    StreamPhaseDeadline deadline_;
    bool closed_ = false;
};

// One Hysteria UDP session handed to the inbound handler. Every read yields
// one reassembled datagram tagged with its target; every write sends one
// datagram to the target it carries. Byte-stream I/O is not supported.
// The owning connection keeps a raw pointer while the session is registered;
// destruction unregisters it, and connection close detaches it first.
class UdpSessionStream final : public AsyncStream {
public:
    // Bounds queued Buffer data capacity, not only the datagrams' payload sizes.
    static constexpr size_t kMaxQueuedBytes = 512 * 1024;

    UdpSessionStream(net::io_context& io_context, uint32_t session_id,
                     TargetAddress first_target,
                     std::weak_ptr<Connection> owner);
    ~UdpSessionStream() noexcept override;

    [[nodiscard]] uint32_t SessionId() const noexcept { return session_id_; }
    // Target of the datagram that opened the session.
    [[nodiscard]] const TargetAddress& FirstTarget() const noexcept { return first_target_; }

    [[nodiscard]] bool Push(const TargetAddress& target, std::span<const uint8_t> payload);
    // The owning connection closed; pending reads end and writes fail.
    void Detach() noexcept;

    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::WaitForPeer;
    }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override;
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override;
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer packet) override;
    void ShutdownWrite() override {}
    void Cancel() noexcept override;
    void Close() override;
    [[nodiscard]] int NativeHandle() const override { return -1; }
    [[nodiscard]] bool IsOpen() const override { return !closed_; }

protected:
    StreamPhaseDeadline* LogicalPhaseDeadline() noexcept override { return &deadline_; }

private:
    void WakeReader() noexcept;

    std::shared_ptr<ExecutionDomain> domain_;
    uint32_t session_id_;
    TargetAddress first_target_;
    std::weak_ptr<Connection> owner_;
    SignalChannel signal_;
    memory::ThreadLocalDeque<buf::MultiBuffer> input_;
    size_t queued_buffer_count_ = 0;
    bool cancelled_ = false;
    bool closed_ = false;
    StreamPhaseDeadline deadline_;
};

}  // namespace transport::internet::hysteria
