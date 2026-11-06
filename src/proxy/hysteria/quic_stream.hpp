#pragma once

#include "acppnode/transport/async_stream.hpp"

#include <memory>

namespace acpp::proxy::hysteria {

class QuicStreamOwner {
public:
    virtual ~QuicStreamOwner() noexcept = default;
    virtual net::awaitable<void> WriteStream(
        int64_t stream_id, buf::MultiBuffer payload) = 0;
    virtual void ConsumeStream(int64_t stream_id, size_t bytes) noexcept = 0;
    virtual void ShutdownStreamWrite(int64_t stream_id) noexcept = 0;
    virtual void CancelStream(int64_t stream_id) noexcept = 0;
};

class QuicStreamState final : public memory::ThreadAllocated {
public:
    static constexpr size_t kMaxQueuedInputBytes = 512 * 1024;

    QuicStreamState(net::io_context& io_context, int64_t stream_id,
                    std::weak_ptr<QuicStreamOwner> owner);

    [[nodiscard]] int64_t Id() const noexcept { return stream_id_; }
    [[nodiscard]] bool PushInput(std::span<const uint8_t> data, bool fin);
    void AcknowledgeInput(size_t bytes) noexcept;
    void RemoteReset() noexcept;
    void Cancel() noexcept;

    net::awaitable<size_t> Read(net::mutable_buffer buffer);
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer();
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload);
    void ShutdownWrite() noexcept;

    [[nodiscard]] bool Open() const noexcept { return !cancelled_; }

private:
    void WakeReader() noexcept;

    net::io_context& io_context_;
    int64_t stream_id_;
    std::weak_ptr<QuicStreamOwner> owner_;
    SignalChannel input_signal_;
    buf::MultiBuffer input_;
    bool input_done_ = false;
    bool write_done_ = false;
    bool cancelled_ = false;
};

class QuicStream final : public AsyncStream {
public:
    explicit QuicStream(std::shared_ptr<QuicStreamState> state) noexcept;
    ~QuicStream() noexcept override;

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

private:
    std::shared_ptr<QuicStreamState> state_;
};

}  // namespace acpp::proxy::hysteria
