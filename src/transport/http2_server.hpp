#pragma once
#include "transport/h2_frame.hpp"
#include "transport/h2_inbound_payload.hpp"
#include "transport/xhttp_session.hpp"
#include "transport/async_write_gate.hpp"
#include "transport/tcp_stream.hpp"
#include "common/awaitable_task_group.hpp"
#include "common/allocator.hpp"
#include "infra/log.hpp"
#include <unordered_map>
#include <vector>

namespace transport {
class Http2ServerSession;

// Shared between the session (frame demultiplexer) and the logical stream
// owner. The session keeps it while the stream id is open; the owner keeps it
// until its Http2ServerSubStream is destroyed.
class Http2ServerSubStreamState final {
public:
    Http2ServerSubStreamState(const net::any_io_executor& executor,
                              std::shared_ptr<Http2ServerSession> session,
                              uint32_t stream_id,
                              H2PayloadCodec payload_codec,
                              int64_t initial_send_window);
    ~Http2ServerSubStreamState() noexcept { DropQueuedData(); }

    transport::CancellationSource& Cancellation() noexcept { return cancellation_; }
    [[nodiscard]] std::shared_ptr<Http2ServerSession> LockSession() const noexcept {
        return session_.lock();
    }
    [[nodiscard]] net::io_context& IoContext() const noexcept {
        return static_cast<net::io_context&>(net::query(
            const_cast<common::SignalChannel&>(input_signal_).get_executor(),
            net::execution::context));
    }
    void SetUploadBudget(const std::shared_ptr<XHttpPacketUpSession>& budget) noexcept {
        upload_budget_ = budget;
    }

    // Queues a received DATA payload. False asks the session to reset the
    // stream: the per-stream or XHTTP session budget is exhausted. `session`
    // is the demultiplexer delivering the frame.
    bool EnqueueData(Http2ServerSession& session, H2Frame& frame,
                     std::span<const uint8_t> data);
    void CloseInput();
    void CancelFromSession(IoErrorCode error = io_error::operation_aborted) noexcept;
    [[nodiscard]] bool InputEnded() const noexcept { return input_done_ && !cancelled_; }
    void CancelPendingOperations() noexcept;
    void CloseLocal() noexcept;
    void AbortLocal() noexcept;
    void ShutdownRead() noexcept;
    void ShutdownWrite() noexcept;

    // RFC 9113 6.9 send window of this stream; only the session adjusts it.
    [[nodiscard]] H2SendWindow& SendWindow() noexcept { return send_window_; }
    [[nodiscard]] int64_t& ReceiveWindow() noexcept { return receive_window_; }
    [[nodiscard]] uint32_t& ConsumedCredit() noexcept { return consumed_credit_; }
    [[nodiscard]] bool AcceptsData() const noexcept {
        return !input_done_ && !read_closed_ && !cancelled_;
    }
    // Waits until the session changes a send window this stream depends on.
    // Cancel() aborts the wait; stream teardown wakes it for a re-check.
    net::awaitable<void> WaitSendCredit();
    void WakeSendWaiter() noexcept {
        if (credit_signal_) {
            (void)credit_signal_->try_send(IoErrorCode{});
        }
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer);
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer);
    net::awaitable<common::MultiBuffer> ReadMultiBuffer();
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers);
    net::awaitable<void> AsyncShutdownWrite();

    void ReleaseOwner() noexcept {
        owner_released_ = true;
        if (owner_signal_) {
            (void)owner_signal_->try_send(IoErrorCode{});
        }
    }
    static net::awaitable<void> JoinOwner(
        std::shared_ptr<Http2ServerSubStreamState> state,
        std::shared_ptr<XHttpPacketUpSession> upload_session = {});

private:
    friend struct H2InboundPayload;
    struct QueuedDataFrame {
        common::BufferGuard payload;
    };

    void WakeInputReader() noexcept {
        (void)input_signal_.try_send(IoErrorCode{});
    }

    [[nodiscard]] bool FrontDataReady() noexcept;
    net::awaitable<bool> WaitForDataFrame();
    [[nodiscard]] bool RawReady() noexcept { return !cancelled_ && FrontDataReady(); }
    [[nodiscard]] size_t ConsumeRaw(net::mutable_buffer) noexcept;
    [[nodiscard]] common::MultiBuffer ConsumeRawMultiBuffer() noexcept;
    [[nodiscard]] std::span<const uint8_t> HunkInput();
    void ConsumeHunkInput(size_t offered, size_t consumed) noexcept;
    void HunkFailure() noexcept;
    void ReleaseHunkStorage() noexcept;
    // `session` is the caller's lock of session_ for the current synchronous
    // step; null when the session is gone.
    void PopFrontDataFrame(Http2ServerSession* session) noexcept;
    void DropQueuedData() noexcept;
    void ConsumeData(Http2ServerSession* session, size_t size) noexcept;
    void ReleaseDecoderStorage(Http2ServerSession* session) noexcept;
    [[nodiscard]] std::shared_ptr<Http2ServerSession> LockWritableSession() const;

    common::SignalChannel input_signal_;
    // JoinOwner's frame-local channel, published only while it waits.
    common::SignalChannel* owner_signal_ = nullptr;
    std::optional<common::SignalChannel> credit_signal_;
    H2SendWindow send_window_;
    int64_t receive_window_ = H2SendWindow::kDefault;
    uint32_t consumed_credit_ = 0;
    // Cancel() bumps these so pending read/send-credit waits fail.
    uint64_t read_abort_epoch_ = 0;
    uint64_t write_abort_epoch_ = 0;
    bool owner_released_ = false;
    IoErrorCode terminal_error_ = io_error::operation_aborted;
    std::weak_ptr<Http2ServerSession> session_;
    transport::CancellationSource cancellation_;
    std::weak_ptr<XHttpPacketUpSession> upload_budget_;
    size_t upload_reserved_ = 0;
    uint32_t stream_id_ = 0;
    H2PayloadCodec payload_codec_ = H2PayloadCodec::GrpcHunk;
    H2InboundPayload inbound_;
    common::RingDeque<QueuedDataFrame> data_frames_;
    size_t queued_bytes_ = 0;
    size_t queued_storage_ = 0;
    size_t decoder_reserved_ = 0;
    bool input_done_ = false;
    bool read_closed_ = false;
    bool write_closed_ = false;
    bool trailers_sent_ = false;
    bool closing_local_ = false;
    bool cancelled_ = false;
};

class Http2ServerSubStream final : public AsyncStream {
public:
    explicit Http2ServerSubStream(std::shared_ptr<Http2ServerSubStreamState> state)
        : state_(std::move(state)), deadline_(state_->IoContext(), *this) {}

    transport::CancellationSource& Cancellation() noexcept override {
        return state_->Cancellation();
    }

    ~Http2ServerSubStream() noexcept override {
        Close();
        state_->ReleaseOwner();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        return state_->AsyncRead(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (closed_) {
            throw IoSystemError(io_error::connection_reset, "gRPC write on closed stream");
        }
        return state_->AsyncWrite(buffer);
    }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        return state_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        if (closed_) {
            mb.clear();
            throw IoSystemError(io_error::connection_reset, "gRPC WriteMultiBuffer on closed stream");
        }
        return AsyncStream::WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (closed_) {
            throw IoSystemError(io_error::connection_reset, "gRPC WriteBuffers on closed stream");
        }
        return state_->WriteBuffers(buffers);
    }

    void ShutdownRead() override {
        if (!closed_) {
            state_->ShutdownRead();
        }
    }

    void ShutdownWrite() override {
        if (!closed_) {
            state_->ShutdownWrite();
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return state_->AsyncShutdownWrite();
    }

    void Cancel() noexcept override {
        state_->CancelPendingOperations();
    }

    void Close() override {
        deadline_.Clear();
        if (closed_) {
            return;
        }
        closed_ = true;
        state_->CloseLocal();
    }

    void CloseAbortive() override {
        deadline_.Clear();
        if (closed_) {
            return;
        }
        closed_ = true;
        state_->AbortLocal();
    }

    int NativeHandle() const override;
    bool IsOpen() const override;

protected:
    StreamPhaseDeadline* LogicalPhaseDeadline() noexcept override { return &deadline_; }
    TcpStream* BaseTcpStream() override;
    const TcpStream* BaseTcpStream() const override;

private:
    // Never null: constructed from a live state and never reset.
    std::shared_ptr<Http2ServerSubStreamState> state_;
    StreamPhaseDeadline deadline_;
    bool closed_ = false;
};
class Http2ServerSession final
    : public std::enable_shared_from_this<Http2ServerSession>
    , private transport::CancellationSubscription {
public:
    struct RequestScope {
        size_t& count;
        explicit RequestScope(size_t& count) : count(count) { ++count; }
        ~RequestScope() { --count; }
    };

    // `http_config` (required for RawData) and `xhttp_config` are borrowed
    // from the handshake caller, which awaits Run() to completion.
    Http2ServerSession(app::GroupCoordinator& coordinator, net::io_context& io_context,
                       std::unique_ptr<AsyncStream> stream,
                       std::shared_ptr<InboundTransportStreamHandler> stream_handler,
                       H2PayloadCodec payload_codec,
                       uint64_t conn_id,
                       const HttpConfig* http_config,
                       const XHttpConfig* xhttp_config,
                       const GrpcConfig* grpc_config,
                       uint32_t initial_receive_window);

    ~Http2ServerSession() noexcept;

    Http2ServerSession(const Http2ServerSession&) = delete;
    Http2ServerSession& operator=(const Http2ServerSession&) = delete;

    net::awaitable<void> Run();
    net::awaitable<void> FinishStream(uint32_t id, bool reset);
    void Spawn(net::awaitable<void> task);
    // No per-frame task queue: consumption coalesces into a single writer.
    // Discarded input returns connection credit too, but never resurrects a
    // reset/half-closed stream's receive window (RFC 9113 6.9). `sub` is null
    // for connection-only credit. A state leaves streams_ only through
    // CancelFromSession, so AcceptsData() alone stands for "open in streams_".
    // May CancelAll, which can drop the session's last reference to `sub`.
    void ReturnReceiveCredit(Http2ServerSubStreamState* sub, size_t size) noexcept;

    [[nodiscard]] bool ReserveReceiveMemory(size_t size) noexcept {
        if (size > kHttp2ReceiveMemoryLimit - receive_memory_) return false;
        receive_memory_ += size;
        return true;
    }

    void ReleaseReceiveMemory(size_t size) noexcept {
        receive_memory_ -= size;
    }

    void RejectReceiveBudget(uint32_t stream_id) noexcept;

    [[nodiscard]] const AsyncStream* InnerStream() const noexcept {
        return stream_.get();
    }

    [[nodiscard]] AsyncStream* InnerStream() noexcept {
        return stream_.get();
    }

    void RemoveStream(uint32_t stream_id, IoErrorCode error = io_error::operation_aborted) noexcept;
    void CancelAll(IoErrorCode error = io_error::operation_aborted) noexcept;

    net::awaitable<bool> WriteFrameSerialized(
        H2FrameType type,
        uint8_t flags,
        uint32_t stream_id,
        std::span<const uint8_t> payload = {});

    net::awaitable<bool> WriteInitialPreface(uint32_t initial_window);

    net::awaitable<bool> WriteGrpcMessageSerialized(
        uint32_t stream_id,
        std::span<const uint8_t> data);

    // Sends DATA within the connection and stream send windows (RFC 9113
    // 6.9.1). The physical gate is held per frame, so other streams and the
    // read loop's control frames proceed while this stream waits for credit.
    net::awaitable<bool> WriteDataSerialized(
        uint32_t stream_id,
        std::span<const net::const_buffer> buffers);

    net::awaitable<bool> WriteTrailersSerialized(uint32_t stream_id);
    net::awaitable<void> RunReadLoop();

private:
    struct DataFault {
        H2Error error;
        bool connection;
    };

    net::awaitable<void> FlushReceiveCredit();

    [[nodiscard]] bool ConnectionWritable() const noexcept {
        return !cancelled_ && stream_;
    }

    [[nodiscard]] bool StreamWritable(uint32_t stream_id) const noexcept {
        return ConnectionWritable() && streams_.contains(stream_id);
    }

    net::awaitable<void> RunPacketUpload(
        std::unique_ptr<AsyncStream> stream,
        std::shared_ptr<XHttpPacketUpSession> session, uint64_t seq);

    net::awaitable<void> RunRequest(
        std::unique_ptr<AsyncStream> stream, InboundTransportMetadata metadata);

    // Hands the logical stream to the request sink, optionally joined to an
    // XHTTP session as its downlink. Without a sink the stream ends cleanly.
    void DeliverRequest(std::shared_ptr<Http2ServerSubStreamState> sub,
                        std::shared_ptr<XHttpPacketUpSession> split_session,
                        InboundTransportMetadata metadata);

    // 200 response headers, then the request's own END_STREAM, if any.
    net::awaitable<bool> AcceptStream(uint32_t stream_id,
                                      bool end_stream,
                                      Http2ServerSubStreamState& sub);

    net::awaitable<bool> ResetStream(uint32_t stream_id, H2Error error);
    net::awaitable<void> SendReceiveBudgetReset(uint32_t stream_id);
    net::awaitable<bool> FailConnection(H2Error error);

    [[nodiscard]] bool IsKnownClientStream(uint32_t stream_id) const noexcept {
        return stream_id != 0 && (stream_id & 1u) != 0 && stream_id <= last_remote_stream_id_;
    }

    // Non-DATA frames (RunReadLoop accounts DATA itself). Returns false once
    // the connection must stop reading.
    net::awaitable<bool> DispatchFrame(H2Frame frame);

    // SETTINGS_INITIAL_WINDOW_SIZE moves every open stream window by the
    // change (RFC 9113 6.9.2); overflow is a FLOW_CONTROL_ERROR.
    [[nodiscard]] std::optional<H2Error> ApplyPeerSettings(std::span<const uint8_t> payload);

    // RFC 9113 6.9: connection-level faults fail the connection; stream-level
    // ones reset only that stream. Closed streams may still receive updates.
    net::awaitable<bool> ReceiveWindowUpdate(const H2Frame& frame);

    // A new request, or trailers ending an open one.
    net::awaitable<bool> ReceiveHeaders(H2Frame frame);
    net::awaitable<bool> RouteXHttpRequest(
        uint32_t stream_id, bool end_stream, H2RequestHeaders request,
        std::shared_ptr<Http2ServerSubStreamState> sub);

    // Accounts for one DATA frame. A returned fault is still to be reported:
    // FailConnection when `connection`, otherwise ResetStream on the frame's stream.
    [[nodiscard]] std::optional<DataFault> ReceiveData(H2Frame& frame);

    void OnCancellation(transport::Cancellation) noexcept override {
        CancelAll();
    }

    app::GroupCoordinator& coordinator_;
    net::io_context& io_context_;
    std::unique_ptr<AsyncStream> stream_;
    std::shared_ptr<InboundTransportStreamHandler> stream_handler_;
    AsyncWriteGate write_gate_;
    std::unordered_map<uint32_t, std::shared_ptr<Http2ServerSubStreamState>>
        streams_;
    H2PayloadCodec payload_codec_ = H2PayloadCodec::GrpcHunk;
    const HttpConfig* http_config_ = nullptr;
    const XHttpConfig* xhttp_config_ = nullptr;
    const GrpcConfig* grpc_config_ = nullptr;
    // HPACK blocks encoded once per connection; neither uses the dynamic table.
    std::vector<uint8_t> response_header_block_;
    HpackDecoder hpack_decoder_;
    uint64_t conn_id_ = 0;
    uint32_t last_remote_stream_id_ = 0;
    common::AwaitableTaskGroup* tasks_ = nullptr;
    size_t active_requests_ = 0;
    bool ready_ = false;
    bool cancelled_ = false;
    H2SendWindow conn_send_window_;
    uint32_t peer_initial_window_ = H2SendWindow::kDefault;
    int64_t connection_receive_window_ = kHttp2ConnectionReceiveWindow;
    uint32_t initial_receive_window_ = H2SendWindow::kDefault;
    uint32_t consumed_connection_credit_ = 0;
    size_t receive_memory_ = 0;
    bool local_settings_acked_ = false;
    bool credit_flush_running_ = false;
};
}  // namespace transport
