#pragma once
#include "transport/internet/h2_frame.hpp"
#include "transport/internet/h2_inbound_payload.hpp"
#include "transport/internet/xhttp_session.hpp"
#include "transport/internet/async_write_gate.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "common/awaitable_task_group.hpp"
#include "common/hash_container_shrink.hpp"
#include "infra/log.hpp"

namespace transport::internet::h2 {
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
    bool EnqueueData(Http2ServerSession& session, memory::ByteVector frame_payload,
                     size_t offset, size_t size);
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
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer();
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
        memory::ByteVector payload;
        size_t offset = 0;
        size_t end = 0;
    };

    void WakeInputReader() noexcept {
        (void)input_signal_.try_send(IoErrorCode{});
    }

    [[nodiscard]] bool FrontDataReady() noexcept;
    net::awaitable<bool> WaitForDataFrame();
    [[nodiscard]] bool RawReady() noexcept { return !cancelled_ && FrontDataReady(); }
    [[nodiscard]] size_t ConsumeRaw(net::mutable_buffer) noexcept;
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
    memory::RingDeque<QueuedDataFrame> data_frames_;
    // Read position inside data_frames_.front().
    size_t read_offset_ = 0;
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

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        return state_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
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
                       uint32_t initial_receive_window)
        : coordinator_(coordinator)
        , io_context_(io_context)
        , stream_(std::move(stream))
        , stream_handler_(std::move(stream_handler))
        , payload_codec_(payload_codec)
        , http_config_(http_config)
        , xhttp_config_(xhttp_config)
        , grpc_config_(grpc_config)
        , conn_id_(conn_id) {
        initial_receive_window_ = initial_receive_window;
        if (!stream_ || !stream_->DeferWriteCancellation()) {
            throw std::invalid_argument("HTTP/2 requires a physical transport with deferred write cancellation");
        }
        if (payload_codec_ == H2PayloadCodec::RawData) {
            if (!http_config_) {
                throw std::invalid_argument("HTTP/2 raw session requires an HTTP config");
            }
            response_header_block_ = EncodeHttpResponseHeaders(http_config_->headers);
        }
        Resubscribe(stream_->Cancellation());
    }

    ~Http2ServerSession() noexcept {
        Unsubscribe();
        CancelAll();
    }

    Http2ServerSession(const Http2ServerSession&) = delete;
    Http2ServerSession& operator=(const Http2ServerSession&) = delete;

    net::awaitable<void> Run() {
        try {
            co_await common::RunAwaitableTaskGroup(io_context_.get_executor(),
                [this](common::AwaitableTaskGroup& tasks) {
                    tasks_ = &tasks;
                    tasks.Spawn(RunReadLoop());
                });
        } catch (...) {
            tasks_ = nullptr;
            CancelAll();
            throw;
        }
        tasks_ = nullptr;
        CancelAll();
    }

    net::awaitable<void> FinishStream(uint32_t id, bool reset) {
        try {
            if (reset) {
                (void)co_await ResetStream(id, H2Error::Cancel);
            } else if (payload_codec_ == H2PayloadCodec::RawData) {
                (void)co_await WriteFrameSerialized(H2FrameType::DATA, kFlagEndStream, id);
            } else {
                (void)co_await WriteTrailersSerialized(id);
            }
        } catch (...) {
            CancelAll();
        }
        RemoveStream(id);
    }

    void Spawn(net::awaitable<void> task) {
        if (cancelled_ || !tasks_) throw IoSystemError(io_error::operation_aborted);
        tasks_->Spawn(std::move(task));
    }
    // No per-frame task queue: consumption coalesces into a single writer.
    // Discarded input returns connection credit too, but never resurrects a
    // reset/half-closed stream's receive window (RFC 9113 6.9). `sub` is null
    // for connection-only credit. A state leaves streams_ only through
    // CancelFromSession, so AcceptsData() alone stands for "open in streams_".
    // May CancelAll, which can drop the session's last reference to `sub`.
    void ReturnReceiveCredit(Http2ServerSubStreamState* sub, size_t size) noexcept {
        if (size == 0 || cancelled_) return;
        consumed_connection_credit_ += static_cast<uint32_t>(size);
        if (sub && sub->AcceptsData()) {
            sub->ConsumedCredit() += static_cast<uint32_t>(size);
        }
        if (credit_flush_running_) return;
        credit_flush_running_ = true;
        try {
            Spawn(FlushReceiveCredit());
        } catch (...) {
            credit_flush_running_ = false;
            CancelAll();
        }
    }

    [[nodiscard]] bool ReserveReceiveMemory(size_t size) noexcept {
        if (size > kHttp2ReceiveMemoryLimit - receive_memory_) return false;
        receive_memory_ += size;
        return true;
    }

    void ReleaseReceiveMemory(size_t size) noexcept {
        receive_memory_ -= size;
    }

    void RejectReceiveBudget(uint32_t stream_id) noexcept {
        RemoveStream(stream_id, io_error::no_buffer_space);
        try {
            Spawn(SendReceiveBudgetReset(stream_id));
        } catch (...) {
            CancelAll();
        }
    }

    [[nodiscard]] const AsyncStream* InnerStream() const noexcept {
        return stream_.get();
    }

    [[nodiscard]] AsyncStream* InnerStream() noexcept {
        return stream_.get();
    }

    void RemoveStream(uint32_t stream_id, IoErrorCode error = io_error::operation_aborted) noexcept {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        auto sub = std::move(it->second);
        streams_.erase(it);
        common::MaybeShrinkHashContainer(streams_, 8);
        if (sub) {
            sub->CancelFromSession(error);
        }
    }

    void CancelAll(IoErrorCode error = io_error::operation_aborted) noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        write_gate_.Cancel();
        auto streams = std::move(streams_);
        for (auto& [stream_id, sub] : streams) {
            (void)stream_id;
            if (sub) {
                sub->CancelFromSession(error);
            }
        }
        streams_.clear();
        if (stream_) {
            stream_->CloseAbortive();
        }
    }

    net::awaitable<bool> WriteFrameSerialized(
        H2FrameType type,
        uint8_t flags,
        uint32_t stream_id,
        std::span<const uint8_t> payload = {}) {
        auto write_lease = write_gate_.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate_.Acquire();
        // RST_STREAM may target a stream that was already removed.
        if (!write_lease ||
            (stream_id == 0 || type == H2FrameType::RST_STREAM
                 ? !ConnectionWritable() : !StreamWritable(stream_id))) {
            co_return false;
        }
        const net::const_buffer buffer{payload.data(), payload.size()};
        co_await WriteH2FrameBuffers(
            *stream_, type, flags, stream_id,
            std::span<const net::const_buffer>(&buffer, 1));
        co_return true;
    }

    net::awaitable<bool> WriteGrpcMessageSerialized(
        uint32_t stream_id,
        std::span<const uint8_t> data) {
        return ForEachGrpcHunkRecord(data,
            [this, stream_id](std::span<const net::const_buffer> record) {
                return WriteDataSerialized(stream_id, record);
            });
    }

    // Sends DATA within the connection and stream send windows (RFC 9113
    // 6.9.1). The physical gate is held per frame, so other streams and the
    // read loop's control frames proceed while this stream waits for credit.
    net::awaitable<bool> WriteDataSerialized(
        uint32_t stream_id,
        std::span<const net::const_buffer> buffers) {
        H2DataCursor cursor(buffers);
        const auto cancellation = co_await net::this_coro::cancellation_state;
        while (cursor.Remaining() != 0) {
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            auto write_lease = write_gate_.TryAcquire();
            if (!write_lease) write_lease = co_await write_gate_.Acquire();
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            const auto it = streams_.find(stream_id);
            if (!write_lease || !ConnectionWritable() || it == streams_.end()) {
                co_return false;
            }
            auto& send_window = it->second->SendWindow();
            const size_t credit = std::min({cursor.Remaining(),
                                            kHttp2MaxFramePayload,
                                            conn_send_window_.Available(),
                                            send_window.Available()});
            if (credit == 0) {
                write_lease.Reset();
                const auto sub = it->second;
                co_await sub->WaitSendCredit();
                continue;
            }
            const auto payload = cursor.Next(credit);
            const size_t size = H2DataCursor::Size(payload);
            conn_send_window_.Consume(size);
            send_window.Consume(size);
            co_await WriteH2FrameBuffers(*stream_, H2FrameType::DATA, 0, stream_id, payload);
        }
        co_return true;
    }

    net::awaitable<bool> WriteTrailersSerialized(uint32_t stream_id) {
        return WriteFrameSerialized(
            H2FrameType::HEADERS, kFlagEndHeaders | kFlagEndStream, stream_id, kGrpcTrailerBlock);
    }

    net::awaitable<void> RunReadLoop() {
        try {
            while (!cancelled_ && stream_) {
                auto frame = co_await ReadH2Frame(*stream_);
                if (!frame) {
                    const bool ended = std::all_of(streams_.begin(), streams_.end(),
                        [](const auto& entry) { return entry.second->InputEnded(); });
                    if (ended) co_return;
                    throw IoSystemError(io_error::connection_reset, "HTTP/2 missing END_STREAM");
                }

                // DATA, the dominant frame, is accounted synchronously; only
                // fault reporting suspends.
                if (frame->type == H2FrameType::DATA) {
                    if (!IsKnownClientStream(frame->stream_id)) {
                        (void)co_await FailConnection(H2Error::Protocol);
                        break;
                    }
                    if (const auto fault = ReceiveData(*frame)) {
                        if (fault->connection) {
                            (void)co_await FailConnection(fault->error);
                        } else if (!co_await ResetStream(frame->stream_id, fault->error) &&
                                   fault->error == H2Error::ExcessiveLoad) {
                            CancelAll();
                        }
                    }
                    continue;
                }
                if (!co_await DispatchFrame(std::move(*frame))) break;
            }
        } catch (const IoSystemError& error) {
            CancelAll(error.code());
            co_return;
        } catch (const std::exception& e) {
            LOG_CONN_DEBUG(conn_id_, "HTTP/2 server read loop failed > {}", e.what());
        } catch (...) {
            LOG_CONN_DEBUG(conn_id_, "HTTP/2 server read loop failed > unknown exception");
        }
        CancelAll();
    }

private:
    net::awaitable<void> FlushReceiveCredit() {
        try {
            while (!cancelled_) {
                auto lease = write_gate_.TryAcquire();
                if (!lease) lease = co_await write_gate_.Acquire();
                if (!lease || !ConnectionWritable()) break;
                const uint32_t conn_increment = std::exchange(consumed_connection_credit_, 0);
                if (conn_increment != 0) {
                    connection_receive_window_ += conn_increment;
                }
                uint32_t target_stream_id = 0;
                uint32_t stream_increment = 0;
                bool more_streams = false;
                // Do not retain an unordered_map iterator over an await.
                for (auto& [stream_id, sub] : streams_) {
                    if (!sub->AcceptsData()) {
                        sub->ConsumedCredit() = 0;
                        continue;
                    }
                    if (sub->ConsumedCredit() == 0) continue;
                    if (stream_increment == 0) {
                        target_stream_id = stream_id;
                        stream_increment = std::exchange(sub->ConsumedCredit(), 0);
                        sub->ReceiveWindow() += stream_increment;
                    } else {
                        more_streams = true;
                    }
                }
                if (conn_increment == 0 && stream_increment == 0) break;
                co_await SendWindowUpdates(
                    *stream_, conn_increment, target_stream_id, stream_increment);
                if (!more_streams && consumed_connection_credit_ == 0) break;
            }
        } catch (...) {
            CancelAll();
        }
        credit_flush_running_ = false;
    }

    [[nodiscard]] bool ConnectionWritable() const noexcept {
        return !cancelled_ && stream_;
    }

    [[nodiscard]] bool StreamWritable(uint32_t stream_id) const noexcept {
        return ConnectionWritable() && streams_.contains(stream_id);
    }

    net::awaitable<void> RunPacketUpload(
        std::unique_ptr<AsyncStream> stream,
        std::shared_ptr<XHttpPacketUpSession> session, uint64_t seq) {
        RequestScope active(active_requests_);
        try {
            XHttpPacketUpSession::Upload upload(*session, *stream);
            buf::MultiBuffer payload;
            while (co_await upload.Read(payload, buf::Buffer::kSize) != 0) {
            }
            if (!upload.Commit(seq, std::move(payload)))
                throw IoSystemError(io_error::no_buffer_space);
            if (!session->DownlinkAttached() &&
                !co_await session->AwaitDownlink(stream->Cancellation())) {
                throw IoSystemError(io_error::timed_out);
            }
            session.reset();
            co_await stream->AsyncShutdownWrite();
            stream->Close();
        } catch (...) {
            stream->CloseAbortive();
        }
    }

    net::awaitable<void> RunRequest(
        std::unique_ptr<AsyncStream> stream, InboundTransportMetadata metadata) {
        RequestScope active(active_requests_);
        try {
            co_await stream_handler_->OnInboundTransportStream(
                std::move(stream), std::move(metadata));
        } catch (const std::exception& error) {
            LOG_CONN_DEBUG(conn_id_, "HTTP/2 logical request failed > {}", error.what());
        } catch (...) {
            LOG_CONN_DEBUG(conn_id_, "HTTP/2 logical request failed > unknown exception");
        }
    }

    // Hands the logical stream to the request sink, optionally joined to an
    // XHTTP session as its downlink. Without a sink the stream ends cleanly.
    void DeliverRequest(std::shared_ptr<Http2ServerSubStreamState> sub,
                        std::shared_ptr<XHttpPacketUpSession> split_session,
                        InboundTransportMetadata metadata) {
        if (!stream_handler_) {
            if (split_session) split_session->Close();
            sub->CloseLocal();
            return;
        }
        try {
            std::unique_ptr<AsyncStream> stream =
                std::make_unique<Http2ServerSubStream>(sub);
            if (split_session) {
                stream = MakeXHttpSplitStream(split_session, std::move(stream));
            }
            if (cancelled_ || !tasks_) throw IoSystemError(io_error::operation_aborted);
            auto& source = stream->Cancellation();
            // Bind before the proxy handshake, which can write (and wait for the
            // physical gate) before the dispatcher installs its read subscription.
            tasks_->Spawn(RunRequest(std::move(stream), std::move(metadata)), &source);
        } catch (...) {
            if (split_session) split_session->Close();
            sub->AbortLocal();
            throw;
        }
    }

    // 200 response headers, then the request's own END_STREAM, if any.
    net::awaitable<bool> AcceptStream(uint32_t stream_id,
                                      bool end_stream,
                                      Http2ServerSubStreamState& sub) {
        if (!ready_) {
            if (stream_handler_) stream_handler_->OnInboundTransportReady(*stream_);
            ready_ = true;
        }
        const std::span<const uint8_t> response_headers =
            payload_codec_ == H2PayloadCodec::RawData
                ? std::span<const uint8_t>(response_header_block_)
                : std::span<const uint8_t>(kGrpcResponseHeaderBlock);
        if (!co_await WriteFrameSerialized(
                H2FrameType::HEADERS, kFlagEndHeaders, stream_id, response_headers)) {
            co_return false;
        }
        if (end_stream) {
            sub.CloseInput();
        }
        co_return true;
    }

    net::awaitable<bool> ResetStream(uint32_t stream_id, H2Error error) {
        RemoveStream(stream_id, error == H2Error::ExcessiveLoad ||
            error == H2Error::RefusedStream ? IoErrorCode(io_error::no_buffer_space) :
            IoErrorCode(io_error::operation_aborted));
        std::array<uint8_t, 4> payload{};
        common::StoreU32BE(payload.data(), static_cast<uint32_t>(error));
        co_return co_await WriteFrameSerialized(H2FrameType::RST_STREAM, 0, stream_id, payload);
    }

    net::awaitable<void> SendReceiveBudgetReset(uint32_t stream_id) {
        if (!co_await ResetStream(stream_id, H2Error::ExcessiveLoad)) CancelAll();
    }

    net::awaitable<bool> FailConnection(H2Error error) {
        const auto payload = EncodeGoaway(last_remote_stream_id_, error);
        (void)co_await WriteFrameSerialized(H2FrameType::GOAWAY, 0, 0, payload);
        CancelAll();
        co_return false;
    }

    [[nodiscard]] bool IsKnownClientStream(uint32_t stream_id) const noexcept {
        return stream_id != 0 && (stream_id & 1u) != 0 && stream_id <= last_remote_stream_id_;
    }

    // Non-DATA frames (RunReadLoop accounts DATA itself). Returns false once
    // the connection must stop reading.
    net::awaitable<bool> DispatchFrame(H2Frame frame) {
        switch (frame.type) {
        case H2FrameType::SETTINGS:
            if (frame.stream_id != 0) co_return co_await FailConnection(H2Error::Protocol);
            if (frame.payload.size() % 6 != 0 ||
                ((frame.flags & kFlagAck) && !frame.payload.empty())) {
                co_return co_await FailConnection(H2Error::FrameSize);
            }
            if (!(frame.flags & kFlagAck)) {
                if (const auto error = ApplyPeerSettings(frame.payload)) {
                    co_return co_await FailConnection(*error);
                }
                co_return co_await WriteFrameSerialized(H2FrameType::SETTINGS, kFlagAck, 0);
            }
            if (!local_settings_acked_) {
                local_settings_acked_ = true;
                // Before ACK, allow DATA sent with the old default window.
                const int64_t delta = static_cast<int64_t>(initial_receive_window_) -
                    std::max<int64_t>(initial_receive_window_, H2SendWindow::kDefault);
                for (auto& [id, sub] : streams_) {
                    (void)id;
                    sub->ReceiveWindow() += delta;
                }
            }
            break;
        case H2FrameType::PING:
            if (frame.stream_id != 0) co_return co_await FailConnection(H2Error::Protocol);
            if (frame.payload.size() != 8) co_return co_await FailConnection(H2Error::FrameSize);
            if (!(frame.flags & kFlagAck)) {
                co_return co_await WriteFrameSerialized(
                    H2FrameType::PING, kFlagAck, 0, frame.payload);
            }
            break;
        case H2FrameType::WINDOW_UPDATE:
            co_return co_await ReceiveWindowUpdate(frame);
        case H2FrameType::HEADERS: {
            const auto id = frame.stream_id;
            bool exhausted = false;
            try {
                co_return co_await ReceiveHeaders(std::move(frame));
            } catch (const std::bad_alloc&) {
                if (cancelled_) throw;
                exhausted = true;
            }
            if (exhausted) co_return co_await ResetStream(id, H2Error::RefusedStream);
            co_return false;
        }
        case H2FrameType::PRIORITY:
            if (frame.stream_id == 0) co_return co_await FailConnection(H2Error::Protocol);
            if (frame.payload.size() != 5) co_return co_await FailConnection(H2Error::FrameSize);
            break;
        case H2FrameType::RST_STREAM:
            if (frame.payload.size() != 4) co_return co_await FailConnection(H2Error::FrameSize);
            if (!IsKnownClientStream(frame.stream_id)) {
                co_return co_await FailConnection(H2Error::Protocol);
            }
            RemoveStream(frame.stream_id, io_error::connection_reset);
            break;
        case H2FrameType::GOAWAY:
            CancelAll();
            co_return false;
        case H2FrameType::CONTINUATION:
        case H2FrameType::PUSH_PROMISE:
            co_return co_await FailConnection(H2Error::Protocol);
        default:
            break;
        }
        co_return !cancelled_;
    }

    // SETTINGS_INITIAL_WINDOW_SIZE moves every open stream window by the
    // change (RFC 9113 6.9.2); overflow is a FLOW_CONTROL_ERROR.
    [[nodiscard]] std::optional<H2Error> ApplyPeerSettings(std::span<const uint8_t> payload) {
        const auto initial_window = PeerInitialWindowSetting(payload);
        if (!initial_window) return initial_window.error();
        if (!*initial_window) return std::nullopt;
        const int64_t delta = static_cast<int64_t>(**initial_window) -
                              static_cast<int64_t>(peer_initial_window_);
        for (auto& [stream_id, sub] : streams_) {
            (void)stream_id;
            if (!sub->SendWindow().Adjust(delta)) return H2Error::FlowControl;
        }
        peer_initial_window_ = **initial_window;
        for (auto& [stream_id, sub] : streams_) {
            (void)stream_id;
            sub->WakeSendWaiter();
        }
        return std::nullopt;
    }

    // RFC 9113 6.9: connection-level faults fail the connection; stream-level
    // ones reset only that stream. Closed streams may still receive updates.
    net::awaitable<bool> ReceiveWindowUpdate(const H2Frame& frame) {
        const auto increment = WindowUpdateIncrement(frame);
        if (frame.stream_id == 0) {
            if (!increment) co_return co_await FailConnection(increment.error());
            if (!conn_send_window_.Adjust(*increment)) {
                co_return co_await FailConnection(H2Error::FlowControl);
            }
            for (auto& [stream_id, sub] : streams_) {
                (void)stream_id;
                sub->WakeSendWaiter();
            }
            co_return true;
        }
        if (!IsKnownClientStream(frame.stream_id)) {
            co_return co_await FailConnection(H2Error::Protocol);
        }
        if (!increment && increment.error() == H2Error::FrameSize) {
            co_return co_await FailConnection(H2Error::FrameSize);
        }
        const auto it = streams_.find(frame.stream_id);
        if (it == streams_.end()) co_return true;
        if (!increment) co_return co_await ResetStream(frame.stream_id, increment.error());
        if (!it->second->SendWindow().Adjust(*increment)) {
            co_return co_await ResetStream(frame.stream_id, H2Error::FlowControl);
        }
        it->second->WakeSendWaiter();
        co_return true;
    }

    // A new request, or trailers ending an open one.
    net::awaitable<bool> ReceiveHeaders(H2Frame frame) {
        // RFC 9113 6.2: HEADERS on stream 0 is a connection error.
        if (frame.stream_id == 0) {
            co_return co_await FailConnection(H2Error::Protocol);
        }

        const bool end_stream = (frame.flags & kFlagEndStream) != 0;
        const uint32_t stream_id = frame.stream_id;
        const bool trailers = streams_.contains(stream_id);
        const std::string_view real_ip_header = http_config_
            ? std::string_view(http_config_->real_ip_header) : std::string_view{};
        const bool closed_client_stream =
            !trailers && (stream_id & 1u) != 0 && stream_id <= last_remote_stream_id_;
        tl::expected<std::optional<H2RequestHeaders>, H2Error> parsed;
        try {
            parsed = co_await ParseH2RequestHeaders(
                *stream_, hpack_decoder_, std::move(frame),
                real_ip_header, trailers || closed_client_stream);
        } catch (const std::bad_alloc&) {
            CancelAll();
            throw;
        }
        if (!parsed) {
            co_return co_await FailConnection(parsed.error());
        }
        auto request = std::move(*parsed);
        if (closed_client_stream) {
            if (end_stream && request.has_value()) {
                co_return true;
            }
            co_return co_await FailConnection(H2Error::Protocol);
        }
        if (trailers) {
            // RFC 9113 8.1: trailers end this request, not its connection;
            // malformed trailers are a stream error (8.1.1).
            auto it = streams_.find(stream_id);
            if (it != streams_.end() && it->second->InputEnded())
                co_return co_await ResetStream(stream_id, H2Error::StreamClosed);
            if (!request || !end_stream)
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            if (it != streams_.end()) it->second->CloseInput();
            co_return true;
        }
        if ((stream_id & 1u) == 0 || stream_id <= last_remote_stream_id_) {
            co_return co_await FailConnection(H2Error::Protocol);
        }
        last_remote_stream_id_ = stream_id;
        if (!request) {
            // RFC 9113 8.1.1: a malformed request is a stream error of type
            // PROTOCOL_ERROR; the connection and its other streams continue.
            co_return co_await ResetStream(stream_id, H2Error::Protocol);
        }
        if (streams_.size() >= kHttp2MaxConcurrentStreams ||
            active_requests_ >= kHttp2MaxConcurrentStreams) {
            co_return co_await ResetStream(stream_id, H2Error::RefusedStream);
        }
        if (payload_codec_ == H2PayloadCodec::RawData && !xhttp_config_ && http_config_) {
            if (!detail::PathPrefixMatchesSegment(http_config_->path, request->path) ||
                (!http_config_->method.empty() &&
                 !common::EqualsAsciiCI(request->method, http_config_->method))) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            if (const std::string_view expected_host =
                    ResolveConfiguredHttpHost(http_config_->host, &http_config_->headers);
                !expected_host.empty() &&
                !AuthorityMatchesHost(request->authority, expected_host)) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
        }
        if (payload_codec_ == H2PayloadCodec::GrpcHunk && grpc_config_) {
            if (!common::EqualsAsciiCI(request->method, "POST") ||
                !detail::PathMatchesExactly(grpc_config_->request_path, request->path)) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            if (const std::string_view expected_authority = common::TrimAscii(grpc_config_->authority);
                !expected_authority.empty() &&
                !AuthorityMatchesHost(request->authority, expected_authority)) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
        }
        auto sub = std::make_shared<Http2ServerSubStreamState>(
            io_context_.get_executor(), shared_from_this(), stream_id,
            payload_codec_, peer_initial_window_);
        sub->ReceiveWindow() = local_settings_acked_ ? initial_receive_window_ :
            std::max<int64_t>(initial_receive_window_, H2SendWindow::kDefault);
        streams_.emplace(stream_id, sub);

        if (xhttp_config_ && payload_codec_ == H2PayloadCodec::RawData) {
            co_return co_await RouteXHttpRequest(
                stream_id, end_stream, std::move(*request), std::move(sub));
        }
        if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
            co_return false;
        }

        LOG_CONN_DEBUG(conn_id_,
            "{} server accepted logical stream_id={}",
            payload_codec_ == H2PayloadCodec::RawData ? "HTTP/2" : "gRPC",
            stream_id);
        DeliverRequest(std::move(sub), nullptr, std::move(request->metadata));
        co_return true;
    }
    net::awaitable<bool> RouteXHttpRequest(
        uint32_t stream_id, bool end_stream, H2RequestHeaders request,
        std::shared_ptr<Http2ServerSubStreamState> sub);

    struct DataFault {
        H2Error error;
        bool connection;
    };

    // Accounts for one DATA frame. A returned fault is still to be reported:
    // FailConnection when `connection`, otherwise ResetStream on the frame's stream.
    [[nodiscard]] std::optional<DataFault> ReceiveData(H2Frame& frame) {
        // The complete DATA payload consumes credit, including Pad Length and
        // padding (RFC 9113 6.1). Closed/reset streams still consume connection
        // credit, and discarding those bytes returns it exactly once.
        const size_t flow_size = frame.payload.size();
        if (static_cast<int64_t>(flow_size) > connection_receive_window_) {
            return DataFault{H2Error::FlowControl, true};
        }
        connection_receive_window_ -= static_cast<int64_t>(flow_size);
        auto it = streams_.find(frame.stream_id);
        if (it == streams_.end()) {
            ReturnReceiveCredit(nullptr, flow_size);
            return std::nullopt;
        }
        // Borrowed from streams_: every ReturnReceiveCredit below may CancelAll
        // and destroy the state, so each one is the last use of `sub`.
        auto& sub = *it->second;
        if (flow_size != 0 && static_cast<int64_t>(flow_size) > sub.ReceiveWindow()) {
            ReturnReceiveCredit(nullptr, flow_size);
            return DataFault{H2Error::FlowControl, false};
        }
        sub.ReceiveWindow() -= static_cast<int64_t>(flow_size);
        if (sub.InputEnded()) {
            ReturnReceiveCredit(nullptr, flow_size);
            return DataFault{H2Error::StreamClosed, false};
        }
        if ((frame.flags & kFlagPadded) != 0 &&
            (frame.payload.empty() || frame.payload.front() >= frame.payload.size())) {
            return DataFault{H2Error::Protocol, true};
        }
        if (!sub.AcceptsData()) {
            if ((frame.flags & kFlagEndStream) != 0) sub.CloseInput();
            ReturnReceiveCredit(nullptr, flow_size);
            return std::nullopt;
        }
        const auto data = H2DataPayload(frame);
        const size_t data_size = data.size();
        const size_t offset = data_size == 0 ? 0 :
            static_cast<size_t>(data.data() - frame.payload.data());
        bool queued = data_size == 0;
        try {
            if (data_size != 0) {
                queued = sub.EnqueueData(*this, std::move(frame.payload), offset, data_size);
            }
        } catch (const std::bad_alloc&) {
            queued = false;
        }
        if (!queued) {
            ReturnReceiveCredit(nullptr, flow_size);
            return DataFault{H2Error::ExcessiveLoad, false};
        }
        if ((frame.flags & kFlagEndStream) != 0) sub.CloseInput();
        // Padding is consumed by the framing layer; body credit belongs to the
        // logical reader, not to this demultiplexer.
        ReturnReceiveCredit(&sub, flow_size - data_size);
        return std::nullopt;
    }

    void OnCancellation(transport::Cancellation) noexcept override {
        CancelAll();
    }

    app::GroupCoordinator& coordinator_;
    net::io_context& io_context_;
    std::unique_ptr<AsyncStream> stream_;
    std::shared_ptr<InboundTransportStreamHandler> stream_handler_;
    AsyncWriteGate write_gate_;
    memory::UnorderedMap<uint32_t, std::shared_ptr<Http2ServerSubStreamState>>
        streams_;
    H2PayloadCodec payload_codec_ = H2PayloadCodec::GrpcHunk;
    const HttpConfig* http_config_ = nullptr;
    const XHttpConfig* xhttp_config_ = nullptr;
    const GrpcConfig* grpc_config_ = nullptr;
    // HPACK blocks encoded once per connection; neither uses the dynamic table.
    memory::ByteVector response_header_block_;
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
}
