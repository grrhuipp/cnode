#include "transport/h2_frame.hpp"
#include "transport/h2_inbound_payload.hpp"
#include "transport/async_write_gate.hpp"
#include "transport/tcp_stream.hpp"
#include "infra/log.hpp"
#include <vector>
#include "common/allocator.hpp"

namespace transport {
// Client half of one request on a dedicated connection. Frames are pulled on
// demand: the reader, or a writer short of flow-control credit, pumps one frame
// at a time while the other side waits for that pump. Received DATA is charged
// against the receive windows this client advertised and queues for the
// reader; its credit returns to the peer only when the reader takes it, so the
// queue never outgrows those windows (RFC 9113 6.9.1).
class Http2ClientStream final : public AsyncStream,
                                private transport::CancellationSubscription {
public:
    Http2ClientStream(std::unique_ptr<AsyncStream> inner,
                      uint32_t stream_id,
                      H2PayloadCodec payload_codec,
                      uint32_t local_initial_window,
                      uint32_t conn_recv_window = H2SendWindow::kDefault,
                      bool write_closed = false)
        : inner_(std::move(inner))
        , stream_id_(stream_id)
        , payload_codec_(payload_codec)
        , inbound_{payload_codec, {}}
        , conn_recv_window_(std::max<int64_t>(conn_recv_window, H2SendWindow::kDefault))
        , stream_recv_window_(std::max<int64_t>(local_initial_window, H2SendWindow::kDefault))
        , local_initial_window_(local_initial_window)
        , write_closed_(write_closed) {
        if (inner_) {
            (void)inner_->DeferWriteCancellation();
            Resubscribe(inner_->Cancellation());
        }
    }

    ~Http2ClientStream() noexcept override {
        Unsubscribe();
        Close();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        return inbound_.Read(*this, buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (payload_codec_ == H2PayloadCodec::RawData) {
            co_await SendData(std::span<const net::const_buffer>(&buffer, 1));
            co_return buffer.size();
        }
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        co_await SendGrpcHunkMessage(std::span<const uint8_t>(data, buffer.size()));
        co_return buffer.size();
    }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        return inbound_.ReadMultiBuffer(*this);
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (payload_codec_ == H2PayloadCodec::RawData) {
            return SendData(buffers);
        }
        return WriteGrpcBuffers(buffers);
    }

    void ShutdownRead() override {
        read_closed_ = true;
        inbound_.decoder.Clear();
        ReleaseDataFrame();
        received_.clear();
    }

    void ShutdownWrite() override {
        write_closed_ = true;
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        auto lease = write_gate_.TryAcquire();
        if (!lease) lease = co_await AcquireWrite();
        if (write_closed_) {
            co_return;
        }
        write_closed_ = true;
        (void)co_await WriteH2Frame(*inner_, H2FrameType::DATA, kFlagEndStream, stream_id_);
    }

    void Cancel() noexcept override {
        AbortPumpWaits();
        inner_->Cancel();
    }

    transport::CancellationSource& Cancellation() noexcept override {
        return inner_->Cancellation();
    }

    void Close() override {
        Unsubscribe();
        write_gate_.Cancel();
        AbortPumpWaits();
        NotifyClosed();
        if (closed_) {
            return;
        }
        closed_ = true;
        inbound_.decoder.Clear();
        ReleaseDataFrame();
        received_.clear();
        inner_->Close();
    }

    void CloseAbortive() override {
        Unsubscribe();
        write_gate_.Cancel();
        AbortPumpWaits();
        NotifyClosed();
        if (closed_) {
            return;
        }
        closed_ = true;
        inbound_.decoder.Clear();
        ReleaseDataFrame();
        received_.clear();
        inner_->CloseAbortive();
    }

    int NativeHandle() const override {
        return inner_->NativeHandle();
    }

    bool IsOpen() const override {
        return !closed_ && inner_->IsOpen();
    }

protected:
    TcpStream* BaseTcpStream() override {
        return BaseTcpStreamOf(*inner_);
    }

    const TcpStream* BaseTcpStream() const override {
        return BaseTcpStreamOf(*inner_);
    }

private:
    friend struct H2InboundPayload;
    // DATA payload taken off the wire; payload->Bytes() is body, and flow_bytes
    // (padding included) is the flow-controlled length (6.1).
    struct QueuedDataFrame {
        common::BufferGuard payload;
        uint32_t flow_bytes = 0;
    };

    net::awaitable<void> WriteGrpcBuffers(
        std::span<const net::const_buffer> buffers) {
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            co_await SendGrpcHunkMessage(std::span<const uint8_t>(data, buffer.size()));
        }
    }

    void ReleaseDataFrame() noexcept {
        data_frame_.reset();
    }

    [[nodiscard]] size_t ConsumeRaw(net::mutable_buffer buffer) noexcept {
        const size_t size = std::min(buffer.size(), data_frame_->Len());
        std::memcpy(buffer.data(), data_frame_->Bytes().data(), size);
        data_frame_->Advance(size);
        if (data_frame_->IsEmpty()) ReleaseDataFrame();
        return size;
    }

    [[nodiscard]] common::MultiBuffer ConsumeRawMultiBuffer() noexcept {
        return common::MultiBuffer{std::move(data_frame_)};
    }

    net::awaitable<bool> WaitForDataFrame() {
        while (!data_frame_ || data_frame_->IsEmpty()) {
            ReleaseDataFrame();
            if (!co_await TakeReceivedData()) co_return false;
        }
        co_return true;
    }

    [[nodiscard]] bool RawReady() const noexcept {
        return data_frame_ && !data_frame_->IsEmpty();
    }
    [[nodiscard]] std::span<const uint8_t> HunkInput() const noexcept {
        return data_frame_->Bytes();
    }
    void ConsumeHunkInput(size_t, size_t consumed) noexcept {
        data_frame_->Advance(consumed);
        if (data_frame_->IsEmpty()) ReleaseDataFrame();
    }
    void HunkFailure() noexcept { CloseAbortive(); }
    void ReleaseHunkStorage() noexcept { inbound_.decoder.Clear(); }

    net::awaitable<AsyncWriteGate::Lease> AcquireWrite() {
        auto lease = co_await write_gate_.Acquire();
        if (!lease) {
            const auto cancellation = co_await net::this_coro::cancellation_state;
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted, "HTTP/2 write cancelled");
            }
            throw IoSystemError(io_error::connection_reset, "HTTP/2 write cancelled");
        }
        co_return lease;
    }

    net::awaitable<void> WriteControlFrame(H2FrameType type,
                                           uint8_t flags,
                                           uint32_t stream_id,
                                           std::span<const uint8_t> payload = {}) {
        auto lease = write_gate_.TryAcquire();
        if (!lease) lease = co_await AcquireWrite();
        const net::const_buffer buffer{payload.data(), payload.size()};
        (void)co_await WriteH2FrameBuffers(
            *inner_, type, flags, stream_id,
            std::span<const net::const_buffer>(&buffer, 1));
    }

    // Sends body bytes as DATA frames within the peer's connection and stream
    // windows (RFC 9113 6.9.1). The physical write gate is held per frame, so
    // a reader pumping frames can still answer SETTINGS and PING meanwhile.
    net::awaitable<void> SendData(std::span<const net::const_buffer> buffers) {
        H2DataCursor cursor(buffers);
        const auto cancellation = co_await net::this_coro::cancellation_state;
        while (cursor.Remaining() != 0) {
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            auto lease = write_gate_.TryAcquire();
            if (!lease) lease = co_await AcquireWrite();
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            if (write_closed_) throw IoSystemError(io_error::connection_reset, "HTTP/2 write on closed stream");
            const size_t credit = std::min({cursor.Remaining(),
                                            kHttp2MaxFramePayload,
                                            conn_send_window_.Available(),
                                            stream_send_window_.Available()});
            if (credit == 0) {
                lease.Reset();
                co_await AdvanceFrames(writer_wake_);
                continue;
            }
            const auto payload = cursor.Next(credit);
            const size_t size = H2DataCursor::Size(payload);
            conn_send_window_.Consume(size);
            stream_send_window_.Consume(size);
            co_await WriteH2FrameBuffers(*inner_, H2FrameType::DATA, 0, stream_id_, payload);
        }
    }

    net::awaitable<void> SendGrpcHunkMessage(std::span<const uint8_t> data) {
        GrpcHunkCursor cursor(data);
        do {
            co_await SendData(cursor.Next());
        } while (!cursor.Done());
    }

    // Moves the next received DATA payload to the read position and returns
    // its flow-control credit to the peer.
    net::awaitable<bool> TakeReceivedData() {
        while (received_.empty()) {
            if (read_closed_ || input_done_) co_return false;
            co_await AdvanceFrames(reader_wake_);
        }
        if (read_closed_) co_return false;
        AsyncWriteGate::Lease lease;
        if (received_.front().flow_bytes != 0) {
            lease = write_gate_.TryAcquire();
            if (!lease) lease = co_await AcquireWrite();
            if (read_closed_ || received_.empty()) co_return false;
        }
        auto& front = received_.front();
        const uint32_t credit = front.flow_bytes;
        data_frame_ = std::move(front.payload);
        received_.pop_front();

        if (credit != 0) {
            // After END_STREAM the peer sends no more DATA on this stream.
            if (!input_done_) {
                co_await SendWindowUpdates(*inner_, credit, stream_id_, credit);
                conn_recv_window_ += credit;
                stream_recv_window_ += credit;
            } else {
                co_await SendWindowUpdates(*inner_, credit, stream_id_, 0);
                conn_recv_window_ += credit;
            }
        }
        co_return true;
    }

    // Pumps one frame, or waits for the pump another operation is running.
    // The channel lives in this frame; `waiter` publishes it only while
    // suspended. Nothing suspends between the pumping_ check and publishing,
    // so the pump cannot finish unseen.
    net::awaitable<void> AdvanceFrames(common::SignalChannel*& waiter) {
        if (pump_failure_) std::rethrow_exception(pump_failure_);
        if (!pumping_) {
            co_await PumpFrame();
            co_return;
        }
        const uint64_t epoch = abort_epoch_;
        common::SignalChannel wake(co_await net::this_coro::executor, 1);
        waiter = &wake;
        struct WaitScope {
            common::SignalChannel*& waiter;
            ~WaitScope() noexcept { waiter = nullptr; }
        } scope{waiter};
        auto [ec] = co_await wake.async_receive(net::as_tuple(net::use_awaitable));
        if (ec || epoch != abort_epoch_) {
            throw IoSystemError(io_error::operation_aborted, "HTTP/2 frame wait aborted");
        }
        if (pump_failure_) std::rethrow_exception(pump_failure_);
    }

    // A failed pump may have consumed part of a frame, so its error is kept
    // and rethrown to every later pump user instead of reading a torn stream.
    net::awaitable<void> PumpFrame() {
        pumping_ = true;
        std::exception_ptr failure;
        std::exception_ptr stored_failure;
        bool store_failure = true;
        bool frame_read = false;
        try {
            std::optional<H2Frame> frame;
            try {
                frame = co_await ReadH2Frame(*inner_);
            } catch (const IoSystemError& error) {
                if (error.code() == io_error::operation_aborted) {
                    store_failure = false;
                }
                throw;
            }
            if (!frame) {
                throw IoSystemError(io_error::connection_reset,
                                    "HTTP/2 peer closed before END_STREAM");
            }
            frame_read = true;
            co_await DispatchFrame(std::move(*frame));
        } catch (const IoSystemError& error) {
            failure = std::current_exception();
            stored_failure = failure;
            if (store_failure || frame_read) {
                inner_->CloseAbortive();
            }
            if (frame_read && error.code() == io_error::operation_aborted) {
                stored_failure = std::make_exception_ptr(
                    IoSystemError(io_error::connection_reset,
                                  "cancelled mid-HTTP/2 frame dispatch"));
            }
        } catch (...) {
            failure = std::current_exception();
            stored_failure = failure;
            if (store_failure || frame_read) {
                inner_->CloseAbortive();
            }
        }
        pumping_ = false;
        if (failure && store_failure) pump_failure_ = stored_failure;
        WakePumpWaiters();
        if (failure) std::rethrow_exception(failure);
    }

    void WakePumpWaiters() noexcept {
        if (auto* wake = std::exchange(reader_wake_, nullptr)) {
            (void)wake->try_send(IoErrorCode{});
        }
        if (auto* wake = std::exchange(writer_wake_, nullptr)) {
            (void)wake->try_send(IoErrorCode{});
        }
    }

    void AbortPumpWaits() noexcept {
        ++abort_epoch_;
        WakePumpWaiters();
    }

    void OnCancellation(transport::Cancellation event) noexcept override {
        AbortPumpWaits();
        if (event.terminal) {
            write_gate_.Cancel();
        } else if (inner_) {
            Resubscribe(inner_->Cancellation());
        }
    }

    net::awaitable<void> DispatchFrame(H2Frame frame) {
        switch (frame.type) {
        case H2FrameType::SETTINGS:
            co_await ReceiveSettings(frame);
            break;
        case H2FrameType::PING:
            if (frame.stream_id != 0) {
                co_await FailConnection(H2Error::Protocol);
                throw IoSystemError(io_error::connection_reset, "HTTP/2 PING on non-zero stream");
            }
            if (frame.Payload().size() != 8) {
                co_await FailConnection(H2Error::FrameSize);
                throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 PING frame size");
            }
            if ((frame.flags & kFlagAck) == 0) {
                co_await WriteControlFrame(H2FrameType::PING, kFlagAck, 0, frame.Payload());
            }
            break;
        case H2FrameType::WINDOW_UPDATE:
            co_await ReceiveWindowUpdate(frame);
            break;
        case H2FrameType::HEADERS:
            if (frame.stream_id != stream_id_) {
                co_await FailConnection(H2Error::Protocol);
                throw IoSystemError(io_error::connection_reset, "HTTP/2 HEADERS on unexpected stream");
            }
            if (!response_headers_received_) {
                if (co_await ReadResponseHeaders(std::move(frame))) {
                    input_done_ = true;
                    response_decoder_.Clear();
                }
            } else {
                co_await ReadResponseTrailers(std::move(frame));
                input_done_ = true;
                response_decoder_.Clear();
            }
            break;
        case H2FrameType::DATA:
            co_await ReceiveData(std::move(frame));
            break;
        case H2FrameType::PRIORITY:
            if (frame.stream_id == 0) {
                co_await FailConnection(H2Error::Protocol);
                throw IoSystemError(io_error::connection_reset, "HTTP/2 PRIORITY on stream 0");
            }
            if (frame.Payload().size() != 5) {
                co_await FailConnection(H2Error::FrameSize);
                throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 PRIORITY frame size");
            }
            break;
        case H2FrameType::RST_STREAM:
            if (frame.stream_id == 0) {
                co_await FailConnection(H2Error::Protocol);
                throw IoSystemError(io_error::connection_reset, "HTTP/2 RST_STREAM on stream 0");
            }
            if (frame.Payload().size() != 4) {
                co_await FailConnection(H2Error::FrameSize);
                throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 RST_STREAM frame size");
            }
            if (frame.stream_id != stream_id_) {
                co_await FailConnection(H2Error::Protocol);
                throw IoSystemError(io_error::connection_reset, "HTTP/2 RST_STREAM on idle stream");
            }
            throw IoSystemError(io_error::connection_reset, "HTTP/2 stream reset by peer");
        case H2FrameType::GOAWAY:
            throw IoSystemError(io_error::connection_reset, "HTTP/2 connection closed by peer");
        case H2FrameType::CONTINUATION:
        case H2FrameType::PUSH_PROMISE:
            co_await FailConnection(H2Error::Protocol);
            throw IoSystemError(io_error::connection_reset, "unexpected HTTP/2 frame");
        default:
            break;
        }
    }

    // Applies SETTINGS_INITIAL_WINDOW_SIZE to the open stream (6.9.2) before
    // acknowledging. Frames never exceed the 16 KiB SETTINGS_MAX_FRAME_SIZE
    // floor, so the peer's larger limit needs no tracking.
    net::awaitable<void> ReceiveSettings(const H2Frame& frame) {
        const bool ack = (frame.flags & kFlagAck) != 0;
        if (frame.stream_id != 0) {
            co_await FailConnection(H2Error::Protocol);
            throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 SETTINGS frame");
        }
        const auto payload = frame.Payload();
        if (payload.size() % 6 != 0 || (ack && !payload.empty())) {
            co_await FailConnection(H2Error::FrameSize);
            throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 SETTINGS frame");
        }
        if (ack) {
            // The peer applied this client's SETTINGS before acknowledging
            // them; DATA it sent earlier used the default stream window.
            if (!local_settings_acked_) {
                local_settings_acked_ = true;
                stream_recv_window_ += static_cast<int64_t>(local_initial_window_) -
                                       std::max<int64_t>(local_initial_window_, H2SendWindow::kDefault);
            }
            co_return;
        }
        const auto initial_window = PeerInitialWindowSetting(payload);
        if (!initial_window) {
            co_await FailConnection(H2Error::FlowControl);
            throw IoSystemError(io_error::connection_reset, "HTTP/2 initial window exceeds 2^31-1");
        }
        if (*initial_window) {
            const int64_t delta = static_cast<int64_t>(**initial_window) -
                                  static_cast<int64_t>(peer_initial_window_);
            if (!stream_send_window_.Adjust(delta)) {
                co_await FailConnection(H2Error::FlowControl);
                throw IoSystemError(io_error::connection_reset, "HTTP/2 stream window overflow");
            }
            peer_initial_window_ = **initial_window;
        }
        co_await WriteControlFrame(H2FrameType::SETTINGS, kFlagAck, 0);
    }

    net::awaitable<void> ReceiveWindowUpdate(const H2Frame& frame) {
        if (frame.stream_id != 0 && frame.stream_id != stream_id_) {
            co_await FailConnection(H2Error::Protocol);
            throw IoSystemError(io_error::connection_reset, "HTTP/2 WINDOW_UPDATE on idle stream");
        }
        const auto increment = WindowUpdateIncrement(frame);
        if (!increment) {
            co_await FailConnection(increment.error());
            throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 WINDOW_UPDATE");
        }
        if (frame.stream_id == 0) {
            if (!conn_send_window_.Adjust(*increment)) {
                co_await FailConnection(H2Error::FlowControl);
                throw IoSystemError(io_error::connection_reset, "HTTP/2 connection window overflow");
            }
        } else {
            if (!stream_send_window_.Adjust(*increment)) {
                co_await FailConnection(H2Error::FlowControl);
                throw IoSystemError(io_error::connection_reset, "HTTP/2 stream window overflow");
            }
        }
    }

    // The whole DATA payload, padding included, counts against both receive
    // windows (6.1, 6.9.1); exceeding either is a FLOW_CONTROL_ERROR
    // connection error (6.9.1, 5.4.1).
    net::awaitable<void> ReceiveData(H2Frame frame) {
        if (frame.stream_id == 0) {
            co_await FailConnection(H2Error::Protocol);
            throw IoSystemError(io_error::connection_reset, "HTTP/2 DATA on stream 0");
        }
        if (frame.stream_id != stream_id_) {
            co_await FailConnection(H2Error::Protocol);
            throw IoSystemError(io_error::connection_reset, "HTTP/2 DATA on unexpected stream");
        }
        const auto raw_payload = frame.Payload();
        const auto flow_len = static_cast<int64_t>(raw_payload.size());
        if (flow_len > conn_recv_window_ || flow_len > stream_recv_window_) {
            co_await FailConnection(H2Error::FlowControl);
            throw IoSystemError(io_error::connection_reset, "HTTP/2 DATA exceeded the advertised receive window");
        }
        conn_recv_window_ -= flow_len;
        stream_recv_window_ -= flow_len;
        if ((frame.flags & kFlagPadded) != 0 &&
            (raw_payload.empty() || raw_payload.front() >= raw_payload.size())) {
            throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 DATA padding");
        }
        if (!response_headers_received_) {
            co_await FailConnection(H2Error::Protocol);
            throw IoSystemError(io_error::connection_reset, "HTTP/2 DATA arrived before response headers");
        }
        if (input_done_) {
            co_await FailConnection(H2Error::StreamClosed);
            throw IoSystemError(io_error::connection_reset, "HTTP/2 DATA after END_STREAM");
        }
        input_done_ = (frame.flags & kFlagEndStream) != 0;
        if (read_closed_) {
            if (flow_len > 0) {
                auto lease = write_gate_.TryAcquire();
                if (!lease) lease = co_await AcquireWrite();
                conn_recv_window_ += flow_len;
                co_await SendWindowUpdates(*inner_, static_cast<uint32_t>(flow_len), stream_id_, 0);
            }
            co_return;
        }
        if (raw_payload.empty()) {
            co_return;
        }
        const auto data = H2DataPayload(frame);
        if (data.empty()) {
            if (!received_.empty()) {
                received_.back().flow_bytes += static_cast<uint32_t>(flow_len);
            } else {
                auto lease = write_gate_.TryAcquire();
                if (!lease) lease = co_await AcquireWrite();
                const auto inc = static_cast<uint32_t>(flow_len);
                conn_recv_window_ += flow_len;
                if (!input_done_) {
                    stream_recv_window_ += flow_len;
                    co_await SendWindowUpdates(*inner_, inc, stream_id_, inc);
                } else {
                    co_await SendWindowUpdates(*inner_, inc, stream_id_, 0);
                }
            }
            co_return;
        }
        if (frame.buffer_payload) {
            const size_t offset = static_cast<size_t>(
                data.data() - frame.buffer_payload->data);
            frame.buffer_payload->start = offset;
            frame.buffer_payload->end = offset + data.size();
            received_.push_back(QueuedDataFrame{
                .payload = std::move(frame.buffer_payload),
                .flow_bytes = static_cast<uint32_t>(flow_len),
            });
        } else if (!received_.empty() &&
                   data.size() <= received_.back().payload->Available()) {
            auto& tail = received_.back();
            std::memcpy(tail.payload->Tail().data(), data.data(), data.size());
            tail.payload->Produce(data.size());
            tail.flow_bytes += static_cast<uint32_t>(flow_len);
        } else {
            common::BufferGuard buf{common::Buffer::New()};
            if (!buf) throw std::bad_alloc();
            std::memcpy(buf->data, data.data(), data.size());
            buf->Produce(data.size());
            received_.push_back(QueuedDataFrame{
                .payload = std::move(buf),
                .flow_bytes = static_cast<uint32_t>(flow_len),
            });
        }
    }

    // Reports a connection error to the peer (5.4.1); the caller then fails
    // the stream. Only stream 1 exists, and the peer opens none.
    net::awaitable<void> FailConnection(H2Error error) {
        const auto payload = EncodeGoaway(0, error);
        co_await WriteControlFrame(H2FrameType::GOAWAY, 0, 0, payload);
    }

    // Returns true when the response already ended the stream.
    net::awaitable<bool> ReadResponseHeaders(H2Frame frame) {
        const bool end_stream = (frame.flags & kFlagEndStream) != 0;
        std::array<char, 4> status_buf{};
        size_t status_len = 0;
        bool has_status = false;
        bool seen_regular = false;
        const char* header_error = nullptr;
        const auto decoded = co_await ReadH2HeaderFields(
            *inner_, response_decoder_, std::move(frame),
            [&](std::string_view name, std::string_view value) {
                if (header_error) return;
                if (name.starts_with(':')) {
                    if (seen_regular || name != ":status" || has_status) {
                        header_error = "invalid HTTP/2 response pseudo-headers";
                        return;
                    }
                    has_status = true;
                    status_len = std::min(value.size(), status_buf.size());
                    std::memcpy(status_buf.data(), value.data(), status_len);
                } else {
                    if (!IsValidHttp2HeaderName(name)) {
                        header_error = "invalid HTTP/2 response header name";
                        return;
                    }
                    seen_regular = true;
                }
            });
        if (!decoded) {
            co_await FailConnection(decoded.error());
            throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 response header block");
        }
        if (header_error) {
            co_await FailConnection(H2Error::Protocol);
            throw IoSystemError(io_error::connection_reset, header_error);
        }
        const std::string_view status(status_buf.data(), status_len);
        const auto is_digit = [](char ch) noexcept {
            return ch >= '0' && ch <= '9';
        };
        if (!has_status || status.size() != 3 ||
            !is_digit(status[0]) || !is_digit(status[1]) || !is_digit(status[2])) {
            co_await FailConnection(H2Error::Protocol);
            throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 :status header");
        }
        if (status.front() == '1') {
            if (status == "101" || end_stream) {
                co_await FailConnection(H2Error::Protocol);
                throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 informational response");
            }
            co_return false;
        }
        if (status.front() != '2') {
            throw IoSystemError(io_error::connection_reset, "HTTP/2 server rejected request");
        }
        response_headers_received_ = true;
        co_return end_stream;
    }

    net::awaitable<void> ReadResponseTrailers(H2Frame frame) {
        if ((frame.flags & kFlagEndStream) == 0 || input_done_) {
            co_await FailConnection(H2Error::Protocol);
            throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 response trailers");
        }
        const char* trailer_error = nullptr;
        const auto decoded = co_await ReadH2HeaderFields(
            *inner_, response_decoder_, std::move(frame),
            [&](std::string_view name, std::string_view) {
                if (trailer_error) return;
                if (name.starts_with(':')) {
                    trailer_error = "pseudo-header in HTTP/2 response trailers";
                    return;
                }
                if (!IsValidHttp2HeaderName(name)) {
                    trailer_error = "invalid HTTP/2 trailer header name";
                }
            });
        if (!decoded) {
            co_await FailConnection(decoded.error());
            throw IoSystemError(io_error::connection_reset, "invalid HTTP/2 trailer header block");
        }
        if (trailer_error) {
            co_await FailConnection(H2Error::Protocol);
            throw IoSystemError(io_error::connection_reset, trailer_error);
        }
    }
    std::unique_ptr<AsyncStream> inner_;
    AsyncWriteGate write_gate_;
    uint32_t stream_id_ = 1;
    H2PayloadCodec payload_codec_ = H2PayloadCodec::GrpcHunk;
    H2InboundPayload inbound_;
    HpackDecoder response_decoder_;
    // Received DATA the reader has not taken yet.
    common::RingDeque<QueuedDataFrame> received_;
    // Current DATA frame payload; data_frame_->Bytes() is unread body.
    common::BufferGuard data_frame_;
    H2SendWindow conn_send_window_;
    H2SendWindow stream_send_window_;
    uint32_t peer_initial_window_ = H2SendWindow::kDefault;
    // Receive windows this client advertised. The connection window stays at
    // the default; the stream window takes local_initial_window_ once the
    // peer acknowledges the SETTINGS carrying it (6.9.2). Signed: a smaller
    // setting may leave the stream window negative until credit returns.
    int64_t conn_recv_window_ = H2SendWindow::kDefault;
    int64_t stream_recv_window_ = H2SendWindow::kDefault;
    uint32_t local_initial_window_ = H2SendWindow::kDefault;
    bool local_settings_acked_ = false;
    // Frame pump: one reader of inner_ at a time; the other side waits on a
    // channel in its own frame, published here only while it waits (one
    // reader and one writer at most). Abort bumps the epoch so pending waits
    // fail instead of re-checking a stream that Cancel()/Close() ended.
    common::SignalChannel* reader_wake_ = nullptr;
    common::SignalChannel* writer_wake_ = nullptr;
    std::exception_ptr pump_failure_;
    uint64_t abort_epoch_ = 0;
    bool pumping_ = false;
    bool read_closed_ = false;
    bool write_closed_ = false;
    bool closed_ = false;
    bool response_headers_received_ = false;
    bool input_done_ = false;
};
// Client preface, SETTINGS and the request HEADERS on stream 1.
net::awaitable<bool> SendHttp2ClientRequest(AsyncStream& stream,
                                            uint32_t initial_window,
                                            uint32_t conn_window,
                                            std::span<const uint8_t> header_block,
                                            bool end_stream) {
    if (header_block.size() > 0x00ff'ffffu) {
        throw IoSystemError(io_error::message_size, "HTTP/2 frame payload too large");
    }
    std::array<uint8_t, 24 + 9 + 6 + 13 + 9> prefix{};
    size_t pos = 0;
    std::memcpy(prefix.data(), kHttp2ClientPreface.data(), kHttp2ClientPreface.size());
    pos += kHttp2ClientPreface.size();

    const auto settings = EncodeInitialWindowSetting(initial_window);
    EncodeH2FrameHeader(
        prefix.data() + pos, static_cast<uint32_t>(settings.size()), H2FrameType::SETTINGS, 0, 0);
    pos += kHttp2FrameHeaderSize;
    std::memcpy(prefix.data() + pos, settings.data(), settings.size());
    pos += settings.size();

    if (conn_window > H2SendWindow::kDefault) {
        EncodeWindowUpdateFrame(
            prefix.data() + pos, 0, conn_window - static_cast<uint32_t>(H2SendWindow::kDefault));
        pos += 13;
    }

    const uint8_t header_flags = static_cast<uint8_t>(
        kFlagEndHeaders | (end_stream ? kFlagEndStream : 0));
    EncodeH2FrameHeader(
        prefix.data() + pos,
        static_cast<uint32_t>(header_block.size()),
        H2FrameType::HEADERS,
        header_flags,
        1);
    pos += kHttp2FrameHeaderSize;

    const std::array<net::const_buffer, 2> buffers{
        net::buffer(prefix.data(), pos),
        net::buffer(header_block.data(), header_block.size()),
    };
    try {
        co_await stream.WriteBuffers(
            std::span<const net::const_buffer>(buffers.data(), header_block.empty() ? 1 : 2));
        co_return true;
    } catch (...) {
        stream.CloseAbortive();
        co_return false;
    }
}

net::awaitable<TransportBuildResult> OpenHttp2ClientStream(
    std::unique_ptr<AsyncStream> stream,
    std::optional<uint32_t> configured_initial_window,
    std::span<const uint8_t> header_block,
    H2PayloadCodec payload_codec,
    bool end_stream,
    std::string_view label,
    std::string_view authority,
    std::string_view path,
    uint64_t conn_id) {
    const uint32_t initial_window = std::min<uint32_t>(
        configured_initial_window.value_or(kDefaultInitialWindow),
        kHttp2MaxQueuedStreamBytes);
    const uint32_t conn_window = std::min<uint32_t>(
        configured_initial_window.value_or(H2SendWindow::kDefault),
        kHttp2MaxQueuedStreamBytes);
    if (!co_await SendHttp2ClientRequest(
            *stream,
            initial_window,
            conn_window,
            header_block,
            end_stream)) {
        co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    }

    LOG_CONN_DEBUG(conn_id,
        "{} client handshake sent authority={} path={}",
        label,
        authority.empty() ? std::string_view("-") : PublicHttpTargetForLog(authority),
        PublicHttpTargetForLog(path));
    co_return std::make_unique<Http2ClientStream>(
        std::move(stream),
        1,
        payload_codec,
        initial_window,
        conn_window,
        end_stream);
}
net::awaitable<TransportBuildResult> DoGrpcClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id) {
    const std::string_view path = cfg.request_path;
    const auto headers = EncodeGrpcRequestHeaders(
        authority,
        path,
        tls,
        cfg.user_agent.empty() ? std::string_view("grpc-go/1.0")
                               : std::string_view(cfg.user_agent));
    co_return co_await OpenHttp2ClientStream(
        std::move(stream),
        cfg.initial_window_size,
        headers.Span(),
        H2PayloadCodec::GrpcHunk,
        false,
        "gRPC",
        authority,
        path,
        conn_id);
}

net::awaitable<TransportBuildResult> DoHttp2ClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    HttpClientRequestView req,
    std::string_view authority,
    bool tls,
    uint64_t conn_id) {
    const auto headers = EncodeHttpRequestHeaders(authority, tls, req);
    const bool end_stream = common::EqualsAsciiCI(req.method, "GET");
    co_return co_await OpenHttp2ClientStream(
        std::move(stream),
        req.initial_window_size,
        headers.Span(),
        H2PayloadCodec::RawData,
        end_stream,
        "HTTP/2",
        authority,
        EffectiveHttpPath(req.path),
        conn_id);
}

}  // namespace transport
