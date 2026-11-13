#include "transport/http2_server.hpp"

namespace transport {
// The release signal lives in this frame and is published only while it
// exists. ReleaseOwner sets owner_released_ before signalling, and nothing
// suspends between checking it and receiving, so no release goes unseen.
net::awaitable<void> Http2ServerSubStreamState::JoinOwner(
    std::shared_ptr<Http2ServerSubStreamState> state,
    std::shared_ptr<XHttpPacketUpSession> upload_session) {
    std::optional<common::SignalChannel> owner_signal;
    struct Unpublish {
        common::SignalChannel*& published;
        ~Unpublish() noexcept { published = nullptr; }
    } unpublish{state->owner_signal_};
    const auto wait_owner = [&] {
        if (!owner_signal) {
            owner_signal.emplace(state->input_signal_.get_executor(), 1);
            state->owner_signal_ = &*owner_signal;
        }
        return owner_signal->async_receive(net::use_awaitable);
    };
    bool cancelled = false;
    try {
        if (!state->owner_released_) co_await wait_owner();
    } catch (...) {
        cancelled = true;
        if (upload_session) upload_session->Close();
        if (auto session = state->LockSession()) session->CancelAll();
    }
    if (cancelled) {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        if (!state->owner_released_) co_await wait_owner();
    }
}

Http2ServerSubStreamState::Http2ServerSubStreamState(
    const net::any_io_executor& executor,
    std::shared_ptr<Http2ServerSession> session,
    uint32_t stream_id,
    H2PayloadCodec payload_codec,
    int64_t initial_send_window)
    : input_signal_(executor, 1)
    , send_window_(initial_send_window)
    , session_(std::move(session))
    , stream_id_(stream_id)
    , payload_codec_(payload_codec)
    , inbound_{payload_codec, {}} {}

net::awaitable<void> Http2ServerSubStreamState::WaitSendCredit() {
    const uint64_t epoch = write_abort_epoch_;
    if (!credit_signal_) {
        credit_signal_.emplace(input_signal_.get_executor(), 1);
    }
    auto [ec] = co_await credit_signal_->async_receive(net::as_tuple(net::use_awaitable));
    if (ec || epoch != write_abort_epoch_) {
        throw IoSystemError(io_error::operation_aborted, "HTTP/2 send window wait aborted");
    }
}

bool Http2ServerSubStreamState::EnqueueData(
    Http2ServerSession& session,
    H2Frame& frame,
    std::span<const uint8_t> data) {
    if (!AcceptsData()) return false;
    const size_t size = data.size();
    if (size > kHttp2MaxQueuedStreamBytes - queued_bytes_) return false;
    // Pack small/split DATA frames into the tail, including a prefix of a
    // larger successor. Otherwise legal fragmentation leaves an 8 KiB hole
    // per tiny frame and exhausts storage before the advertised byte window.
    size_t coalesced = 0;
    if (!data_frames_.empty()) {
        auto& tail = *data_frames_.back().payload;
        if (size <= tail.capacity - tail.end) {
            std::memcpy(tail.data + tail.end, data.data(), size);
            tail.end += size;
            queued_bytes_ += size;
            WakeInputReader();
            return true;
        }
        coalesced = tail.capacity - tail.end;
    }
    common::BufferGuard frame_payload;
    size_t offset = 0;
    size_t storage = 0;
    if (frame.buffer_payload) {
        offset = static_cast<size_t>(data.data() - frame.buffer_payload->data);
        storage = frame.buffer_payload->capacity;
    } else {
        frame_payload.reset(common::Buffer::New());
        if (!frame_payload) throw std::bad_alloc();
        storage = frame_payload->capacity;
    }
    if (storage > kHttp2MaxQueuedStreamStorage - queued_storage_ ||
        !session.ReserveReceiveMemory(storage)) return false;
    const auto upload_budget = upload_budget_.lock();
    if (upload_budget && !upload_budget->Reserve(storage)) {
        session.ReleaseReceiveMemory(storage);
        return false;
    }
    if (frame.buffer_payload) {
        frame_payload = std::move(frame.buffer_payload);
        frame_payload->start = offset;
        frame_payload->end = offset + size;
    } else {
        std::memcpy(frame_payload->data, data.data(), size);
        frame_payload->start = 0;
        frame_payload->end = size;
    }
    try {
        data_frames_.push_back(QueuedDataFrame{std::move(frame_payload)});
    } catch (...) {
        session.ReleaseReceiveMemory(storage);
        if (upload_budget) upload_budget->Release(storage);
        throw;
    }
    if (coalesced != 0) {
        // Do not modify the old tail until the new allocation and deque entry
        // are committed: rejection must leave every input byte unqueued.
        auto& tail = *data_frames_[data_frames_.size() - 2].payload;
        auto& added = *data_frames_.back().payload;
        std::memcpy(tail.data + tail.end, added.data + added.start, coalesced);
        tail.end += coalesced;
        const size_t remaining = size - coalesced;
        std::memmove(added.data, added.data + added.start + coalesced, remaining);
        added.start = 0;
        added.end = remaining;
    }
    if (upload_budget) upload_reserved_ += storage;
    queued_storage_ += storage;
    queued_bytes_ += size;
    WakeInputReader();
    return true;
}

void Http2ServerSubStreamState::CloseInput() {
    if (input_done_) {
        return;
    }
    input_done_ = true;
    WakeInputReader();
}

void Http2ServerSubStreamState::CancelFromSession(IoErrorCode error) noexcept {
    if (cancelled_) {
        return;
    }
    cancelled_ = true;
    terminal_error_ = error;
    input_done_ = true;
    read_closed_ = true;
    write_closed_ = true;
    trailers_sent_ = true;
    closing_local_ = true;
    DropQueuedData();
    inbound_.decoder.Clear();
    cancellation_.Stop();
    WakeInputReader();
    WakeSendWaiter();
}

void Http2ServerSubStreamState::CancelPendingOperations() noexcept {
    cancellation_.CancelPending();
    if (cancelled_) {
        return;
    }
    ++read_abort_epoch_;
    ++write_abort_epoch_;
    WakeInputReader();
    WakeSendWaiter();
}

void Http2ServerSubStreamState::AbortLocal() noexcept {
    if (cancelled_) return;
    auto session = LockSession();
    if (!session) {
        CancelFromSession();
        return;
    }
    const auto stream_id = stream_id_;
    session->RemoveStream(stream_id);
    try {
        session->Spawn(session->FinishStream(stream_id, true));
    } catch (...) {
        session->CancelAll();
    }
}

void Http2ServerSubStreamState::CloseLocal() noexcept {
    cancellation_.Stop();
    if (cancelled_ || closing_local_) {
        return;
    }
    closing_local_ = true;
    read_closed_ = true;
    DropQueuedData();
    inbound_.decoder.Clear();
    WakeInputReader();

    auto session = session_.lock();
    if (!session) {
        CancelFromSession();
        return;
    }

    const uint32_t stream_id = stream_id_;
    if (!trailers_sent_) {
        trailers_sent_ = true;
        write_closed_ = true;
        try {
            session->Spawn(session->FinishStream(stream_id, false));
        } catch (...) {
            session->RemoveStream(stream_id);
            session->CancelAll();
        }
    } else {
        session->RemoveStream(stream_id);
    }
}

void Http2ServerSubStreamState::ShutdownRead() noexcept {
    read_closed_ = true;
    DropQueuedData();
    inbound_.decoder.Clear();
    WakeInputReader();
}

void Http2ServerSubStreamState::ShutdownWrite() noexcept {
    write_closed_ = true;
}

std::shared_ptr<Http2ServerSession> Http2ServerSubStreamState::LockWritableSession() const {
    if (write_closed_ || cancelled_) {
        throw IoSystemError(io_error::connection_reset, "gRPC write on closed server stream");
    }
    auto session = session_.lock();
    if (!session) {
        throw IoSystemError(io_error::connection_reset, "gRPC write without server session");
    }
    return session;
}

net::awaitable<size_t> Http2ServerSubStreamState::AsyncRead(
    net::mutable_buffer buffer) {
    return inbound_.Read(*this, buffer);
}

net::awaitable<size_t> Http2ServerSubStreamState::AsyncWrite(
    net::const_buffer buffer) {
    auto session = LockWritableSession();
    if (payload_codec_ == H2PayloadCodec::RawData) {
        if (!co_await session->WriteDataSerialized(
                stream_id_, std::span<const net::const_buffer>(&buffer, 1))) {
            throw IoSystemError(io_error::connection_reset, "HTTP/2 raw server stream write failed");
        }
        co_return buffer.size();
    }
    const auto* data = static_cast<const uint8_t*>(buffer.data());
    if (!co_await session->WriteGrpcMessageSerialized(
            stream_id_, std::span<const uint8_t>(data, buffer.size()))) {
        throw IoSystemError(io_error::connection_reset, "gRPC server stream write failed");
    }
    co_return buffer.size();
}

net::awaitable<common::MultiBuffer> Http2ServerSubStreamState::ReadMultiBuffer() {
    return inbound_.ReadMultiBuffer(*this);
}

net::awaitable<void> Http2ServerSubStreamState::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    auto session = LockWritableSession();
    if (payload_codec_ == H2PayloadCodec::RawData) {
        const bool has_data = std::any_of(buffers.begin(), buffers.end(),
            [](const net::const_buffer& buffer) { return buffer.size() > 0; });
        if (!has_data) {
            co_return;
        }
        if (!co_await session->WriteDataSerialized(stream_id_, buffers)) {
            throw IoSystemError(io_error::connection_reset, "HTTP/2 raw server stream WriteBuffers failed");
        }
        co_return;
    }

    for (const auto& buffer : buffers) {
        if (buffer.size() == 0) {
            continue;
        }
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        if (!co_await session->WriteGrpcMessageSerialized(
                stream_id_, std::span<const uint8_t>(data, buffer.size()))) {
            throw IoSystemError(io_error::connection_reset, "gRPC server stream write failed");
        }
    }
}

net::awaitable<void> Http2ServerSubStreamState::AsyncShutdownWrite() {
    if (trailers_sent_) {
        co_return;
    }
    write_closed_ = true;
    trailers_sent_ = true;
    if (auto session = session_.lock()) {
        const bool sent = payload_codec_ == H2PayloadCodec::RawData
            ? co_await session->WriteFrameSerialized(
                  H2FrameType::DATA, kFlagEndStream, stream_id_)
            : co_await session->WriteTrailersSerialized(stream_id_);
        if (!sent) {
            trailers_sent_ = false;
        }
    }
}

void Http2ServerSubStreamState::PopFrontDataFrame(Http2ServerSession* session) noexcept {
    const auto& front = data_frames_.front();
    const size_t storage = front.payload->capacity;
    queued_storage_ -= storage;
    if (session) session->ReleaseReceiveMemory(storage);
    if (upload_reserved_ != 0) {
        if (auto budget = upload_budget_.lock()) {
            budget->Release(storage);
        }
        upload_reserved_ -= std::min(upload_reserved_, storage);
    }
    data_frames_.pop_front();
}

void Http2ServerSubStreamState::DropQueuedData() noexcept {
    const size_t discarded = std::exchange(queued_bytes_, 0);
    const size_t upload_reserved = std::exchange(upload_reserved_, 0);
    if (upload_reserved != 0) {
        if (auto budget = upload_budget_.lock()) {
            budget->Release(upload_reserved);
        }
    }
    upload_budget_.reset();
    data_frames_.clear();
    const auto session = LockSession();
    ReleaseDecoderStorage(session.get());
    if (session) {
        session->ReleaseReceiveMemory(std::exchange(queued_storage_, 0));
        session->ReturnReceiveCredit(nullptr, discarded);
    }
}

void Http2ServerSubStreamState::ConsumeData(Http2ServerSession* session, size_t size) noexcept {
    queued_bytes_ -= size;
    if (session) session->ReturnReceiveCredit(this, size);
}

void Http2ServerSubStreamState::ReleaseDecoderStorage(Http2ServerSession* session) noexcept {
    if (session) session->ReleaseReceiveMemory(std::exchange(decoder_reserved_, 0));
}

bool Http2ServerSubStreamState::FrontDataReady() noexcept {
    while (!data_frames_.empty()) {
        if (!data_frames_.front().payload->IsEmpty()) {
            return true;
        }
        PopFrontDataFrame(LockSession().get());
    }
    return false;
}


net::awaitable<bool> Http2ServerSubStreamState::WaitForDataFrame() {
    while (!cancelled_) {
        if (FrontDataReady()) {
            co_return true;
        }

        if (input_done_ || read_closed_) {
            co_return false;
        }

        const uint64_t epoch = read_abort_epoch_;
        auto [ec] = co_await input_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (ec || epoch != read_abort_epoch_) {
            throw IoSystemError(io_error::operation_aborted, "HTTP/2 raw read cancelled");
        }
    }
    throw IoSystemError(terminal_error_, "HTTP/2 stream terminated");
}

std::span<const uint8_t> Http2ServerSubStreamState::HunkInput() {
    const auto& front = data_frames_.front();
    auto bytes = front.payload->Bytes();
    bytes = bytes.first(std::min(bytes.size(), inbound_.decoder.NextFeedLimit()));
    // 解码器增长与帧队列使用同一连接预算；在实际 Feed 分配前计入保守上界。
    const size_t reserve = 2 * bytes.size() + (decoder_reserved_ == 0 ? 256 : 0);
    const auto session = LockSession();
    if (!session || !session->ReserveReceiveMemory(reserve)) {
        if (session) session->RejectReceiveBudget(stream_id_);
        else AbortLocal();
        throw IoSystemError(io_error::no_buffer_space, "HTTP/2 gRPC receive budget exhausted");
    }
    decoder_reserved_ += reserve;
    return bytes;
}

void Http2ServerSubStreamState::ConsumeHunkInput(
    size_t offered, size_t consumed) noexcept {
    const auto session = LockSession();
    const size_t unused = 2 * (offered - consumed);
    session->ReleaseReceiveMemory(unused);
    decoder_reserved_ -= unused;
    data_frames_.front().payload->Advance(consumed);
    if (data_frames_.front().payload->IsEmpty()) PopFrontDataFrame(session.get());
    if (inbound_.decoder.Payload().empty() && inbound_.decoder.AtMessageBoundary())
        ReleaseDecoderStorage(session.get());
    ConsumeData(session.get(), consumed);
}

void Http2ServerSubStreamState::HunkFailure() noexcept {
    ReleaseDecoderStorage(LockSession().get());
    AbortLocal();
}

void Http2ServerSubStreamState::ReleaseHunkStorage() noexcept {
    ReleaseDecoderStorage(LockSession().get());
}

size_t Http2ServerSubStreamState::ConsumeRaw(net::mutable_buffer buffer) noexcept {
    const auto session = LockSession();
    auto& front = *data_frames_.front().payload;
    const size_t size = std::min(buffer.size(), front.Len());
    std::memcpy(buffer.data(), front.Bytes().data(), size);
    front.Advance(size);
    if (front.IsEmpty()) PopFrontDataFrame(session.get());
    ConsumeData(session.get(), size);
    return size;
}

common::MultiBuffer Http2ServerSubStreamState::ConsumeRawMultiBuffer() noexcept {
    const auto session = LockSession();
    auto& front = data_frames_.front();
    const size_t size = front.payload->Len();
    const size_t storage = front.payload->capacity;
    common::BufferGuard buffer = std::move(front.payload);
    queued_storage_ -= storage;
    if (session) session->ReleaseReceiveMemory(storage);
    if (upload_reserved_ != 0) {
        if (auto budget = upload_budget_.lock()) {
            budget->Release(storage);
        }
        upload_reserved_ -= std::min(upload_reserved_, storage);
    }
    data_frames_.pop_front();
    ConsumeData(session.get(), size);
    return common::MultiBuffer{std::move(buffer)};
}

int Http2ServerSubStream::NativeHandle() const {
    if (closed_) {
        return -1;
    }
    auto session = state_->LockSession();
    const auto* inner = session ? session->InnerStream() : nullptr;
    return inner ? inner->NativeHandle() : -1;
}

bool Http2ServerSubStream::IsOpen() const {
    if (closed_) {
        return false;
    }
    auto session = state_->LockSession();
    const auto* inner = session ? session->InnerStream() : nullptr;
    return inner && inner->IsOpen();
}

TcpStream* Http2ServerSubStream::BaseTcpStream() {
    if (closed_) {
        return nullptr;
    }
    auto session = state_->LockSession();
    auto* inner = session ? session->InnerStream() : nullptr;
    return inner ? BaseTcpStreamOf(*inner) : nullptr;
}

const TcpStream* Http2ServerSubStream::BaseTcpStream() const {
    if (closed_) {
        return nullptr;
    }
    auto session = state_->LockSession();
    const auto* inner = session ? session->InnerStream() : nullptr;
    return inner ? BaseTcpStreamOf(*inner) : nullptr;
}


Http2ServerSession::Http2ServerSession(
    app::GroupCoordinator& coordinator, net::io_context& io_context,
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
        if (xhttp_config_) {
            const std::string_view default_ct =
                (!xhttp_config_->no_sse_header &&
                 !FindHttpHeader(xhttp_config_->headers, "Content-Type"))
                    ? std::string_view("text/event-stream")
                    : std::string_view{};
            response_header_block_ =
                EncodeHttpResponseHeaders(xhttp_config_->headers, default_ct);
        } else if (http_config_) {
            response_header_block_ = EncodeHttpResponseHeaders(http_config_->headers);
        } else {
            throw std::invalid_argument("HTTP/2 raw session requires an HTTP or XHTTP config");
        }
    }
    Resubscribe(stream_->Cancellation());
}

Http2ServerSession::~Http2ServerSession() noexcept {
    Unsubscribe();
    CancelAll();
}

net::awaitable<void> Http2ServerSession::Run() {
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

net::awaitable<void> Http2ServerSession::FinishStream(uint32_t id, bool reset) {
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

void Http2ServerSession::Spawn(net::awaitable<void> task) {
    if (cancelled_ || !tasks_) throw IoSystemError(io_error::operation_aborted);
    tasks_->Spawn(std::move(task));
}

void Http2ServerSession::ReturnReceiveCredit(Http2ServerSubStreamState* sub, size_t size) noexcept {
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

void Http2ServerSession::RejectReceiveBudget(uint32_t stream_id) noexcept {
    RemoveStream(stream_id, io_error::no_buffer_space);
    try {
        Spawn(SendReceiveBudgetReset(stream_id));
    } catch (...) {
        CancelAll();
    }
}

void Http2ServerSession::RemoveStream(uint32_t stream_id, IoErrorCode error) noexcept {
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

void Http2ServerSession::CancelAll(IoErrorCode error) noexcept {
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

net::awaitable<bool> Http2ServerSession::WriteFrameSerialized(
    H2FrameType type,
    uint8_t flags,
    uint32_t stream_id,
    std::span<const uint8_t> payload) {
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

net::awaitable<bool> Http2ServerSession::WriteInitialPreface(uint32_t initial_window) {
    auto write_lease = write_gate_.TryAcquire();
    if (!write_lease) write_lease = co_await write_gate_.Acquire();
    if (!write_lease || !ConnectionWritable()) {
        co_return false;
    }
    std::array<uint8_t, kHttp2FrameHeaderSize + 12 + 13> frames{};
    EncodeH2FrameHeader(frames.data(), 12, H2FrameType::SETTINGS, 0, 0);
    const auto initial_window_setting = EncodeInitialWindowSetting(initial_window);
    std::memcpy(frames.data() + kHttp2FrameHeaderSize,
                initial_window_setting.data(),
                initial_window_setting.size());
    frames[kHttp2FrameHeaderSize + 6] = 0;
    frames[kHttp2FrameHeaderSize + 7] = 3; // SETTINGS_MAX_CONCURRENT_STREAMS
    common::StoreU32BE(frames.data() + kHttp2FrameHeaderSize + 8, kHttp2MaxConcurrentStreams);
    EncodeWindowUpdateFrame(
        frames.data() + kHttp2FrameHeaderSize + 12,
        0,
        kHttp2ConnectionReceiveWindow - H2SendWindow::kDefault);
    const net::const_buffer buf = net::buffer(frames);
    try {
        co_await stream_->WriteBuffers(std::span<const net::const_buffer>(&buf, 1));
        co_return true;
    } catch (...) {
        stream_->CloseAbortive();
        throw;
    }
}

net::awaitable<bool> Http2ServerSession::WriteGrpcMessageSerialized(
    uint32_t stream_id,
    std::span<const uint8_t> data) {
    GrpcHunkCursor cursor(data);
    do {
        if (!co_await WriteDataSerialized(stream_id, cursor.Next())) {
            co_return false;
        }
    } while (!cursor.Done());
    co_return true;
}

net::awaitable<bool> Http2ServerSession::WriteDataSerialized(
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

net::awaitable<bool> Http2ServerSession::WriteTrailersSerialized(uint32_t stream_id) {
    return WriteFrameSerialized(
        H2FrameType::HEADERS, kFlagEndHeaders | kFlagEndStream, stream_id, kGrpcTrailerBlock);
}

net::awaitable<void> Http2ServerSession::RunReadLoop() {
    try {
        while (!cancelled_ && stream_) {
            auto frame = co_await ReadH2Frame(*stream_);
            if (!frame) {
                const bool ended = std::all_of(streams_.begin(), streams_.end(),
                    [](const auto& entry) { return entry.second->InputEnded(); });
                if (ended) co_return;
                throw IoSystemError(io_error::connection_reset, "HTTP/2 missing END_STREAM");
            }

            // DATA and WINDOW_UPDATE, the dominant steady-state frames, are
            // accounted synchronously; only fault reporting suspends.
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
            if (frame->type == H2FrameType::WINDOW_UPDATE) {
                if (const auto fault = ReceiveWindowUpdate(*frame)) {
                    if (fault->connection) {
                        (void)co_await FailConnection(fault->error);
                        break;
                    }
                    if (!co_await ResetStream(frame->stream_id, fault->error)) {
                        break;
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

net::awaitable<void> Http2ServerSession::FlushReceiveCredit() {
    try {
        while (!cancelled_) {
            auto lease = write_gate_.TryAcquire();
            if (!lease) lease = co_await write_gate_.Acquire();
            if (!lease || !ConnectionWritable()) break;
            const uint32_t conn_increment = std::exchange(consumed_connection_credit_, 0);
            if (conn_increment != 0) {
                connection_receive_window_ += conn_increment;
            }
            static constexpr size_t kMaxBatchedStreamUpdates = 16;
            std::array<uint8_t, 13 * (1 + kMaxBatchedStreamUpdates)> frames{};
            size_t encoded_bytes = 0;
            if (conn_increment != 0) {
                EncodeWindowUpdateFrame(frames.data(), 0, conn_increment);
                encoded_bytes += 13;
            }
            size_t batched_streams = 0;
            bool more_streams = false;
            // Do not retain an unordered_map iterator over an await.
            for (auto& [stream_id, sub] : streams_) {
                if (!sub->AcceptsData()) {
                    sub->ConsumedCredit() = 0;
                    continue;
                }
                if (sub->ConsumedCredit() == 0) continue;
                if (batched_streams < kMaxBatchedStreamUpdates) {
                    const uint32_t inc = std::exchange(sub->ConsumedCredit(), 0);
                    sub->ReceiveWindow() += inc;
                    EncodeWindowUpdateFrame(frames.data() + encoded_bytes, stream_id, inc);
                    encoded_bytes += 13;
                    ++batched_streams;
                } else {
                    more_streams = true;
                }
            }
            if (encoded_bytes == 0) break;
            const net::const_buffer buf = net::buffer(frames.data(), encoded_bytes);
            try {
                co_await stream_->WriteBuffers(std::span<const net::const_buffer>(&buf, 1));
            } catch (...) {
                stream_->CloseAbortive();
                throw;
            }
            if (!more_streams && consumed_connection_credit_ == 0) break;
        }
    } catch (...) {
        CancelAll();
    }
    credit_flush_running_ = false;
}

net::awaitable<void> Http2ServerSession::RunPacketUpload(
    std::unique_ptr<AsyncStream> stream,
    std::shared_ptr<XHttpPacketUpSession> session, uint64_t seq) {
    RequestScope active(active_requests_);
    try {
        XHttpPacketUpSession::Upload upload(*session, *stream);
        common::MultiBuffer payload;
        while (co_await upload.Read(payload, common::Buffer::kSize) != 0) {
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

net::awaitable<void> Http2ServerSession::RunRequest(
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

void Http2ServerSession::DeliverRequest(
    std::shared_ptr<Http2ServerSubStreamState> sub,
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

net::awaitable<bool> Http2ServerSession::AcceptStream(
    uint32_t stream_id,
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

net::awaitable<bool> Http2ServerSession::ResetStream(uint32_t stream_id, H2Error error) {
    RemoveStream(stream_id, error == H2Error::ExcessiveLoad ||
        error == H2Error::RefusedStream ? IoErrorCode(io_error::no_buffer_space) :
        IoErrorCode(io_error::operation_aborted));
    std::array<uint8_t, 4> payload{};
    common::StoreU32BE(payload.data(), static_cast<uint32_t>(error));
    co_return co_await WriteFrameSerialized(H2FrameType::RST_STREAM, 0, stream_id, payload);
}

net::awaitable<void> Http2ServerSession::SendReceiveBudgetReset(uint32_t stream_id) {
    if (!co_await ResetStream(stream_id, H2Error::ExcessiveLoad)) CancelAll();
}

net::awaitable<bool> Http2ServerSession::FailConnection(H2Error error) {
    const auto payload = EncodeGoaway(last_remote_stream_id_, error);
    (void)co_await WriteFrameSerialized(H2FrameType::GOAWAY, 0, 0, payload);
    CancelAll();
    co_return false;
}

net::awaitable<bool> Http2ServerSession::DispatchFrame(H2Frame frame) {
    switch (frame.type) {
    case H2FrameType::SETTINGS: {
        if (frame.stream_id != 0) co_return co_await FailConnection(H2Error::Protocol);
        const auto settings_payload = frame.Payload();
        if (settings_payload.size() % 6 != 0 ||
            ((frame.flags & kFlagAck) && !settings_payload.empty())) {
            co_return co_await FailConnection(H2Error::FrameSize);
        }
        if (!(frame.flags & kFlagAck)) {
            if (const auto error = ApplyPeerSettings(settings_payload)) {
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
    }
    case H2FrameType::PING:
        if (frame.stream_id != 0) co_return co_await FailConnection(H2Error::Protocol);
        if (frame.Payload().size() != 8) co_return co_await FailConnection(H2Error::FrameSize);
        if (!(frame.flags & kFlagAck)) {
            co_return co_await WriteFrameSerialized(
                H2FrameType::PING, kFlagAck, 0, frame.Payload());
        }
        break;
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
        if (frame.Payload().size() != 5) co_return co_await FailConnection(H2Error::FrameSize);
        break;
    case H2FrameType::RST_STREAM:
        if (frame.Payload().size() != 4) co_return co_await FailConnection(H2Error::FrameSize);
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

std::optional<H2Error> Http2ServerSession::ApplyPeerSettings(std::span<const uint8_t> payload) {
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

std::optional<Http2ServerSession::DataFault> Http2ServerSession::ReceiveWindowUpdate(
    const H2Frame& frame) {
    const auto increment = WindowUpdateIncrement(frame);
    if (frame.stream_id == 0) {
        if (!increment) return DataFault{increment.error(), true};
        if (!conn_send_window_.Adjust(*increment)) {
            return DataFault{H2Error::FlowControl, true};
        }
        for (auto& [stream_id, sub] : streams_) {
            (void)stream_id;
            sub->WakeSendWaiter();
        }
        return std::nullopt;
    }
    if (!IsKnownClientStream(frame.stream_id)) {
        return DataFault{H2Error::Protocol, true};
    }
    if (!increment && increment.error() == H2Error::FrameSize) {
        return DataFault{H2Error::FrameSize, true};
    }
    const auto it = streams_.find(frame.stream_id);
    if (it == streams_.end()) return std::nullopt;
    if (!increment) return DataFault{increment.error(), false};
    if (!it->second->SendWindow().Adjust(*increment)) {
        return DataFault{H2Error::FlowControl, false};
    }
    it->second->WakeSendWaiter();
    return std::nullopt;
}

net::awaitable<bool> Http2ServerSession::ReceiveHeaders(H2Frame frame) {
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
        parsed = (frame.flags & kFlagEndHeaders) != 0
            ? TryParseSingleH2RequestHeaders(
                  hpack_decoder_, frame, real_ip_header, trailers || closed_client_stream)
            : co_await ParseH2RequestHeaders(
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
        if (!PathPrefixMatchesSegment(http_config_->path, request->path) ||
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
            !PathMatchesExactly(grpc_config_->request_path, request->path)) {
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

net::awaitable<bool> Http2ServerSession::RouteXHttpRequest(
    uint32_t stream_id,
    bool end_stream,
    H2RequestHeaders request,
    std::shared_ptr<Http2ServerSubStreamState> sub) {
    if (const std::string_view expected_host =
            ResolveConfiguredHttpHost(xhttp_config_->host, &xhttp_config_->headers);
        !expected_host.empty() &&
        !AuthorityMatchesHost(request.authority, expected_host)) {
        LOG_CONN_DEBUG(conn_id_,
            "XHTTP server H2 host mismatch expected='{}' actual='{}'",
            PublicHttpTargetForLog(expected_host),
            PublicHttpTargetForLog(request.authority));
        co_return co_await ResetStream(stream_id, H2Error::Protocol);
    }

    const auto meta = ParseXHttpRequestMeta(
        xhttp_config_->normalized_path,
        request.path,
        request.method);
    if (!XHttpKindAllowed(meta.kind, *xhttp_config_))
        co_return co_await ResetStream(stream_id, H2Error::Protocol);
    switch (meta.kind) {
    case XHttpRequestMeta::Kind::StreamOne: {
        if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
            co_return false;
        }
        LOG_CONN_DEBUG(conn_id_, "XHTTP server H2 stream-one ready stream_id={}",
                      stream_id);
        DeliverRequest(std::move(sub), nullptr, std::move(request.metadata));
        co_return true;
    }
    case XHttpRequestMeta::Kind::PacketDown: {
        auto xsession = co_await GetXHttpPacketSession(coordinator_,
            io_context_, xhttp_config_->session_namespace,
            meta.session_id, XHttpSessionAccess::Open);
        if (!xsession) co_return co_await ResetStream(stream_id, H2Error::Protocol);
        XHttpDownlinkClaim claim(*xsession);
        if (!claim) co_return co_await ResetStream(stream_id, H2Error::Protocol);
        if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
            co_return false;
        }
        LOG_CONN_DEBUG(conn_id_, "XHTTP server H2 split downlink ready session={} stream_id={} mode={}",
                      meta.session_id,
                      stream_id,
                      xhttp_config_->AcceptsStreamUp() ? "stream-up" : "packet-up");
        claim.Release();
        DeliverRequest(std::move(sub), std::move(xsession), std::move(request.metadata));
        co_return true;
    }
    case XHttpRequestMeta::Kind::StreamUp: {
        auto xsession = co_await GetXHttpPacketSession(coordinator_,
            io_context_, xhttp_config_->session_namespace,
            meta.session_id, XHttpSessionAccess::Open);
        if (!xsession) {
            co_return co_await ResetStream(stream_id, H2Error::Protocol);
        }
        if (!xsession->CanAttachStream()) {
            LOG_CONN_DEBUG(conn_id_,
                "XHTTP server rejected concurrent H2 stream-up session={}",
                meta.session_id);
            constexpr std::array<uint8_t, 1> kBadRequestStatus{
                0x80 | kHpackStaticStatusBadRequest};
            const bool ok = co_await WriteFrameSerialized(
                H2FrameType::HEADERS, kFlagEndHeaders | kFlagEndStream,
                stream_id, kBadRequestStatus);
            RemoveStream(stream_id);
            co_return ok;
        }
        bool accepting = true;
        struct StreamUpGuard {
            XHttpPacketUpSession* session;
            bool& active;
            ~StreamUpGuard() {
                if (active && session->CanAttachStream()) session->Close();
            }
        } guard{xsession.get(), accepting};
        if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
            co_return false;
        }
        accepting = false;
        LOG_CONN_DEBUG(conn_id_, "XHTTP server H2 stream-up upload ready session={} stream_id={}",
                      meta.session_id,
                      stream_id);
        sub->SetUploadBudget(xsession);
        auto upload = std::make_unique<Http2ServerSubStream>(sub);
        if (!xsession->AttachStream(std::move(upload))) {
            LOG_CONN_DEBUG(conn_id_,
                "XHTTP server rejected concurrent H2 stream-up session={}",
                meta.session_id);
            co_return co_await ResetStream(stream_id, H2Error::Protocol);
        }
        auto* raw_xsession = xsession.get();
        try {
            Spawn(Http2ServerSubStreamState::JoinOwner(std::move(sub), std::move(xsession)));
        } catch (...) {
            raw_xsession->Close();
            throw;
        }
        co_return true;
    }
    case XHttpRequestMeta::Kind::PacketUp: {
        auto xsession = TryGetLocalXHttpPacketSession(
            io_context_, xhttp_config_->session_namespace, meta.session_id);
        if (!xsession) {
            xsession = co_await GetXHttpPacketSession(coordinator_,
                io_context_, xhttp_config_->session_namespace,
                meta.session_id, XHttpSessionAccess::Upload);
        }
        if (!xsession) {
            co_return co_await ResetStream(stream_id, H2Error::Protocol);
        }
        if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
            co_return false;
        }
        sub->SetUploadBudget(xsession);
        auto upload = std::make_unique<Http2ServerSubStream>(std::move(sub));
        bool spawn_failed = false;
        try {
            Spawn(RunPacketUpload(std::move(upload), std::move(xsession), meta.seq));
        } catch (...) {
            spawn_failed = true;
        }
        if (spawn_failed) {
            co_return co_await ResetStream(stream_id, H2Error::Cancel);
        }
        co_return true;
    }
    case XHttpRequestMeta::Kind::Unknown:
        break;
    }
    LOG_CONN_DEBUG(conn_id_, "XHTTP server received unknown H2 request method='{}' path='{}'",
                  PublicHttpMethodForLog(request.method),
                  PublicHttpTargetForLog(request.path));
    co_return co_await ResetStream(stream_id, H2Error::Protocol);
}

std::optional<Http2ServerSession::DataFault> Http2ServerSession::ReceiveData(H2Frame& frame) {
    // The complete DATA payload consumes credit, including Pad Length and
    // padding (RFC 9113 6.1). Closed/reset streams still consume connection
    // credit, and discarding those bytes returns it exactly once.
    const auto raw_payload = frame.Payload();
    const size_t flow_size = raw_payload.size();
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
        (raw_payload.empty() || raw_payload.front() >= raw_payload.size())) {
        return DataFault{H2Error::Protocol, true};
    }
    if (!sub.AcceptsData()) {
        if ((frame.flags & kFlagEndStream) != 0) sub.CloseInput();
        ReturnReceiveCredit(nullptr, flow_size);
        return std::nullopt;
    }
    const auto data = H2DataPayload(frame);
    const size_t data_size = data.size();
    bool queued = data_size == 0;
    try {
        if (data_size != 0) {
            queued = sub.EnqueueData(*this, frame, data);
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
namespace {

net::awaitable<TransportBuildResult> StartHttp2ServerSession(
    app::GroupCoordinator& coordinator,
    std::unique_ptr<AsyncStream> stream,
    uint32_t initial_window,
    H2PayloadCodec payload_codec,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id,
    const HttpConfig* http_config,
    const XHttpConfig* xhttp_config,
    const GrpcConfig* grpc_config,
    bool read_client_preface) {
    if (read_client_preface) {
        std::array<uint8_t, kHttp2ClientPreface.size()> preface{};
        size_t done = 0;
        while (done < preface.size()) {
            const size_t n = co_await stream->AsyncRead(
                net::buffer(preface.data() + done, preface.size() - done));
            if (n == 0) {
                LOG_CONN_DEBUG(conn_id, "gRPC server received invalid HTTP/2 client preface");
                co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            done += n;
        }
        if (std::string_view(reinterpret_cast<const char*>(preface.data()), preface.size()) !=
            kHttp2ClientPreface) {
            LOG_CONN_DEBUG(conn_id, "gRPC server received invalid HTTP/2 client preface");
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
    }
    // SETTINGS is a receiver-selected limit, not a promise to allocate an
    // arbitrarily large configured window.
    initial_window = std::min<uint32_t>(initial_window, kHttp2MaxQueuedStreamBytes);
    auto session = std::make_shared<Http2ServerSession>(
        coordinator, io_context, std::move(stream), std::move(stream_handler), payload_codec,
        conn_id, http_config, xhttp_config, grpc_config, initial_window);
    if (!co_await session->WriteInitialPreface(initial_window)) {
        co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    }
    co_await session->Run();
    co_return std::unique_ptr<AsyncStream>{};
}

}  // namespace

net::awaitable<TransportBuildResult> DoGrpcServerHandshake(
    app::GroupCoordinator& coordinator,
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id) {
    return StartHttp2ServerSession(coordinator,
        std::move(stream),
        cfg.initial_window_size.value_or(kDefaultInitialWindow),
        H2PayloadCodec::GrpcHunk,
        io_context,
        std::move(stream_handler),
        conn_id,
        nullptr,
        nullptr,
        &cfg,
        true);
}

net::awaitable<TransportBuildResult> RunHttp2ServerSession(
    app::GroupCoordinator& coordinator,
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig* cfg,
    const XHttpConfig* xhttp_cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id) {
    const uint32_t initial_window = (cfg && cfg->initial_window_size)
        ? *cfg->initial_window_size : kDefaultInitialWindow;
    return StartHttp2ServerSession(coordinator,
        std::move(stream),
        initial_window,
        H2PayloadCodec::RawData,
        io_context,
        std::move(stream_handler),
        conn_id,
        cfg,
        xhttp_cfg,
        nullptr,
        false);
}

}  // namespace transport
