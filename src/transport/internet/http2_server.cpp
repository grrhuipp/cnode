#include "transport/internet/http2_server.hpp"
#include "common/allocator.hpp"
#include <vector>

namespace transport::internet::h2 {
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
    std::pmr::vector<uint8_t> frame_payload,
    size_t offset,
    size_t size) {
    if (!AcceptsData()) return false;
    if (offset > frame_payload.size() || size > frame_payload.size() - offset) return false;
    if (size > kHttp2MaxQueuedStreamBytes - queued_bytes_) return false;
    // Pack small/split DATA frames into the tail, including a prefix of a
    // larger successor. Otherwise legal fragmentation leaves an 8 KiB hole
    // per tiny frame and exhausts storage before the advertised byte window.
    size_t coalesced = 0;
    if (!data_frames_.empty()) {
        auto& tail = data_frames_.back();
        if (size <= tail.payload.capacity() - tail.end) {
            tail.payload.resize(tail.end + size);
            std::memcpy(tail.payload.data() + tail.end, frame_payload.data() + offset, size);
            tail.end += size;
            queued_bytes_ += size;
            WakeInputReader();
            return true;
        }
        coalesced = tail.payload.capacity() - tail.end;
    }
    if (frame_payload.capacity() < buf::Buffer::kSize) frame_payload.reserve(buf::Buffer::kSize);
    const size_t storage = frame_payload.capacity();
    if (storage > kHttp2MaxQueuedStreamStorage - queued_storage_ ||
        !session.ReserveReceiveMemory(storage)) return false;
    const auto upload_budget = upload_budget_.lock();
    if (upload_budget && !upload_budget->Reserve(storage)) {
        session.ReleaseReceiveMemory(storage);
        return false;
    }
    try {
        data_frames_.push_back(QueuedDataFrame{
            .payload = std::move(frame_payload),
            .offset = offset,
            .end = offset + size,
        });
    } catch (...) {
        session.ReleaseReceiveMemory(storage);
        if (upload_budget) upload_budget->Release(storage);
        throw;
    }
    if (coalesced != 0) {
        // Do not modify the old tail until the new allocation and deque entry
        // are committed: rejection must leave every input byte unqueued.
        auto& tail = data_frames_[data_frames_.size() - 2];
        auto& added = data_frames_.back();
        tail.payload.resize(tail.end + coalesced);
        std::memcpy(tail.payload.data() + tail.end,
                    added.payload.data() + offset, coalesced);
        tail.end += coalesced;
        const size_t remaining = size - coalesced;
        std::memmove(added.payload.data(),
                     added.payload.data() + offset + coalesced, remaining);
        added.payload.resize(remaining);
        added.offset = 0;
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

net::awaitable<buf::MultiBuffer> Http2ServerSubStreamState::ReadMultiBuffer() {
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
    const size_t storage = front.payload.capacity();
    queued_storage_ -= storage;
    if (session) session->ReleaseReceiveMemory(storage);
    if (upload_reserved_ != 0) {
        if (auto budget = upload_budget_.lock()) {
            budget->Release(storage);
        }
        upload_reserved_ -= std::min(upload_reserved_, storage);
    }
    data_frames_.pop_front();
    read_offset_ = 0;
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
    read_offset_ = 0;
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
        const auto& front = data_frames_.front();
        if (read_offset_ < front.offset) {
            read_offset_ = front.offset;
        }
        if (read_offset_ < front.end) {
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
    auto bytes = std::span<const uint8_t>(front.payload).subspan(
        read_offset_, front.end - read_offset_);
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
    read_offset_ += consumed;
    if (read_offset_ == data_frames_.front().end) PopFrontDataFrame(session.get());
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
    const auto& front = data_frames_.front();
    const size_t size = std::min(buffer.size(), front.end - read_offset_);
    std::memcpy(buffer.data(), front.payload.data() + read_offset_, size);
    read_offset_ += size;
    if (read_offset_ == front.end) PopFrontDataFrame(session.get());
    ConsumeData(session.get(), size);
    return size;
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
    const GrpcConfig* grpc_config) {
    // SETTINGS is a receiver-selected limit, not a promise to allocate an
    // arbitrarily large configured window.
    initial_window = std::min<uint32_t>(initial_window, kHttp2MaxQueuedStreamBytes);
    auto session = std::make_shared<Http2ServerSession>(
        coordinator, io_context, std::move(stream), std::move(stream_handler), payload_codec,
        conn_id, http_config, xhttp_config, grpc_config, initial_window);
    const auto initial_window_setting = EncodeInitialWindowSetting(initial_window);
    std::array<uint8_t, 12> settings{};
    std::copy(initial_window_setting.begin(), initial_window_setting.end(), settings.begin());
    settings[6] = 0;
    settings[7] = 3; // SETTINGS_MAX_CONCURRENT_STREAMS
    common::StoreU32BE(settings.data() + 8, kHttp2MaxConcurrentStreams);
    if (!co_await session->WriteFrameSerialized(H2FrameType::SETTINGS, 0, 0, settings)) {
        co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    }
    std::array<uint8_t, 4> connection_credit{};
    common::StoreU32BE(connection_credit.data(),
               kHttp2ConnectionReceiveWindow - H2SendWindow::kDefault);
    if (!co_await session->WriteFrameSerialized(
            H2FrameType::WINDOW_UPDATE, 0, 0, connection_credit)) {
        co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    }
    co_await session->Run();
    co_return std::unique_ptr<AsyncStream>{};
}
}
