#include "quic_stream.hpp"

#include "hysteria_protocol.hpp"
#include "quic_connection.hpp"

#include "common/buf/multi_buffer.hpp"
#include "transport/link_error.hpp"

#include <asio/as_tuple.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <cstring>

namespace transport::internet::hysteria {

QuicStreamState::QuicStreamState(
    net::io_context& io_context, int64_t stream_id,
    std::weak_ptr<Connection> owner)
    : domain_(ExecutionDomain::Current())
    , stream_id_(stream_id)
    , owner_(std::move(owner))
    , input_signal_(domain_->Executor(), 1) { (void)io_context; }

bool QuicStreamState::PushInput(std::span<const uint8_t> data, bool fin) {
    if (cancelled_ || input_done_ ||
        data.size() > kMaxQueuedInputBytes -
            std::min(input_.byte_size(), kMaxQueuedInputBytes)) {
        return false;
    }
    if (!buf::AppendSpanToMultiBuffer(data, input_)) return false;
    input_done_ = fin;
    WakeReader();
    return true;
}

void QuicStreamState::DiscardInput(size_t bytes) noexcept {
    AcknowledgeInput(input_.DropPrefixBytes(bytes));
}

void QuicStreamState::AcknowledgeInput(size_t bytes) noexcept {
    if (bytes == 0) return;
    if (auto owner = owner_.lock()) owner->ConsumeStream(stream_id_, bytes);
}

void QuicStreamState::OnStreamClosed() noexcept {
    auto owner = std::exchange(owner_, {}).lock();
    const auto stream_id = stream_id_;
    const size_t unread = input_.byte_size();
    input_done_ = true;
    write_done_ = true;
    WakeReader();
    NotifyWritable();
    // The buffered tail may still be drained, but must not retain connection
    // credit or acknowledge it twice after the transport stream is gone.
    if (owner && unread != 0) owner->ConsumeStream(stream_id, unread);
}

void QuicStreamState::RemoteReset() noexcept {
    auto owner = std::exchange(owner_, {}).lock();
    const auto stream_id = stream_id_;
    const size_t unread = input_.byte_size();
    cancelled_ = true;
    input_done_ = true;
    write_done_ = true;
    input_.clear();
    WakeReader();
    NotifyWritable();
    cancellation_.Stop();
    if (owner && unread != 0) owner->ConsumeStream(stream_id, unread);
}

void QuicStreamState::Cancel() noexcept {
    if (cancelled_) return;
    auto owner = std::exchange(owner_, {}).lock();
    const auto stream_id = stream_id_;
    const size_t unread = input_.byte_size();
    cancelled_ = true;
    input_done_ = true;
    write_done_ = true;
    input_.clear();
    WakeReader();
    NotifyWritable();
    cancellation_.Stop();
    if (owner) {
        owner->CancelStream(stream_id);
        if (unread != 0) owner->ConsumeStream(stream_id, unread);
    }
}

net::awaitable<size_t> QuicStreamState::Read(net::mutable_buffer buffer) {
    for (;;) {
        if (!input_.empty()) {
            const size_t bytes = input_.ConsumePrefixTo(
                {static_cast<uint8_t*>(buffer.data()), buffer.size()});
            AcknowledgeInput(bytes);
            co_return bytes;
        }
        if (cancelled_)
            throw transport::LinkError(ErrorCode::CANCELLED);
        if (input_done_) co_return 0;
        auto [error] = co_await input_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error == net::experimental::error::channel_cancelled)
            error = net::error::operation_aborted;
        if (error)
            throw IoSystemError(error, "QUIC stream input cancelled");
    }
}

net::awaitable<buf::MultiBuffer> QuicStreamState::ReadMultiBuffer() {
    for (;;) {
        if (!input_.empty()) {
            const size_t bytes = input_.byte_size();
            auto result = std::move(input_);
            input_.ReleaseIfIdle();
            AcknowledgeInput(bytes);
            co_return result;
        }
        if (cancelled_)
            throw transport::LinkError(ErrorCode::CANCELLED);
        if (input_done_) co_return buf::MultiBuffer{};
        auto [error] = co_await input_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error == net::experimental::error::channel_cancelled)
            error = net::error::operation_aborted;
        if (error)
            throw IoSystemError(error, "QUIC stream input cancelled");
    }
}

net::awaitable<void> QuicStreamState::WriteMultiBuffer(buf::MultiBuffer payload) {
    CheckWriteOpen();
    auto owner = owner_.lock();
    if (!owner) {
        payload.clear();
        throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
    }
    co_await owner->WriteStream(stream_id_, std::move(payload));
}

void QuicStreamState::ShutdownWrite() noexcept {
    if (write_done_) return;
    write_done_ = true;
    NotifyWritable();
    if (auto owner = owner_.lock()) owner->ShutdownStreamWrite(stream_id_);
}

void QuicStreamState::CheckWriteOpen() const {
    if (cancelled_) throw transport::LinkError(ErrorCode::CANCELLED);
    if (write_done_) throw transport::WriteClosed();
}

net::awaitable<void> QuicStreamState::WaitWritable() {
    CheckWriteOpen();
    if (!output_wait_)
        output_wait_ = std::make_unique<OutputWait>(domain_->Executor());
    struct PendingWriteWait {
        QuicStreamState& owner;
        OutputWait& wait;
        ~PendingWriteWait() {
            if (--wait.waiters == 0) owner.output_wait_.reset();
        }
    } pending{*this, *output_wait_};
    ++pending.wait.waiters;
    const auto cancellation = co_await net::this_coro::cancellation_state;
    auto [error] = co_await pending.wait.ready.async_receive(
        net::as_tuple(net::use_awaitable));
    CheckWriteOpen();
    if (cancellation.cancelled() != net::cancellation_type::none)
        throw IoSystemError(net::error::operation_aborted, "QUIC stream output cancelled");
    // channel.cancel() is the broadcast event, not stream cancellation.
    if (error && error != net::experimental::error::channel_cancelled)
        throw IoSystemError(error, "QUIC stream output cancelled");
}

void QuicStreamState::NotifyWritable() noexcept {
    if (output_wait_) output_wait_->ready.cancel();
}

void QuicStreamState::WakeReader() noexcept {
    (void)input_signal_.try_send(IoErrorCode{});
}

QuicStream::QuicStream(std::shared_ptr<QuicStreamState> state)
    : state_(std::move(state))
    , deadline_(state_->IoContext(), *this) {}

QuicStream::~QuicStream() noexcept {
    Close();
}

net::awaitable<size_t> QuicStream::AsyncRead(net::mutable_buffer buffer) {
    if (closed_) co_return 0;
    co_return co_await state_->Read(buffer);
}

net::awaitable<size_t> QuicStream::AsyncWrite(net::const_buffer buffer) {
    if (closed_) throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
    buf::MultiBuffer payload;
    const auto bytes = std::span(
        static_cast<const uint8_t*>(buffer.data()), buffer.size());
    if (!buf::AppendSpanToMultiBuffer(bytes, payload)) throw std::bad_alloc();
    co_await state_->WriteMultiBuffer(std::move(payload));
    co_return buffer.size();
}

net::awaitable<buf::MultiBuffer> QuicStream::ReadMultiBuffer() {
    if (closed_) co_return buf::MultiBuffer{};
    co_return co_await state_->ReadMultiBuffer();
}

net::awaitable<void> QuicStream::WriteMultiBuffer(buf::MultiBuffer payload) {
    if (closed_) {
        payload.clear();
        throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
    }
    co_await state_->WriteMultiBuffer(std::move(payload));
}

net::awaitable<void> QuicStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    buf::MultiBuffer payload;
    for (const auto& buffer : buffers) {
        const auto bytes = std::span(
            static_cast<const uint8_t*>(buffer.data()), buffer.size());
        if (!buf::AppendSpanToMultiBuffer(bytes, payload)) throw std::bad_alloc();
    }
    co_await WriteMultiBuffer(std::move(payload));
}

void QuicStream::ShutdownWrite() {
    if (!closed_) state_->ShutdownWrite();
}

void QuicStream::Cancel() noexcept {
    if (!closed_) state_->Cancel();
}

void QuicStream::Close() {
    deadline_.Clear();
    if (std::exchange(closed_, true)) return;
    if (!state_->DuplexFinished()) state_->Cancel();
}

void QuicStream::CloseAbortive() {
    deadline_.Clear();
    if (std::exchange(closed_, true)) return;
    state_->Cancel();
}

bool QuicStream::IsOpen() const {
    return !closed_ && state_->Open();
}

UdpSessionStream::UdpSessionStream(
    net::io_context& io_context, uint32_t session_id,
    TargetAddress first_target, std::weak_ptr<Connection> owner)
    : domain_(ExecutionDomain::Current())
    , session_id_(session_id)
    , first_target_(std::move(first_target))
    , owner_(std::move(owner))
    , signal_(domain_->Executor(), 1)
    , deadline_(io_context, *this) {}

UdpSessionStream::~UdpSessionStream() noexcept {
    Close();
}

bool UdpSessionStream::Push(
    const TargetAddress& target, std::span<const uint8_t> payload) {
    if (closed_ || cancelled_) return false;
    // Datagrams cannot share a block. Count rounded capacity before allocating,
    // without subtracting an externally sized payload from the byte budget.
    const size_t buffer_count = payload.empty()
        ? 1 : 1 + (payload.size() - 1) / buf::Buffer::kSize;
    if (buffer_count > kMaxQueuedBytes / buf::Buffer::kSize - queued_buffer_count_)
        return false;
    buf::MultiBuffer packet;
    if (!buf::AppendSpanToMultiBuffer(payload, packet) ||
        !buf::SetUdpTarget(packet, target)) return false;
    input_.push_back(std::move(packet));
    queued_buffer_count_ += buffer_count;
    WakeReader();
    return true;
}

void UdpSessionStream::Detach() noexcept {
    owner_.reset();
    if (closed_) return;
    closed_ = true;
    input_.clear();
    queued_buffer_count_ = 0;
    WakeReader();
    NotifyClosed();
}

net::awaitable<size_t> UdpSessionStream::AsyncRead(net::mutable_buffer) {
    throw transport::LinkError(ErrorCode::NOT_SUPPORTED);
}

net::awaitable<size_t> UdpSessionStream::AsyncWrite(net::const_buffer) {
    throw transport::LinkError(ErrorCode::NOT_SUPPORTED);
}

net::awaitable<buf::MultiBuffer> UdpSessionStream::ReadMultiBuffer() {
    for (;;) {
        if (cancelled_) throw transport::LinkError(ErrorCode::CANCELLED);
        if (!input_.empty()) {
            auto packet = std::move(input_.front());
            input_.pop_front();
            queued_buffer_count_ -= packet.size();
            co_return packet;
        }
        if (closed_) co_return buf::MultiBuffer{};
        auto [error] = co_await signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error == net::experimental::error::channel_cancelled)
            error = net::error::operation_aborted;
        if (error)
            throw IoSystemError(error, "Hysteria UDP session input cancelled");
    }
}

net::awaitable<void> UdpSessionStream::WriteMultiBuffer(buf::MultiBuffer packet) {
    const auto datagram = buf::InspectUdpDatagram(packet);
    if (datagram.status == buf::UdpDatagramStatus::Empty) co_return;
    if (!datagram.Valid() || datagram.payload_size > kMaxUdpPayloadLength) {
        packet.clear();
        throw transport::LinkError(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    auto owner = owner_.lock();
    if (closed_ || !owner) {
        packet.clear();
        throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
    }
    bool sent = false;
    if (datagram.buffer_count == 1) {
        sent = owner->SendUdpMessage(
            session_id_, *datagram.target, datagram.single_buffer->Bytes());
    } else {
        memory::ThreadLocalVector<uint8_t> payload;
        payload.reserve(datagram.payload_size);
        for (const auto* buffer : packet) {
            if (!buffer || buffer->IsEmpty()) continue;
            const auto bytes = buffer->Bytes();
            payload.insert(payload.end(), bytes.begin(), bytes.end());
        }
        sent = owner->SendUdpMessage(session_id_, *datagram.target, payload);
    }
    packet.clear();
    if (!sent) throw transport::LinkError(ErrorCode::RESOURCE_EXHAUSTED);
}

void UdpSessionStream::Cancel() noexcept {
    cancelled_ = true;
    // No later read can consume this input; release it before callbacks can
    // retain or destroy the cancelled host.
    input_.clear();
    queued_buffer_count_ = 0;
    WakeReader();
    NotifyCancellation();
}

void UdpSessionStream::Close() {
    deadline_.Clear();
    if (closed_) return;
    closed_ = true;
    input_.clear();
    queued_buffer_count_ = 0;
    WakeReader();
    if (auto owner = std::exchange(owner_, {}).lock())
        owner->CloseUdpSession(session_id_);
    NotifyClosed();
}

void UdpSessionStream::WakeReader() noexcept {
    (void)signal_.try_send(IoErrorCode{});
}

}  // namespace transport::internet::hysteria
