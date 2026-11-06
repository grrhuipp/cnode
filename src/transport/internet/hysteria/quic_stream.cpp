#include "quic_stream.hpp"

#include "hysteria_protocol.hpp"

#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/transport/link_error.hpp"

#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>

#include <cstring>

namespace acpp::transport::internet::hysteria {

QuicStreamState::QuicStreamState(
    net::io_context& io_context, int64_t stream_id,
    std::weak_ptr<QuicStreamOwner> owner)
    : io_context_(io_context)
    , stream_id_(stream_id)
    , owner_(std::move(owner))
    , input_signal_(io_context, 1) {}

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

void QuicStreamState::RemoteReset() noexcept {
    Cancel();
}

void QuicStreamState::Cancel() noexcept {
    if (cancelled_) return;
    cancelled_ = true;
    input_done_ = true;
    input_.clear();
    WakeReader();
    if (auto owner = owner_.lock()) owner->CancelStream(stream_id_);
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
        if (error)
            throw IoSystemError(error, "QUIC stream input cancelled");
    }
}

net::awaitable<void> QuicStreamState::WriteMultiBuffer(buf::MultiBuffer payload) {
    if (cancelled_) {
        payload.clear();
        throw transport::LinkError(ErrorCode::CANCELLED);
    }
    if (write_done_) {
        payload.clear();
        throw transport::WriteClosed();
    }
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
    if (auto owner = owner_.lock()) owner->ShutdownStreamWrite(stream_id_);
}

void QuicStreamState::WakeReader() noexcept {
    if (!io_context_.stopped()) (void)input_signal_.try_send(IoErrorCode{});
}

QuicStream::QuicStream(std::shared_ptr<QuicStreamState> state)
    : state_(std::move(state))
    , deadline_(state_->IoContext(), *this) {}

QuicStream::~QuicStream() noexcept {
    deadline_.Clear();
    if (state_) state_->Cancel();
}

net::awaitable<size_t> QuicStream::AsyncRead(net::mutable_buffer buffer) {
    if (!state_) co_return 0;
    co_return co_await state_->Read(buffer);
}

net::awaitable<size_t> QuicStream::AsyncWrite(net::const_buffer buffer) {
    if (!state_) throw transport::LinkError(ErrorCode::CONNECTION_CLOSED);
    buf::MultiBuffer payload;
    const auto bytes = std::span(
        static_cast<const uint8_t*>(buffer.data()), buffer.size());
    if (!buf::AppendSpanToMultiBuffer(bytes, payload)) throw std::bad_alloc();
    co_await state_->WriteMultiBuffer(std::move(payload));
    co_return buffer.size();
}

net::awaitable<buf::MultiBuffer> QuicStream::ReadMultiBuffer() {
    if (!state_) co_return buf::MultiBuffer{};
    co_return co_await state_->ReadMultiBuffer();
}

net::awaitable<void> QuicStream::WriteMultiBuffer(buf::MultiBuffer payload) {
    if (!state_) {
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
    if (state_) state_->ShutdownWrite();
}

void QuicStream::Cancel() noexcept {
    if (state_) state_->Cancel();
    NotifyCancellation();
}

void QuicStream::Close() {
    deadline_.Clear();
    Cancel();
    state_.reset();
    NotifyClosed();
}

bool QuicStream::IsOpen() const {
    return state_ && state_->Open();
}

UdpSessionStream::UdpSessionStream(
    net::io_context& io_context, uint32_t session_id,
    TargetAddress first_target, std::weak_ptr<QuicStreamOwner> owner)
    : io_context_(io_context)
    , session_id_(session_id)
    , first_target_(std::move(first_target))
    , owner_(std::move(owner))
    , signal_(io_context, 1)
    , deadline_(io_context, *this) {}

UdpSessionStream::~UdpSessionStream() noexcept {
    Close();
}

bool UdpSessionStream::Push(
    const TargetAddress& target, std::span<const uint8_t> payload) {
    if (closed_ || cancelled_ || payload.empty() ||
        queued_bytes_ > kMaxQueuedBytes - payload.size()) return false;
    buf::MultiBuffer packet;
    if (!buf::AppendSpanToMultiBuffer(payload, packet)) return false;
    for (auto* buffer : packet) buffer->SetUDP(target);
    input_.push_back(std::move(packet));
    queued_bytes_ += payload.size();
    WakeReader();
    return true;
}

void UdpSessionStream::Detach() noexcept {
    owner_.reset();
    if (closed_) return;
    closed_ = true;
    input_.clear();
    queued_bytes_ = 0;
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
            queued_bytes_ -= std::min(queued_bytes_, packet.byte_size());
            co_return packet;
        }
        if (closed_) co_return buf::MultiBuffer{};
        auto [error] = co_await signal_.async_receive(
            net::as_tuple(net::use_awaitable));
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
    WakeReader();
    NotifyCancellation();
}

void UdpSessionStream::Close() {
    deadline_.Clear();
    if (closed_) return;
    closed_ = true;
    input_.clear();
    queued_bytes_ = 0;
    WakeReader();
    if (auto owner = std::exchange(owner_, {}).lock())
        owner->CloseUdpSession(session_id_);
    NotifyClosed();
}

void UdpSessionStream::WakeReader() noexcept {
    if (!io_context_.stopped()) (void)signal_.try_send(IoErrorCode{});
}

}  // namespace acpp::transport::internet::hysteria
