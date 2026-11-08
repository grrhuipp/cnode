#include "udp_framing.hpp"

#include "trojan_codec.hpp"
#include "common/buffer_util.hpp"
#include "common/address_codec.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"

#include <array>
#include <limits>
#include <new>

namespace trojan {

void UdpFramer::Feed(buf::MultiBuffer input) {
    if (state_ != State::Active) {
        throw IoSystemError(io_error::invalid_argument, "inactive Trojan UDP stream");
    }
    try {
        buf::AppendPacketStreamInput(pending_, std::move(input));
    } catch (...) {
        Fail();
        throw;
    }
}

bool UdpFramer::Next(FramedUdpPacket& out) {
    out = {};
    if (state_ == State::Failed) {
        throw IoSystemError(io_error::invalid_argument, "failed Trojan UDP stream");
    }
    if (state_ == State::Finished) return false;
    if (!target_) {
        // SOCKS5 address, length and CRLF only.
        std::array<uint8_t, kMaxEncodedAddressSize + 4> header{};
        const size_t copied = pending_.CopyPrefixTo(header);
        auto address = DecodeAddress(
            std::span<const uint8_t>(header.data(), copied),
            AddressWireFormat::Socks5,
            {.require_non_empty_domain = true, .allow_metadata = false});
        if (address.status == AddressDecodeStatus::Incomplete) return false;
        if (address.status == AddressDecodeStatus::Invalid || !address.target.IsValid()) {
            Fail();
            throw IoSystemError(io_error::invalid_argument, "invalid Trojan UDP address");
        }
        const size_t pos = address.consumed;
        if (copied < pos + 4) return false;
        if (header[pos + 2] != '\r' || header[pos + 3] != '\n') {
            Fail();
            throw IoSystemError(io_error::invalid_argument, "invalid Trojan UDP delimiter");
        }
        payload_size_ = (static_cast<size_t>(header[pos]) << 8) | header[pos + 1];
        target_.emplace(std::move(address.target));
        (void)pending_.DropPrefixBytes(pos + 4);
    }
    const size_t bytes = payload_size_;
    if (pending_.byte_size() < bytes) return false;
    if (!pending_.MovePrefixTo(out.payload, bytes)) {
        Fail();
        throw std::bad_alloc();
    }
    pending_.ReleaseIfIdle();
    out.target = std::move(*target_);
    target_.reset();
    if (!buf::SetUdpTarget(out.payload, out.target)) {
        Fail();
        throw std::bad_alloc();
    }
    return true;
}

void UdpFramer::Finish() {
    if (state_ == State::Failed || target_ || pending_.byte_size() != 0) {
        Fail();
        throw IoSystemError(io_error::invalid_argument, "truncated Trojan UDP stream");
    }
    state_ = State::Finished;
}

void UdpFramer::Fail() noexcept {
    pending_.clear();
    target_.reset();
    payload_size_ = 0;
    state_ = State::Failed;
}

net::awaitable<buf::MultiBuffer> ReadUdpDatagram(
    AsyncStream& stream,
    UdpFramer& framer) {
    if (framer.Finished()) co_return buf::MultiBuffer{};
    while (true) {
        FramedUdpPacket packet;
        if (framer.Next(packet)) {
            co_return std::move(packet.payload);
        }
        buf::MultiBuffer raw = co_await ReadMultiBufferOrThrowOnCancel(stream);
        if (raw.byte_size() == 0) {
            framer.Finish();
            co_return buf::MultiBuffer{};
        }
        framer.Feed(std::move(raw));
    }
}

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    buf::MultiBuffer payload) {
    const auto datagram = buf::InspectUdpDatagram(payload);
    if (datagram.status == buf::UdpDatagramStatus::Empty) {
        co_return;
    }
    if (!datagram.Valid() || !datagram.target->IsValid()) {
        throw IoSystemError(
            io_error::invalid_argument,
            "Trojan UDP datagram contains missing or mixed endpoints");
    }

    std::array<uint8_t, 272> header{};
    const size_t header_size = EncodeUdpPacketHeaderTo(
        *datagram.target,
        datagram.payload_size,
        header.data(),
        header.size());
    if (header_size == 0) {
        throw IoSystemError(
            io_error::message_size, "invalid Trojan UDP datagram size or target");
    }

    ConstBufferSpanBuilder<1 + buf::MultiBuffer::kInlineCapacity> framed;
    framed.Append(net::buffer(header.data(), header_size));
    framed.AppendMultiBuffer(payload);
    co_await writer.WriteBuffers(framed.Span());
}

net::awaitable<void> WriteUdpDatagram(
    transport::MultiBufferWriter& writer,
    const TargetAddress& target,
    std::span<const net::const_buffer> payload) {
    const auto payload_size = buf::TrySumBufferSizes(
        payload, std::numeric_limits<uint16_t>::max());
    if (!payload_size) {
        throw IoSystemError(
            io_error::message_size, "Trojan UDP datagram is too large");
    }

    std::array<uint8_t, 272> header{};
    const size_t header_size = EncodeUdpPacketHeaderTo(
        target,
        *payload_size,
        header.data(),
        header.size());
    if (header_size == 0) {
        throw IoSystemError(
            io_error::invalid_argument, "invalid Trojan UDP target");
    }

    ConstBufferSpanBuilder<8> framed;
    framed.Append(net::buffer(header.data(), header_size));
    framed.AppendBuffers(payload);
    co_await writer.WriteBuffers(framed.Span());
}

}  // namespace trojan
