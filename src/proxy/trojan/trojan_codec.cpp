#include "proxy/trojan/trojan_codec.hpp"
#include "common/address_codec.hpp"
#include "common/binary_text_codec.hpp"
#include "common/length_prefixed_packet_buffer.hpp"
#include "common/eof_cancellation.hpp"
#include "common/byte_reader.hpp"
#include "proxy/udp_datagram_frame.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <new>

namespace proxy {

// ============================================================================
// TCP 请求编解码
// ============================================================================

TrojanRequestDecodeResult DecodeTrojanRequest(std::span<const uint8_t> data) {
    TrojanRequestDecodeResult result;
    // hash(56) + CRLF + command, validated before the address is awaited.
    if (data.size() < kRequestPrefixSize) {
        result.required = kRequestPrefixSize;
        return result;
    }
    for (size_t i = 0; i < kPasswordHashSize; ++i) {
        if (common::HexDigitValue(data[i]) < 0) {
            result.status = TrojanRequestDecodeStatus::InvalidHeader;
            return result;
        }
    }
    const uint8_t command = data[kPasswordHashSize + 2];
    if (data[kPasswordHashSize] != 0x0D || data[kPasswordHashSize + 1] != 0x0A ||
        (command != static_cast<uint8_t>(TrojanCommand::CONNECT) &&
         command != static_cast<uint8_t>(TrojanCommand::UDP_ASSOCIATE))) {
        result.status = TrojanRequestDecodeStatus::InvalidHeader;
        return result;
    }

    auto address = common::DecodeAddress(
        data.subspan(kRequestPrefixSize), common::AddressWireFormat::Socks5,
        {.require_non_empty_domain = true, .allow_metadata = true});
    if (address.status == common::AddressDecodeStatus::Invalid) {
        result.status = TrojanRequestDecodeStatus::InvalidAddress;
        return result;
    }
    // A request always ends with CRLF after the address, so asking for it with
    // every partial address stage never reads past the header and lets the
    // final stage complete without decoding the address again.
    const size_t address_end = kRequestPrefixSize + address.consumed;
    if (address.status == common::AddressDecodeStatus::Incomplete || data.size() < address_end + 2) {
        result.required = address.status == common::AddressDecodeStatus::Incomplete
            ? kRequestPrefixSize + address.required + 2
            : address_end + 2;
        return result;
    }
    if (data[address_end] != 0x0D || data[address_end + 1] != 0x0A) {
        result.status = TrojanRequestDecodeStatus::InvalidHeader;
        return result;
    }
    if (!address.target.IsValid()) {
        result.status = TrojanRequestDecodeStatus::InvalidAddress;
        return result;
    }
    std::memcpy(result.request.password_hash.data(), data.data(), kPasswordHashSize);
    result.request.command = static_cast<TrojanCommand>(command);
    result.request.target = std::move(address.target);
    result.request.forwarded = std::move(address.forwarded);
    result.consumed = address_end + 2;
    result.status = TrojanRequestDecodeStatus::Complete;
    return result;
}

size_t EncodeRequestTo(
    std::span<const char, 56> password_hash,
    TrojanCommand cmd,
    const common::TargetAddress& target,
    uint8_t* output,
    size_t output_size,
    common::ForwardedMetadataView forwarded) {

    const size_t addr_size = common::AddressEncodedSize(target, forwarded);
    if (addr_size == 0) {
        return 0;
    }
    const size_t header_size = 56 + 2 + 1 + addr_size + 2;

    if (!output || header_size > output_size) {
        return 0;
    }
    const auto out_begin = reinterpret_cast<uintptr_t>(output);
    auto overlaps_output = [out_begin, header_size](const void* ptr, size_t len) noexcept {
        if (!ptr || len == 0) {
            return false;
        }
        const auto in_begin = reinterpret_cast<uintptr_t>(ptr);
        return in_begin <= out_begin
            ? out_begin - in_begin < len
            : in_begin - out_begin < header_size;
    };
    if (overlaps_output(password_hash.data(), password_hash.size()) ||
        (target.IsDomain() && overlaps_output(target.host.data(), target.host.size())) ||
        overlaps_output(forwarded.user_email.data(), forwarded.user_email.size()) ||
        overlaps_output(forwarded.inbound_tag.data(), forwarded.inbound_tag.size())) {
        return 0;
    }
    common::ByteWriter writer(output, header_size);

    writer.WriteString(std::string_view(password_hash.data(), password_hash.size()));
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);
    writer.WriteU8(static_cast<uint8_t>(cmd));

    const size_t encoded = common::EncodeAddressTo(target, output + writer.Position(),
        header_size - writer.Position(), common::AddressWireFormat::Socks5, forwarded);
    if (encoded == 0) return 0;
    common::ByteWriter tail(output + writer.Position() + encoded,
                    header_size - writer.Position() - encoded);
    tail.WriteU8(0x0D);
    tail.WriteU8(0x0A);

    return writer.Position() + encoded + tail.Position();
}

size_t EncodeUdpPacketHeaderTo(
    const common::TargetAddress& target,
    size_t payload_len,
    uint8_t* output,
    size_t output_size) {
    if (payload_len > 0xFFFF) {
        return 0;
    }

    const size_t address_size = common::AddressEncodedSize(target);
    if (!output || address_size == 0 || address_size + kUdpPacketTrailerSize > output_size) {
        return 0;
    }
    const size_t encoded = common::EncodeAddressTo(
        target, output, output_size, common::AddressWireFormat::Socks5);
    if (encoded == 0) return 0;
    common::ByteWriter writer(output + encoded, output_size - encoded);
    writer.WriteU16BE(static_cast<uint16_t>(payload_len));
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);

    return encoded + writer.Position();
}


void TrojanUdpFramer::Feed(common::MultiBuffer input) {
    if (state_ != State::Active) {
        throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    try {
        if (!common::AppendPacketStreamInput(pending_, std::move(input))) {
            throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
    } catch (...) {
        Fail();
        throw;
    }
}

bool TrojanUdpFramer::Next(TrojanFramedUdpPacket& out) {
    out = {};
    if (state_ == State::Failed) {
        throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (state_ == State::Finished) return false;
    if (!target_) {
        // SOCKS5 address without metadata, length and CRLF only.
        std::array<uint8_t, kMaxUdpPacketHeaderSize> scratch;
        const size_t copied = std::min(pending_.byte_size(), scratch.size());
        std::span<const uint8_t> header = pending_.FrontSpan();
        if (header.size() >= copied) {
            header = header.first(copied);
        } else {
            (void)pending_.CopyPrefixTo(std::span<uint8_t>(scratch.data(), copied));
            header = std::span<const uint8_t>(scratch.data(), copied);
        }
        auto address = common::DecodeAddress(
            header,
            common::AddressWireFormat::Socks5,
            {.require_non_empty_domain = true, .allow_metadata = false});
        if (address.status == common::AddressDecodeStatus::Incomplete) return false;
        if (address.status == common::AddressDecodeStatus::Invalid || !address.target.IsValid()) {
            Fail();
            throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        const size_t pos = address.consumed;
        if (copied < pos + kUdpPacketTrailerSize) return false;
        if (header[pos + 2] != '\r' || header[pos + 3] != '\n') {
            Fail();
            throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        payload_size_ = common::LoadU16BE(&header[pos]);
        target_.emplace(std::move(address.target));
        (void)pending_.DropPrefixBytes(pos + kUdpPacketTrailerSize);
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
    if (!common::SetUdpTarget(out.payload, out.target)) {
        Fail();
        throw std::bad_alloc();
    }
    return true;
}

void TrojanUdpFramer::Finish() {
    if (state_ == State::Failed || target_ || pending_.byte_size() != 0) {
        Fail();
        throw transport::LinkError(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    state_ = State::Finished;
}

void TrojanUdpFramer::Fail() noexcept {
    pending_.clear();
    target_.reset();
    payload_size_ = 0;
    state_ = State::Failed;
}

net::awaitable<common::MultiBuffer> ReadUdpDatagram(
    transport::AsyncStream& stream,
    TrojanUdpFramer& framer) {
    if (framer.Finished()) co_return common::MultiBuffer{};
    while (true) {
        TrojanFramedUdpPacket packet;
        if (framer.Next(packet)) {
            co_return std::move(packet.payload);
        }
        common::MultiBuffer raw = co_await stream.ReadMultiBuffer();
        if (raw.byte_size() == 0) {
            co_await common::ThrowIfCancelledOnEof();
            framer.Finish();
            co_return common::MultiBuffer{};
        }
        framer.Feed(std::move(raw));
    }
}

// 报头编码只会因目标地址失败：长度已由 RequireUdp* 限制在 uint16 内。
static size_t EncodeRequiredUdpPacketHeader(
    const common::TargetAddress& target,
    size_t payload_size,
    std::array<uint8_t, kMaxUdpPacketHeaderSize>& header) {
    const size_t header_size = EncodeUdpPacketHeaderTo(
        target, payload_size, header.data(), header.size());
    if (header_size == 0) {
        throw transport::LinkError(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    return header_size;
}

net::awaitable<void> WriteTrojanUdpDatagram(
    transport::MultiBufferWriter& writer,
    common::MultiBuffer payload) {
    const auto datagram = proxy::RequireUdpDatagram(payload, nullptr);
    if (!datagram) {
        co_return;
    }
    std::array<uint8_t, kMaxUdpPacketHeaderSize> header;
    const size_t header_size =
        EncodeRequiredUdpPacketHeader(*datagram->target, datagram->payload_size, header);
    co_await proxy::WriteFramedDatagram(
        writer, std::span<const uint8_t>(header.data(), header_size), payload);
}

net::awaitable<void> WriteTrojanUdpDatagram(
    transport::MultiBufferWriter& writer,
    const common::TargetAddress& target,
    std::span<const net::const_buffer> payload) {
    const size_t payload_size = proxy::RequireUdpPayloadSize(payload);
    std::array<uint8_t, kMaxUdpPacketHeaderSize> header;
    const size_t header_size = EncodeRequiredUdpPacketHeader(target, payload_size, header);
    co_await proxy::WriteFramedDatagram(
        writer, std::span<const uint8_t>(header.data(), header_size), payload);
}

}  // namespace proxy
