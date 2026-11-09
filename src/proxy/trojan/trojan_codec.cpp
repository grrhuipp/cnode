#include "trojan_codec.hpp"
#include "common/address_codec.hpp"
#include "common/binary_text_codec.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "common/buffer_util.hpp"
#include "common/byte_reader.hpp"

#include <array>
#include <cstring>
#include <limits>
#include <new>

namespace trojan {

// ============================================================================
// TCP 请求编解码
// ============================================================================

RequestDecodeResult DecodeRequest(std::span<const uint8_t> data) {
    RequestDecodeResult result;
    // hash(56) + CRLF + command, validated before the address is awaited.
    if (data.size() < kRequestPrefixSize) {
        result.required = kRequestPrefixSize;
        return result;
    }
    for (size_t i = 0; i < kPasswordHashSize; ++i) {
        if (HexDigitValue(data[i]) < 0) {
            result.status = RequestDecodeStatus::InvalidHeader;
            return result;
        }
    }
    const uint8_t command = data[kPasswordHashSize + 2];
    if (data[kPasswordHashSize] != 0x0D || data[kPasswordHashSize + 1] != 0x0A ||
        (command != static_cast<uint8_t>(TrojanCommand::CONNECT) &&
         command != static_cast<uint8_t>(TrojanCommand::UDP_ASSOCIATE))) {
        result.status = RequestDecodeStatus::InvalidHeader;
        return result;
    }

    auto address = DecodeAddress(
        data.subspan(kRequestPrefixSize), AddressWireFormat::Socks5,
        {.require_non_empty_domain = true, .allow_metadata = true});
    if (address.status == AddressDecodeStatus::Invalid) {
        result.status = RequestDecodeStatus::InvalidAddress;
        return result;
    }
    // A request always ends with CRLF after the address, so asking for it with
    // every partial address stage never reads past the header and lets the
    // final stage complete without decoding the address again.
    const size_t address_end = kRequestPrefixSize + address.consumed;
    if (address.status == AddressDecodeStatus::Incomplete || data.size() < address_end + 2) {
        result.required = address.status == AddressDecodeStatus::Incomplete
            ? kRequestPrefixSize + address.required + 2
            : address_end + 2;
        return result;
    }
    if (data[address_end] != 0x0D || data[address_end + 1] != 0x0A) {
        result.status = RequestDecodeStatus::InvalidHeader;
        return result;
    }
    if (!address.target.IsValid()) {
        result.status = RequestDecodeStatus::InvalidAddress;
        return result;
    }
    std::memcpy(result.request.password_hash.data(), data.data(), kPasswordHashSize);
    result.request.command = static_cast<TrojanCommand>(command);
    result.request.target = std::move(address.target);
    result.request.forwarded = std::move(address.forwarded);
    result.consumed = address_end + 2;
    result.status = RequestDecodeStatus::Complete;
    return result;
}

size_t EncodeRequestTo(
    std::span<const char, 56> password_hash,
    TrojanCommand cmd,
    const TargetAddress& target,
    uint8_t* output,
    size_t output_size,
    ForwardedMetadataView forwarded) {

    const size_t addr_size = AddressEncodedSize(target, forwarded);
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
    ByteWriter writer(output, header_size);

    writer.WriteString(std::string_view(password_hash.data(), password_hash.size()));
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);
    writer.WriteU8(static_cast<uint8_t>(cmd));

    const size_t encoded = EncodeAddressTo(target, output + writer.Position(),
        header_size - writer.Position(), AddressWireFormat::Socks5, forwarded);
    if (encoded == 0) return 0;
    ByteWriter tail(output + writer.Position() + encoded,
                    header_size - writer.Position() - encoded);
    tail.WriteU8(0x0D);
    tail.WriteU8(0x0A);

    return writer.Position() + encoded + tail.Position();
}

size_t EncodeUdpPacketHeaderTo(
    const TargetAddress& target,
    size_t payload_len,
    uint8_t* output,
    size_t output_size) {
    if (payload_len > 0xFFFF) {
        return 0;
    }

    const size_t address_size = AddressEncodedSize(target);
    if (!output || address_size == 0 || address_size + 4 > output_size) return 0;
    const size_t encoded = EncodeAddressTo(
        target, output, output_size, AddressWireFormat::Socks5);
    if (encoded == 0) return 0;
    ByteWriter writer(output + encoded, output_size - encoded);
    writer.WriteU16BE(static_cast<uint16_t>(payload_len));
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);

    return encoded + writer.Position();
}


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
        buf::MultiBuffer raw = co_await stream.ReadMultiBuffer();
        if (raw.byte_size() == 0) {
            co_await ThrowIfCancelledOnEof();
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

    ConstBufferSpanBuilder<16> buffers;
    buffers.AppendMultiBuffer(payload);
    co_await WriteUdpDatagram(writer, *datagram.target, buffers.Span());
    payload.clear();
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
