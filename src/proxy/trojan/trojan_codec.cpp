#include "trojan_codec.hpp"
#include "common/binary_text_codec.hpp"
#include "common/address_codec.hpp"
#include "common/byte_reader.hpp"

#include <cstring>

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
    const uint8_t* payload,
    size_t payload_len,
    ForwardedMetadataView forwarded) {

    const size_t addr_size = AddressEncodedSize(target, forwarded);
    if (addr_size == 0 || payload_len > output_size ||
        (payload_len != 0 && !payload)) {
        return 0;
    }
    const size_t header_size = 56 + 2 + 1 + addr_size + 2;

    if (!output || header_size > output_size - payload_len) {
        return 0;
    }
    const size_t total_out_size = header_size + payload_len;
    const auto out_begin = reinterpret_cast<uintptr_t>(output);
    auto overlaps_output = [out_begin, total_out_size](const void* ptr, size_t len) noexcept {
        if (!ptr || len == 0) {
            return false;
        }
        const auto in_begin = reinterpret_cast<uintptr_t>(ptr);
        return in_begin <= out_begin
            ? out_begin - in_begin < len
            : in_begin - out_begin < total_out_size;
    };
    if (overlaps_output(password_hash.data(), password_hash.size()) ||
        (target.IsDomain() && overlaps_output(target.host.data(), target.host.size())) ||
        overlaps_output(forwarded.user_email.data(), forwarded.user_email.size()) ||
        overlaps_output(forwarded.inbound_tag.data(), forwarded.inbound_tag.size())) {
        return 0;
    }
    if (payload && payload_len > 0) {
        std::memmove(output + header_size, payload, payload_len);
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

    return writer.Position() + encoded + tail.Position() + payload_len;
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


}  // namespace trojan
