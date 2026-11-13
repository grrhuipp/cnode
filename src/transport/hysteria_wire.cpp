#include "transport/hysteria_wire.hpp"

#include "common/byte_reader.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <charconv>
#include <limits>
#include <cstring>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace transport {

namespace {

[[nodiscard]] std::string_view TargetHost(
    const common::TargetAddress& target, std::optional<common::AddressText>& storage) {
    if (target.IsDomain()) return {target.host.data(), target.host.size()};
    if (!target.resolved_addr) return {};
    storage.emplace(*target.resolved_addr);
    return storage->View();
}

[[nodiscard]] tl::expected<common::TargetAddress, ProtocolError>
ParseV1Target(std::span<const uint8_t> host, uint16_t port) {
    if (host.empty() || host.size() > kMaxAddressLength || port == 0)
        return tl::unexpected(ProtocolError::Invalid);
    common::TargetAddress target(
        std::string_view(reinterpret_cast<const char*>(host.data()), host.size()), port);
    if (!target.IsValid()) return tl::unexpected(ProtocolError::Invalid);
    return target;
}

[[nodiscard]] bool ValidFragmentIndex(HysteriaVersion version, uint8_t index, uint8_t count) noexcept {
    // HY2 declares Fragment ID irrelevant for an unfragmented packet.
    return count != 0 && ((version == HysteriaVersion::V2 && count == 1) || index < count);
}

[[nodiscard]] bool RequiresUdpTarget(HysteriaVersion version, uint8_t index, uint8_t count) noexcept {
    return version == HysteriaVersion::V1 || count == 1 || index == 0;
}

}  // namespace

tl::expected<UdpTargetText, ProtocolError> PrepareUdpTargetText(
    HysteriaVersion version, const common::TargetAddress& target,
    std::optional<common::AddressText>& address_storage) {
    UdpTargetText text;
    text.port = target.port;
    if (target.IsValid()) text.host = TargetHost(target, address_storage);
    if (version == HysteriaVersion::V1) {
        if (text.host.empty() || text.host.size() > kMaxAddressLength)
            return tl::unexpected(ProtocolError::Invalid);
        return text;
    }
    if (text.host.empty()) return text;
    const auto [end, error] = std::to_chars(
        text.port_text.data(), text.port_text.data() + text.port_text.size(), target.port);
    if (error != std::errc{}) return tl::unexpected(ProtocolError::Invalid);
    text.port_text_size = static_cast<size_t>(end - text.port_text.data());
    text.bracket_v6 = text.host.find(':') != std::string_view::npos;
    const size_t suffix = (text.bracket_v6 ? 2 : 0) + 1 + text.port_text_size;
    if (text.host.size() > std::numeric_limits<size_t>::max() - suffix)
        return tl::unexpected(ProtocolError::TooLarge);
    text.authority_size = text.host.size() + suffix;
    return text;
}

tl::expected<size_t, ProtocolError> UdpTargetHeaderSize(
    HysteriaVersion version, const UdpTargetText& text) {
    if (version == HysteriaVersion::V1) return 14 + text.host.size();
    const size_t width = common::QuicVarintSize(text.authority_size);
    if (width == 0 ||
        text.authority_size > std::numeric_limits<size_t>::max() - 8 - width)
        return tl::unexpected(ProtocolError::TooLarge);
    return 8 + width + text.authority_size;
}

tl::expected<size_t, ProtocolError> EncodeUdpFragmentHeader(
    HysteriaVersion version, const HysteriaUdpMessage& message, const UdpTargetText& text,
    std::span<uint8_t> out) noexcept {
    size_t pos = 0;
    auto write_bytes = [&](const void* src, size_t len) noexcept {
        if (len != 0) std::memcpy(out.data() + pos, src, len);
        pos += len;
    };
    if (out.size() < 8) return tl::unexpected(ProtocolError::TooLarge);
    common::StoreU32BE(out.data() + pos, message.session_id);
    pos += 4;
    if (version == HysteriaVersion::V1) {
        if (out.size() < 14 + text.host.size())
            return tl::unexpected(ProtocolError::TooLarge);
        common::StoreU16BE(out.data() + pos, static_cast<uint16_t>(text.host.size()));
        pos += 2;
        write_bytes(text.host.data(), text.host.size());
        common::StoreU16BE(out.data() + pos, text.port);
        pos += 2;
        common::StoreU16BE(out.data() + pos, message.packet_id);
        pos += 2;
        out[pos++] = message.fragment_id;
        out[pos++] = message.fragment_count;
        common::StoreU16BE(out.data() + pos, static_cast<uint16_t>(message.payload.size()));
        pos += 2;
        return pos;
    }
    common::StoreU16BE(out.data() + pos, message.packet_id);
    pos += 2;
    out[pos++] = message.fragment_id;
    out[pos++] = message.fragment_count;
    const size_t width = common::QuicVarintSize(text.authority_size);
    const size_t needed = 8 + width + (text.host.empty() ? 0 : text.authority_size);
    if (width == 0 || out.size() < needed)
        return tl::unexpected(ProtocolError::TooLarge);
    const uint8_t prefix = static_cast<uint8_t>(
        (width == 1 ? 0 : width == 2 ? 1 : width == 4 ? 2 : 3) << 6);
    out[pos++] = static_cast<uint8_t>((text.authority_size >> ((width - 1) * 8)) | prefix);
    for (size_t i = 1; i < width; ++i)
        out[pos++] = static_cast<uint8_t>(text.authority_size >> ((width - 1 - i) * 8));
    if (!text.host.empty()) {
        if (text.bracket_v6) out[pos++] = '[';
        write_bytes(text.host.data(), text.host.size());
        if (text.bracket_v6) out[pos++] = ']';
        out[pos++] = ':';
        write_bytes(text.port_text.data(), text.port_text_size);
    }
    return pos;
}

tl::expected<std::vector<uint8_t>, ProtocolError> EncodeUdpFragment(
    HysteriaVersion version, const HysteriaUdpMessage& message, const UdpTargetText& text,
    size_t header_size) {
    std::vector<uint8_t> output(header_size + message.payload.size());
    const auto written = EncodeUdpFragmentHeader(
        version, message, text, std::span<uint8_t>(output.data(), header_size));
    if (!written) return tl::unexpected(written.error());
    output.resize(*written + message.payload.size());
    if (!message.payload.empty()) {
        std::memcpy(output.data() + *written, message.payload.data(), message.payload.size());
    }
    return output;
}

tl::expected<V1ClientHello, ProtocolError>
ParseV1ClientHello(std::span<const uint8_t> input) {
    common::ByteReader reader(input);
    const uint8_t version = reader.ReadU8();
    if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);
    if (version != kV1ProtocolVersion)
        return tl::unexpected(ProtocolError::UnsupportedVersion);
    const uint64_t send_bps = reader.ReadU64BE();
    const uint64_t receive_bps = reader.ReadU64BE();
    const uint16_t auth_size = reader.ReadU16BE();
    if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);
    if (auth_size > kMaxAuthLength) return tl::unexpected(ProtocolError::TooLarge);
    const auto auth = reader.ReadBytes(auth_size);
    if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);
    if (!reader.Empty()) return tl::unexpected(ProtocolError::Invalid);
    V1ClientHello hello;
    hello.send_bps = send_bps;
    hello.receive_bps = receive_bps;
    hello.auth.assign(reinterpret_cast<const char*>(auth.data()), auth.size());
    return hello;
}

size_t EncodeV1ServerHelloTo(
    std::span<uint8_t> out, bool accepted, uint64_t send_bps,
    uint64_t receive_bps, std::string_view message) noexcept {
    message = message.substr(0, std::min(message.size(), kMaxMessageLength));
    const size_t needed = 19 + message.size();
    if (out.size() < needed) return 0;
    out[0] = accepted ? 1 : 0;
    common::StoreU64BE(out.data() + 1, send_bps);
    common::StoreU64BE(out.data() + 9, receive_bps);
    common::StoreU16BE(out.data() + 17, static_cast<uint16_t>(message.size()));
    if (!message.empty()) {
        std::memcpy(out.data() + 19, message.data(), message.size());
    }
    return needed;
}

std::vector<uint8_t> EncodeV1ServerHello(
    bool accepted, uint64_t send_bps, uint64_t receive_bps, std::string_view message) {
    message = message.substr(0, std::min(message.size(), kMaxMessageLength));
    std::vector<uint8_t> output(19 + message.size());
    (void)EncodeV1ServerHelloTo(output, accepted, send_bps, receive_bps, message);
    return output;
}

tl::expected<V1Request, ProtocolError>
ParseV1Request(std::span<const uint8_t> input) {
    common::ByteReader reader(input);
    const uint8_t udp = reader.ReadU8();
    if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);
    if (udp > 1) return tl::unexpected(ProtocolError::Invalid);
    const uint16_t host_size = reader.ReadU16BE();
    if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);
    if (host_size > kMaxAddressLength)
        return tl::unexpected(ProtocolError::TooLarge);
    const auto host = reader.ReadBytes(host_size);
    const uint16_t port = reader.ReadU16BE();
    if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);
    if (udp != 0 && host.empty() && port == 0)
        return V1Request{true, {}, reader.Position()};
    if (host.empty()) return tl::unexpected(ProtocolError::Invalid);
    auto target = ParseV1Target(host, port);
    if (!target) return tl::unexpected(target.error());
    return V1Request{udp != 0, std::move(*target), reader.Position()};
}

size_t EncodeV1ResponseTo(
    std::span<uint8_t> out, bool accepted, uint32_t udp_session_id,
    std::string_view message) noexcept {
    message = message.substr(0, std::min(message.size(), kMaxMessageLength));
    const size_t needed = 7 + message.size();
    if (out.size() < needed) return 0;
    out[0] = accepted ? 1 : 0;
    common::StoreU32BE(out.data() + 1, udp_session_id);
    common::StoreU16BE(out.data() + 5, static_cast<uint16_t>(message.size()));
    if (!message.empty()) {
        std::memcpy(out.data() + 7, message.data(), message.size());
    }
    return needed;
}

std::vector<uint8_t> EncodeV1Response(
    bool accepted, uint32_t udp_session_id, std::string_view message) {
    message = message.substr(0, std::min(message.size(), kMaxMessageLength));
    std::vector<uint8_t> output(7 + message.size());
    (void)EncodeV1ResponseTo(output, accepted, udp_session_id, message);
    return output;
}

tl::expected<V2TcpRequest, ProtocolError>
ParseV2TcpRequest(std::span<const uint8_t> input) {
    common::ByteReader reader(input);
    const auto request_type = reader.ReadQuicVarint();
    if (!request_type) return tl::unexpected(ProtocolError::Incomplete);
    if (*request_type != kV2TcpRequestType) return tl::unexpected(ProtocolError::Invalid);
    const auto address_size = reader.ReadQuicVarint();
    if (!address_size) return tl::unexpected(ProtocolError::Incomplete);
    if (*address_size == 0 || *address_size > kMaxAddressLength)
        return tl::unexpected(ProtocolError::TooLarge);
    const auto address = reader.ReadBytes(static_cast<size_t>(*address_size));
    if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);
    const auto padding_size = reader.ReadQuicVarint();
    if (!padding_size) return tl::unexpected(ProtocolError::Incomplete);
    if (*padding_size > kMaxPaddingLength) return tl::unexpected(ProtocolError::TooLarge);
    if (!reader.Skip(static_cast<size_t>(*padding_size)))
        return tl::unexpected(ProtocolError::Incomplete);
    const auto text = std::string_view(
        reinterpret_cast<const char*>(address.data()), address.size());
    auto target = common::TargetAddress::Parse(text);
    if (!target) return tl::unexpected(ProtocolError::Invalid);
    return V2TcpRequest{std::move(*target), reader.Position()};
}

tl::expected<HysteriaUdpMessage, ProtocolError>
ParseUdpMessage(HysteriaVersion version, std::span<const uint8_t> input) {
    common::ByteReader reader(input);
    const uint32_t session_id = reader.ReadU32BE();
    if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);

    HysteriaUdpMessage result;
    result.session_id = session_id;
    if (version == HysteriaVersion::V1) {
        const uint16_t host_size = reader.ReadU16BE();
        if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);
        if (host_size == 0 || host_size > kMaxAddressLength)
            return tl::unexpected(ProtocolError::TooLarge);
        const auto host = reader.ReadBytes(host_size);
        const uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);
        auto target = ParseV1Target(host, port);
        if (!target) return tl::unexpected(target.error());
        result.target = std::move(*target);
        const uint16_t packet_id = reader.ReadU16BE();
        const uint8_t fragment_id = reader.ReadU8();
        const uint8_t fragment_count = reader.ReadU8();
        const uint16_t payload_size = reader.ReadU16BE();
        if (!reader.Ok())
            return tl::unexpected(ProtocolError::Incomplete);
        if (!ValidFragmentIndex(version, fragment_id, fragment_count))
            return tl::unexpected(ProtocolError::Invalid);
        if (payload_size > kMaxUdpPayloadLength)
            return tl::unexpected(ProtocolError::TooLarge);
        const auto payload = reader.ReadBytes(payload_size);
        if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);
        if (!reader.Empty()) return tl::unexpected(ProtocolError::Invalid);
        result.packet_id = packet_id;
        result.fragment_id = fragment_id;
        result.fragment_count = fragment_count;
        result.payload = payload;
        return result;
    }

    const uint16_t packet_id = reader.ReadU16BE();
    const uint8_t fragment_id = reader.ReadU8();
    const uint8_t fragment_count = reader.ReadU8();
    const auto address_size = reader.ReadQuicVarint();
    if (!reader.Ok() || !address_size)
        return tl::unexpected(ProtocolError::Incomplete);
    if (!ValidFragmentIndex(version, fragment_id, fragment_count))
        return tl::unexpected(ProtocolError::Invalid);
    if (*address_size > kMaxAddressLength)
        return tl::unexpected(ProtocolError::TooLarge);
    const auto address = reader.ReadBytes(static_cast<size_t>(*address_size));
    if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);
    if (!address.empty()) {
        const auto text = std::string_view(
            reinterpret_cast<const char*>(address.data()), address.size());
        auto target = common::TargetAddress::Parse(text);
        if (!target) return tl::unexpected(ProtocolError::Invalid);
        result.target = std::move(*target);
    } else if (RequiresUdpTarget(version, fragment_id, fragment_count)) {
        return tl::unexpected(ProtocolError::Invalid);
    }
    if (reader.Remaining() > kMaxUdpPayloadLength)
        return tl::unexpected(ProtocolError::TooLarge);
    result.packet_id = packet_id;
    result.fragment_id = fragment_id;
    result.fragment_count = fragment_count;
    result.payload = reader.ReadBytes(reader.Remaining());
    return result;
}

tl::expected<size_t, ProtocolError>
UdpMessageHeaderSize(HysteriaVersion version, const common::TargetAddress& target) {
    std::optional<common::AddressText> address_storage;
    const auto text = PrepareUdpTargetText(version, target, address_storage);
    if (!text) return tl::unexpected(text.error());
    return UdpTargetHeaderSize(version, *text);
}

tl::expected<std::vector<uint8_t>, ProtocolError>
EncodeUdpMessage(HysteriaVersion version, const HysteriaUdpMessage& message) {
    if (!ValidFragmentIndex(version, message.fragment_id, message.fragment_count) ||
        message.payload.size() > kMaxUdpPayloadLength)
        return tl::unexpected(ProtocolError::Invalid);

    std::optional<common::AddressText> address_storage;
    const auto text = PrepareUdpTargetText(version, message.target, address_storage);
    if (!text) return tl::unexpected(text.error());
    if (text->host.empty() && RequiresUdpTarget(
            version, message.fragment_id, message.fragment_count))
        return tl::unexpected(ProtocolError::Invalid);
    const auto header_size = UdpTargetHeaderSize(version, *text);
    if (!header_size) return tl::unexpected(header_size.error());
    if (message.payload.size() > std::numeric_limits<size_t>::max() - *header_size)
        return tl::unexpected(ProtocolError::TooLarge);
    return EncodeUdpFragment(version, message, *text, *header_size);
}

std::array<uint8_t, 32> HashCredential(std::string_view credential) noexcept {
    std::array<uint8_t, 32> digest{};
    SHA256(reinterpret_cast<const uint8_t*>(credential.data()), credential.size(), digest.data());
    return digest;
}

}  // namespace transport
