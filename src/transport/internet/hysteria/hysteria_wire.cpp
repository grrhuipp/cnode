#include "transport/internet/hysteria/hysteria_wire.hpp"

#include "common/byte_reader.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <charconv>
#include <limits>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace transport::internet::hysteria {

namespace {

void AppendU16(std::vector<uint8_t>& output, uint16_t value) {
    std::array<uint8_t, 2> bytes{};
    common::StoreU16BE(bytes.data(), value);
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void AppendU32(std::vector<uint8_t>& output, uint32_t value) {
    std::array<uint8_t, 4> bytes{};
    common::StoreU32BE(bytes.data(), value);
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void AppendU64(std::vector<uint8_t>& output, uint64_t value) {
    std::array<uint8_t, 8> bytes{};
    common::StoreU64BE(bytes.data(), value);
    output.insert(output.end(), bytes.begin(), bytes.end());
}

bool AppendVarint(std::vector<uint8_t>& output, uint64_t value) {
    const size_t width = common::QuicVarintSize(value);
    if (width == 0) return false;
    const uint8_t prefix = static_cast<uint8_t>(
        (width == 1 ? 0 : width == 2 ? 1 : width == 4 ? 2 : 3) << 6);
    output.push_back(static_cast<uint8_t>((value >> ((width - 1) * 8)) | prefix));
    for (size_t i = 1; i < width; ++i)
        output.push_back(static_cast<uint8_t>(value >> ((width - 1 - i) * 8)));
    return true;
}

[[nodiscard]] std::string_view TargetHost(
    const common::TargetAddress& target, std::optional<iputil::AddressText>& storage) {
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

[[nodiscard]] bool ValidFragmentIndex(Version version, uint8_t index, uint8_t count) noexcept {
    // HY2 declares Fragment ID irrelevant for an unfragmented packet.
    return count != 0 && ((version == Version::V2 && count == 1) || index < count);
}

[[nodiscard]] bool RequiresUdpTarget(Version version, uint8_t index, uint8_t count) noexcept {
    return version == Version::V1 || count == 1 || index == 0;
}

}  // namespace

tl::expected<UdpTargetText, ProtocolError> PrepareUdpTargetText(
    Version version, const common::TargetAddress& target,
    std::optional<iputil::AddressText>& address_storage) {
    UdpTargetText text;
    text.port = target.port;
    if (target.IsValid()) text.host = TargetHost(target, address_storage);
    if (version == Version::V1) {
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
    Version version, const UdpTargetText& text) {
    if (version == Version::V1) return 14 + text.host.size();
    const size_t width = common::QuicVarintSize(text.authority_size);
    if (width == 0 ||
        text.authority_size > std::numeric_limits<size_t>::max() - 8 - width)
        return tl::unexpected(ProtocolError::TooLarge);
    return 8 + width + text.authority_size;
}

tl::expected<std::vector<uint8_t>, ProtocolError> EncodeUdpFragment(
    Version version, const UdpMessage& message, const UdpTargetText& text,
    size_t header_size) {
    std::vector<uint8_t> output;
    output.reserve(header_size + message.payload.size());
    AppendU32(output, message.session_id);
    if (version == Version::V1) {
        AppendU16(output, static_cast<uint16_t>(text.host.size()));
        output.insert(output.end(), text.host.begin(), text.host.end());
        AppendU16(output, text.port);
        AppendU16(output, message.packet_id);
        output.push_back(message.fragment_id);
        output.push_back(message.fragment_count);
        AppendU16(output, static_cast<uint16_t>(message.payload.size()));
    } else {
        AppendU16(output, message.packet_id);
        output.push_back(message.fragment_id);
        output.push_back(message.fragment_count);
        if (!AppendVarint(output, text.authority_size))
            return tl::unexpected(ProtocolError::TooLarge);
        if (!text.host.empty()) {
            if (text.bracket_v6) output.push_back('[');
            output.insert(output.end(), text.host.begin(), text.host.end());
            if (text.bracket_v6) output.push_back(']');
            output.push_back(':');
            output.insert(output.end(), text.port_text.data(),
                          text.port_text.data() + text.port_text_size);
        }
    }
    output.insert(output.end(), message.payload.begin(), message.payload.end());
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

std::vector<uint8_t> EncodeV1ServerHello(
    bool accepted, uint64_t send_bps, uint64_t receive_bps, std::string_view message) {
    message = message.substr(0, std::min(message.size(), kMaxMessageLength));
    std::vector<uint8_t> output;
    output.reserve(19 + message.size());
    output.push_back(accepted ? 1 : 0);
    AppendU64(output, send_bps);
    AppendU64(output, receive_bps);
    AppendU16(output, static_cast<uint16_t>(message.size()));
    output.insert(output.end(), message.begin(), message.end());
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

std::vector<uint8_t> EncodeV1Response(
    bool accepted, uint32_t udp_session_id, std::string_view message) {
    message = message.substr(0, std::min(message.size(), kMaxMessageLength));
    std::vector<uint8_t> output;
    output.reserve(7 + message.size());
    output.push_back(accepted ? 1 : 0);
    AppendU32(output, udp_session_id);
    AppendU16(output, static_cast<uint16_t>(message.size()));
    output.insert(output.end(), message.begin(), message.end());
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

tl::expected<UdpMessage, ProtocolError>
ParseUdpMessage(Version version, std::span<const uint8_t> input) {
    common::ByteReader reader(input);
    const uint32_t session_id = reader.ReadU32BE();
    if (!reader.Ok()) return tl::unexpected(ProtocolError::Incomplete);

    UdpMessage result;
    result.session_id = session_id;
    if (version == Version::V1) {
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
UdpMessageHeaderSize(Version version, const common::TargetAddress& target) {
    std::optional<iputil::AddressText> address_storage;
    const auto text = PrepareUdpTargetText(version, target, address_storage);
    if (!text) return tl::unexpected(text.error());
    return UdpTargetHeaderSize(version, *text);
}

tl::expected<std::vector<uint8_t>, ProtocolError>
EncodeUdpMessage(Version version, const UdpMessage& message) {
    if (!ValidFragmentIndex(version, message.fragment_id, message.fragment_count) ||
        message.payload.size() > kMaxUdpPayloadLength)
        return tl::unexpected(ProtocolError::Invalid);

    std::optional<iputil::AddressText> address_storage;
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

}  // namespace transport::internet::hysteria
