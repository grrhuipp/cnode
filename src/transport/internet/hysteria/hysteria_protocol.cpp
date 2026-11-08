#include "hysteria_protocol.hpp"

#include "common/ip_address.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <charconv>
#include <limits>

namespace transport::internet::hysteria {
namespace {

class Cursor final {
public:
    explicit Cursor(std::span<const uint8_t> input) noexcept : input_(input) {}

    [[nodiscard]] size_t position() const noexcept { return position_; }
    [[nodiscard]] size_t remaining() const noexcept { return input_.size() - position_; }

    [[nodiscard]] tl::expected<uint8_t, ProtocolError> U8() noexcept {
        if (remaining() < 1) return tl::unexpected(ProtocolError::Incomplete);
        return input_[position_++];
    }

    [[nodiscard]] tl::expected<uint16_t, ProtocolError> U16() noexcept {
        if (remaining() < 2) return tl::unexpected(ProtocolError::Incomplete);
        const auto value = static_cast<uint16_t>(
            (static_cast<uint16_t>(input_[position_]) << 8) |
            input_[position_ + 1]);
        position_ += 2;
        return value;
    }

    [[nodiscard]] tl::expected<uint32_t, ProtocolError> U32() noexcept {
        if (remaining() < 4) return tl::unexpected(ProtocolError::Incomplete);
        uint32_t value = 0;
        for (size_t i = 0; i < 4; ++i) value = (value << 8) | input_[position_ + i];
        position_ += 4;
        return value;
    }

    [[nodiscard]] tl::expected<uint64_t, ProtocolError> U64() noexcept {
        if (remaining() < 8) return tl::unexpected(ProtocolError::Incomplete);
        uint64_t value = 0;
        for (size_t i = 0; i < 8; ++i) value = (value << 8) | input_[position_ + i];
        position_ += 8;
        return value;
    }

    [[nodiscard]] tl::expected<uint64_t, ProtocolError> Varint() noexcept {
        if (remaining() < 1) return tl::unexpected(ProtocolError::Incomplete);
        const size_t width = size_t{1} << (input_[position_] >> 6);
        if (remaining() < width) return tl::unexpected(ProtocolError::Incomplete);
        uint64_t value = input_[position_] & 0x3fu;
        for (size_t i = 1; i < width; ++i) value = (value << 8) | input_[position_ + i];
        position_ += width;
        return value;
    }

    [[nodiscard]] tl::expected<std::span<const uint8_t>, ProtocolError>
    Bytes(size_t size) noexcept {
        if (remaining() < size) return tl::unexpected(ProtocolError::Incomplete);
        auto result = input_.subspan(position_, size);
        position_ += size;
        return result;
    }

private:
    std::span<const uint8_t> input_;
    size_t position_ = 0;
};

void AppendU16(std::vector<uint8_t>& output, uint16_t value) {
    output.push_back(static_cast<uint8_t>(value >> 8));
    output.push_back(static_cast<uint8_t>(value));
}

void AppendU32(std::vector<uint8_t>& output, uint32_t value) {
    for (unsigned shift : {24u, 16u, 8u, 0u})
        output.push_back(static_cast<uint8_t>(value >> shift));
}

void AppendU64(std::vector<uint8_t>& output, uint64_t value) {
    for (unsigned shift : {56u, 48u, 40u, 32u, 24u, 16u, 8u, 0u})
        output.push_back(static_cast<uint8_t>(value >> shift));
}

[[nodiscard]] size_t VarintWidth(uint64_t value) noexcept {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    if (value <= 4611686018427387903ULL) return 8;
    return 0;
}

bool AppendVarint(std::vector<uint8_t>& output, uint64_t value) {
    const size_t width = VarintWidth(value);
    if (width == 0) return false;
    const uint8_t prefix = static_cast<uint8_t>(
        (width == 1 ? 0 : width == 2 ? 1 : width == 4 ? 2 : 3) << 6);
    const size_t start = output.size();
    output.resize(start + width);
    for (size_t i = 0; i < width; ++i) {
        output[start + width - 1 - i] = static_cast<uint8_t>(value >> (i * 8));
    }
    output[start] = static_cast<uint8_t>(output[start] | prefix);
    return true;
}

[[nodiscard]] std::string_view TargetHost(
    const TargetAddress& target, std::optional<iputil::AddressText>& storage) {
    if (target.IsDomain()) return {target.host.data(), target.host.size()};
    if (!target.resolved_addr) return {};
    storage.emplace(*target.resolved_addr);
    return storage->View();
}

[[nodiscard]] tl::expected<TargetAddress, ProtocolError>
ParseV1Target(std::span<const uint8_t> host, uint16_t port) {
    if (host.empty() || host.size() > kMaxAddressLength || port == 0)
        return tl::unexpected(ProtocolError::Invalid);
    TargetAddress target(
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

struct UdpTargetText {
    // host 借用调用方的 target 或 address_storage，只用于同步计长与编码。
    std::string_view host;
    std::array<char, 5> port{};
    size_t port_size = 0;
    size_t authority_size = 0;
    bool bracket_v6 = false;
};

[[nodiscard]] tl::expected<UdpTargetText, ProtocolError> PrepareUdpTargetText(
    Version version, const TargetAddress& target,
    std::optional<iputil::AddressText>& address_storage) {
    UdpTargetText text;
    if (target.IsValid()) text.host = TargetHost(target, address_storage);
    if (version == Version::V1) {
        if (text.host.empty() || text.host.size() > kMaxAddressLength)
            return tl::unexpected(ProtocolError::Invalid);
        return text;
    }
    if (text.host.empty()) return text;
    const auto [end, error] = std::to_chars(
        text.port.data(), text.port.data() + text.port.size(), target.port);
    if (error != std::errc{}) return tl::unexpected(ProtocolError::Invalid);
    text.port_size = static_cast<size_t>(end - text.port.data());
    text.bracket_v6 = text.host.find(':') != std::string_view::npos;
    const size_t suffix = (text.bracket_v6 ? 2 : 0) + 1 + text.port_size;
    if (text.host.size() > std::numeric_limits<size_t>::max() - suffix)
        return tl::unexpected(ProtocolError::TooLarge);
    text.authority_size = text.host.size() + suffix;
    return text;
}

[[nodiscard]] tl::expected<size_t, ProtocolError> UdpHeaderSize(
    Version version, const UdpTargetText& text) {
    if (version == Version::V1) return 14 + text.host.size();
    const size_t width = VarintWidth(text.authority_size);
    if (width == 0 ||
        text.authority_size > std::numeric_limits<size_t>::max() - 8 - width)
        return tl::unexpected(ProtocolError::TooLarge);
    return 8 + width + text.authority_size;
}

}  // namespace

tl::expected<V1ClientHello, ProtocolError>
ParseV1ClientHello(std::span<const uint8_t> input) {
    Cursor cursor(input);
    const auto version = cursor.U8();
    if (!version) return tl::unexpected(version.error());
    if (*version != kV1ProtocolVersion)
        return tl::unexpected(ProtocolError::UnsupportedVersion);
    const auto send_bps = cursor.U64();
    if (!send_bps) return tl::unexpected(send_bps.error());
    const auto receive_bps = cursor.U64();
    if (!receive_bps) return tl::unexpected(receive_bps.error());
    const auto auth_size = cursor.U16();
    if (!auth_size) return tl::unexpected(auth_size.error());
    if (*auth_size > kMaxAuthLength) return tl::unexpected(ProtocolError::TooLarge);
    const auto auth = cursor.Bytes(*auth_size);
    if (!auth) return tl::unexpected(auth.error());
    if (cursor.remaining() != 0) return tl::unexpected(ProtocolError::Invalid);
    V1ClientHello hello;
    hello.send_bps = *send_bps;
    hello.receive_bps = *receive_bps;
    hello.auth.assign(reinterpret_cast<const char*>(auth->data()), auth->size());
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
    Cursor cursor(input);
    const auto udp = cursor.U8();
    if (!udp) return tl::unexpected(udp.error());
    if (*udp > 1) return tl::unexpected(ProtocolError::Invalid);
    const auto host_size = cursor.U16();
    if (!host_size) return tl::unexpected(host_size.error());
    if (*host_size > kMaxAddressLength)
        return tl::unexpected(ProtocolError::TooLarge);
    const auto host = cursor.Bytes(*host_size);
    if (!host) return tl::unexpected(host.error());
    const auto port = cursor.U16();
    if (!port) return tl::unexpected(port.error());
    if (*udp != 0 && host->empty() && *port == 0)
        return V1Request{true, {}, cursor.position()};
    if (host->empty()) return tl::unexpected(ProtocolError::Invalid);
    auto target = ParseV1Target(*host, *port);
    if (!target) return tl::unexpected(target.error());
    return V1Request{*udp != 0, std::move(*target), cursor.position()};
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
    Cursor cursor(input);
    const auto request_type = cursor.Varint();
    if (!request_type) return tl::unexpected(request_type.error());
    if (*request_type != kV2TcpRequestType) return tl::unexpected(ProtocolError::Invalid);
    const auto address_size = cursor.Varint();
    if (!address_size) return tl::unexpected(address_size.error());
    if (*address_size == 0 || *address_size > kMaxAddressLength)
        return tl::unexpected(ProtocolError::TooLarge);
    const auto address = cursor.Bytes(static_cast<size_t>(*address_size));
    if (!address) return tl::unexpected(address.error());
    const auto padding_size = cursor.Varint();
    if (!padding_size) return tl::unexpected(padding_size.error());
    if (*padding_size > kMaxPaddingLength) return tl::unexpected(ProtocolError::TooLarge);
    const auto padding = cursor.Bytes(static_cast<size_t>(*padding_size));
    if (!padding) return tl::unexpected(padding.error());
    const auto text = std::string_view(
        reinterpret_cast<const char*>(address->data()), address->size());
    auto target = TargetAddress::Parse(text);
    if (!target) return tl::unexpected(ProtocolError::Invalid);
    return V2TcpRequest{std::move(*target), cursor.position()};
}

std::vector<uint8_t> EncodeV2TcpResponse(
    bool accepted, std::string_view message, std::span<const uint8_t> padding) {
    message = message.substr(0, std::min(message.size(), kMaxMessageLength));
    padding = padding.first(std::min(padding.size(), kMaxPaddingLength));
    std::vector<uint8_t> output;
    output.reserve(1 + 8 + message.size() + padding.size());
    output.push_back(accepted ? 0 : 1);
    AppendVarint(output, message.size());
    output.insert(output.end(), message.begin(), message.end());
    AppendVarint(output, padding.size());
    output.insert(output.end(), padding.begin(), padding.end());
    return output;
}

tl::expected<UdpMessage, ProtocolError>
ParseUdpMessage(Version version, std::span<const uint8_t> input) {
    Cursor cursor(input);
    const auto session_id = cursor.U32();
    if (!session_id) return tl::unexpected(session_id.error());

    UdpMessage result;
    result.session_id = *session_id;
    if (version == Version::V1) {
        const auto host_size = cursor.U16();
        if (!host_size) return tl::unexpected(host_size.error());
        if (*host_size == 0 || *host_size > kMaxAddressLength)
            return tl::unexpected(ProtocolError::TooLarge);
        const auto host = cursor.Bytes(*host_size);
        if (!host) return tl::unexpected(host.error());
        const auto port = cursor.U16();
        if (!port) return tl::unexpected(port.error());
        auto target = ParseV1Target(*host, *port);
        if (!target) return tl::unexpected(target.error());
        result.target = std::move(*target);
        const auto packet_id = cursor.U16();
        const auto fragment_id = cursor.U8();
        const auto fragment_count = cursor.U8();
        const auto payload_size = cursor.U16();
        if (!packet_id || !fragment_id || !fragment_count || !payload_size)
            return tl::unexpected(ProtocolError::Incomplete);
        if (!ValidFragmentIndex(version, *fragment_id, *fragment_count))
            return tl::unexpected(ProtocolError::Invalid);
        if (*payload_size > kMaxUdpPayloadLength)
            return tl::unexpected(ProtocolError::TooLarge);
        const auto payload = cursor.Bytes(*payload_size);
        if (!payload) return tl::unexpected(payload.error());
        if (cursor.remaining() != 0) return tl::unexpected(ProtocolError::Invalid);
        result.packet_id = *packet_id;
        result.fragment_id = *fragment_id;
        result.fragment_count = *fragment_count;
        result.payload = *payload;
        return result;
    }

    const auto packet_id = cursor.U16();
    const auto fragment_id = cursor.U8();
    const auto fragment_count = cursor.U8();
    const auto address_size = cursor.Varint();
    if (!packet_id || !fragment_id || !fragment_count || !address_size)
        return tl::unexpected(ProtocolError::Incomplete);
    if (!ValidFragmentIndex(version, *fragment_id, *fragment_count))
        return tl::unexpected(ProtocolError::Invalid);
    if (*address_size > kMaxAddressLength)
        return tl::unexpected(ProtocolError::TooLarge);
    const auto address = cursor.Bytes(static_cast<size_t>(*address_size));
    if (!address) return tl::unexpected(address.error());
    if (!address->empty()) {
        const auto text = std::string_view(
            reinterpret_cast<const char*>(address->data()), address->size());
        auto target = TargetAddress::Parse(text);
        if (!target) return tl::unexpected(ProtocolError::Invalid);
        result.target = std::move(*target);
    } else if (RequiresUdpTarget(version, *fragment_id, *fragment_count)) {
        return tl::unexpected(ProtocolError::Invalid);
    }
    if (cursor.remaining() > kMaxUdpPayloadLength)
        return tl::unexpected(ProtocolError::TooLarge);
    result.packet_id = *packet_id;
    result.fragment_id = *fragment_id;
    result.fragment_count = *fragment_count;
    result.payload = *cursor.Bytes(cursor.remaining());
    return result;
}

tl::expected<size_t, ProtocolError>
UdpMessageHeaderSize(Version version, const TargetAddress& target) {
    std::optional<iputil::AddressText> address_storage;
    const auto text = PrepareUdpTargetText(version, target, address_storage);
    if (!text) return tl::unexpected(text.error());
    return UdpHeaderSize(version, *text);
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
    const auto header_size = UdpHeaderSize(version, *text);
    if (!header_size) return tl::unexpected(header_size.error());
    if (message.payload.size() > std::numeric_limits<size_t>::max() - *header_size)
        return tl::unexpected(ProtocolError::TooLarge);

    std::vector<uint8_t> output;
    output.reserve(*header_size + message.payload.size());
    AppendU32(output, message.session_id);
    if (version == Version::V1) {
        AppendU16(output, static_cast<uint16_t>(text->host.size()));
        output.insert(output.end(), text->host.begin(), text->host.end());
        AppendU16(output, message.target.port);
        AppendU16(output, message.packet_id);
        output.push_back(message.fragment_id);
        output.push_back(message.fragment_count);
        AppendU16(output, static_cast<uint16_t>(message.payload.size()));
    } else {
        AppendU16(output, message.packet_id);
        output.push_back(message.fragment_id);
        output.push_back(message.fragment_count);
        if (!AppendVarint(output, text->authority_size))
            return tl::unexpected(ProtocolError::TooLarge);
        if (!text->host.empty()) {
            if (text->bracket_v6) output.push_back('[');
            output.insert(output.end(), text->host.begin(), text->host.end());
            if (text->bracket_v6) output.push_back(']');
            output.push_back(':');
            output.insert(output.end(), text->port.data(), text->port.data() + text->port_size);
        }
    }
    output.insert(output.end(), message.payload.begin(), message.payload.end());
    return output;
}

std::array<uint8_t, 32> HashCredential(std::string_view credential) noexcept {
    std::array<uint8_t, 32> digest{};
    SHA256(reinterpret_cast<const uint8_t*>(credential.data()), credential.size(), digest.data());
    return digest;
}

}  // namespace transport::internet::hysteria
