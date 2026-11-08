#pragma once

#include "common/target_address.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <tl/expected.hpp>

namespace transport::internet::hysteria {

enum class Version : uint8_t {
    V1,
    V2,
};

enum class ProtocolError : uint8_t {
    Incomplete,
    Invalid,
    TooLarge,
    UnsupportedVersion,
};

inline constexpr uint8_t kV1ProtocolVersion = 3;
inline constexpr uint64_t kV2TcpRequestType = 0x401;
inline constexpr size_t kMaxAuthLength = 4096;
inline constexpr size_t kMaxAddressLength = 2048;
inline constexpr size_t kMaxMessageLength = 2048;
inline constexpr size_t kMaxPaddingLength = 4096;
inline constexpr size_t kMaxUdpPayloadLength = 4096;

struct V1ClientHello {
    uint64_t send_bps = 0;
    uint64_t receive_bps = 0;
    std::string auth;
};

struct V1Request {
    bool udp = false;
    TargetAddress target;
    size_t header_bytes = 0;
};

struct V2TcpRequest {
    TargetAddress target;
    size_t header_bytes = 0;
};

struct UdpMessage {
    uint32_t session_id = 0;
    uint16_t packet_id = 0;
    uint8_t fragment_id = 0;
    uint8_t fragment_count = 1;
    TargetAddress target;
    std::span<const uint8_t> payload;
};

[[nodiscard]] tl::expected<V1ClientHello, ProtocolError>
ParseV1ClientHello(std::span<const uint8_t> input);

[[nodiscard]] std::vector<uint8_t>
EncodeV1ServerHello(bool accepted, uint64_t send_bps, uint64_t receive_bps,
                    std::string_view message);

[[nodiscard]] tl::expected<V1Request, ProtocolError>
ParseV1Request(std::span<const uint8_t> input);

[[nodiscard]] std::vector<uint8_t>
EncodeV1Response(bool accepted, uint32_t udp_session_id, std::string_view message);

[[nodiscard]] tl::expected<V2TcpRequest, ProtocolError>
ParseV2TcpRequest(std::span<const uint8_t> input);

[[nodiscard]] std::vector<uint8_t>
EncodeV2TcpResponse(bool accepted, std::string_view message,
                    std::span<const uint8_t> padding = {});

[[nodiscard]] tl::expected<UdpMessage, ProtocolError>
ParseUdpMessage(Version version, std::span<const uint8_t> input);

// V2 的空目标按无地址续片计长；是否必须带目标仍由报文语义校验决定。
[[nodiscard]] tl::expected<size_t, ProtocolError>
UdpMessageHeaderSize(Version version, const TargetAddress& target);

[[nodiscard]] tl::expected<std::vector<uint8_t>, ProtocolError>
EncodeUdpMessage(Version version, const UdpMessage& message);

[[nodiscard]] std::array<uint8_t, 32> HashCredential(std::string_view credential) noexcept;

}  // namespace transport::internet::hysteria
