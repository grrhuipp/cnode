#pragma once

#include "common/allocator.hpp"
#include "common/ip_utils.hpp"
#include "common/target_address.hpp"

#include <tl/expected.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

// Hysteria v1/v2 线格式编解码：只借用输入视图产出值，不依赖 QUIC/HTTP3 实现，
// 供传输层（连接级认证与 UDP 会话）与入站处理器（请求流目标）共用。
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
    memory::String auth;
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

[[nodiscard]] memory::ByteVector
EncodeV1ServerHello(bool accepted, uint64_t send_bps, uint64_t receive_bps,
                    std::string_view message);

[[nodiscard]] tl::expected<V1Request, ProtocolError>
ParseV1Request(std::span<const uint8_t> input);

[[nodiscard]] memory::ByteVector
EncodeV1Response(bool accepted, uint32_t udp_session_id, std::string_view message);

[[nodiscard]] tl::expected<V2TcpRequest, ProtocolError>
ParseV2TcpRequest(std::span<const uint8_t> input);

[[nodiscard]] tl::expected<UdpMessage, ProtocolError>
ParseUdpMessage(Version version, std::span<const uint8_t> input);

// V2 的空目标按无地址续片计长；是否必须带目标仍由报文语义校验决定。
[[nodiscard]] tl::expected<size_t, ProtocolError>
UdpMessageHeaderSize(Version version, const TargetAddress& target);

// 输出归属当前分配域，可直接移动到连接的待发送队列。
[[nodiscard]] tl::expected<memory::ByteVector, ProtocolError>
EncodeUdpMessage(Version version, const UdpMessage& message);

// 已格式化的 UDP 目标：分片发送时地址只格式化一次，逐片复用。
// host 借用调用方的 target 或 address_storage，二者须覆盖本对象寿命。
struct UdpTargetText {
    std::string_view host;
    uint16_t port = 0;
    std::array<char, 5> port_text{};
    size_t port_text_size = 0;
    size_t authority_size = 0;
    bool bracket_v6 = false;
};

[[nodiscard]] tl::expected<UdpTargetText, ProtocolError> PrepareUdpTargetText(
    Version version, const TargetAddress& target,
    std::optional<iputil::AddressText>& address_storage);

[[nodiscard]] tl::expected<size_t, ProtocolError>
UdpTargetHeaderSize(Version version, const UdpTargetText& text);

// 以预格式化目标编码一片；|message.target| 不读，分片号与载荷上限由调用方
// 按 |header_size|（UdpTargetHeaderSize 的结果）预先约束。
[[nodiscard]] tl::expected<memory::ByteVector, ProtocolError> EncodeUdpFragment(
    Version version, const UdpMessage& message, const UdpTargetText& text,
    size_t header_size);

[[nodiscard]] std::array<uint8_t, 32> HashCredential(std::string_view credential) noexcept;

}  // namespace transport::internet::hysteria
