#pragma once

// ============================================================================
// trojan_codec.hpp - Trojan 协议编解码
//
// 职责：协议常量、请求结构体、握手结果、编解码逻辑（TCP + UDP）
// ============================================================================

#include "proxy/outbound_endpoint_base.hpp"
#include "common/address_codec.hpp"
#include "common/binary_text_codec.hpp"
#include "common/asio_types.hpp"
#include "common/multi_buffer.hpp"
#include "common/target_address.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <openssl/sha.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
namespace proxy {

using TrojanPasswordHash = std::array<char, 56>;

[[nodiscard]] inline TrojanPasswordHash HashTrojanPassword(std::string_view password) noexcept {
    std::array<unsigned char, SHA224_DIGEST_LENGTH> digest{};
    SHA224(reinterpret_cast<const unsigned char*>(password.data()),
           password.size(), digest.data());
    TrojanPasswordHash result{};
    common::EncodeHexLowerTo(digest, result);
    return result;
}

// ============================================================================
// Trojan 命令类型
// ============================================================================
enum class TrojanCommand : uint8_t {
    CONNECT = 0x01,
    UDP_ASSOCIATE = 0x03,
};

// ============================================================================
// Trojan 请求
// ============================================================================
struct TrojanRequest {
    TrojanPasswordHash   password_hash{};  // SHA224 密码哈希（十六进制，56字节）
    TrojanCommand        command = TrojanCommand::CONNECT;
    common::TargetAddress        target;
    std::optional<common::ForwardedMetadata> forwarded;

    [[nodiscard]] std::string_view PasswordHashView() const noexcept {
        return {password_hash.data(), password_hash.size()};
    }
};

inline constexpr size_t kPasswordHashSize = std::tuple_size_v<TrojanPasswordHash>;
// hash + CRLF + command; the SOCKS5 address and a final CRLF follow.
inline constexpr size_t kRequestPrefixSize = kPasswordHashSize + 3;
// UDP 包头：不带元数据的 SOCKS5 地址之后是 2 字节长度与 CRLF。
inline constexpr size_t kUdpPacketTrailerSize = 2 + 2;
inline constexpr size_t kMaxUdpPacketHeaderSize =
    common::kMaxBaseEncodedAddressSize + kUdpPacketTrailerSize;

enum class TrojanRequestDecodeStatus : uint8_t { Complete, Incomplete, InvalidHeader, InvalidAddress };

struct TrojanRequestDecodeResult {
    TrojanRequestDecodeStatus status = TrojanRequestDecodeStatus::Incomplete;
    TrojanRequest request;
    size_t consumed = 0;
    // Incomplete only: minimum total request bytes for the next stage; never
    // beyond the end of a valid request header.
    size_t required = 0;
};

// Single-pass incremental decode of the buffered request prefix: each call
// reports the next required length until the header is complete.
[[nodiscard]] TrojanRequestDecodeResult DecodeTrojanRequest(std::span<const uint8_t> data);

// 返回写入字节数，0 表示目标非法或缓冲区不足。
[[nodiscard]] size_t EncodeRequestTo(
    std::span<const char, 56> password_hash,
    TrojanCommand cmd,
    const common::TargetAddress& target,
    uint8_t* output,
    size_t output_size,
    common::ForwardedMetadataView forwarded = {});

// 返回写入字节数，0 表示目标非法、负载超过 uint16 或缓冲区不足。
[[nodiscard]] size_t EncodeUdpPacketHeaderTo(
    const common::TargetAddress& target,
    size_t payload_len,
    uint8_t* output,
    size_t output_size);

struct TrojanFramedUdpPacket {
    common::TargetAddress target;
    common::MultiBuffer payload;
};

// Owns stream fragments until one complete tagged datagram, including an empty
// payload, can be transferred. An empty container is reserved for stream EOF.
// Malformed/truncated input, budget overflow and use after EOF/failure throw
// LinkError(PROTOCOL_DECODE_FAILED); source I/O errors are propagated unchanged.
class TrojanUdpFramer {
public:
    void Feed(common::MultiBuffer input);
    [[nodiscard]] bool Next(TrojanFramedUdpPacket& out);
    void Finish();
    [[nodiscard]] bool Finished() const noexcept { return state_ == State::Finished; }

private:
    enum class State : uint8_t { Active, Finished, Failed };
    void Fail() noexcept;

    common::MultiBuffer pending_;
    std::optional<common::TargetAddress> target_;
    size_t payload_size_ = 0;
    State state_ = State::Active;
};

net::awaitable<common::MultiBuffer> ReadUdpDatagram(
    transport::AsyncStream& stream,
    TrojanUdpFramer& framer);

net::awaitable<void> WriteTrojanUdpDatagram(
    transport::MultiBufferWriter& writer,
    common::MultiBuffer payload);

net::awaitable<void> WriteTrojanUdpDatagram(
    transport::MultiBufferWriter& writer,
    const common::TargetAddress& target,
    std::span<const net::const_buffer> payload);

class TrojanUdpStreamEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    explicit TrojanUdpStreamEndpoint(
        transport::AsyncStream& stream,
        common::TargetAddress fallback_target = {},
        transport::EofAction read_eof_action = transport::EofAction::ShutdownPeerWrite) noexcept
        : OutboundStreamEndpointBase(stream)
        , fallback_target_(std::move(fallback_target))
        , read_eof_action_(read_eof_action) {}

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        return ReadUdpDatagram(stream_, framer_);
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        return WriteTrojanUdpDatagram(stream_, std::move(mb));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        return WriteTrojanUdpDatagram(stream_, fallback_target_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return stream_.AsyncShutdownWrite();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return read_eof_action_;
    }

private:
    common::TargetAddress fallback_target_{};
    TrojanUdpFramer framer_;
    transport::EofAction read_eof_action_;
};

}  // namespace proxy
