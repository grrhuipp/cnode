#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/proxy/anytls/user_info.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace acpp {
class AsyncStream;
}

namespace acpp::anytls {

inline constexpr uint8_t kCmdWaste = 0;
inline constexpr uint8_t kCmdSYN = 1;
inline constexpr uint8_t kCmdPSH = 2;
inline constexpr uint8_t kCmdFIN = 3;
inline constexpr uint8_t kCmdSettings = 4;
inline constexpr uint8_t kCmdAlert = 5;
inline constexpr uint8_t kCmdUpdatePaddingScheme = 6;
inline constexpr uint8_t kCmdSYNACK = 7;
inline constexpr uint8_t kCmdHeartRequest = 8;
inline constexpr uint8_t kCmdHeartResponse = 9;
inline constexpr uint8_t kCmdServerSettings = 10;

inline constexpr size_t kFrameHeaderSize = 7;
inline constexpr size_t kMaxFramePayload = 0xffff;
inline constexpr uint16_t kDefaultAuthPaddingSize = 30;
inline constexpr std::string_view kUotMagicAddress = "sp.v2.udp-over-tcp.arpa";

struct FrameHeader {
    uint8_t cmd = 0;
    uint32_t sid = 0;
    uint16_t length = 0;
};

struct PaddingScheme {
    std::string raw;
    std::string md5;
    uint32_t stop = 0;
    std::unordered_map<std::string, std::string> records;
};

[[nodiscard]] PaddingScheme DefaultPaddingScheme();
[[nodiscard]] std::optional<PaddingScheme> ParsePaddingScheme(std::string_view raw);
[[nodiscard]] uint16_t AuthPaddingSize(const PaddingScheme& scheme) noexcept;
[[nodiscard]] std::string DefaultClientSettings();
[[nodiscard]] std::expected<std::string, ErrorCode> EncodeSocksAddress(const TargetAddress& target);
[[nodiscard]] bool IsUotMagicAddress(const TargetAddress& target) noexcept;

struct UotRequest {
    bool is_connect = false;
    TargetAddress destination;
    size_t consumed = 0;
};

[[nodiscard]] std::expected<std::string, ErrorCode> EncodeUotRequest(
    const TargetAddress& target,
    bool is_connect);
[[nodiscard]] std::expected<UotRequest, ErrorCode> DecodeUotRequest(std::span<const uint8_t> data);
[[nodiscard]] std::expected<std::string, ErrorCode> BuildFrameBytes(
    uint8_t cmd,
    uint32_t sid,
    std::span<const uint8_t> payload);

net::awaitable<std::expected<void, ErrorCode>>
WriteAll(AsyncStream& stream, std::span<const uint8_t> data);

net::awaitable<std::expected<void, ErrorCode>>
WriteFrame(AsyncStream& stream, uint8_t cmd, uint32_t sid, std::span<const uint8_t> payload);

net::awaitable<std::expected<void, ErrorCode>>
WriteFrameBody(AsyncStream& stream, uint8_t cmd, uint32_t sid, buf::Buffer& body);

net::awaitable<std::expected<void, ErrorCode>>
WritePacketWithPadding(AsyncStream& stream,
                       const PaddingScheme& scheme,
                       uint32_t packet_index,
                       std::string packet);

net::awaitable<std::expected<void, ErrorCode>>
WriteMultiBufferAsFrames(AsyncStream& stream, uint8_t cmd, uint32_t sid, buf::MultiBuffer mb);

net::awaitable<std::expected<void, ErrorCode>>
WriteMultiBufferAsFramesWithPadding(AsyncStream& stream,
                                    const PaddingScheme& scheme,
                                    uint32_t packet_index,
                                    uint8_t cmd,
                                    uint32_t sid,
                                    buf::MultiBuffer mb);

net::awaitable<std::expected<FrameHeader, ErrorCode>>
ReadFrameHeader(AsyncStream& stream);

net::awaitable<std::expected<std::string, ErrorCode>>
ReadFrameText(AsyncStream& stream, uint16_t length);

net::awaitable<std::expected<void, ErrorCode>>
DiscardFramePayload(AsyncStream& stream, uint16_t length);

net::awaitable<std::expected<buf::MultiBuffer, ErrorCode>>
ReadFramePayload(AsyncStream& stream, uint16_t length);

}  // namespace acpp::anytls
