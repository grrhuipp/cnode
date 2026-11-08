#pragma once

#include "common.hpp"
#include "common/allocator.hpp"
#include "common/address_codec.hpp"
#include "common/target_address.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace vless {

inline constexpr uint8_t kVersion = 0x00;

// Version, UUID, addons length, 255 addon bytes, command and the largest
// port-first address (port, type, length, 253-byte domain).
inline constexpr size_t kMaxRequestHeaderSize = 1 + 16 + 1 + 255 + 1 + kMaxEncodedAddressSize;

// The server never sends response addons.
inline constexpr std::array<uint8_t, 2> kResponseHeader{kVersion, 0};

enum class Command : uint8_t {
    TCP = 0x01,
    UDP = 0x02,
    MUX = 0x03,
};

struct RequestHeader {
    std::array<uint8_t, 16> uuid{};
    uint8_t addons_len = 0;
    memory::ThreadLocalString flow;
    Command command = Command::TCP;
    TargetAddress target;
    std::optional<ForwardedMetadata> forwarded;
};

enum class RequestHeaderDecodeStatus : uint8_t {
    Complete,
    Incomplete,
    InvalidVersion,
    InvalidCommand,
    InvalidAddress,
    InvalidAddons,
};

struct RequestHeaderDecodeResult {
    RequestHeaderDecodeStatus status = RequestHeaderDecodeStatus::Incomplete;
    RequestHeader header;
    // Complete only: bytes belonging to the header.
    size_t consumed = 0;
    // Incomplete only: minimum total prefix length needed for the next stage.
    size_t required = 0;
};

// Re-submit the same growing prefix until it is complete or invalid; every
// Incomplete result names the next structural boundary, never a guess.
[[nodiscard]] RequestHeaderDecodeResult DecodeRequestHeader(
    std::span<const uint8_t> data);

[[nodiscard]] size_t EncodeRequestHeaderTo(
    const std::array<uint8_t, 16>& uuid,
    Command command,
    const TargetAddress& target,
    uint8_t* output,
    size_t output_size,
    std::string_view flow = {},
    ForwardedMetadataView forwarded = {});

}  // namespace vless
