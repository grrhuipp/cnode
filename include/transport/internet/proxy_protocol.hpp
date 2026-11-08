#pragma once

#include "common/asio_types.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>

enum class ProxyProtocolParseStatus : uint8_t {
    NotProxy = 0,
    Incomplete,
    Success,
    Invalid,
};

// Upper bound for one PROXY v1/v2 header read from an accepted stream; it
// bounds the header itself, not payload read along with it.
inline constexpr std::size_t kProxyHeaderMaxBytes = 2048;

enum class ProxyProtocolReadStatus : uint8_t {
    Ok = 0,
    TimedOut,
    Truncated,
    TooLarge,
    Invalid,
};

// ============================================================================
// PROXY Protocol 解析结果
// ============================================================================
struct ProxyProtocolResult {
    ProxyProtocolParseStatus status = ProxyProtocolParseStatus::NotProxy;
    // Normalized source; absent for v1 UNKNOWN, v2 LOCAL and non-INET families.
    std::optional<net::ip::address> src_addr;
    uint16_t src_port = 0;
    size_t consumed = 0;  // 消耗的字节数

    [[nodiscard]] bool success() const noexcept {
        return status == ProxyProtocolParseStatus::Success;
    }

    [[nodiscard]] bool incomplete() const noexcept {
        return status == ProxyProtocolParseStatus::Incomplete;
    }
};

struct ProxyProtocolReadResult {
    ProxyProtocolReadStatus status = ProxyProtocolReadStatus::Ok;
    ProxyProtocolResult result;

    [[nodiscard]] bool ok() const noexcept {
        return status == ProxyProtocolReadStatus::Ok;
    }

    [[nodiscard]] bool timed_out() const noexcept {
        return status == ProxyProtocolReadStatus::TimedOut;
    }
};

// Auto-detects v1 (text) and v2 (binary). Bytes that cannot start a PROXY
// header yield NotProxy; a valid prefix of one yields Incomplete.
[[nodiscard]] ProxyProtocolResult ParseProxyProtocolHeader(std::span<const uint8_t> data);

// Encodes a v1 (version=1) or v2 (version=2) header; 0 for other versions.
[[nodiscard]] size_t EncodeProxyProtocolHeader(
    uint8_t version,
    const tcp::endpoint& src,
    const tcp::endpoint& dst,
    std::span<uint8_t, 108> out) noexcept;

