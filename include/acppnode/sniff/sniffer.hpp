#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/target_address.hpp"
#include <span>
#include <optional>

namespace acpp {

// ============================================================================
// 嗅探结果
// ============================================================================
struct SniffResult {
    bool success = false;           // 是否嗅探成功
    std::string protocol;           // 协议类型："tls", "http", "quic"
    std::string domain;             // 嗅探到的域名
    uint16_t port = 0;              // 嗅探到的端口（HTTP 可能有）

    // 转换为 TargetAddress
    [[nodiscard]] TargetAddress ToTarget() const {
        TargetAddress addr;
        addr.type = AddressType::Domain;
        addr.host = domain;
        addr.port = port;
        return addr;
    }

    [[nodiscard]] std::string ToString() const {
        if (!success) return "none";
        if (port > 0) {
            return protocol + ":" + domain + ":" + std::to_string(port);
        }
        return protocol + ":" + domain;
    }
};

// ============================================================================
// TLS 嗅探（从 ClientHello SNI 扩展中提取域名）
// ============================================================================
class TlsSniffer {
public:
    SniffResult Sniff(std::span<const uint8_t> data);

private:
    std::optional<std::string> ParseClientHello(std::span<const uint8_t> data);
    std::optional<std::string> ExtractSNI(std::span<const uint8_t> extensions);
};

// ============================================================================
// HTTP 嗅探（从 Host 头提取域名）
// ============================================================================
class HttpSniffer {
public:
    SniffResult Sniff(std::span<const uint8_t> data);

private:
    std::optional<std::pair<std::string, uint16_t>> ParseHttpHost(
        std::span<const uint8_t> data);
};

// ============================================================================
// 复合嗅探：依次尝试 TLS → HTTP，零堆分配
// ============================================================================
[[nodiscard]] SniffResult Sniff(std::span<const uint8_t> data);

}  // namespace acpp
