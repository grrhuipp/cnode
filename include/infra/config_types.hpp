#pragma once

#include "common/asio_types.hpp"
#include "common/defaults.hpp"
#include "core/constants.hpp"
#include "features/routing/dispatch_policy.hpp"
#include "infra/json.hpp"
#include "infra/runtime_config_types.hpp"
#include "proxy/sniff_config.hpp"
#include "transport/internet/stream_settings.hpp"
#include "transport/internet/inbound_listen.hpp"
#include "transport/internet/proxy_protocol_mode.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>


// ============================================================================
// 日志配置
// ============================================================================
struct LogConfig {
    std::string level = std::string(constants::logging::kDefaultLevel);  // none/trace/debug/info/warning(warn)/error
    std::filesystem::path log_dir = std::filesystem::path(constants::paths::kDefaultLogDir);
    std::filesystem::path access_path;
    std::filesystem::path error_path;
    uint16_t max_days = defaults::kLogRetentionDays;  // 日志保留天数（按天切割）
    bool rotate_daily = true;                         // 按本地日期切割日志
    bool gzip = true;                                 // 历史日志 gzip 压缩

    static LogConfig FromJson(const json::object& j);
};

// ============================================================================
// DNS 配置
// ============================================================================
struct DnsConfig {
    std::vector<udp::endpoint> servers{
        {net::ip::address_v4({8, 8, 8, 8}), 53},
        {net::ip::address_v4({1, 1, 1, 1}), 53},
    };
    uint32_t timeout = defaults::kDnsTimeout;
    uint32_t cache_size = defaults::kDnsCacheSize;
    uint32_t min_ttl = defaults::kDnsMinTTL;
    uint32_t max_ttl = defaults::kDnsMaxTTL;

    static DnsConfig FromJson(const json::object& j);
};

// ============================================================================
// 入站配置
// ============================================================================

// How a Shadowsocks 2022 user credential becomes its user key. Static sources
// carry base64 PSKs; panels carry user UUIDs from which SS2022 keys derive.
enum class Ss2022UserKey : uint8_t {
    Base64Psk,
    UuidDerived,
};

// Protocol-specific inbound source fields. Every source maps its own field
// names into this one shape; protocols parse it once on the cold path.
struct InboundProtocolSettings {
    std::string method = std::string(constants::protocol::kAes256Gcm);
    // SS2022 server identity PSK (EIH). Empty disables the identity header.
    std::string identity_password;
    Ss2022UserKey ss2022_user_key = Ss2022UserKey::Base64Psk;
    std::string padding_scheme;
    std::string vless_decryption = std::string(constants::protocol::kNone);
    uint32_t hysteria_up_mbps = 0;
    uint32_t hysteria_down_mbps = 0;
};

// One authenticated user. `credential` is already the protocol credential
// (UUID, password or PSK); sources resolve their own field aliases.
struct InboundUserSpec {
    int64_t user_id = 0;
    std::string email;
    std::string credential;
    std::string flow;
    uint64_t speed_limit = 0;
    uint32_t device_limit = 0;
};

// The source-neutral inbound aggregate. Panel and static sources both map to
// it; the shared builder prepares runtime state only from this value.
struct InboundSpec {
    std::string tag;
    std::vector<std::string> all_tags;
    // Opaque reporting identity; empty disables per-user reporting.
    std::string accounting_key;
    std::string protocol;
    InboundListen listen;
    uint16_t port = 0;
    ProxyProtocolMode proxy_protocol = ProxyProtocolMode::Auto;
    InboundProtocolSettings settings;
    std::vector<InboundUserSpec> users;
    // Normalized and validated by the source's shared field parsers.
    StreamSettings stream_settings;
    SniffConfig sniffing;
    routing::OutboundSelectionPolicy outbound_policy{
        routing::ForceOutbound(std::string(constants::protocol::kDirect))};
};

// Static inbound source as written in inbounds.json. Only tag fallback and
// outbound selection remain static-specific; the rest maps 1:1 to InboundSpec.
struct StaticInboundConfig {
    std::vector<std::string> tags;
    std::string protocol;
    InboundListen listen;
    uint16_t port = 0;
    InboundProtocolSettings settings;
    std::vector<InboundUserSpec> users;
    StreamSettings stream_settings;
    SniffConfig sniffing;
    ProxyProtocolMode proxy_protocol = ProxyProtocolMode::Auto;
    bool routing_enabled = false;
    std::optional<std::string> outbound_tag;
    static StaticInboundConfig FromJson(const json::object& j);
};

