#pragma once

#include "common/defaults.hpp"
#include "core/constants.hpp"
#include "infra/config_types.hpp"
#include "infra/json.hpp"
#include "infra/runtime_config_types.hpp"
#include "transport/internet/http_headers.hpp"
#include "transport/internet/inbound_listen.hpp"
#include "transport/internet/outbound_bind.hpp"
#include "transport/internet/proxy_protocol.hpp"
#include "transport/internet/stream_settings.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tl/expected.hpp>
#include <utility>
#include <vector>

struct TlsPemMaterial;

namespace proxy::freedom::outbound {

enum class DomainStrategy : uint8_t {
    AsIs,
    UseIP,
    UseIPv6v4,
    UseIPv4,
    UseIPv4v6,
    UseIPv6,
    ForceIP,
    ForceIPv6v4,
    ForceIPv6,
    ForceIPv4v6,
    ForceIPv4,
};

[[nodiscard]] inline std::optional<DomainStrategy> ParseDomainStrategy(std::string_view value) {
    using transport::internet::EqualsAsciiCI;
    if (EqualsAsciiCI(value, "asis")) return DomainStrategy::AsIs;
    if (EqualsAsciiCI(value, "useip")) return DomainStrategy::UseIP;
    if (EqualsAsciiCI(value, "useipv6v4")) return DomainStrategy::UseIPv6v4;
    if (EqualsAsciiCI(value, "useipv4")) return DomainStrategy::UseIPv4;
    if (EqualsAsciiCI(value, "useipv4v6")) return DomainStrategy::UseIPv4v6;
    if (EqualsAsciiCI(value, "useipv6")) return DomainStrategy::UseIPv6;
    if (EqualsAsciiCI(value, "forceip")) return DomainStrategy::ForceIP;
    if (EqualsAsciiCI(value, "forceipv6v4")) return DomainStrategy::ForceIPv6v4;
    if (EqualsAsciiCI(value, "forceipv6")) return DomainStrategy::ForceIPv6;
    if (EqualsAsciiCI(value, "forceipv4v6")) return DomainStrategy::ForceIPv4v6;
    if (EqualsAsciiCI(value, "forceipv4")) return DomainStrategy::ForceIPv4;
    return std::nullopt;
}

}  // namespace proxy::freedom::outbound

class PanelNodeIds {
public:
    PanelNodeIds() = default;

    [[nodiscard]] bool Empty() const noexcept { return values_.empty(); }
    [[nodiscard]] int Front() const noexcept { return values_.front(); }
    [[nodiscard]] std::span<const int> Values() const noexcept { return values_; }

    [[nodiscard]] static PanelNodeIds Parse(const json::value& value);
    [[nodiscard]] static PanelNodeIds Single(int node_id);

private:
    std::vector<int> values_;
};

struct PanelApiUrlParts {
    std::string host;
    uint16_t port = 0;
    std::string path_prefix;
    bool use_ssl = false;
};

[[nodiscard]] bool IsValidPanelName(std::string_view name) noexcept;
[[nodiscard]] bool IsValidPanelKey(std::string_view key) noexcept;
[[nodiscard]] std::optional<PanelApiUrlParts> ParsePanelApiUrl(std::string_view url);

// ============================================================================
// 面板配置
//
// 对齐 XrayR service/controller/config.go：
//   - 只承载面板/控制面冷路径配置语义
//   - 不属于 core/config 的通用节点运行配置
// ============================================================================
struct PanelConfig {
    std::string Name;                        // 面板名称
    std::string Type = std::string(constants::panel::kV2BoardType);  // 面板类型
    std::string APIHost;                      // API 地址
    std::string Key;                          // API 密钥
    std::chrono::seconds RequestTimeout{defaults::kPanelRequestTimeout};
    PanelNodeIds NodeIDs;
    std::string NodeType = std::string(constants::panel::kDefaultNodeType);
    // Local durable accounting state; resolved relative to the loaded config directory.
    std::filesystem::path TrafficJournalDir = "traffic-journal";
    InboundListen ListenIP;
    OutboundBind SendIP = OutboundBind::Auto();
    bool EnableDNS = true;
    proxy::freedom::outbound::DomainStrategy DNSType =
        proxy::freedom::outbound::DomainStrategy::UseIP;
    ProxyProtocolMode ProxyProtocol = ProxyProtocolMode::Auto; // off / auto / on

    // TLS 能力配置。
    // true 表示本实例可以为面板中 tls=true 的节点终止 TLS；并不强制所有节点启用 TLS。
    // 实际启用条件为 TLSEnable && 节点 tls=true。
    bool TLSEnable = false;
    std::string TLSCert;                    // 证书文件路径（空则自签名）
    std::string TLSKey;                     // 私钥文件路径（空则自签名）
    std::shared_ptr<const TlsPemMaterial> TLSPem;
    static PanelConfig FromJson(const json::object& j);
    [[nodiscard]] bool Validate() const;
};
struct Config {
    LogConfig log;
    DnsConfig dns;
    LimitsConfig limits;
    TimeoutsConfig timeouts;
    RoutingConfig routing;
    std::vector<PanelConfig> panels;
    std::vector<StaticInboundConfig> static_inbounds;
    std::vector<infra::OutboundSourceConfig> outbounds;
    uint32_t workers = 0;  // 加载时将 0 归一化为可用 CPU 核心数。
    std::filesystem::path config_dir;
};

// 文件与目录共用解析入口；侧车固定从主配置所在目录读取。
[[nodiscard]] std::optional<Config> LoadConfig(const std::filesystem::path& path);
[[nodiscard]] std::optional<Config> ParseConfig(const json::object& source);
[[nodiscard]] bool ValidateConfig(const Config& config);
[[nodiscard]] std::vector<std::string> GetUsedGeoIPTags(const RoutingConfig& routing);
[[nodiscard]] std::vector<std::string> GetUsedGeoSiteTags(const RoutingConfig& routing);

enum class ConfigSemanticError {
    None,
    NoOutbounds,
    EmptyOutboundTag,
    ReservedOutboundTag,
    DuplicateOutboundTag,
    EmptyRouteOutboundTag,
    UnknownRouteOutboundTag,
    EmptyStaticInboundOutboundTag,
    UnknownStaticInboundOutboundTag,
};

struct ConfigSemanticValidation {
    ConfigSemanticError error = ConfigSemanticError::None;
    size_t index = 0;
    std::string_view tag;

    [[nodiscard]] bool Ok() const noexcept {
        return error == ConfigSemanticError::None;
    }
};

enum class StaticInboundSemanticError {
    None,
    InvalidPort,
    EmptyTag,
    ReservedTag,
    DuplicateTag,
    DuplicateEndpoint,
};

struct StaticInboundSemanticValidation {
    StaticInboundSemanticError error = StaticInboundSemanticError::None;
    size_t index = 0;
    size_t conflicting_index = 0;
    std::string detail;

    [[nodiscard]] bool Ok() const noexcept {
        return error == StaticInboundSemanticError::None;
    }

    [[nodiscard]] std::string Message() const;
};

[[nodiscard]] ConfigSemanticValidation ValidateOutboundSelectionSemantics(
    std::span<const infra::OutboundSourceConfig> outbounds,
    std::span<const RouteRuleConfig> rules,
    std::span<const StaticInboundConfig> inbounds);

[[nodiscard]] StaticInboundSemanticValidation ValidateStaticInboundSemantics(
    std::span<const StaticInboundConfig> inbounds);


namespace infra {

// Cold-path configuration normalization. A string preserves the existing
// binding semantics; an ordered array chooses only assigned local addresses.
[[nodiscard]] inline OutboundBind ParseOutboundBindConfig(
    const json::value& value, const json::value* strategy = nullptr) {
    if (value.is_string()) {
        if (strategy) {
            throw std::invalid_argument(
                "sendThroughStrategy requires an array sendThrough");
        }
        auto result = OutboundBind::Parse(value.as_string());
        if (!result) {
            throw std::invalid_argument(
                "sendThrough must be auto, wildcard, an IP address, or an array of IPs/CIDRs");
        }
        return std::move(*result);
    }
    if (!value.is_array()) {
        throw std::invalid_argument("sendThrough must be a string or an array of IPs/CIDRs");
    }

    auto policy = OutboundBind::ChoicePolicy::Random;
    if (strategy) {
        if (!strategy->is_string()) {
            throw std::invalid_argument(
                "sendThroughStrategy must be random, ip_hash, or user_hash");
        }
        if (transport::internet::EqualsAsciiCI(strategy->as_string(), "random")) {
            policy = OutboundBind::ChoicePolicy::Random;
        } else if (transport::internet::EqualsAsciiCI(strategy->as_string(), "ip_hash")) {
            policy = OutboundBind::ChoicePolicy::IpHash;
        } else if (transport::internet::EqualsAsciiCI(strategy->as_string(), "user_hash")) {
            policy = OutboundBind::ChoicePolicy::UserHash;
        } else {
            throw std::invalid_argument(
                "sendThroughStrategy must be random, ip_hash, or user_hash");
        }
    }
    std::vector<std::string_view> entries;
    entries.reserve(value.as_array().size());
    for (const auto& entry : value.as_array()) {
        if (!entry.is_string()) {
            throw std::invalid_argument("sendThrough array must contain only IP/CIDR strings");
        }
        entries.push_back(entry.as_string());
    }
    auto result = OutboundBind::ParseCandidates(entries, policy);
    if (!result) {
        throw std::invalid_argument("sendThrough array contains an invalid IP/CIDR or is empty");
    }
    return std::move(*result);
}

[[nodiscard]] inline std::optional<OutboundBind> ParseOptionalOutboundBind(
    const json::object& source, std::string_view context) {
    if (source.contains("send_through") ||
        source.contains("send_through_strategy")) {
        throw std::invalid_argument(
            std::string(context) +
            " binding must use sendThrough/sendThroughStrategy without underscores");
    }
    const auto* send_through = source.if_contains("sendThrough");
    const auto* strategy = source.if_contains("sendThroughStrategy");
    if (strategy && !send_through) {
        throw std::invalid_argument(
            std::string(context) + " sendThroughStrategy requires sendThrough");
    }
    if (!send_through) {
        return std::nullopt;
    }
    return ParseOutboundBindConfig(*send_through, strategy);
}


// ---------------------------------------------------------------------------
// REALITY (Xray-core infra/conf/transport_internet.go REALITYConfig semantics)
// ---------------------------------------------------------------------------

// A REALITY server name names a TLS ClientHello SNI: a DNS hostname, never an
// IP literal and never with a trailing dot.
[[nodiscard]] bool IsValidRealityServerName(std::string_view name) noexcept;

// Server-side REALITY fields after wire mapping. `std::nullopt` means the
// field was not declared; a declared empty value is invalid where Xray-core
// rejects it.
struct RealityServerInput {
    std::optional<std::string> private_key;
    // An empty entry permits a ClientHello without SNI.
    std::vector<std::string> server_names;
    // Each entry holds "" .. 16 hex characters.
    std::vector<std::string> short_ids;
    std::optional<std::string> dest;  // "host:port"
    uint64_t xver = 0;
    std::optional<std::string> mldsa65_seed;
    std::string min_client_ver;  // "" = unbounded
    std::string max_client_ver;  // "" = unbounded
    uint64_t max_time_diff = 0;
};

// Validates and writes the server-side fields into `out`; client-only fields
// of `out` are left untouched.
[[nodiscard]] tl::expected<void, std::string> ApplyRealityServerInput(
    const RealityServerInput& input, RealityConfig& out);

// Requirements of a REALITY config terminating client connections.
[[nodiscard]] tl::expected<void, std::string> ValidateInboundReality(
    const RealityConfig& config);

// ---------------------------------------------------------------------------
// TLS / transport request fields
// ---------------------------------------------------------------------------

// "" stays unset; otherwise an IP literal or DNS hostname, lowercased.
[[nodiscard]] tl::expected<std::string, std::string> NormalizeTlsServerName(
    std::string_view value, std::string_view field);

// "" selects the transport default "/"; otherwise an HTTP request target.
[[nodiscard]] tl::expected<std::string, std::string> NormalizeTransportPath(
    std::string_view value, std::string_view field);

// "" stays unset; otherwise an HTTP authority, lowercased.
[[nodiscard]] tl::expected<std::string, std::string> NormalizeHttpAuthority(
    std::string_view value, std::string_view field);

// gRPC serviceName: no whitespace, controls or '#', and the derived request
// path must be a valid HTTP request target.
[[nodiscard]] tl::expected<void, std::string> ValidateGrpcServiceName(
    std::string_view value, std::string_view field);

// ---------------------------------------------------------------------------
// Sniffing
// ---------------------------------------------------------------------------

// Xray destOverride names to the SniffConfig bitset; fakedns is rejected.
[[nodiscard]] tl::expected<uint8_t, std::string> ParseSniffDestOverride(
    std::span<const std::string> protocols);

// ---------------------------------------------------------------------------
// AnyTLS padding scheme
// ---------------------------------------------------------------------------

// A string or an array of strings joined with '\n'; null leaves the scheme
// unset (""). A non-empty scheme must parse and fit one UpdatePaddingScheme
// frame.
[[nodiscard]] tl::expected<std::string, std::string> ParseAnyTlsPaddingScheme(
    const json::value& value, std::string_view field);

// ---------------------------------------------------------------------------
// Proxy Protocol & HTTP/2 initial window
// ---------------------------------------------------------------------------

[[nodiscard]] InboundListen ParseInboundListen(
    const json::object& object,
    std::string_view key,
    std::string_view field_label,
    InboundListen fallback = InboundListen{});

// Header presence policy is independent of v1/v2 format detection.
[[nodiscard]] inline ProxyProtocolMode ParseProxyProtocolMode(
    const json::object& object, std::string_view key,
    ProxyProtocolMode fallback = ProxyProtocolMode::Auto) {
    const auto* value = object.if_contains(key);
    if (!value) return fallback;
    if (value->is_string()) {
        const auto mode = naming::LowerAscii(value->as_string());
        if (mode == "off") return ProxyProtocolMode::Off;
        if (mode == "auto") return ProxyProtocolMode::Auto;
        if (mode == "on") return ProxyProtocolMode::On;
    }
    throw std::invalid_argument(
        "proxyProtocol must be off, auto or on");
}

inline constexpr uint32_t kHttp2MaxInitialWindow = 0x7fffffffU;

[[nodiscard]] inline tl::expected<std::optional<uint32_t>, std::string>
ParseHttp2InitialWindow(const json::object& source) {
    if (source.contains("initial_windows_size") ||
        source.contains("initial_window_size")) {
        return tl::unexpected(std::string(
            "initial_windows_size/initial_window_size is not supported; use initialWindowSize"));
    }
    auto parsed = ParseJsonUint64(
        source,
        "initialWindowSize",
        kHttp2MaxInitialWindow);
    if (!parsed) {
        return tl::unexpected(std::move(parsed.error()));
    }
    if (!*parsed) {
        return std::optional<uint32_t>{};
    }
    return std::optional<uint32_t>{static_cast<uint32_t>(**parsed)};
}
}  // namespace infra

using infra::kHttp2MaxInitialWindow;
using infra::ParseHttp2InitialWindow;
using infra::ParseProxyProtocolMode;
using infra::ParseInboundListen;
