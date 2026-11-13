#pragma once

#include "common/defaults.hpp"
#include "common/constants.hpp"
#include "infra/config_types.hpp"
#include "infra/json.hpp"
#include "transport/inbound_listen.hpp"
#include "transport/proxy_protocol.hpp"
#include "transport/stream_settings.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tl/expected.hpp>
#include <utility>
#include <vector>

namespace transport {

struct TlsPemMaterial;

}  // namespace transport

namespace infra {
[[nodiscard]] transport::WsConfig ParseWsConfig(const object& source);
[[nodiscard]] transport::HttpUpgradeConfig ParseHttpUpgradeConfig(const object& source);
[[nodiscard]] transport::HttpConfig ParseHttpConfig(const object& source);
[[nodiscard]] transport::GrpcConfig ParseGrpcConfig(const object& source);
[[nodiscard]] transport::XHttpConfig ParseXHttpConfig(const object& source);
[[nodiscard]] transport::RealityConfig ParseRealityConfig(const object& source);
[[nodiscard]] transport::StreamSettings ParseStreamSettings(const object& source, transport::StreamEndpointRole role);
[[nodiscard]] OutboundSettings ParseOutboundSettings(
    std::string_view protocol, const object& settings);

class PanelNodeIds {
public:
    PanelNodeIds() = default;

    [[nodiscard]] bool Empty() const noexcept { return values_.empty(); }
    [[nodiscard]] int Front() const noexcept { return values_.front(); }
    [[nodiscard]] std::span<const int> Values() const noexcept { return values_; }

    [[nodiscard]] static PanelNodeIds Parse(const infra::value& value);
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
    std::string Type = std::string(common::kV2BoardType);  // 面板类型
    std::string APIHost;                      // API 地址
    std::string Key;                          // API 密钥
    std::chrono::seconds RequestTimeout{common::kPanelRequestTimeout};
    PanelNodeIds NodeIDs;
    std::string NodeType = std::string(common::kDefaultNodeType);
    // Local durable accounting state; resolved relative to the loaded config directory.
    std::filesystem::path TrafficJournalDir = "traffic-journal";
    transport::InboundListen ListenIP;
    transport::OutboundBind SendIP = transport::OutboundBind::Auto();
    bool EnableDNS = true;
    proxy::DomainStrategy DNSType =
        proxy::DomainStrategy::UseIP;
    transport::ProxyProtocolMode ProxyProtocol = transport::ProxyProtocolMode::Auto; // off / auto / on

    // TLS 能力配置。
    // true 表示本实例可以为面板中 tls=true 的节点终止 TLS；并不强制所有节点启用 TLS。
    // 实际启用条件为 TLSEnable && 节点 tls=true。
    bool TLSEnable = false;
    std::string TLSCert;                    // 证书文件路径（空则自签名）
    std::string TLSKey;                     // 私钥文件路径（空则自签名）
    std::shared_ptr<const transport::TlsPemMaterial> TLSPem;
    static PanelConfig FromJson(const object& j);
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
    std::vector<OutboundSourceConfig> outbounds;
    uint32_t workers = 0;  // 加载时将 0 归一化为可用 CPU 核心数。
    std::filesystem::path config_dir;
};

// 文件与目录共用解析入口；侧车固定从主配置所在目录读取。
[[nodiscard]] std::optional<Config> LoadConfig(const std::filesystem::path& path);
[[nodiscard]] std::optional<Config> ParseConfig(const object& source);
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
    std::span<const OutboundSourceConfig> outbounds,
    std::span<const RouteRuleConfig> rules,
    std::span<const StaticInboundConfig> inbounds);

[[nodiscard]] StaticInboundSemanticValidation ValidateStaticInboundSemantics(
    std::span<const StaticInboundConfig> inbounds);


// Cold-path configuration normalization. A string preserves the existing
// binding semantics; an ordered array chooses only assigned local addresses.
[[nodiscard]] transport::OutboundBind ParseOutboundBindConfig(
    const infra::value& value, const infra::value* strategy = nullptr);
[[nodiscard]] std::optional<transport::OutboundBind> ParseOptionalOutboundBind(
    const object& source, std::string_view context);


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
    const RealityServerInput& input, transport::RealityConfig& out);

// Requirements of a REALITY config terminating client connections.
[[nodiscard]] tl::expected<void, std::string> ValidateInboundReality(
    const transport::RealityConfig& config);

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
    const infra::value& value, std::string_view field);

// ---------------------------------------------------------------------------
// Proxy Protocol & HTTP/2 initial window
// ---------------------------------------------------------------------------

[[nodiscard]] transport::InboundListen ParseInboundListen(
    const object& object,
    std::string_view key,
    std::string_view field_label,
    transport::InboundListen fallback = transport::InboundListen{});

// Header presence policy is independent of v1/v2 format detection.
[[nodiscard]] transport::ProxyProtocolMode ParseProxyProtocolMode(
    const object& object, std::string_view key,
    transport::ProxyProtocolMode fallback = transport::ProxyProtocolMode::Auto);

inline constexpr uint32_t kHttp2MaxInitialWindow = 0x7fffffffU;
[[nodiscard]] tl::expected<std::optional<uint32_t>, std::string>
ParseHttp2InitialWindow(const object& source);

}  // namespace infra

