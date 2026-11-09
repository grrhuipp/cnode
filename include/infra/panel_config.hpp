#pragma once

#include "core/constants.hpp"
#include "common/defaults.hpp"
#include "infra/json.hpp"
#include <span>
#include "transport/internet/outbound_bind.hpp"
#include "transport/internet/inbound_listen.hpp"
#include "transport/internet/proxy_protocol.hpp"
#include "transport/internet/http_headers.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
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

