#pragma once

#include "core/constants.hpp"
#include "common/defaults.hpp"
#include "infra/json.hpp"
#include "infra/panel_node_ids.hpp"
#include "transport/internet/outbound_bind.hpp"
#include "transport/internet/inbound_listen.hpp"
#include "transport/internet/proxy_protocol_mode.hpp"
#include "proxy/freedom_domain_strategy.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>


struct TlsPemMaterial;

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

