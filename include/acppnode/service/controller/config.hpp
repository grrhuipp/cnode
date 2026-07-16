#pragma once

#include "acppnode/core/constants.hpp"
#include "acppnode/infra/json.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"
#include "acppnode/transport/internet/proxy_protocol_mode.hpp"

#include <string>
#include <vector>

namespace acpp {

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
    std::vector<int> NodeIDs;                 // 节点 ID 列表
    std::string NodeType = std::string(constants::panel::kDefaultNodeType);
    std::string ListenIP = std::string(constants::network::kDualStackAuto);
    OutboundBind SendIP = OutboundBind::Auto();
    bool EnableDNS = true;
    std::string DNSType;
    ProxyProtocolMode ProxyProtocol = ProxyProtocolMode::Auto; // off / auto / on

    // TLS 能力配置。
    // true 表示本实例可以为面板中 tls=true 的节点终止 TLS；并不强制所有节点启用 TLS。
    // 实际启用条件为 TLSEnable && 节点 tls=true。
    bool TLSEnable = false;
    std::string TLSCert;                    // 证书文件路径（空则自签名）
    std::string TLSKey;                     // 私钥文件路径（空则自签名）

    static PanelConfig FromJson(const json::object& j);
    [[nodiscard]] bool Validate() const;
};

}  // namespace acpp
