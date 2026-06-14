#pragma once

#include "acppnode/core/constants.hpp"
#include "acppnode/infra/json.hpp"
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
    std::string SendIP = std::string(constants::binding::kAuto);
    bool EnableDNS = true;
    std::string DNSType;
    ProxyProtocolMode ProxyProtocol = ProxyProtocolMode::Auto; // off / auto / on

    // TLS 配置
    // false: 强制关闭 TLS（由外部 nginx/caddy 处理）
    // true:  程序处理 TLS，并以本地配置决定是否加载证书/自签
    bool TLSEnable = false;
    std::string TLSCert;                    // 证书文件路径（空则自签名）
    std::string TLSKey;                     // 私钥文件路径（空则自签名）

    static PanelConfig FromJson(const json::object& j);
    [[nodiscard]] bool Validate() const;
};

}  // namespace acpp
