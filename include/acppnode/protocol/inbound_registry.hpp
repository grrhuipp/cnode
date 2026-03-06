#pragma once

#include "acppnode/common.hpp"
#include "acppnode/handlers/inbound_handler.hpp"
#include "acppnode/handlers/udp_inbound_handler.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/panel/v2board_panel.hpp"

#include <boost/json.hpp>

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

namespace vmess {
class VMessUserManager;
}
namespace trojan {
class TrojanUserManager;
}
namespace ss {
class SsUserManager;
class SsUdpInboundHandler;
}

// ============================================================================
// InboundProtocolDeps - 入站协议构建依赖（由 Worker 提供）
// ============================================================================
struct InboundProtocolDeps {
    vmess::VMessUserManager*  vmess_user_manager  = nullptr;
    trojan::TrojanUserManager* trojan_user_manager = nullptr;
    ss::SsUserManager*        ss_user_manager     = nullptr;
    StatsShard*               stats               = nullptr;
};

// ============================================================================
// InboundBuildRequest - 入站处理器构建请求
// ============================================================================
struct InboundBuildRequest {
    std::string tag;
    std::string protocol;
    std::string cipher_method;  // SS 使用；其他协议可忽略
    std::function<void(const std::string&)> auth_callback;
};

// ============================================================================
// InboundProtocolRegistration - 入站协议注册项
// ============================================================================
struct InboundProtocolRegistration {
    // 创建 TCP 入站处理器（必须）
    std::function<std::unique_ptr<IInboundHandler>(
        const InboundProtocolDeps& deps,
        ConnectionLimiterPtr limiter,
        const InboundBuildRequest& req)> create_tcp_handler;

    // 创建 UDP 入站处理器（可选）
    std::function<std::unique_ptr<ss::SsUdpInboundHandler>(
        const InboundProtocolDeps& deps,
        ConnectionLimiterPtr limiter,
        const InboundBuildRequest& req)> create_udp_handler;

    // 静态配置用户加载到 SharedStore（可选）
    std::function<bool(std::string_view tag, const boost::json::object& settings)> load_static_users;

    // 将 SharedStore 同步到当前 Worker（可选）
    std::function<void(const InboundProtocolDeps& deps, std::string_view tag)> sync_worker_users;

    // 面板用户更新到 SharedStore（可选）
    std::function<void(
        std::string_view tag,
        const NodeConfig& node_config,
        const std::vector<PanelUser>& panel_users)> update_panel_users;

    // 清空 SharedStore 用户（可选）
    std::function<void(std::string_view tag)> clear_users;
};

// ============================================================================
// InboundFactory - 入站协议注册中心
//
// 目标：
//   - main/panel_sync 不再写协议 if/else 进行处理器创建和用户同步
//   - 新增协议只需扩展注册项
// ============================================================================
class InboundFactory {
public:
    [[nodiscard]] static InboundFactory& Instance() noexcept;

    void Register(std::string_view protocol, InboundProtocolRegistration registration);

    [[nodiscard]] bool Has(std::string_view protocol) const;

    [[nodiscard]] std::vector<std::string> RegisteredProtocols() const;

    [[nodiscard]] std::shared_ptr<IInboundHandler> CreateTcpHandler(
        std::string_view protocol,
        const InboundProtocolDeps& deps,
        ConnectionLimiterPtr limiter,
        const InboundBuildRequest& req) const;

    [[nodiscard]] std::unique_ptr<ss::SsUdpInboundHandler> CreateUdpHandler(
        std::string_view protocol,
        const InboundProtocolDeps& deps,
        ConnectionLimiterPtr limiter,
        const InboundBuildRequest& req) const;

    // 返回 false 表示协议未注册或解析失败
    [[nodiscard]] bool LoadStaticUsers(
        std::string_view protocol,
        std::string_view tag,
        const boost::json::object& settings) const;

    void SyncWorkerUsers(
        std::string_view protocol,
        const InboundProtocolDeps& deps,
        std::string_view tag) const;

    void UpdatePanelUsers(
        std::string_view protocol,
        std::string_view tag,
        const NodeConfig& node_config,
        const std::vector<PanelUser>& panel_users) const;

    void ClearUsers(std::string_view protocol, std::string_view tag) const;

private:
    std::map<std::string, InboundProtocolRegistration, std::less<>> regs_;
};

}  // namespace acpp
