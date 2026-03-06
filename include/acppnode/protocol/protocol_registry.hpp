#pragma once

#include "acppnode/common.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/protocol/outbound.hpp"
#include "acppnode/dns/dns_service.hpp"

#include <chrono>
#include <map>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace acpp {

// Forward declarations
class UDPSessionManager;

// ============================================================================
// OutboundFactory - 出站协议自注册中心（Xray proxy.RegisterOutboundHandlerCreator 设计）
//
// 使用方式：在每个出站协议的 .cpp 文件末尾添加静态注册块：
//
//   namespace {
//   const bool kRegistered = (acpp::OutboundFactory::Instance().Register(
//       "vmess",
//       [](const acpp::OutboundConfig& cfg, acpp::net::any_io_executor exec,
//          acpp::IDnsService* dns, acpp::UDPSessionManager* udp,
//          std::chrono::seconds timeout) -> std::unique_ptr<acpp::IOutbound> {
//           // 解析 cfg.settings，创建并返回出站实例
//           // 返回 nullptr 表示配置无效
//       }), true);
//   }  // namespace
//
// 优点：
//   - 新增协议不需要修改 worker.cpp（开闭原则）
//   - 协议 JSON 解析逻辑内聚在协议文件中
//   - 动态扩展，可按需链接协议实现
// ============================================================================
class OutboundFactory {
public:
    // 出站创建函数：接收统一参数，返回出站实例（nullptr = 配置无效）
    using Creator = std::function<std::unique_ptr<IOutbound>(
        const OutboundConfig& config,       // tag + settings(JSON) + stream_settings
        net::any_io_executor executor,      // Worker 的 executor
        IDnsService* dns,                   // DNS 服务（可为 nullptr）
        UDPSessionManager* udp_mgr,         // UDP 会话管理器（可为 nullptr）
        std::chrono::seconds dial_timeout   // 拨号超时
    )>;

    // 全局单例（Meyers singleton，线程安全）
    [[nodiscard]] static OutboundFactory& Instance() noexcept;

    // 注册协议（重复注册会覆盖）
    // 仅在 static init 期间调用，不需要运行时线程安全保证
    void Register(std::string_view protocol, Creator creator);

    // 根据 config.protocol 创建出站实例
    // 返回 nullptr 如果协议未注册或配置无效
    [[nodiscard]] std::unique_ptr<IOutbound> Create(
        const OutboundConfig& config,
        net::any_io_executor executor,
        IDnsService* dns,
        UDPSessionManager* udp_mgr,
        std::chrono::seconds dial_timeout) const;

    // 检查协议是否已注册
    [[nodiscard]] bool Has(std::string_view protocol) const;

    // 获取所有已注册的协议名称（调试用）
    [[nodiscard]] std::vector<std::string> RegisteredProtocols() const;

private:
    // std::less<> 启用透明比较，允许 string_view 直接 lookup 无需构造 string
    std::map<std::string, Creator, std::less<>> creators_;
};

}  // namespace acpp
