#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/stream_settings.hpp"
#include "acppnode/handlers/outbound_handler.hpp"

#include <expected>

namespace acpp {

// 前向声明
struct UDPPacket;

// ============================================================================
// UDP 拨号结果
// ============================================================================
struct UDPDialResult {
    ErrorCode error = ErrorCode::SUCCESS;
    
    // 发送函数：发送 UDP 包到目标
    // callback_id: 关联的回调 ID，用于记录发送目标，支持 Full Cone 回包路由
    unique_function<cobalt::task<ErrorCode>(const UDPPacket&, uint64_t callback_id)> send;
    
    // 设置全局回调函数（兼容旧接口）
    std::function<void(std::function<void(const UDPPacket&)>)> set_callback;
    
    // 注册回调：返回 callback_id，用于后续取消
    // destination 格式: "ip:port"（空字符串表示 Full Cone 模式）
    std::function<uint64_t(const std::string&, std::function<void(const UDPPacket&)>)> register_callback;
    
    // 取消回调
    std::function<void(uint64_t)> unregister_callback;
    
    // 会话 ID（用于管理）
    std::string session_id;
    
    [[nodiscard]] bool Ok() const noexcept { return error == ErrorCode::SUCCESS && static_cast<bool>(send); }
};

// ============================================================================
// OutboundTransportTarget - 出站传输目标（统一由 TransportDialer 执行拨号）
// ============================================================================
struct OutboundTransportTarget {
    std::string host;                               // 目标主机（可为域名或 IP）
    uint16_t port = 0;
    std::optional<net::ip::address> bind_local;    // 可选本地绑定地址
    std::string server_name;                        // TLS SNI / WS Host（可空）
    const StreamSettings* stream_settings = nullptr; // 传输层组合配置
    std::chrono::seconds timeout{defaults::kDialTimeout};
};

// ============================================================================
// IOutbound - 出站接口
// ============================================================================
class IOutbound {
public:
    virtual ~IOutbound() noexcept = default;

    // 解析并返回出站传输目标（连接由 TransportDialer 统一执行）
    virtual cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
        ResolveTransportTarget(SessionContext& ctx) = 0;
    
    // UDP 拨号（Full Cone）
    // executor: 当前连接所在的 executor，用于创建 UDP session
    // on_packet: 收到回包时的回调（可选，也可通过返回的 set_callback 设置）
    virtual cobalt::task<UDPDialResult> DialUDP(
        SessionContext& ctx,
        net::any_io_executor executor,
        std::function<void(const UDPPacket&)> on_packet) {
        co_return UDPDialResult{ErrorCode::NOT_SUPPORTED, nullptr, nullptr, nullptr, nullptr, ""};
    }

    // 获取出站标识
    [[nodiscard]] virtual std::string Tag() const = 0;

    // 获取出站协议处理器（三层架构：Dial 只负责传输层，协议层由此处理器完成）
    // 返回 nullptr 表示不需要协议握手（如透传出站）
    [[nodiscard]] virtual IOutboundHandler* GetOutboundHandler() { return nullptr; }

    // 获取 SendThrough 配置
    [[nodiscard]] virtual std::string SendThrough() const { return "auto"; }

    // 是否支持 UDP
    [[nodiscard]] virtual bool SupportsUDP() const { return false; }
};

// ============================================================================
// OutboundManager - 出站管理器（单实现，无需虚接口）
// ============================================================================
class OutboundManager final {
public:
    OutboundManager() = default;

    [[nodiscard]] IOutbound* GetOutbound(const std::string& tag) {
        auto it = outbounds_.find(tag);
        return (it != outbounds_.end()) ? it->second.get() : nullptr;
    }

    [[nodiscard]] std::vector<std::string> GetAllTags() const {
        std::vector<std::string> tags;
        tags.reserve(outbounds_.size());
        for (const auto& [tag, _] : outbounds_) {
            tags.push_back(tag);
        }
        return tags;
    }

    void RegisterOutbound(std::unique_ptr<IOutbound> outbound) {
        if (outbound) {
            outbounds_[outbound->Tag()] = std::move(outbound);
        }
    }

private:
    std::unordered_map<std::string, std::unique_ptr<IOutbound>> outbounds_;
};

}  // namespace acpp
