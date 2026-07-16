#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/common/defaults.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace acpp {

namespace app::dns {
class DNS;
}  // namespace app::dns

// ============================================================================
// Full Cone NAT 会话 (Per-Worker, 单线程访问，无需锁)
//
// 支持多个 TCP 连接共享一个 UDP socket:
// - 每个 TCP 连接注册一个 callback，用唯一的 callback_id
// - 发送时记录 callback_id -> 目标映射
// - 收到回包时，根据发送者查找对应的 callback
// ============================================================================
class UDPSession {
public:
    UDPSession(net::io_context& io_context,
               const std::string& session_id,
               ::acpp::app::dns::DNS& dns_service);
    ~UDPSession();

    UDPSession(const UDPSession&) = delete;
    UDPSession& operator=(const UDPSession&) = delete;
    UDPSession(UDPSession&&) = delete;
    UDPSession& operator=(UDPSession&&) = delete;

    // 启动会话（绑定本地端口）
    ErrorCode Start(const net::ip::address& bind_address);

    // UDP 发送/接收接口
    net::awaitable<ErrorCode> SendTo(
        const TargetAddress& target,
        const uint8_t* data,
        size_t len,
        uint64_t callback_id);

    net::awaitable<ErrorCode> SendTo(
        const TargetAddress& target,
        buf::MultiBuffer payload,
        uint64_t callback_id);

    net::awaitable<ErrorCode> SendTo(
        const TargetAddress& target,
        const uint8_t* data,
        size_t len);

    void Touch();

    // 注册 Full Cone 回调，返回 callback_id 用于后续取消；空回调返回 0。
    // 注意：Per-Worker 模式，无需 executor 参数，回调在同一线程执行
    uint64_t RegisterCallback(PacketCallback callback);

    // 取消注册
    void UnregisterCallback(uint64_t callback_id);

    // 开始接收循环
    void StartReceive();

    // 停止会话
    void Stop();

    // 检查是否过期
    bool IsExpired(std::chrono::seconds timeout) const;

    // 获取本地端口
    uint16_t LocalPort() const;

    // 获取会话 ID
    const std::string& SessionId() const;

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

// ============================================================================
// UDP 会话管理器 (Per-Worker, 单线程访问，无需锁)
// ============================================================================
class UDPSessionManager {
public:
    explicit UDPSessionManager(net::io_context& io_context,
                                ::acpp::app::dns::DNS& dns_service,
                                std::chrono::seconds session_timeout = std::chrono::seconds(defaults::kUdpSessionTimeout));
    ~UDPSessionManager();

    // 获取或创建会话
    UDPSession* GetOrCreateSession(
        const std::string& session_id,
        const net::ip::address& bind_address);

    // 获取现有会话
    UDPSession* GetSession(const std::string& session_id);

    // 移除会话
    void RemoveSession(const std::string& session_id);

    // 启动清理定时器
    void StartCleanup();

    // 停止所有会话
    void StopAll();

    // 获取活跃会话数量
    size_t ActiveSessionCount() const;

private:
    void CleanupExpiredSessions();

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp
