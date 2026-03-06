#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/dns/dns_service.hpp"

#include <array>
#include <vector>
#include <memory>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <functional>

namespace acpp {

using udp = boost::asio::ip::udp;

// Forward declaration
class IDnsService;

// ============================================================================
// Full Cone NAT 会话 (Per-Worker, 单线程访问，无需锁)
// 
// 支持多个 TCP 连接共享一个 UDP socket:
// - 每个 TCP 连接注册一个 callback，用唯一的 callback_id
// - 发送时记录 callback_id -> destination 映射
// - 收到回包时，根据发送者查找对应的 callback
// ============================================================================
class UDPSession : public std::enable_shared_from_this<UDPSession> {
public:
    using PacketCallback = std::function<void(const UDPPacket&)>;
    
    UDPSession(net::any_io_executor executor,
               const std::string& session_id,
               PacketCallback on_packet,
               IDnsService* dns_service = nullptr);
    ~UDPSession();
    
    // 启动会话（绑定本地端口）
    ErrorCode Start(const std::string& bind_address = "0.0.0.0");
    
    // 发送数据包到目标（关联 callback_id 用于回包路由）
    cobalt::task<ErrorCode> Send(const UDPPacket& packet, uint64_t callback_id = 0);
    
    // UDP 发送/接收接口
    cobalt::task<ErrorCode> SendTo(
        const TargetAddress& target,
        const uint8_t* data,
        size_t len);

    void SetReceiveCallback(UDPReceiveCallback callback);

    void Touch() { last_active_ = std::chrono::steady_clock::now(); }
    
    // 注册回调：
    // - destination 非空: 精确匹配，只接收来自该地址的回包
    // - destination 为空: Full Cone 模式，接收发送过的目标的回包
    // 返回 callback_id 用于后续取消
    // 注意：Per-Worker 模式，无需 executor 参数，回调在同一线程执行
    uint64_t RegisterCallback(const std::string& destination, 
                              PacketCallback callback);
    
    // 取消注册
    void UnregisterCallback(uint64_t callback_id);
    
    // 开始接收循环
    void StartReceive();
    
    // 停止会话
    void Stop();
    
    // 设置/更新全局回调 - 用于兼容
    void SetCallback(PacketCallback callback);
    
    // 检查是否过期
    bool IsExpired(std::chrono::seconds timeout) const {
        return std::chrono::steady_clock::now() - last_active_ > timeout;
    }
    
    // 获取本地端口
    uint16_t LocalPort() const { return local_port_; }
    
    // 获取会话 ID
    const std::string& SessionId() const { return session_id_; }
    
    // 统计
    uint64_t PacketsSent() const { return packets_sent_; }
    uint64_t PacketsReceived() const { return packets_received_; }
    uint64_t BytesSent() const { return bytes_sent_; }
    uint64_t BytesReceived() const { return bytes_received_; }

private:
    void DoReceive();
    void AddTargetMapping(const std::string& target_key, uint64_t callback_id);
    void RemoveTargetMappings(uint64_t callback_id);
    
    net::any_io_executor executor_;
    std::string session_id_;
    PacketCallback on_packet_;              // 全局回调（兼容）
    UDPReceiveCallback receive_callback_;   // UDP 接收回调
    IDnsService* dns_service_ = nullptr;    // DNS 服务（外部传入，不拥有）
    
    // ========================================================================
    // Full Cone 回调路由 (Per-Worker 单线程，无需锁)
    // 
    // 使用双向索引加速查找：
    // 1. callback_id -> CallbackEntry（包含 callback 和元数据）
    // 2. target_key -> set<callback_id>（反向索引，用于快速路由）
    // ========================================================================
    struct CallbackEntry {
        std::string destination;  // 空 = Full Cone, 非空 = 精确匹配
        PacketCallback callback;
        std::unordered_set<std::string> sent_targets;  // 发送过的目标地址
    };
    
    std::unordered_map<uint64_t, CallbackEntry> registered_callbacks_;
    
    // 反向索引: target_key -> set<callback_id>
    // 用于快速查找哪些 callback 关心这个目标地址
    std::unordered_map<std::string, std::unordered_set<uint64_t>> target_to_callbacks_;
    
    uint64_t next_callback_id_ = 1;
    
    udp::socket socket_;
    uint16_t local_port_ = 0;
    
    // ========================================================================
    // 接收缓冲区内存优化
    // 
    // 原设计：固定 64KB 缓冲区
    //   - 问题：大多数 UDP 包 < 1500B (MTU)
    //   - 内存浪费：64KB/会话
    //
    // 优化后：使用更小的默认缓冲区
    //   - 默认 8KB：满足大多数 DNS/游戏/VoIP 场景
    //   - 最大仍支持 64KB（按需）
    //   - 节省：~56KB/会话
    // ========================================================================
    static constexpr size_t DEFAULT_RECV_BUF_SIZE = 8 * 1024;   // 8KB 默认
    static constexpr size_t MAX_RECV_BUF_SIZE = 65536;          // 64KB 最大
    
    std::array<uint8_t, DEFAULT_RECV_BUF_SIZE> recv_buffer_;
    udp::endpoint sender_endpoint_;
    
    std::chrono::steady_clock::time_point last_active_;
    bool running_ = false;
    
    // 统计
    uint64_t packets_sent_ = 0;
    uint64_t packets_received_ = 0;
    uint64_t bytes_sent_ = 0;
    uint64_t bytes_received_ = 0;
};

// ============================================================================
// UDP 会话管理器 (Per-Worker, 单线程访问，无需锁)
// ============================================================================
class UDPSessionManager {
public:
    explicit UDPSessionManager(net::any_io_executor executor,
                                IDnsService* dns_service = nullptr,
                                std::chrono::seconds session_timeout = std::chrono::seconds(300));
    ~UDPSessionManager();
    
    // 获取或创建会话
    std::shared_ptr<UDPSession> GetOrCreateSession(
        const std::string& session_id,
        net::any_io_executor executor,
        UDPSession::PacketCallback on_packet,
        const std::string& bind_address = "0.0.0.0");
    
    // 获取现有会话
    std::shared_ptr<UDPSession> GetSession(const std::string& session_id);
    
    // 移除会话
    void RemoveSession(const std::string& session_id);
    
    // 启动清理定时器
    void StartCleanup();
    
    // 停止所有会话
    void StopAll();
    
    // 获取活跃会话数量
    size_t ActiveSessionCount() const { return sessions_.size(); }
    
    // 统计
    uint64_t TotalPacketsSent() const { return total_packets_sent_; }
    uint64_t TotalPacketsReceived() const { return total_packets_received_; }

private:
    void CleanupExpiredSessions();
    
    net::any_io_executor executor_;
    IDnsService* dns_service_ = nullptr;
    std::chrono::seconds session_timeout_;
    
    std::unordered_map<std::string, std::shared_ptr<UDPSession>> sessions_;
    
    net::steady_timer cleanup_timer_;
    bool running_ = false;
    
    uint64_t total_packets_sent_ = 0;
    uint64_t total_packets_received_ = 0;
};

}  // namespace acpp
