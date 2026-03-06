#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/protocol_data.hpp"
#include "acppnode/sniff/sniffer.hpp"
#include <memory>

namespace acpp {

// ============================================================================
// 会话上下文
// ============================================================================
struct SessionContext {
    // 连接标识
    uint64_t conn_id = 0;
    uint32_t worker_id = 0;
    
    // 来源信息
    tcp::endpoint src_addr;                   // 客户端地址
    tcp::endpoint inbound_local_addr;         // 入站本地地址（源进源出用）
    std::string client_ip;                    // 客户端 IP（可能来自 Proxy Protocol）
    std::string inbound_tag;                    // 主标签（日志/流量统计/map key）
    std::vector<std::string> inbound_tags;     // 所有标签（路由匹配任一）
    
    // 面板用户信息
    std::string panel_name;                  // 面板名称
    int node_id = 0;                         // 节点 ID
    int64_t user_id = 0;                     // 用户 ID
    std::string user_email;                  // 用户邮箱/标识
    
    // 目标信息
    TargetAddress target;                    // 原始目标（协议解析得到）
    TargetAddress sniffed_target;            // 嗅探目标（Sniff 得到）
    TargetAddress final_target;              // 最终目标（可能被 Redirect 修改）
    Network network = Network::TCP;
    
    // 入站协议类型 (vmess/trojan/etc)
    std::string inbound_protocol;
    
    // DNS 解析结果
    std::string dns_result;                  // "cache" / "resolve" / "none"
    net::ip::address resolved_ip;            // 解析后的 IP
    
    // Sniff 结果（SessionHandler 在 SNIFFING 阶段写入）
    SniffResult sniff_result;
    
    // 路由结果
    std::string outbound_tag;
    std::string redirect_target;             // Redirect 目标（如有）
    
    // 出口信息
    net::ip::address local_ip;               // 本机出口 IP
    
    // 状态
    ConnState state = ConnState::ACCEPTED;
    
    // 时间戳（微秒，使用 steady_clock）
    int64_t accept_time_us = 0;
    int64_t handshake_done_us = 0;
    int64_t sniff_done_us = 0;
    int64_t dial_done_us = 0;
    int64_t close_time_us = 0;
    
    // 流量统计
    uint64_t bytes_up = 0;                   // 上行字节数
    uint64_t bytes_down = 0;                 // 下行字节数
    
    // 限速 (bytes/s), 0 = 不限速
    uint64_t speed_limit = 0;
    
    // 错误信息
    ErrorCode error_code = ErrorCode::OK;
    std::string error_msg;
    
    // 协议特定数据（类型安全：各协议定义 XxxProtocolData : IProtocolData）
    // 取用：static_cast<XxxProtocolData*>(protocol_data.get())
    std::unique_ptr<IProtocolData> protocol_data;

    // 连接断开时的清理回调（由 ParseStream 认证成功后设置，ctx 析构时自动触发）
    // 约束：
    //   - 必须可在 SessionContext 所在线程同步执行
    //   - 不得捕获比 SessionContext 更早销毁对象的引用/裸指针
    //   - 应视为 noexcept；析构路径会吞掉异常以避免传播
    std::function<void()> on_disconnect;

    // 首包数据（用于 Sniff 后回放）
    std::vector<uint8_t> first_packet;

    // 构造函数
    SessionContext() {
        conn_id = GenerateConnId();
        accept_time_us = NowMicros();
    }

    // 析构函数：自动调用在线追踪的 disconnect 回调
    ~SessionContext() noexcept {
        if (on_disconnect) {
            try { on_disconnect(); } catch (...) {}
        }
    }
    
    // 设置错误
    void SetError(ErrorCode code, std::string_view msg = "") {
        error_code = code;
        error_msg = msg.empty() ? std::string(ErrorCodeToString(code)) : std::string(msg);
    }
    
    // 状态转换
    void TransitionTo(ConnState new_state) {
        state = new_state;
        
        // 记录时间戳
        int64_t now = NowMicros();
        switch (new_state) {
            case ConnState::SNIFFING:
                handshake_done_us = now;
                break;
            case ConnState::ROUTING:
                sniff_done_us = now;
                break;
            case ConnState::RELAYING:
                dial_done_us = now;
                break;
            case ConnState::CLOSED:
                close_time_us = now;
                break;
            default:
                break;
        }
    }
    
    // 获取有效目标地址：final_target 优先（Sniff/Redirect 修改后），否则原始 target
    [[nodiscard]] const TargetAddress& EffectiveTarget() const noexcept {
        return final_target.IsValid() ? final_target : target;
    }

    // 获取用户标识（用于日志）
    [[nodiscard]] std::string GetUserIdent() const {
        if (!user_email.empty()) {
            return user_email;
        }
        return std::to_string(user_id);
    }
    
    // 生成 Access Log 行
    [[nodiscard]] std::string ToAccessLog() const;
    
    // 生成完整 Access Log（包含连接结果）
    [[nodiscard]] std::string ToAccessLogComplete(
        std::string_view status,
        uint64_t bytes_up,
        uint64_t bytes_down,
        int64_t duration_ms) const;
    
    // 计算连接持续时间（毫秒）
    [[nodiscard]] int64_t DurationMs() const noexcept {
        int64_t end = close_time_us > 0 ? close_time_us : NowMicros();
        return (end - accept_time_us) / 1000;
    }
};

}  // namespace acpp
