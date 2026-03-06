#pragma once

// ============================================================================
// connection_guard.hpp - 连接相关的 RAII 守卫
//
// 用途：
// - 统一管理连接限制的获取和释放
// - 统一管理连接统计
// - 统一管理用户在线状态
// ============================================================================

#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/infra/log.hpp"

#include <string>
#include <utility>

namespace acpp {

// ============================================================================
// ConnectionLimitGuard - 连接限制 RAII 守卫
// 
// 生命周期：
// 1. 构造时：全局连接数已在外部增加
// 2. MarkIPAccepted()：IP 检查通过，切换到 IP 级别跟踪
// 3. 析构时：根据状态释放正确的资源
// 
// 使用示例：
//   ConnectionLimitGuard guard(limiter, client_ip);
//   
//   // PROXY Protocol 可能更新真实 IP
//   guard.UpdateIP(real_ip);
//   
//   // IP 检查通过
//   if (limiter->TryAcceptIP(tag, real_ip) == NONE) {
//       guard.MarkIPAccepted();
//   } else {
//       return;  // guard 析构会释放 global
//   }
// ============================================================================
class ConnectionLimitGuard {
public:
    ConnectionLimitGuard(ConnectionLimiterPtr limiter, std::string ip)
        : limiter_(std::move(limiter))
        , ip_(std::move(ip))
        , ip_accepted_(false)
        , dismissed_(false) {}
    
    ~ConnectionLimitGuard() noexcept {
        if (dismissed_ || !limiter_) {
            return;
        }
        
        try {
            if (ip_accepted_) {
                limiter_->Release(ip_);
            } else {
                limiter_->ReleaseGlobal();
            }
        } catch (...) {
            // 析构函数中不能抛出异常
        }
    }
    
    // IP 检查通过后调用 - 切换到 IP 级别跟踪
    void MarkIPAccepted() noexcept { 
        ip_accepted_ = true; 
    }
    
    // 更新 IP（用于 PROXY Protocol 解析后）
    void UpdateIP(std::string new_ip) noexcept { 
        ip_ = std::move(new_ip); 
    }
    
    // 获取当前 IP
    const std::string& IP() const noexcept { 
        return ip_; 
    }
    
    // 是否已接受 IP
    bool IsIPAccepted() const noexcept { 
        return ip_accepted_; 
    }
    
    // 取消守卫（不释放资源）- 用于转移所有权
    void Dismiss() noexcept { 
        dismissed_ = true; 
    }
    
    // 禁止拷贝
    ConnectionLimitGuard(const ConnectionLimitGuard&) = delete;
    ConnectionLimitGuard& operator=(const ConnectionLimitGuard&) = delete;
    
    // 允许移动
    ConnectionLimitGuard(ConnectionLimitGuard&& other) noexcept
        : limiter_(std::move(other.limiter_))
        , ip_(std::move(other.ip_))
        , ip_accepted_(other.ip_accepted_)
        , dismissed_(other.dismissed_) {
        other.dismissed_ = true;
    }
    
    ConnectionLimitGuard& operator=(ConnectionLimitGuard&& other) noexcept {
        if (this != &other) {
            // 先释放当前资源
            if (!dismissed_ && limiter_) {
                try {
                    if (ip_accepted_) {
                        limiter_->Release(ip_);
                    } else {
                        limiter_->ReleaseGlobal();
                    }
                } catch (...) {}
            }
            
            limiter_ = std::move(other.limiter_);
            ip_ = std::move(other.ip_);
            ip_accepted_ = other.ip_accepted_;
            dismissed_ = other.dismissed_;
            other.dismissed_ = true;
        }
        return *this;
    }

private:
    ConnectionLimiterPtr limiter_;
    std::string ip_;
    bool ip_accepted_;
    bool dismissed_;
};

// ============================================================================
// ConnectionStatsGuard - 连接统计 RAII 守卫
// 
// 构造时增加活跃连接数，析构时减少
// ============================================================================
class ConnectionStatsGuard {
public:
    explicit ConnectionStatsGuard(StatsShard& stats) noexcept
        : stats_(&stats) {
        stats_->OnConnectionAccepted();
    }
    
    ~ConnectionStatsGuard() noexcept {
        if (stats_) {
            stats_->OnConnectionClosed();
        }
    }
    
    // 禁止拷贝
    ConnectionStatsGuard(const ConnectionStatsGuard&) = delete;
    ConnectionStatsGuard& operator=(const ConnectionStatsGuard&) = delete;
    
    // 允许移动
    ConnectionStatsGuard(ConnectionStatsGuard&& other) noexcept
        : stats_(other.stats_) {
        other.stats_ = nullptr;
    }
    
    ConnectionStatsGuard& operator=(ConnectionStatsGuard&& other) noexcept {
        if (this != &other) {
            if (stats_) {
                stats_->OnConnectionClosed();
            }
            stats_ = other.stats_;
            other.stats_ = nullptr;
        }
        return *this;
    }

private:
    StatsShard* stats_;
};

// ============================================================================
// UserConnectionGuard - 用户连接 RAII 守卫
// 
// 管理用户在线状态的跟踪
// ============================================================================
template<typename UserManager>
class UserConnectionGuard {
public:
    UserConnectionGuard(UserManager& mgr, std::string tag, uint64_t user_id)
        : mgr_(&mgr)
        , tag_(std::move(tag))
        , user_id_(user_id)
        , dismissed_(false) {}
    
    ~UserConnectionGuard() noexcept {
        if (!dismissed_ && mgr_ && user_id_ != 0) {
            try {
                mgr_->OnUserDisconnected(tag_, user_id_);
            } catch (...) {
                // 忽略异常
            }
        }
    }
    
    uint64_t UserId() const noexcept { return user_id_; }
    const std::string& Tag() const noexcept { return tag_; }
    
    void Dismiss() noexcept { dismissed_ = true; }
    
    // 禁止拷贝
    UserConnectionGuard(const UserConnectionGuard&) = delete;
    UserConnectionGuard& operator=(const UserConnectionGuard&) = delete;
    
    // 允许移动
    UserConnectionGuard(UserConnectionGuard&& other) noexcept
        : mgr_(other.mgr_)
        , tag_(std::move(other.tag_))
        , user_id_(other.user_id_)
        , dismissed_(other.dismissed_) {
        other.dismissed_ = true;
    }

private:
    UserManager* mgr_;
    std::string tag_;
    uint64_t user_id_;
    bool dismissed_;
};

}  // namespace acpp
