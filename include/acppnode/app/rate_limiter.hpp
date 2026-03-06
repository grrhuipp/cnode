#pragma once
// ============================================================================
// 统一无锁连接限制器 (Lock-Free Unified Rate Limiter)
// 
// 设计特点：
// 1. 完全无锁 - 全部使用 atomic CAS 操作
// 2. 固定内存 - 无动态分配，启动时分配固定大小
// 3. O(1) 操作 - 开放寻址哈希表，最坏 O(探测长度)
// 4. Cache 友好 - 每个槽位 64 字节对齐
// 5. 统一接口 - 所有协议共用（VMess/Trojan/等）
// ============================================================================

#include <atomic>
#include <array>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <cstdint>
#include "acppnode/infra/log.hpp"

namespace acpp {

// ============================================================================
// 配置
// ============================================================================
struct RateLimitConfig {
    uint32_t max_connections = 0;              // 全局最大连接数 (0=不限制)
    uint32_t max_conn_per_ip = 0;              // 单 IP 最大并发连接 (0=不限制)
    uint32_t max_rate_per_ip = 0;              // 单 IP 每秒最大新连接 (0=不限制)
    uint32_t auth_fail_limit = 10;             // 认证失败阈值 (屏蔽源 IP)
    uint32_t auth_fail_window = 60;            // 认证失败计数窗口（秒），超过此时间重置计数
    uint32_t auth_ban_seconds = 180;           // 认证失败屏蔽秒数
};

// ============================================================================
// 拒绝原因
// ============================================================================
enum class Reject : uint8_t {
    None = 0,
    GlobalLimit,      // 全局连接超限
    IPConnLimit,      // IP 连接超限
    IPRateLimit,      // IP 速率超限
    IPBanned,         // IP 被屏蔽（认证失败）
};

inline const char* ToString(Reject r) {
    static const char* names[] = {
        "None", "GlobalLimit", "IPConnLimit", 
        "IPRateLimit", "IPBanned"
    };
    return names[static_cast<int>(r)];
}

// ============================================================================
// 时间戳（秒）
// ============================================================================
inline uint32_t Now() {
    using namespace std::chrono;
    return static_cast<uint32_t>(
        duration_cast<seconds>(steady_clock::now().time_since_epoch()).count());
}

// ============================================================================
// IP 哈希 (FNV-1a)
// ============================================================================
inline uint64_t Hash(const char* s, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint8_t>(s[i]);
        h *= 1099511628211ULL;
    }
    return h;
}

inline uint64_t Hash(const std::string& s) { 
    return Hash(s.data(), s.size()); 
}

// ============================================================================
// IP 槽位（64 字节，cache line 对齐）
// ============================================================================
struct alignas(64) Slot {
    std::atomic<uint64_t> hash{0};           // IP 哈希 (0=空槽)
    std::atomic<uint32_t> conns{0};          // 当前连接数
    std::atomic<uint32_t> rate{0};           // 当前秒连接数
    std::atomic<uint32_t> rate_ts{0};        // rate 的时间戳
    std::atomic<uint32_t> auth_fails{0};     // 认证失败计数
    std::atomic<uint32_t> auth_ts{0};        // 最后认证失败时间
    std::atomic<uint32_t> ban_until{0};      // 屏蔽解除时间
    uint32_t _pad[8];                        // 填充到 64 字节
    
    bool Match(uint64_t h) const { 
        return hash.load(std::memory_order_relaxed) == h; 
    }
    
    bool Empty() const { 
        return hash.load(std::memory_order_relaxed) == 0; 
    }
    
    bool Idle(uint32_t now) const {
        return conns.load(std::memory_order_relaxed) == 0 &&
               ban_until.load(std::memory_order_relaxed) <= now;
    }
    
    bool TryAcquire(uint64_t h) {
        uint64_t expected = 0;
        return hash.compare_exchange_strong(expected, h,
            std::memory_order_acq_rel, std::memory_order_relaxed);
    }
    
    void Clear() {
        conns.store(0, std::memory_order_relaxed);
        rate.store(0, std::memory_order_relaxed);
        rate_ts.store(0, std::memory_order_relaxed);
        auth_fails.store(0, std::memory_order_relaxed);
        auth_ts.store(0, std::memory_order_relaxed);
        ban_until.store(0, std::memory_order_relaxed);
    }
};

static_assert(sizeof(Slot) == 64, "Slot must be 64 bytes");

// ============================================================================
// 统一限制器
// ============================================================================
template<size_t N = 65536>  // 槽位数量，必须是 2 的幂
class RateLimiter {
    static_assert((N & (N - 1)) == 0, "N must be power of 2");
    static constexpr size_t kMask = N - 1;
    static constexpr size_t kProbe = 32;  // 最大探测长度（增加以应对高冲突场景如 NAT）

public:
    explicit RateLimiter(const RateLimitConfig& cfg = {}) : cfg_(cfg) {}
    
    // ========================================================================
    // 阶段1: 全局检查 (accept 时调用)
    // ========================================================================
    Reject CheckGlobal() {
        if (cfg_.max_connections == 0) {
            total_.fetch_add(1, std::memory_order_relaxed);
            return Reject::None;
        }
        
        uint32_t cur = total_.load(std::memory_order_relaxed);
        while (cur < cfg_.max_connections) {
            if (total_.compare_exchange_weak(cur, cur + 1,
                    std::memory_order_acq_rel, std::memory_order_relaxed)) {
                return Reject::None;
            }
        }
        return Reject::GlobalLimit;
    }
    
    void UndoGlobal() {
        total_.fetch_sub(1, std::memory_order_relaxed);
    }
    
    // ========================================================================
    // 阶段2: IP 检查 (获取真实 IP 后调用)
    // tag: 入站标签，用于区分不同节点的 banned 状态
    // ========================================================================
    Reject CheckIP(const std::string& ip) {
        return CheckIP("", ip);
    }
    
    Reject CheckIP(const std::string& tag, const std::string& ip) {
        uint64_t h = Hash(ip);
        uint32_t now = Now();
        
        Slot* s = FindOrCreate(h, now);
        if (!s) return Reject::None;  // 槽位满，降级放行
        
        // 1. 检查屏蔽（按 tag+ip 检查，不同节点独立）
        if (cfg_.auth_fail_limit > 0) {
            uint64_t ban_h = tag.empty() ? h : Hash(tag + ":" + ip);
            if (const Slot* ban_s = FindConst(ban_h)) {
                if (ban_s->ban_until.load(std::memory_order_relaxed) > now) {
                    return Reject::IPBanned;
                }
            }
        }
        
        // 2. 连接数限制（按 IP 全局限制）
        if (cfg_.max_conn_per_ip > 0) {
            uint32_t c = s->conns.load(std::memory_order_relaxed);
            while (c < cfg_.max_conn_per_ip) {
                if (s->conns.compare_exchange_weak(c, c + 1,
                        std::memory_order_acq_rel, std::memory_order_relaxed)) {
                    goto rate_check;
                }
            }
            return Reject::IPConnLimit;
        } else {
            s->conns.fetch_add(1, std::memory_order_relaxed);
        }
        
    rate_check:
        // 3. 速率限制
        if (cfg_.max_rate_per_ip > 0) {
            uint32_t ts = s->rate_ts.load(std::memory_order_relaxed);
            if (ts != now) {
                s->rate.store(1, std::memory_order_relaxed);
                s->rate_ts.store(now, std::memory_order_relaxed);
            } else {
                uint32_t r = s->rate.fetch_add(1, std::memory_order_relaxed) + 1;
                if (r > cfg_.max_rate_per_ip) {
                    s->conns.fetch_sub(1, std::memory_order_relaxed);
                    return Reject::IPRateLimit;
                }
            }
        }
        
        return Reject::None;
    }
    
    // ========================================================================
    // 释放连接
    // ========================================================================
    void Release(const std::string& ip) {
        uint64_t h = Hash(ip);
        if (Slot* s = Find(h)) {
            s->conns.fetch_sub(1, std::memory_order_relaxed);
        }
        total_.fetch_sub(1, std::memory_order_relaxed);
    }
    
    // ========================================================================
    // 记录认证失败（屏蔽源 IP）
    // 注意：tag 用于区分不同的入站节点，同一 IP 在不同节点独立计数
    // ========================================================================
    void OnAuthFail(const std::string& ip) {
        OnAuthFail("", ip);  // 兼容旧调用
    }
    
    void OnAuthFail(const std::string& tag, const std::string& ip) {
        if (cfg_.auth_fail_limit == 0) return;
        // 该 tag 未启用 ban 追踪时跳过（用户列表未同步完成）
        {
            std::lock_guard lock(ban_tags_mutex_);
            if (!ban_enabled_tags_.contains(tag)) return;
        }
        
        // 使用 tag+ip 的组合哈希，不同节点独立计数
        uint64_t h = tag.empty() ? Hash(ip) : Hash(tag + ":" + ip);
        uint32_t now = Now();
        Slot* s = FindOrCreate(h, now);
        if (!s) return;
        
        // 已被屏蔽则跳过
        if (s->ban_until.load(std::memory_order_relaxed) > now) return;
        
        uint32_t last = s->auth_ts.load(std::memory_order_relaxed);
        
        // 1 秒内去重：同一秒内多次失败只算 1 次（防止客户端重试导致快速累积）
        if (last == now) return;
        
        // 超时重置计数（使用独立的失败计数窗口）
        if (last > 0 && now - last > cfg_.auth_fail_window) {
            s->auth_fails.store(0, std::memory_order_relaxed);
        }
        
        // 更新时间戳（必须在计数之前，确保去重生效）
        s->auth_ts.store(now, std::memory_order_relaxed);
        
        uint32_t cnt = s->auth_fails.fetch_add(1, std::memory_order_relaxed) + 1;
        
        // 达到阈值则屏蔽
        if (cnt >= cfg_.auth_fail_limit) {
            s->ban_until.store(now + cfg_.auth_ban_seconds, std::memory_order_relaxed);
            LOG_CONN_FAIL("[{}] IP {} banned for {}s (auth failures: {})", 
                         tag, ip, cfg_.auth_ban_seconds, cnt);
            // 重置失败计数，ban 解除后重新开始计数
            s->auth_fails.store(0, std::memory_order_relaxed);
        }
    }
    
    // ========================================================================
    // 启用 Ban 追踪（per-tag：每个节点用户同步完成后独立启用）
    // ========================================================================
    void EnableBanTrackingForTag(const std::string& tag) {
        std::lock_guard lock(ban_tags_mutex_);
        ban_enabled_tags_.insert(tag);
    }

    bool IsBanTrackingEnabledForTag(const std::string& tag) const {
        std::lock_guard lock(ban_tags_mutex_);
        return ban_enabled_tags_.contains(tag);
    }

    bool IsBanTrackingEnabled() const {
        std::lock_guard lock(ban_tags_mutex_);
        return !ban_enabled_tags_.empty();
    }
    
    // ========================================================================
    // 查询
    // ========================================================================
    uint32_t TotalConns() const { 
        return total_.load(std::memory_order_relaxed); 
    }
    
    uint32_t IPConns(const std::string& ip) const {
        if (const Slot* s = FindConst(Hash(ip))) {
            return s->conns.load(std::memory_order_relaxed);
        }
        return 0;
    }
    
    bool IsBanned(const std::string& ip) const {
        return IsBanned("", ip);
    }
    
    bool IsBanned(const std::string& tag, const std::string& ip) const {
        uint64_t h = tag.empty() ? Hash(ip) : Hash(tag + ":" + ip);
        uint32_t now = Now();
        if (const Slot* s = FindConst(h)) {
            return s->ban_until.load(std::memory_order_relaxed) > now;
        }
        return false;
    }
    
    const RateLimitConfig& Config() const { return cfg_; }

private:
    Slot* Find(uint64_t h) {
        size_t idx = h & kMask;
        for (size_t i = 0; i < kProbe; ++i) {
            Slot& s = slots_[(idx + i) & kMask];
            if (s.Match(h)) return &s;
            if (s.Empty()) return nullptr;
        }
        return nullptr;
    }
    
    const Slot* FindConst(uint64_t h) const {
        size_t idx = h & kMask;
        for (size_t i = 0; i < kProbe; ++i) {
            const Slot& s = slots_[(idx + i) & kMask];
            if (s.Match(h)) return &s;
            if (s.Empty()) return nullptr;
        }
        return nullptr;
    }
    
    Slot* FindOrCreate(uint64_t h, uint32_t now) {
        size_t idx = h & kMask;
        Slot* idle = nullptr;
        
        for (size_t i = 0; i < kProbe; ++i) {
            Slot& s = slots_[(idx + i) & kMask];
            
            if (s.Match(h)) return &s;
            
            uint64_t sh = s.hash.load(std::memory_order_relaxed);
            if (sh == 0) {
                if (s.TryAcquire(h)) return &s;
                if (s.Match(h)) return &s;
            } else if (!idle && s.Idle(now)) {
                idle = &s;
            }
        }
        
        // 回收空闲槽
        if (idle) {
            uint64_t old = idle->hash.load(std::memory_order_relaxed);
            if (old != 0 && idle->Idle(now)) {
                if (idle->hash.compare_exchange_strong(old, h,
                        std::memory_order_acq_rel, std::memory_order_relaxed)) {
                    idle->Clear();
                    return idle;
                }
            }
        }
        
        return nullptr;
    }
    
    RateLimitConfig cfg_;
    alignas(64) std::atomic<uint32_t> total_{0};
    mutable std::mutex ban_tags_mutex_;
    std::unordered_set<std::string> ban_enabled_tags_;
    alignas(64) std::array<Slot, N> slots_{};
};

// 默认类型
using DefaultRateLimiter = RateLimiter<65536>;
using RateLimiterPtr = std::shared_ptr<DefaultRateLimiter>;

// ============================================================================
// ConnectionLimiter — 协议无关的连接限制器（包装 DefaultRateLimiter）
// ============================================================================
class ConnectionLimiter {
public:
    
    enum class RejectReason {
        NONE = 0,
        MAX_CONNECTIONS,
        MAX_CONNECTIONS_PER_IP,
        IP_BANNED
    };
    
    static const char* RejectReasonToString(RejectReason r) {
        static const char* s[] = {"NONE", "MAX_CONNECTIONS", "MAX_CONNECTIONS_PER_IP", "IP_BANNED"};
        return s[static_cast<int>(r)];
    }
    
    ConnectionLimiter() : lim_(std::make_shared<DefaultRateLimiter>()) {}
    explicit ConnectionLimiter(const RateLimitConfig& c)
        : lim_(std::make_shared<DefaultRateLimiter>(c)), cfg_(c) {}
    
    RejectReason TryAcceptGlobal() {
        return lim_->CheckGlobal() == Reject::None ? 
               RejectReason::NONE : RejectReason::MAX_CONNECTIONS;
    }
    
    RejectReason TryAcceptIP(const std::string& ip) {
        return TryAcceptIP("", ip);
    }
    
    RejectReason TryAcceptIP(const std::string& tag, const std::string& ip) {
        auto r = lim_->CheckIP(tag, ip);
        switch (r) {
            case Reject::IPConnLimit: return RejectReason::MAX_CONNECTIONS_PER_IP;
            case Reject::IPBanned:
            case Reject::IPRateLimit: return RejectReason::IP_BANNED;
            default: return RejectReason::NONE;
        }
    }
    
    RejectReason TryAccept(const std::string& ip) {
        return TryAccept("", ip);
    }
    
    RejectReason TryAccept(const std::string& tag, const std::string& ip) {
        auto r1 = TryAcceptGlobal();
        if (r1 != RejectReason::NONE) return r1;
        auto r2 = TryAcceptIP(tag, ip);
        if (r2 != RejectReason::NONE) { ReleaseGlobal(); return r2; }
        return RejectReason::NONE;
    }
    
    void ReleaseGlobal() { lim_->UndoGlobal(); }
    void Release(const std::string& ip) { lim_->Release(ip); }
    
    void OnAuthFail(const std::string& ip) { lim_->OnAuthFail(ip); }
    void OnAuthFail(const std::string& tag, const std::string& ip) { 
        lim_->OnAuthFail(tag, ip); 
    }
    
    // 启用 Ban 追踪（per-tag：每个节点用户同步完成后独立启用）
    void EnableBanTrackingForTag(const std::string& tag) { lim_->EnableBanTrackingForTag(tag); }
    bool IsBanTrackingEnabledForTag(const std::string& tag) const { return lim_->IsBanTrackingEnabledForTag(tag); }
    bool IsBanTrackingEnabled() const { return lim_->IsBanTrackingEnabled(); }
    
    uint32_t GetTotalConnections() const { return lim_->TotalConns(); }
    uint32_t GetIPConnections(const std::string& ip) const { return lim_->IPConns(ip); }
    
    struct Stats {
        uint32_t total_connections;
        uint32_t max_connections;
        uint32_t max_connections_per_ip;
    };
    
    Stats GetStats() const {
        return {lim_->TotalConns(), cfg_.max_connections, cfg_.max_conn_per_ip};
    }

    const RateLimitConfig& GetConfig() const { return cfg_; }
    DefaultRateLimiter& GetLimiter() { return *lim_; }

private:
    std::shared_ptr<DefaultRateLimiter> lim_;
    RateLimitConfig cfg_;
};

// 注意：ConnectionLimitGuard 已移至 connection_guard.hpp

using ConnectionLimiterPtr = std::shared_ptr<ConnectionLimiter>;

}  // namespace acpp
