#pragma once
#include "acppnode/app/rate_limiter_fwd.hpp"
// ============================================================================
// Worker 私有连接限制器 (Per-Worker Rate Limiter)
//
// 设计特点：
// 1. Worker 私有 - 只在所属 io_context 上访问，无锁/无 atomic
// 2. 固定内存 - 无动态分配，启动时分配固定大小
// 3. O(1) 操作 - 开放寻址哈希表，最坏 O(探测长度)
// 4. Cache 友好 - 每个槽位 64 字节对齐
// 5. 统一接口 - 所有协议共用（VMess/Trojan/SS）
// ============================================================================

#include <array>
#include <chrono>
#include <string_view>
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

inline uint64_t Hash(std::string_view s) {
    return Hash(s.data(), s.size());
}

inline uint64_t HashPair(std::string_view a, std::string_view b) {
    uint64_t h = 14695981039346656037ULL;
    for (char ch : a) {
        h ^= static_cast<uint8_t>(ch);
        h *= 1099511628211ULL;
    }
    h ^= static_cast<uint8_t>(':');
    h *= 1099511628211ULL;
    for (char ch : b) {
        h ^= static_cast<uint8_t>(ch);
        h *= 1099511628211ULL;
    }
    return h;
}

// ============================================================================
// IP 槽位（64 字节，cache line 对齐）
// ============================================================================
struct alignas(64) Slot {
    uint64_t hash = 0;                       // IP 哈希 (0=空槽)
    uint32_t conns = 0;                      // 当前连接数
    uint32_t rate = 0;                       // 当前秒连接数
    uint32_t rate_ts = 0;                    // rate 的时间戳
    uint32_t auth_fails = 0;                 // 认证失败计数
    uint32_t auth_ts = 0;                    // 最后认证失败时间
    uint32_t ban_until = 0;                  // 屏蔽解除时间
    uint32_t _pad[8];                        // 填充到 64 字节

    bool Match(uint64_t h) const {
        return hash == h;
    }

    bool Empty() const {
        return hash == 0;
    }

    bool Idle(uint32_t now) const {
        return conns == 0 && ban_until <= now;
    }

    bool TryAcquire(uint64_t h) {
        if (hash != 0) return false;
        hash = h;
        return true;
    }

    void Clear() {
        conns = 0;
        rate = 0;
        rate_ts = 0;
        auth_fails = 0;
        auth_ts = 0;
        ban_until = 0;
    }
};

static_assert(sizeof(Slot) == 64, "Slot must be 64 bytes");

// ============================================================================
// 统一限制器
// ============================================================================
template<size_t N = 16384>  // Worker 私有槽位数量，必须是 2 的幂
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
            return Reject::None;
        }

        if (total_ >= cfg_.max_connections) return Reject::GlobalLimit;
        ++total_;
        return Reject::None;
    }

    void UndoGlobal() {
        if (cfg_.max_connections == 0) {
            return;
        }
        if (total_ > 0) --total_;
    }

    // ========================================================================
    // 阶段2: IP 检查 (获取真实 IP 后调用)
    // tag: 入站标签，用于区分不同节点的 banned 状态
    // ========================================================================
    Reject CheckIP(std::string_view tag, std::string_view ip) {
        uint64_t h = Hash(ip);
        uint32_t now = Now();

        // 1. 检查屏蔽（按 tag+ip 检查，不同节点独立）
        if (cfg_.auth_fail_limit > 0) {
            uint64_t ban_h = HashPair(tag, ip);
            if (const Slot* ban_s = FindConst(ban_h)) {
                if (ban_s->ban_until > now) {
                    return Reject::IPBanned;
                }
            }
        }

        if (cfg_.max_conn_per_ip == 0 && cfg_.max_rate_per_ip == 0) {
            return Reject::None;
        }

        Slot* s = FindOrCreate(h, now);
        if (!s) return Reject::None;  // 槽位满，降级放行

        // 2. 连接数限制（按 IP 全局限制）
        if (cfg_.max_conn_per_ip > 0) {
            if (s->conns >= cfg_.max_conn_per_ip) return Reject::IPConnLimit;
            ++s->conns;
        }

        // 3. 速率限制
        if (cfg_.max_rate_per_ip > 0) {
            if (s->rate_ts != now) {
                s->rate = 1;
                s->rate_ts = now;
            } else {
                ++s->rate;
                if (s->rate > cfg_.max_rate_per_ip) {
                    if (cfg_.max_conn_per_ip > 0) {
                        --s->conns;
                    }
                    return Reject::IPRateLimit;
                }
            }
        }

        return Reject::None;
    }

    // ========================================================================
    // 释放连接
    // ========================================================================
    void Release(std::string_view ip) {
        if (cfg_.max_conn_per_ip > 0) {
            uint64_t h = Hash(ip);
            if (Slot* s = Find(h)) {
                if (s->conns > 0) --s->conns;
            }
        }
        UndoGlobal();
    }

    // ========================================================================
    // 记录认证失败（屏蔽源 IP）
    // 注意：tag 用于区分不同的入站节点，同一 IP 在不同节点独立计数
    // ========================================================================
    void OnAuthFailTracked(std::string_view tag, std::string_view ip) {
        if (cfg_.auth_fail_limit == 0) return;

        // 使用 tag+ip 的组合哈希，不同节点独立计数
        uint64_t h = HashPair(tag, ip);
        uint32_t now = Now();
        Slot* s = FindOrCreate(h, now);
        if (!s) return;

        // 已被屏蔽则跳过
        if (s->ban_until > now) return;

        uint32_t last = s->auth_ts;

        // 1 秒内去重：同一秒内多次失败只算 1 次（防止客户端重试导致快速累积）
        if (last == now) return;

        // 超时重置计数（使用独立的失败计数窗口）
        if (last > 0 && now - last > cfg_.auth_fail_window) {
            s->auth_fails = 0;
        }

        // 更新时间戳（必须在计数之前，确保去重生效）
        s->auth_ts = now;

        uint32_t cnt = ++s->auth_fails;

        // 达到阈值则屏蔽
        if (cnt >= cfg_.auth_fail_limit) {
            s->ban_until = now + cfg_.auth_ban_seconds;
            LOG_NET_WARN("[{}] IP {} banned for {}s (auth failures: {})",
                         tag, ip, cfg_.auth_ban_seconds, cnt);
            // 重置失败计数，ban 解除后重新开始计数
            s->auth_fails = 0;
        }
    }

    bool IsBanned(std::string_view tag, std::string_view ip) const {
        uint64_t h = HashPair(tag, ip);
        uint32_t now = Now();
        if (const Slot* s = FindConst(h)) {
            return s->ban_until > now;
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

            uint64_t sh = s.hash;
            if (sh == 0) {
                if (s.TryAcquire(h)) return &s;
                if (s.Match(h)) return &s;
            } else if (!idle && s.Idle(now)) {
                idle = &s;
            }
        }

        // 回收空闲槽
        if (idle) {
            if (idle->hash != 0 && idle->Idle(now)) {
                idle->Clear();
                idle->hash = h;
                return idle;
            }
        }

        return nullptr;
    }

    RateLimitConfig cfg_;
    alignas(64) uint32_t total_ = 0;
    alignas(64) std::array<Slot, N> slots_{};
};

// 默认类型
using DefaultRateLimiter = RateLimiter<16384>;

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

    ConnectionLimiter() = default;
    explicit ConnectionLimiter(const RateLimitConfig& c)
        : lim_(c) {}

    RejectReason TryAcceptGlobal() {
        return lim_.CheckGlobal() == Reject::None ?
               RejectReason::NONE : RejectReason::MAX_CONNECTIONS;
    }

    RejectReason TryAcceptIP(std::string_view tag, std::string_view ip) {
        auto r = lim_.CheckIP(tag, ip);
        switch (r) {
            case Reject::IPConnLimit: return RejectReason::MAX_CONNECTIONS_PER_IP;
            case Reject::IPBanned:
            case Reject::IPRateLimit: return RejectReason::IP_BANNED;
            default: return RejectReason::NONE;
        }
    }

    void ReleaseGlobal() { lim_.UndoGlobal(); }
    void Release(std::string_view ip) { lim_.Release(ip); }

    void OnAuthFailTracked(std::string_view tag, std::string_view ip) {
        lim_.OnAuthFailTracked(tag, ip);
    }

    DefaultRateLimiter& GetLimiter() { return lim_; }

private:
    DefaultRateLimiter lim_;
};

}  // namespace acpp
