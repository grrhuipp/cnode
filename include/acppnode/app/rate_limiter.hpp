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
    uint32_t max_connections = 0;      // 全局最大连接数 (0=不限制)
    uint32_t max_conn_per_ip = 0;      // 单 IP 最大并发连接 (0=不限制)
    uint32_t auth_fail_limit = 10;     // 认证失败阈值 (屏蔽源 IP)
    uint32_t auth_fail_window = 60;    // 认证失败计数窗口（秒），超过此时间重置计数
    uint32_t auth_ban_seconds = 180;   // 认证失败屏蔽秒数
};

// ============================================================================
// 时间戳（秒）
// ============================================================================
[[nodiscard]] inline uint32_t Now() noexcept {
    using namespace std::chrono;
    return static_cast<uint32_t>(
        duration_cast<seconds>(steady_clock::now().time_since_epoch()).count());
}

// ============================================================================
// IP 哈希 (FNV-1a)
// ============================================================================
[[nodiscard]] constexpr uint64_t Hash(const char* s, size_t len) noexcept {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint8_t>(s[i]);
        h *= 1099511628211ULL;
    }
    return h == 0 ? 1ULL : h;
}

[[nodiscard]] constexpr uint64_t Hash(std::string_view s) noexcept {
    return Hash(s.data(), s.size());
}

[[nodiscard]] constexpr uint64_t HashPair(
    std::string_view a, std::string_view b) noexcept {
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
    return h == 0 ? 1ULL : h;
}

// ============================================================================
// ConnectionLimiter — Worker 私有无锁连接与认证屏蔽限制器
// ============================================================================
class ConnectionLimiter {
    static constexpr size_t kSlotCount = 16384;
    static_assert((kSlotCount & (kSlotCount - 1)) == 0,
                  "kSlotCount must be power of 2");
    static constexpr size_t kMask = kSlotCount - 1;
    static constexpr size_t kProbe = 32;

    struct Slot {
        uint64_t hash = 0;        // IP 或 tag:IP 哈希 (0=空槽)
        uint32_t conns = 0;       // 当前连接数
        uint32_t auth_fails = 0;  // 认证失败计数
        uint32_t auth_ts = 0;     // 最后认证失败时间
        uint32_t ban_until = 0;   // 屏蔽解除时间

        [[nodiscard]] bool Match(uint64_t h) const noexcept { return hash == h; }
        [[nodiscard]] bool Empty() const noexcept { return hash == 0; }
        [[nodiscard]] bool Idle(uint32_t now) const noexcept {
            return conns == 0 && ban_until <= now;
        }
        void Reset(uint64_t h) noexcept {
            hash = h;
            conns = 0;
            auth_fails = 0;
            auth_ts = 0;
            ban_until = 0;
        }
    };
    static_assert(sizeof(Slot) == 24, "Slot must remain compact (24 bytes)");

public:
    enum class RejectReason : uint8_t {
        NONE = 0,
        MAX_CONNECTIONS,
        MAX_CONNECTIONS_PER_IP,
        IP_BANNED,
    };

    [[nodiscard]] static const char* RejectReasonToString(
        RejectReason r) noexcept {
        static constexpr const char* kNames[] = {
            "NONE", "MAX_CONNECTIONS", "MAX_CONNECTIONS_PER_IP", "IP_BANNED"};
        return kNames[static_cast<size_t>(r)];
    }

    ConnectionLimiter() = default;
    explicit ConnectionLimiter(const RateLimitConfig& cfg) noexcept
        : cfg_(cfg) {}

    [[nodiscard]] RejectReason TryAcceptGlobal() noexcept {
        if (cfg_.max_connections == 0) {
            return RejectReason::NONE;
        }
        if (total_ >= cfg_.max_connections) {
            return RejectReason::MAX_CONNECTIONS;
        }
        ++total_;
        return RejectReason::NONE;
    }

    [[nodiscard]] RejectReason TryAcceptIP(
        std::string_view tag,
        std::string_view ip,
        bool check_auth_ban = true) noexcept {
        const uint32_t now = Now();
        if (check_auth_ban && cfg_.auth_fail_limit > 0) {
            const uint64_t ban_h = HashPair(tag, ip);
            if (const Slot* ban_s = FindConst(ban_h)) {
                if (ban_s->ban_until > now) {
                    return RejectReason::IP_BANNED;
                }
            }
        }

        if (cfg_.max_conn_per_ip == 0) {
            return RejectReason::NONE;
        }

        const uint64_t h = Hash(ip);
        Slot* s = FindOrCreate(h, now);
        if (!s) {
            return RejectReason::NONE;
        }
        if (s->conns >= cfg_.max_conn_per_ip) {
            return RejectReason::MAX_CONNECTIONS_PER_IP;
        }
        ++s->conns;
        return RejectReason::NONE;
    }

    void ReleaseGlobal() noexcept {
        if (cfg_.max_connections > 0 && total_ > 0) {
            --total_;
        }
    }

    void ReleaseHash(uint64_t ip_hash) noexcept {
        if (cfg_.max_conn_per_ip > 0 && ip_hash != 0) {
            if (Slot* s = Find(ip_hash)) {
                if (s->conns > 0) {
                    --s->conns;
                }
            }
        }
        ReleaseGlobal();
    }

    void Release(std::string_view ip) noexcept {
        ReleaseHash(cfg_.max_conn_per_ip > 0 ? Hash(ip) : 0);
    }

    void OnAuthFailTracked(std::string_view tag, std::string_view ip) noexcept {
        if (cfg_.auth_fail_limit == 0) return;

        const uint64_t h = HashPair(tag, ip);
        const uint32_t now = Now();
        Slot* s = FindOrCreate(h, now);
        if (!s || s->ban_until > now) return;

        const uint32_t last = s->auth_ts;
        if (last == now) return;

        if (last > 0 && now - last > cfg_.auth_fail_window) {
            s->auth_fails = 0;
        }
        s->auth_ts = now;

        const uint32_t cnt = ++s->auth_fails;
        if (cnt >= cfg_.auth_fail_limit) {
            s->ban_until = now + cfg_.auth_ban_seconds;
            LOG_NET_WARN("[{}] IP {} banned for {}s (auth failures: {})",
                         tag, ip, cfg_.auth_ban_seconds, cnt);
            s->auth_fails = 0;
        }
    }

    [[nodiscard]] bool IsBanned(
        std::string_view tag, std::string_view ip) const noexcept {
        if (cfg_.auth_fail_limit == 0) return false;
        const uint64_t h = HashPair(tag, ip);
        const uint32_t now = Now();
        if (const Slot* s = FindConst(h)) {
            return s->ban_until > now;
        }
        return false;
    }

private:
    [[nodiscard]] Slot* Find(uint64_t h) noexcept {
        const size_t idx = h & kMask;
        for (size_t i = 0; i < kProbe; ++i) {
            Slot& s = slots_[(idx + i) & kMask];
            if (s.Match(h)) return &s;
            if (s.Empty()) return nullptr;
        }
        return nullptr;
    }

    [[nodiscard]] const Slot* FindConst(uint64_t h) const noexcept {
        const size_t idx = h & kMask;
        for (size_t i = 0; i < kProbe; ++i) {
            const Slot& s = slots_[(idx + i) & kMask];
            if (s.Match(h)) return &s;
            if (s.Empty()) return nullptr;
        }
        return nullptr;
    }

    [[nodiscard]] Slot* FindOrCreate(uint64_t h, uint32_t now) noexcept {
        const size_t idx = h & kMask;
        Slot* idle = nullptr;
        for (size_t i = 0; i < kProbe; ++i) {
            Slot& s = slots_[(idx + i) & kMask];
            if (s.Match(h)) return &s;
            if (s.Empty()) {
                s.hash = h;
                return &s;
            }
            if (!idle && s.Idle(now)) {
                idle = &s;
            }
        }
        if (idle) {
            idle->Reset(h);
            return idle;
        }
        return nullptr;
    }

    RateLimitConfig cfg_;
    uint32_t total_ = 0;
    std::array<Slot, kSlotCount> slots_{};
};

}  // namespace acpp
