#pragma once

// 全局准入协调器私有的 Sans-I/O 配额与封禁表；只有 rate_limiter.cpp 与
// 直接验证表语义的测试包含本头。

#include "app/rate_limiter.hpp"
#include "common/hash.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>

#include <mimalloc.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace auth_limit_detail {
// OpenSSL 的低层 SHA256 上下文可在栈上复制；EVP 每次构造上下文会分配内存。
class Fingerprint {
public:
    explicit Fingerprint(bool credential) {
        SHA256_Init(&initial_);
        constexpr std::string_view credential_namespace = "cnode/auth-credential";
        constexpr std::string_view ip_namespace = "cnode/auth-ip";
        const auto domain = credential ? credential_namespace : ip_namespace;
        SHA256_Update(&initial_, domain.data(), domain.size());
        if (credential) {
            std::array<uint8_t, 32> salt;
            if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
                throw std::runtime_error("authentication fingerprint randomness failed");
            }
            SHA256_Update(&initial_, salt.data(), salt.size());
            OPENSSL_cleanse(salt.data(), salt.size());
        }
    }
    ~Fingerprint() noexcept { OPENSSL_cleanse(&initial_, sizeof(initial_)); }

    [[nodiscard]] AuthCredentialKey Hash(
        std::string_view tag, std::span<const uint8_t> credential,
        uint64_t credential_revision) const noexcept {
        auto context = initial_;
        std::array<uint8_t, 8> revision{};
        for (auto& byte : revision) {
            byte = static_cast<uint8_t>(credential_revision);
            credential_revision >>= 8;
        }
        SHA256_Update(&context, revision.data(), revision.size());
        std::array<uint8_t, 8> length{};
        uint64_t remaining = tag.size();
        for (auto& byte : length) {
            byte = static_cast<uint8_t>(remaining);
            remaining >>= 8;
        }
        SHA256_Update(&context, length.data(), length.size());
        if (!tag.empty()) SHA256_Update(&context, tag.data(), tag.size());
        if (!credential.empty())
            SHA256_Update(&context, credential.data(), credential.size());
        AuthCredentialKey result;
        SHA256_Final(result.data(), &context);
        OPENSSL_cleanse(&context, sizeof(context));
        return result;
    }
private:
    SHA256_CTX initial_;
};
} // namespace auth_limit_detail

// Sans-I/O bounded model; mutable state belongs exclusively to the coordinator.
// 两个指纹上下文构造后只读，凭据指纹可由任意 Worker 线程计算。
class ConnectionLimiterCore {
public:
    static constexpr size_t kSlotCount = 16384;
    static constexpr size_t kProbe = 32;
    static constexpr AuthFailureLimitConfig kCredentialBan{
        .enabled = true, .failure_limit = 10, .window_seconds = 60, .ban_seconds = 180};

    using RejectReason = ConnectionLimiter::RejectReason;

    [[nodiscard]] static uint64_t NowSeconds() noexcept {
        using namespace std::chrono;
        return static_cast<uint64_t>(
            duration_cast<seconds>(steady_clock::now().time_since_epoch()).count());
    }

    explicit ConnectionLimiterCore(const RateLimitConfig& cfg)
        : cfg_(cfg),
          connections_(cfg.max_conn_per_ip ? AllocateZeroedTable<ConnectionSlots>() : nullptr),
          ip_failures_(cfg.ip_ban.enabled ? AllocateZeroedTable<FailureTable>() : nullptr),
          ip_fingerprint_(cfg.ip_ban.enabled
              ? std::optional<auth_limit_detail::Fingerprint>(std::in_place, false)
              : std::nullopt),
          credential_fingerprint_(true),
          credential_failures_(AllocateZeroedTable<FailureTable>()) {}

    [[nodiscard]] bool TracksGlobalConnections() const noexcept {
        return cfg_.max_connections > 0;
    }
    [[nodiscard]] bool TracksIpConnections() const noexcept {
        return cfg_.max_conn_per_ip > 0;
    }
    [[nodiscard]] bool TracksAuthBan() const noexcept { return cfg_.ip_ban.enabled; }

    // 原连接配额表仍为 16384 槽、最多 32 次探测，与两张失败表完全独立。
    [[nodiscard]] static constexpr uint64_t IpHash(std::string_view ip) noexcept {
        const auto hash = Fnv1a64(ip);
        return hash == 0 ? 1 : hash;
    }

    // 未启用 IP 封禁或来源为空时没有封禁键：空来源不得占用槽位或形成空 IP 封禁。
    [[nodiscard]] std::optional<AuthCredentialKey> ComputeIpBanKey(
        std::string_view tag, std::string_view ip) const noexcept {
        if (!TracksAuthBan() || ip.empty()) return std::nullopt;
        return ip_fingerprint_->Hash(tag, std::span(
            reinterpret_cast<const uint8_t*>(ip.data()), ip.size()), 0);
    }
    [[nodiscard]] AuthCredentialKey FingerprintCredential(
        std::string_view tag, std::span<const uint8_t> credential,
        uint64_t credential_revision) const noexcept {
        return credential_fingerprint_.Hash(tag, credential, credential_revision);
    }

    [[nodiscard]] RejectReason TryAcceptGlobal() noexcept {
        if (!TracksGlobalConnections()) return RejectReason::NONE;
        if (total_ >= cfg_.max_connections) return RejectReason::MAX_CONNECTIONS;
        ++total_;
        return RejectReason::NONE;
    }

    [[nodiscard]] RejectReason CheckIPBan(
        const AuthCredentialKey& ban_key, uint64_t now = NowSeconds()) const noexcept {
        if (!TracksAuthBan()) return RejectReason::NONE;
        return ip_failures_->Check(ban_key, cfg_.ip_ban, now, RejectReason::IP_BANNED);
    }

    [[nodiscard]] RejectReason TryAcceptIP(
        uint64_t ip_hash, const std::optional<AuthCredentialKey>& ban_key,
        uint64_t now = NowSeconds()) noexcept {
        if (ban_key) {
            const auto reason = CheckIPBan(*ban_key, now);
            if (reason != RejectReason::NONE) return reason;
        }
        if (!TracksIpConnections()) return RejectReason::NONE;
        auto* slot = FindOrCreateConnection(ip_hash);
        if (!slot) return RejectReason::TRACKING_CAPACITY;
        if (slot->conns >= cfg_.max_conn_per_ip)
            return RejectReason::MAX_CONNECTIONS_PER_IP;
        ++slot->conns;
        return RejectReason::NONE;
    }

    void ReleaseGlobal() noexcept {
        if (TracksGlobalConnections() && total_ > 0) --total_;
    }
    void ReleaseHash(uint64_t hash) noexcept {
        if (!TracksIpConnections() || hash == 0) return;
        const size_t index = hash & kMask;
        for (size_t i = 0; i < kProbe; ++i) {
            auto& slot = (*connections_)[(index + i) & kMask];
            if (slot.hash == hash) {
                if (slot.conns) --slot.conns;
                return;
            }
            if (slot.hash == 0) return;
        }
    }

    void OnAuthFailTracked(
        const std::optional<AuthCredentialKey>& ip_ban_key,
        std::optional<AuthCredentialKey> credential = std::nullopt,
        uint64_t now = NowSeconds()) noexcept {
        if (ip_ban_key && TracksAuthBan())
            ip_failures_->Record(*ip_ban_key, cfg_.ip_ban, now);
        if (credential)
            credential_failures_->Record(*credential, kCredentialBan, now);
    }

    [[nodiscard]] RejectReason CheckCredential(
        const AuthCredentialKey& credential, uint64_t now = NowSeconds()) const noexcept {
        return credential_failures_->Check(
            credential, kCredentialBan, now, RejectReason::CREDENTIAL_BANNED);
    }

private:
    static constexpr size_t kMask = kSlotCount - 1;
    static_assert((kSlotCount & kMask) == 0);

    // 以下表项类型的全零字节即空状态。
    struct ConnectionSlot {
        uint64_t hash;
        uint32_t conns;
    };
    using ConnectionSlots = std::array<ConnectionSlot, kSlotCount>;

    struct FailureCounter {
        uint64_t window_start;
        uint64_t ban_until;
        uint32_t failures;

        [[nodiscard]] bool Banned(uint64_t now) const noexcept { return now < ban_until; }
        [[nodiscard]] bool Expired(
            const AuthFailureLimitConfig& config, uint64_t now) const noexcept {
            return !Banned(now) &&
                (failures == 0 || now - window_start >= config.window_seconds);
        }
        void Record(const AuthFailureLimitConfig& config, uint64_t now) noexcept {
            if (Banned(now)) return; // 拒绝期内既不计数，也不续封。
            if (failures == 0 || now - window_start >= config.window_seconds) {
                failures = 0;
                window_start = now;
            }
            if (++failures >= config.failure_limit) {
                ban_until = now > std::numeric_limits<uint64_t>::max() - config.ban_seconds
                    ? std::numeric_limits<uint64_t>::max() : now + config.ban_seconds;
                failures = 0;
            }
        }
    };

    // 两个真实消费者共用固定窗口算法。每表上限 16384 个键，每次最多探测 32 槽；
    // 只在失败时插入，查询不插入。过期槽惰性复用，无扫描、锁或额外容器。
    // 探测范围没有可用槽时，未知键查询返回 TRACKING_CAPACITY（fail closed）。
    class FailureTable {
        struct Slot {
            AuthCredentialKey key;
            FailureCounter counter;
            bool occupied;
        };
        [[nodiscard]] static size_t Index(const AuthCredentialKey& key) noexcept {
            uint64_t hash;
            std::memcpy(&hash, key.data(), sizeof(hash));
            return hash & kMask;
        }
    public:
        [[nodiscard]] RejectReason Check(
            const AuthCredentialKey& key, const AuthFailureLimitConfig& config,
            uint64_t now, RejectReason banned) const noexcept {
            const size_t index = Index(key);
            bool available = false;
            for (size_t i = 0; i < kProbe; ++i) {
                const auto& slot = slots_[(index + i) & kMask];
                if (!slot.occupied) return RejectReason::NONE;
                if (slot.key == key)
                    return slot.counter.Banned(now) ? banned : RejectReason::NONE;
                available |= slot.counter.Expired(config, now);
            }
            return available ? RejectReason::NONE : RejectReason::TRACKING_CAPACITY;
        }
        void Record(const AuthCredentialKey& key, const AuthFailureLimitConfig& config,
                    uint64_t now) noexcept {
            const size_t index = Index(key);
            Slot* reusable = nullptr;
            for (size_t i = 0; i < kProbe; ++i) {
                auto& slot = slots_[(index + i) & kMask];
                if (slot.occupied && slot.key == key) {
                    slot.counter.Record(config, now);
                    return;
                }
                if (!slot.occupied) {
                    if (!reusable) reusable = &slot;
                    break;
                }
                if (!reusable && slot.counter.Expired(config, now)) reusable = &slot;
            }
            if (!reusable) return; // 后续准入查询将报告容量不足，而不是无保护放行。
            reusable->key = key;
            reusable->counter = {};
            reusable->occupied = true;
            reusable->counter.Record(config, now);
        }
    private:
        std::array<Slot, kSlotCount> slots_;
    };

    template <class Table>
    struct FreeTable {
        void operator()(Table* table) const noexcept { mi_free(table); }
    };
    template <class Table>
    using ZeroedTable = std::unique_ptr<Table, FreeTable<Table>>;
    template <class Table>
    [[nodiscard]] static ZeroedTable<Table> AllocateZeroedTable() {
        static_assert(std::is_trivially_default_constructible_v<Table> &&
                      std::is_trivially_destructible_v<Table>);
        void* memory = mi_zalloc_aligned(sizeof(Table), alignof(Table));
        if (!memory) throw std::bad_alloc();
        // 平凡默认初始化只开始对象生命周期，不覆盖分配器保证的全零存储。
        return ZeroedTable<Table>(::new (memory) Table);
    }

    [[nodiscard]] ConnectionSlot* FindOrCreateConnection(uint64_t hash) noexcept {
        const size_t index = hash & kMask;
        ConnectionSlot* idle = nullptr;
        for (size_t i = 0; i < kProbe; ++i) {
            auto& slot = (*connections_)[(index + i) & kMask];
            if (slot.hash == hash) return &slot;
            if (slot.hash == 0) {
                auto* selected = idle ? idle : &slot;
                *selected = {hash, 0};
                return selected;
            }
            if (!idle && slot.conns == 0) idle = &slot;
        }
        if (idle) *idle = {hash, 0};
        return idle;
    }

    const RateLimitConfig cfg_;
    uint32_t total_ = 0;
    ZeroedTable<ConnectionSlots> connections_;
    ZeroedTable<FailureTable> ip_failures_;
    const std::optional<auth_limit_detail::Fingerprint> ip_fingerprint_;
    const auth_limit_detail::Fingerprint credential_fingerprint_;
    ZeroedTable<FailureTable> credential_failures_;
};
