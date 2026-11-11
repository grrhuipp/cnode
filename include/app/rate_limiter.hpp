#pragma once
class ConnectionLimiter;
struct ConnectionFamily;
#include "common/defaults.hpp"
#include "common/hash.hpp"
#include "app/session_group_executor.hpp"
// ============================================================================
// Process-wide connection/admission control. Session domains share this bounded
// table; migration never creates a new global or per-IP allowance.
// ============================================================================

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string_view>
#include <utility>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <new>
#include <mimalloc.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using AuthCredentialKey = std::array<uint8_t, 32>;

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

struct RateLimitConfig {
    uint32_t max_connections = 0; // 全局最大连接数 (0=不限制)
    uint32_t max_conn_per_ip = 0; // 单 IP 最大并发连接 (0=不限制)
    AuthFailureLimitConfig ip_ban{};
};

// Sans-I/O bounded model; mutable state belongs exclusively to the coordinator.
class ConnectionLimiterCore {
public:
    static constexpr size_t kSlotCount = 16384;
    static constexpr size_t kProbe = 32;
    static constexpr AuthFailureLimitConfig kCredentialBan{
        .enabled = true, .failure_limit = 10, .window_seconds = 60, .ban_seconds = 180};

    enum class RejectReason : uint8_t {
        NONE = 0,
        MAX_CONNECTIONS,
        MAX_CONNECTIONS_PER_IP,
        IP_BANNED,
        CREDENTIAL_BANNED,
        TRACKING_CAPACITY,
    };

    [[nodiscard]] static const char* RejectReasonToString(RejectReason r) noexcept {
        static constexpr const char* names[] = {
            "not rejected (NONE)",
            "total connection limit exceeded (MAX_CONNECTIONS)",
            "per-IP connection limit exceeded (MAX_CONNECTIONS_PER_IP)",
            "IP banned (IP_BANNED)",
            "credential banned (CREDENTIAL_BANNED)",
            "admission tracking capacity exhausted (TRACKING_CAPACITY)"};
        return names[static_cast<size_t>(r)];
    }

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

    [[nodiscard]] AuthCredentialKey IpBanKey(
        std::string_view tag, std::string_view ip) const noexcept {
        return ip_fingerprint_->Hash(tag, std::span(
            reinterpret_cast<const uint8_t*>(ip.data()), ip.size()), 0);
    }
    [[nodiscard]] std::optional<AuthCredentialKey> ComputeIpBanKey(
        std::string_view tag, std::string_view ip) const noexcept {
        if (!TracksAuthBan() || ip.empty()) return std::nullopt;
        return IpBanKey(tag, ip);
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
    [[nodiscard]] RejectReason CheckIPBan(
        std::string_view tag, std::string_view ip, uint64_t now = NowSeconds()) const noexcept {
        if (!TracksAuthBan() || ip.empty()) return RejectReason::NONE;
        return CheckIPBan(IpBanKey(tag, ip), now);
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
    [[nodiscard]] RejectReason TryAcceptIP(
        std::string_view tag, std::string_view ip, bool check_auth_ban = true,
        uint64_t now = NowSeconds()) noexcept {
        return TryAcceptIP(
            TracksIpConnections() ? IpHash(ip) : 0,
            check_auth_ban ? ComputeIpBanKey(tag, ip) : std::nullopt,
            now);
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
    void OnAuthFailTracked(
        std::string_view tag, std::string_view ip,
        std::optional<AuthCredentialKey> credential = std::nullopt,
        uint64_t now = NowSeconds()) noexcept {
        OnAuthFailTracked(ComputeIpBanKey(tag, ip), credential, now);
    }

    [[nodiscard]] bool IsBanned(
        std::string_view tag, std::string_view ip, uint64_t now = NowSeconds()) const noexcept {
        return CheckIPBan(tag, ip, now) == RejectReason::IP_BANNED;
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
    ZeroedTable<FailureTable> credential_failures_;
};

// Lease shared by one physical connection and its logical children; carried in
// session::Inbound so protocol substreams reserve against the same family.
struct ConnectionFamily {
    size_t children = 0; // control-executor only
    bool physical = true;
};

// The control actor owns the only table. Reservations preallocate their return
// node before admission; destruction publishes metadata without allocation,
// waiting, or competing for bounded business-call capacity.
class ConnectionLimiter final : public std::enable_shared_from_this<ConnectionLimiter> {
public:
    using RejectReason = ConnectionLimiterCore::RejectReason;
    static const char* RejectReasonToString(RejectReason reason) noexcept {
        return ConnectionLimiterCore::RejectReasonToString(reason);
    }
    using Family = ConnectionFamily;
private:
    struct Return final : GroupCoordinator::ReservedOperation {
        std::shared_ptr<ConnectionLimiter> owner;
        std::shared_ptr<Family> family;
        uint64_t ip_hash = 0;
        bool physical = false;
        bool child = false;
        bool admitted = false;
        void Invoke() noexcept override {
            if (!admitted) return;
            if (ip_hash) owner->core_.ReleaseHash(ip_hash);
            if (physical) {
                family->physical = false;
                if (family->children == 0) owner->core_.ReleaseGlobal();
            } else if (child) {
                --family->children;
                if (family->children != 0 || !family->physical) owner->core_.ReleaseGlobal();
            }
        }
    };
public:
    class Reservation {
    public:
        Reservation() = default;
        Reservation(Reservation&&) noexcept = default;
        Reservation& operator=(Reservation&& other) noexcept {
            Reset();
            node_ = std::move(other.node_);
            return *this;
        }
        Reservation(const Reservation&) = delete;
        Reservation& operator=(const Reservation&) = delete;
        ~Reservation() { Reset(); }
        [[nodiscard]] const std::shared_ptr<Family>& FamilyLease() const noexcept {
            static const std::shared_ptr<Family> kEmpty{};
            return node_ ? node_->family : kEmpty;
        }
    private:
        friend class ConnectionLimiter;
        explicit Reservation(std::unique_ptr<Return> node) : node_(std::move(node)) {}
        void Reset() noexcept {
            if (!node_) return;
            if (!node_->admitted) { node_.reset(); return; }
            auto coordinator = node_->owner->coordinator_;
            coordinator->PostReserved(std::move(node_));
        }
        std::unique_ptr<Return> node_;
    };
    struct Admission {
        RejectReason reason = RejectReason::NONE;
        Reservation reservation;
    };

    static std::shared_ptr<ConnectionLimiter> Acquire(
        const RateLimitConfig& config, std::shared_ptr<GroupCoordinator> coordinator) {
        if (!coordinator) throw std::invalid_argument("missing admission coordinator");
        auto& services = coordinator->Services();
        return net::use_service<Service>(services).Acquire(config, std::move(coordinator));
    }

    net::awaitable<Admission> ReservePhysical(
        std::string_view tag = {}, std::string_view ip = {},
        bool check_ban = false) {
        const auto ban_key = check_ban ? core_.ComputeIpBanKey(tag, ip) : std::nullopt;
        if (!core_.TracksGlobalConnections() && !ban_key) {
            return []() -> net::awaitable<Admission> {
                co_return Admission{RejectReason::NONE, {}};
            }();
        }
        auto node = std::make_unique<Return>();
        node->owner = shared_from_this();
        if (core_.TracksGlobalConnections()) {
            node->family = std::make_shared<Family>();
        }
        node->physical = true;
        auto reservation = Reservation(std::move(node));
        return coordinator_->PostCall(
            [reservation = std::move(reservation), ban_key]() mutable {
                auto& node = *reservation.node_;
                if (ban_key) {
                    const auto reason = node.owner->core_.CheckIPBan(*ban_key);
                    if (reason != RejectReason::NONE)
                        return Admission{reason, std::move(reservation)};
                }
                const auto reason = node.owner->core_.TryAcceptGlobal();
                node.admitted = (reason == RejectReason::NONE) &&
                    node.owner->core_.TracksGlobalConnections();
                return Admission{reason, std::move(reservation)};
            });
    }

    net::awaitable<Admission> ReserveIP(std::string_view tag, std::string_view ip,
                                      bool check_ban) {
        return Reserve({}, tag, ip, check_ban);
    }
    net::awaitable<Admission> ReserveLogical(std::shared_ptr<Family> family,
        std::string_view tag, std::string_view ip, bool check_ban) {
        return Reserve(std::move(family), tag, ip, check_ban);
    }
    [[nodiscard]] bool TracksAuthBan() const noexcept { return core_.TracksAuthBan(); }
    // False when no quota or ban table is configured: every Reserve* call
    // would return an empty admission, so callers skip the coroutine.
    [[nodiscard]] bool TracksAdmission() const noexcept {
        return core_.TracksGlobalConnections() || core_.TracksIpConnections() ||
               core_.TracksAuthBan();
    }
    [[nodiscard]] AuthCredentialKey FingerprintCredential(
        std::string_view tag, std::span<const uint8_t> credential,
        uint64_t credential_revision) const noexcept {
        return credential_fingerprint_.Hash(tag, credential, credential_revision);
    }
    net::awaitable<RejectReason> CheckCredential(AuthCredentialKey credential) {
        return coordinator_->PostCall(
            [self = shared_from_this(), credential] {
                return self->core_.CheckCredential(credential);
            });
    }
    net::awaitable<bool> IsBanned(std::string_view tag, std::string_view ip) {
        const auto ban_key = core_.ComputeIpBanKey(tag, ip);
        if (!ban_key)
            return []() -> net::awaitable<bool> { co_return false; }();
        return coordinator_->PostCall([self = shared_from_this(), ban_key = *ban_key] {
            return self->core_.CheckIPBan(ban_key) == RejectReason::IP_BANNED;
        });
    }
    net::awaitable<void> OnAuthFailTracked(
        std::string_view tag, std::string_view ip,
        std::optional<AuthCredentialKey> credential = std::nullopt) {
        const auto ip_ban_key = core_.ComputeIpBanKey(tag, ip);
        if (!ip_ban_key && !credential)
            return []() -> net::awaitable<void> { co_return; }();
        return coordinator_->PostCall([self = shared_from_this(), ip_ban_key, credential] {
            self->core_.OnAuthFailTracked(ip_ban_key, credential);
        });
    }
private:
    class Service final : public net::execution_context::service {
    public:
        inline static net::execution_context::id id;
        explicit Service(net::execution_context& context) : service(context) {}
        std::shared_ptr<ConnectionLimiter> Acquire(
            const RateLimitConfig& config, std::shared_ptr<GroupCoordinator> coordinator) {
            const std::lock_guard lock(mutex_);
            if (auto existing = published_.lock()) {
                if (existing->coordinator_ != coordinator)
                    throw std::logic_error("connection limiter coordinator mismatch");
                return existing;
            }
            auto limiter = std::shared_ptr<ConnectionLimiter>(
                new ConnectionLimiter(config, std::move(coordinator)));
            published_ = limiter;
            return limiter;
        }
    private:
        void shutdown() override {
            const std::lock_guard lock(mutex_);
            published_.reset();
        }
        std::mutex mutex_;
        std::weak_ptr<ConnectionLimiter> published_;
    };
    ConnectionLimiter(const RateLimitConfig& config, std::shared_ptr<GroupCoordinator> coordinator)
        : core_(config), credential_fingerprint_(true), coordinator_(std::move(coordinator)) {
        if (!coordinator_) throw std::invalid_argument("missing admission coordinator");
    }
    net::awaitable<Admission> Reserve(std::shared_ptr<Family> family,
        std::string_view tag, std::string_view ip, bool check_ban) {
        const auto ban_key = check_ban ? core_.ComputeIpBanKey(tag, ip) : std::nullopt;
        if (!core_.TracksGlobalConnections()) {
            family.reset();
        }
        if (!core_.TracksGlobalConnections() && !core_.TracksIpConnections() && !ban_key) {
            return []() -> net::awaitable<Admission> {
                co_return Admission{RejectReason::NONE, {}};
            }();
        }
        const uint64_t ip_hash = core_.TracksIpConnections()
            ? ConnectionLimiterCore::IpHash(ip) : 0;
        auto node = std::make_unique<Return>();
        node->owner = shared_from_this();
        node->family = std::move(family);
        node->child = bool(node->family);
        auto reservation = Reservation(std::move(node));
        return coordinator_->PostCall([reservation = std::move(reservation),
            ip_hash, ban_key]() mutable {
            auto& node = *reservation.node_;
            auto& core = node.owner->core_;
            const bool extra_global = node.child &&
                (node.family->children != 0 || !node.family->physical);
            auto reason = extra_global ? core.TryAcceptGlobal() : RejectReason::NONE;
            if (reason == RejectReason::NONE) {
                reason = core.TryAcceptIP(ip_hash, ban_key);
                if (reason != RejectReason::NONE && extra_global) core.ReleaseGlobal();
            }
            if (reason == RejectReason::NONE) {
                const bool tracked_ip = core.TracksIpConnections();
                if (tracked_ip) {
                    node.ip_hash = ip_hash;
                }
                if (node.child) {
                    ++node.family->children;
                }
                node.admitted =
                    (extra_global && core.TracksGlobalConnections()) ||
                    node.child || tracked_ip;
            }
            return Admission{reason, std::move(reservation)};
        });
    }
    ConnectionLimiterCore core_;
    const auth_limit_detail::Fingerprint credential_fingerprint_;
    std::shared_ptr<GroupCoordinator> coordinator_;
};

