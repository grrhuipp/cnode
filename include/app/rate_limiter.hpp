#pragma once
#include "app/rate_limiter_fwd.hpp"
#include "common/allocator.hpp"
#include "app/session_group_executor.hpp"
// ============================================================================
// Process-wide connection/admission control. Session domains share this bounded
// table; migration never creates a new global or per-IP allowance.
// ============================================================================

#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string_view>
#include <utility>
#include <memory>
#include <mutex>
#include <string>
#include "infra/log.hpp"


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
// Sans-I/O bounded model, accessed only by its owning control executor.
// Production requests use ConnectionLimiter below, never this model directly.
class ConnectionLimiterCore {
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
        [[nodiscard]] bool Idle(uint32_t now, uint32_t auth_fail_window) const noexcept {
            return conns == 0 && ban_until <= now &&
                   (auth_fails == 0 || now - auth_ts > auth_fail_window);
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
    // 单 IP 连接槽位键（FNV-1a，0 保留为空槽）。
    [[nodiscard]] static constexpr uint64_t IpHash(std::string_view ip) noexcept {
        return NonZero(Fnv1a(kFnvOffset, ip));
    }

    enum class RejectReason : uint8_t {
        NONE = 0,
        MAX_CONNECTIONS,
        MAX_CONNECTIONS_PER_IP,
        IP_BANNED,
        TRACKING_CAPACITY,
    };

    [[nodiscard]] static const char* RejectReasonToString(
        RejectReason r) noexcept {
        static constexpr const char* kNames[] = {
            "not rejected (NONE)",
            "total connection limit exceeded (MAX_CONNECTIONS)",
            "per-IP connection limit exceeded (MAX_CONNECTIONS_PER_IP)",
            "IP banned (IP_BANNED)",
            "IP tracking capacity exhausted (TRACKING_CAPACITY)"};
        return kNames[static_cast<size_t>(r)];
    }

    explicit ConnectionLimiterCore(const RateLimitConfig& cfg) noexcept
        : cfg_(cfg) {}
    [[nodiscard]] bool TracksGlobalConnections() const noexcept {
        return cfg_.max_connections > 0;
    }

    [[nodiscard]] bool TracksIpConnections() const noexcept {
        return cfg_.max_conn_per_ip > 0;
    }

    [[nodiscard]] bool TracksAuthBan() const noexcept {
        return cfg_.auth_fail_limit > 0;
    }


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
        const uint32_t now = NowSeconds();
        if (check_auth_ban && cfg_.auth_fail_limit > 0) {
            const uint64_t ban_h = BanHash(tag, ip);
            if (const Slot* ban_s = Find(ban_h)) {
                if (ban_s->ban_until > now) {
                    return RejectReason::IP_BANNED;
                }
            }
        }

        if (cfg_.max_conn_per_ip == 0) {
            return RejectReason::NONE;
        }

        const uint64_t h = IpHash(ip);
        Slot* s = FindOrCreate(h, now);
        if (!s) {
            return RejectReason::TRACKING_CAPACITY;
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

    // IP reservations are independent of physical/logical global ownership.
    void ReleaseHash(uint64_t ip_hash) noexcept {
        if (cfg_.max_conn_per_ip > 0 && ip_hash != 0) {
            if (Slot* s = Find(ip_hash)) {
                if (s->conns > 0) {
                    --s->conns;
                }
            }
        }
    }

    void OnAuthFailTracked(std::string_view tag, std::string_view ip) noexcept {
        if (cfg_.auth_fail_limit == 0) return;

        const uint64_t h = BanHash(tag, ip);
        const uint32_t now = NowSeconds();
        Slot* s = FindOrCreate(h, now);
        if (!s || s->ban_until > now) return;

        const uint32_t last = s->auth_ts;
        if (last > 0 && now - last > cfg_.auth_fail_window) {
            s->auth_fails = 0;
        }
        s->auth_ts = now;

        const uint32_t cnt = ++s->auth_fails;
        if (cnt >= cfg_.auth_fail_limit) {
            s->ban_until = now > std::numeric_limits<uint32_t>::max() - cfg_.auth_ban_seconds
                ? std::numeric_limits<uint32_t>::max()
                : now + cfg_.auth_ban_seconds;
            LOG_NET_WARN("IP banned inbound={} source={} duration={}s authentication_failures={}",
                         tag, ip, cfg_.auth_ban_seconds, cnt);
            s->auth_fails = 0;
        }
    }

    [[nodiscard]] bool IsBanned(
        std::string_view tag, std::string_view ip) const noexcept {
        if (cfg_.auth_fail_limit == 0) return false;
        const uint64_t h = BanHash(tag, ip);
        const uint32_t now = NowSeconds();
        if (const Slot* s = Find(h)) {
            return s->ban_until > now;
        }
        return false;
    }

private:
    static constexpr uint64_t kFnvOffset = 14695981039346656037ULL;
    static constexpr uint64_t kFnvPrime = 1099511628211ULL;

    [[nodiscard]] static constexpr uint64_t Fnv1a(
        uint64_t h, std::string_view bytes) noexcept {
        for (const char ch : bytes) {
            h ^= static_cast<uint8_t>(ch);
            h *= kFnvPrime;
        }
        return h;
    }

    [[nodiscard]] static constexpr uint64_t NonZero(uint64_t h) noexcept {
        return h == 0 ? 1ULL : h;
    }

    // 认证屏蔽键与单 IP 连接键共用槽表：标签长度前缀使 (tag, ip) 编码单射，
    // 且其输入以 NUL 字节开头的长度编码，不会与纯文本 IP 键的输入流重合。
    [[nodiscard]] static constexpr uint64_t BanHash(
        std::string_view tag, std::string_view ip) noexcept {
        uint64_t h = kFnvOffset;
        uint64_t length = tag.size();
        for (size_t i = 0; i < sizeof(length); ++i, length >>= 8) {
            h ^= length & 0xFF;
            h *= kFnvPrime;
        }
        return NonZero(Fnv1a(Fnv1a(h, tag), ip));
    }

    [[nodiscard]] static uint32_t NowSeconds() noexcept {
        using namespace std::chrono;
        return static_cast<uint32_t>(
            duration_cast<seconds>(steady_clock::now().time_since_epoch()).count());
    }

    [[nodiscard]] Slot* Find(uint64_t h) noexcept {
        return const_cast<Slot*>(std::as_const(*this).Find(h));
    }

    [[nodiscard]] const Slot* Find(uint64_t h) const noexcept {
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
                if (idle) {
                    idle->Reset(h);
                    return idle;
                }
                s.Reset(h);
                return &s;
            }
            if (!idle && s.Idle(now, cfg_.auth_fail_window)) {
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
        auto node = std::make_unique<Return>();
        node->owner = shared_from_this();
        node->family = std::make_shared<Family>();
        node->physical = true;
        auto reservation = Reservation(std::move(node));
        return coordinator_->PostCall(
            [reservation = std::move(reservation),
             tag = std::string(check_ban ? tag : std::string_view{}),
             ip = std::string(check_ban ? ip : std::string_view{}),
             check_ban]() mutable {
                auto& node = *reservation.node_;
                if (check_ban && node.owner->core_.IsBanned(tag, ip)) {
                    return Admission{RejectReason::IP_BANNED, std::move(reservation)};
                }
                const auto reason = node.owner->core_.TryAcceptGlobal();
                node.admitted = reason == RejectReason::NONE;
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
    net::awaitable<bool> IsBanned(std::string_view tag, std::string_view ip) {
        return coordinator_->PostCall([self = shared_from_this(),
            tag = std::string(tag), ip = std::string(ip)] {
            return self->core_.IsBanned(tag, ip);
        });
    }
    net::awaitable<void> OnAuthFailTracked(std::string_view tag, std::string_view ip) {
        return coordinator_->PostCall([self = shared_from_this(),
            tag = std::string(tag), ip = std::string(ip)] {
            self->core_.OnAuthFailTracked(tag, ip);
        });
    }
    // The control coordinator that also owns session-level device admission
    // for runtimes without an execution domain (native UDP associations).
    [[nodiscard]] GroupCoordinator& Coordinator() const noexcept { return *coordinator_; }
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
        : core_(config), coordinator_(std::move(coordinator)) {
        if (!coordinator_) throw std::invalid_argument("missing admission coordinator");
    }
    net::awaitable<Admission> Reserve(std::shared_ptr<Family> family,
        std::string_view tag, std::string_view ip, bool check_ban) {
        auto node = std::make_unique<Return>();
        node->owner = shared_from_this();
        node->family = std::move(family);
        node->child = bool(node->family);
        auto reservation = Reservation(std::move(node));
        return coordinator_->PostCall([reservation = std::move(reservation),
            tag = std::string(check_ban && core_.TracksAuthBan() ? tag : std::string_view{}),
            ip = std::string(ip), check_ban]() mutable {
            auto& node = *reservation.node_;
            auto& core = node.owner->core_;
            const bool extra_global = node.child &&
                (node.family->children != 0 || !node.family->physical);
            auto reason = extra_global ? core.TryAcceptGlobal() : RejectReason::NONE;
            if (reason == RejectReason::NONE) {
                reason = core.TryAcceptIP(tag, ip, check_ban);
                if (reason != RejectReason::NONE && extra_global) core.ReleaseGlobal();
            }
            if (reason == RejectReason::NONE) {
                const bool tracked_ip = core.TracksIpConnections();
                if (tracked_ip) {
                    node.ip_hash = ConnectionLimiterCore::IpHash(ip);
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
    std::shared_ptr<GroupCoordinator> coordinator_;
};

