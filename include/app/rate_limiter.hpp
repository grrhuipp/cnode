#pragma once

#include "infra/config_types.hpp"
#include "app/session_group_executor.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

// ============================================================================
// 进程级连接准入与认证失败封禁。唯一的有界表由全局准入协调器独占；
// 会话迁移不会产生新的全局或按 IP 配额。表与指纹实现位于
// src/app/connection_limiter_core.hpp 与 src/app/rate_limiter.cpp。
// ============================================================================

namespace app {

using AuthCredentialKey = std::array<uint8_t, 32>;

struct RateLimitConfig {
    uint32_t max_connections = 0; // 全局最大连接数 (0=不限制)
    uint32_t max_conn_per_ip = 0; // 单 IP 最大并发连接 (0=不限制)
    infra::AuthFailureLimitConfig ip_ban{};
};

// Lease shared by one physical connection and its logical children; carried in
// common::Inbound so protocol substreams reserve against the same family.
struct ConnectionFamily {
    size_t children = 0; // control-executor only
    bool physical = true;
};

class ConnectionLimiterCore;

// The control actor owns the only table. Reservations preallocate their return
// node before admission; destruction publishes metadata without allocation,
// waiting, or competing for bounded business-call capacity.
class ConnectionLimiter final : public std::enable_shared_from_this<ConnectionLimiter> {
public:
    enum class RejectReason : uint8_t {
        NONE = 0,
        MAX_CONNECTIONS,
        MAX_CONNECTIONS_PER_IP,
        IP_BANNED,
        CREDENTIAL_BANNED,
        TRACKING_CAPACITY,
    };
    [[nodiscard]] static const char* RejectReasonToString(RejectReason reason) noexcept;
    using Family = ConnectionFamily;
private:
    // 归还节点只在协调器上执行（PostReserved），实现见 rate_limiter.cpp。
    struct Return final : GroupCoordinator::ReservedOperation {
        std::shared_ptr<ConnectionLimiter> owner;
        std::shared_ptr<Family> family;
        uint64_t ip_hash = 0;
        bool physical = false;
        bool child = false;
        bool admitted = false;
        void Invoke() noexcept override;
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
        const RateLimitConfig& config, std::shared_ptr<GroupCoordinator> coordinator);
    ~ConnectionLimiter();
    ConnectionLimiter(const ConnectionLimiter&) = delete;
    ConnectionLimiter& operator=(const ConnectionLimiter&) = delete;

    enum class ReservationScope : uint8_t { Physical, ClientIp, Logical };
    struct ReservationRequest {
        ReservationScope scope;
        std::shared_ptr<Family> family{};
        std::string_view tag{};
        std::string_view ip{};
        bool check_ban = false;
    };
    [[nodiscard]] std::optional<net::awaitable<Admission>> TryReserve(ReservationRequest request);
    [[nodiscard]] bool TracksAuthBan() const noexcept { return config_.ip_ban.enabled; }
    // 任意 Worker 线程可调用：只读取构造后不变的指纹上下文。
    [[nodiscard]] AuthCredentialKey FingerprintCredential(
        std::string_view tag, std::span<const uint8_t> credential,
        uint64_t credential_revision) const noexcept;
    net::awaitable<RejectReason> CheckCredential(AuthCredentialKey credential);
    net::awaitable<bool> IsBanned(std::string_view tag, std::string_view ip);
    net::awaitable<void> OnAuthFailTracked(
        std::string_view tag, std::string_view ip,
        std::optional<AuthCredentialKey> credential = std::nullopt);
private:
    class Service;
    ConnectionLimiter(const RateLimitConfig& config, std::shared_ptr<GroupCoordinator> coordinator);
    net::awaitable<Admission> ReservePhysical(
        std::string_view tag, std::string_view ip, bool check_ban);
    net::awaitable<Admission> Reserve(std::shared_ptr<Family> family,
        std::string_view tag, std::string_view ip, bool check_ban);

    const RateLimitConfig config_;
    // 可变表只在协调器执行器上访问；指纹上下文构造后只读。
    const std::unique_ptr<ConnectionLimiterCore> core_;
    std::shared_ptr<GroupCoordinator> coordinator_;
};

}  // namespace app
