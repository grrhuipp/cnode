#include "app/rate_limiter.hpp"
#include "app/connection_limiter_core.hpp"

#include <mutex>
#include <stdexcept>
#include <utility>

// 每个协调器服务域至多发布一个限流器；各 Worker 在冷路径 Acquire 同一实例。
class app::ConnectionLimiter::Service final : public net::execution_context::service {
public:
    inline static net::execution_context::id id;
    explicit Service(net::execution_context& context) : service(context) {}
    std::shared_ptr<app::ConnectionLimiter> Acquire(
        const app::RateLimitConfig& config, std::shared_ptr<app::GroupCoordinator> coordinator) {
        const std::lock_guard lock(mutex_);
        if (auto existing = published_.lock()) {
            if (existing->coordinator_ != coordinator)
                throw std::logic_error("connection limiter coordinator mismatch");
            return existing;
        }
        auto limiter = std::shared_ptr<app::ConnectionLimiter>(
            new app::ConnectionLimiter(config, std::move(coordinator)));
        published_ = limiter;
        return limiter;
    }
private:
    void shutdown() override {
        const std::lock_guard lock(mutex_);
        published_.reset();
    }
    std::mutex mutex_;
    std::weak_ptr<app::ConnectionLimiter> published_;
};

namespace app {

const char* ConnectionLimiter::RejectReasonToString(RejectReason reason) noexcept {
    static constexpr const char* names[] = {
        "not rejected (NONE)",
        "total connection limit exceeded (MAX_CONNECTIONS)",
        "per-IP connection limit exceeded (MAX_CONNECTIONS_PER_IP)",
        "IP banned (IP_BANNED)",
        "credential banned (CREDENTIAL_BANNED)",
        "admission tracking capacity exhausted (TRACKING_CAPACITY)"};
    return names[static_cast<size_t>(reason)];
}

void ConnectionLimiter::Return::Invoke() noexcept {
    if (!admitted) return;
    auto& core = *owner->core_;
    if (ip_hash) core.ReleaseHash(ip_hash);
    if (physical) {
        family->physical = false;
        if (family->children == 0) core.ReleaseGlobal();
    } else if (child) {
        --family->children;
        if (family->children != 0 || !family->physical) core.ReleaseGlobal();
    }
}

std::shared_ptr<ConnectionLimiter> ConnectionLimiter::Acquire(
    const RateLimitConfig& config, std::shared_ptr<GroupCoordinator> coordinator) {
    if (!coordinator) throw std::invalid_argument("missing admission coordinator");
    auto& services = coordinator->Services();
    return net::use_service<Service>(services).Acquire(config, std::move(coordinator));
}

ConnectionLimiter::ConnectionLimiter(
    const RateLimitConfig& config, std::shared_ptr<GroupCoordinator> coordinator)
    : config_(config),
      core_(std::make_unique<ConnectionLimiterCore>(config)),
      coordinator_(std::move(coordinator)) {
    if (!coordinator_) throw std::invalid_argument("missing admission coordinator");
}

ConnectionLimiter::~ConnectionLimiter() = default;

std::optional<net::awaitable<ConnectionLimiter::Admission>> ConnectionLimiter::TryReserve(
    ReservationRequest request) {
    const bool tracks_ban = request.check_ban && core_->TracksAuthBan() && !request.ip.empty();
    if (request.scope == ReservationScope::Physical) {
        if (!core_->TracksGlobalConnections() && !tracks_ban) return std::nullopt;
        return ReservePhysical(request.tag, request.ip, request.check_ban);
    }
    const bool tracks_family = request.scope == ReservationScope::Logical &&
        request.family && core_->TracksGlobalConnections();
    if (!tracks_family && !core_->TracksIpConnections() && !tracks_ban)
        return std::nullopt;
    return Reserve(request.scope == ReservationScope::Logical ? std::move(request.family) : nullptr,
                   request.tag, request.ip, request.check_ban);
}

net::awaitable<ConnectionLimiter::Admission> ConnectionLimiter::ReservePhysical(
    std::string_view tag, std::string_view ip, bool check_ban) {
    const auto ban_key = check_ban ? core_->ComputeIpBanKey(tag, ip) : std::nullopt;
    auto node = std::make_unique<Return>();
    node->owner = shared_from_this();
    if (core_->TracksGlobalConnections()) {
        node->family = std::make_shared<Family>();
    }
    node->physical = true;
    auto reservation = Reservation(std::move(node));
    return coordinator_->PostCall(
        [reservation = std::move(reservation), ban_key]() mutable {
            auto& node = *reservation.node_;
            auto& core = *node.owner->core_;
            if (ban_key) {
                const auto reason = core.CheckIPBan(*ban_key);
                if (reason != RejectReason::NONE)
                    return Admission{reason, std::move(reservation)};
            }
            const auto reason = core.TryAcceptGlobal();
            node.admitted = (reason == RejectReason::NONE) && core.TracksGlobalConnections();
            return Admission{reason, std::move(reservation)};
        });
}


AuthCredentialKey ConnectionLimiter::FingerprintCredential(
    std::string_view tag, std::span<const uint8_t> credential,
    uint64_t credential_revision) const noexcept {
    return core_->FingerprintCredential(tag, credential, credential_revision);
}

net::awaitable<ConnectionLimiter::RejectReason> ConnectionLimiter::CheckCredential(
    AuthCredentialKey credential) {
    return coordinator_->PostCall(
        [self = shared_from_this(), credential] {
            return self->core_->CheckCredential(credential);
        });
}

net::awaitable<bool> ConnectionLimiter::IsBanned(std::string_view tag, std::string_view ip) {
    const auto ban_key = core_->ComputeIpBanKey(tag, ip);
    if (!ban_key)
        return []() -> net::awaitable<bool> { co_return false; }();
    return coordinator_->PostCall([self = shared_from_this(), ban_key = *ban_key] {
        return self->core_->CheckIPBan(ban_key) == RejectReason::IP_BANNED;
    });
}

net::awaitable<void> ConnectionLimiter::OnAuthFailTracked(
    std::string_view tag, std::string_view ip,
    std::optional<AuthCredentialKey> credential) {
    const auto ip_ban_key = core_->ComputeIpBanKey(tag, ip);
    if (!ip_ban_key && !credential)
        return []() -> net::awaitable<void> { co_return; }();
    return coordinator_->PostCall([self = shared_from_this(), ip_ban_key, credential] {
        self->core_->OnAuthFailTracked(ip_ban_key, credential);
    });
}

net::awaitable<ConnectionLimiter::Admission> ConnectionLimiter::Reserve(
    std::shared_ptr<Family> family, std::string_view tag, std::string_view ip,
    bool check_ban) {
    const auto ban_key = check_ban ? core_->ComputeIpBanKey(tag, ip) : std::nullopt;
    if (!core_->TracksGlobalConnections()) {
        family.reset();
    }
    const uint64_t ip_hash = core_->TracksIpConnections()
        ? ConnectionLimiterCore::IpHash(ip) : 0;
    auto node = std::make_unique<Return>();
    node->owner = shared_from_this();
    node->family = std::move(family);
    node->child = bool(node->family);
    auto reservation = Reservation(std::move(node));
    return coordinator_->PostCall([reservation = std::move(reservation),
        ip_hash, ban_key]() mutable {
        auto& node = *reservation.node_;
        auto& core = *node.owner->core_;
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

}  // namespace app
