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
        "credential banned (CREDENTIAL_BANNED)"};
    return names[static_cast<size_t>(reason)];
}

// 族底座计数：物理连接存活时，底座由物理连接与首个并发子流共用；之后每个
// 并发子流各加一份。最后一个持有者退出时归还底座。
void ConnectionLimiter::Return::Invoke() noexcept {
    if (!admitted) return;
    auto& core = *owner->core_;
    if (ip_hash) core.ReleaseHash(ip_hash);
    if (physical) {
        family->physical = false;
        if (family->children == 0) core.ReleaseGlobal();
        if (family->ip_children == 0) core.ReleaseHash(family->ip_hash);
    } else if (child) {
        --family->children;
        if (family->children != 0 || !family->physical) core.ReleaseGlobal();
        if (shares_family_ip) {
            --family->ip_children;
            if (family->ip_children != 0 || !family->physical) core.ReleaseHash(family->ip_hash);
        }
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
    const bool tracks_connections =
        core_->TracksGlobalConnections() || core_->TracksIpConnections();
    if (request.scope == ReservationScope::Physical ||
        request.scope == ReservationScope::PhysicalClientIp) {
        if (!tracks_connections && !tracks_ban) return std::nullopt;
        return ReservePhysical(request.tag, request.ip, request.check_ban,
            request.scope == ReservationScope::PhysicalClientIp && core_->TracksIpConnections());
    }
    const bool logical = request.scope == ReservationScope::Logical;
    const bool tracks_family = logical && request.family && core_->TracksGlobalConnections();
    if (!tracks_family && !core_->TracksIpConnections() && !tracks_ban)
        return std::nullopt;
    return Reserve(std::move(request.family), request.tag, request.ip, request.check_ban, logical);
}

// 只要跟踪任一连接配额，物理连接就持有族节点，供子流与握手后确定的转发地址
// 共用底座；节点总由物理连接归还。
net::awaitable<ConnectionLimiter::Admission> ConnectionLimiter::ReservePhysical(
    std::string_view tag, std::string_view ip, bool check_ban, bool client_ip) {
    const auto ban_key = check_ban ? core_->ComputeIpBanKey(tag, ip) : std::nullopt;
    if (!core_->TracksGlobalConnections() && !core_->TracksIpConnections()) {
        return coordinator_->PostCall(
            [self = shared_from_this(), ban_key]() {
                const auto reason = ban_key
                    ? self->core_->CheckIPBan(*ban_key)
                    : RejectReason::NONE;
                return Admission{reason, Reservation{}};
            });
    }
    const uint64_t ip_hash = client_ip ? ConnectionLimiterCore::IpHash(ip) : 0;
    auto node = std::make_unique<Return>();
    node->owner = shared_from_this();
    node->family = std::make_shared<Family>();
    node->physical = true;
    auto reservation = Reservation(std::move(node));
    return coordinator_->PostCall(
        [reservation = std::move(reservation), ban_key, ip_hash]() mutable {
            auto& node = *reservation.node_;
            auto& core = *node.owner->core_;
            if (ban_key) {
                const auto reason = core.CheckIPBan(*ban_key);
                if (reason != RejectReason::NONE)
                    return Admission{reason, std::move(reservation)};
            }
            auto reason = core.TryAcceptGlobal();
            if (reason == RejectReason::NONE && ip_hash) {
                const auto admitted_ip = core.TryAcceptIP(ip_hash, std::nullopt);
                reason = admitted_ip.reason;
                if (reason != RejectReason::NONE) core.ReleaseGlobal();
                else node.family->ip_hash = admitted_ip.charged_hash;
            }
            node.admitted = reason == RejectReason::NONE;
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

// Logical：族内子流。ClientIp 携带族时，是握手后才确定客户端地址（真实 IP
// 头）的物理连接补占按 IP 额度：成功即成为该族底座，由物理连接节点归还。
net::awaitable<ConnectionLimiter::Admission> ConnectionLimiter::Reserve(
    std::shared_ptr<Family> family, std::string_view tag, std::string_view ip,
    bool check_ban, bool logical) {
    const auto ban_key = check_ban ? core_->ComputeIpBanKey(tag, ip) : std::nullopt;
    if (!core_->TracksGlobalConnections() && !core_->TracksIpConnections()) {
        family.reset();
    }
    const uint64_t ip_hash = core_->TracksIpConnections()
        ? ConnectionLimiterCore::IpHash(ip) : 0;
    auto node = std::make_unique<Return>();
    node->owner = shared_from_this();
    node->family = std::move(family);
    node->child = logical && node->family;
    auto reservation = Reservation(std::move(node));
    return coordinator_->PostCall([reservation = std::move(reservation),
        ip_hash, ban_key]() mutable {
        auto& node = *reservation.node_;
        auto& core = *node.owner->core_;
        auto* family = node.family.get();
        const bool extra_global = node.child &&
            (family->children != 0 || !family->physical);
        // 与物理连接同地址的子流共用其按 IP 底座；底座已被占用时另加一份。
        const bool family_ip = node.child && ip_hash != 0 && family->ip_hash == ip_hash;
        const bool floor_ip = family_ip && family->ip_children == 0 && family->physical;
        auto reason = extra_global ? core.TryAcceptGlobal() : RejectReason::NONE;
        uint64_t charged_ip = 0;
        if (reason == RejectReason::NONE) {
            if (floor_ip) {
                reason = ban_key ? core.CheckIPBan(*ban_key) : RejectReason::NONE;
            } else {
                const auto admitted_ip = core.TryAcceptIP(ip_hash, ban_key);
                reason = admitted_ip.reason;
                charged_ip = admitted_ip.charged_hash;
            }
            if (reason != RejectReason::NONE && extra_global) core.ReleaseGlobal();
        }
        if (reason == RejectReason::NONE) {
            // 未计入槽位的额外子流不加入底座计数，归还时也不扣减任何槽位。
            if (floor_ip || (family_ip && charged_ip != 0)) {
                node.shares_family_ip = true;
                ++family->ip_children;
            } else if (!node.child && family && charged_ip != 0 &&
                       family->physical && family->ip_hash == 0) {
                family->ip_hash = charged_ip;
            } else {
                node.ip_hash = charged_ip;
            }
            if (node.child) {
                ++family->children;
            }
            node.admitted = node.child || node.ip_hash != 0;
        }
        return Admission{reason, std::move(reservation)};
    });
}

}  // namespace app
