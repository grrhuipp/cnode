#pragma once

#include "udp_ingress.hpp"
#include "../../proxy/shadowsocks/ss_udp.hpp"

#include <atomic>
#include <unordered_map>

namespace acpp::worker_detail {

// Only authenticated identity, replay and ownership metadata live here. The
// receiving Worker retains the datagram; the coordinator never sees payload.
struct UdpHandoffIdentity {
    std::string listener;
    std::string tag;
    const void* configuration = nullptr;
    ClientSessionKey client;
    bool operator==(const UdpHandoffIdentity& other) const noexcept {
        return configuration == other.configuration && listener == other.listener &&
            tag == other.tag && client == other.client;
    }
};
struct UdpHandoffIdentityHash {
    size_t operator()(const UdpHandoffIdentity& key) const noexcept {
        auto hash = ClientSessionKeyHash{}(key.client);
        hash ^= std::hash<std::string>{}(key.listener) + (hash << 6) + (hash >> 2);
        hash ^= std::hash<std::string>{}(key.tag) + (hash << 6) + (hash >> 2);
        return hash ^ std::hash<const void*>{}(key.configuration);
    }
};
struct UdpHandoffRecord {
    ss::Ss2022UdpReplayWindow replay;
    // A claim blocks the old local fast path before its native owner is drained.
    std::atomic<bool> claimed{true};
    std::atomic<int64_t> last_seen{0};
    std::weak_ptr<UdpIngress::ClientSession> session;
    std::weak_ptr<ExecutionDomain> domain;
    // Coordinator-only fields.
    uint32_t owner = 0;
    std::shared_ptr<const void> configuration;

    // Replay permits unseen reordering on the current path. Changing the path
    // additionally requires a packet newer than every committed packet, so a
    // delayed old-address packet cannot steal either ownership or the reply route.
    bool CanAcceptPath(uint64_t packet_id, uint32_t worker,
                       const udp::endpoint& endpoint) const noexcept {
        return !path_packet_id_ || packet_id > *path_packet_id_ ||
            (worker == path_worker_ && endpoint == path_endpoint_);
    }

    bool Accept(uint64_t packet_id, uint32_t worker,
                const udp::endpoint& endpoint) noexcept {
        if (!CanAcceptPath(packet_id, worker, endpoint) || !replay.Accept(packet_id))
            return false;
        if (!path_packet_id_ || packet_id > *path_packet_id_) path_packet_id_ = packet_id;
        path_worker_ = worker;
        path_endpoint_ = endpoint;
        last_seen.store(std::chrono::steady_clock::now().time_since_epoch().count(),
                        std::memory_order_relaxed);
        return true;
    }
private:
    std::optional<uint64_t> path_packet_id_;
    uint32_t path_worker_ = 0;
    udp::endpoint path_endpoint_;
};
class UdpHandoffDirectory final : public net::execution_context::service {
public:
    inline static net::execution_context::id id;
    explicit UdpHandoffDirectory(net::execution_context& context) : service(context) {}

    // Called only on GroupCoordinator. A tombstone is retained after its live
    // association ends until the entire timestamp/replay protection expires.
    std::shared_ptr<UdpHandoffRecord> Claim(const UdpHandoffIdentity& key,
                                          std::shared_ptr<const void> configuration) {
        if (auto found = records_.find(key); found != records_.end()) {
            if (found->second->claimed.exchange(true, std::memory_order_acq_rel)) return {};
            return found->second;
        }
        if (records_.size() >= ss::Ss2022UdpReplayCache::kMaxSessions) {
            const auto expiry = (std::chrono::steady_clock::now() -
                ss::Ss2022UdpReplayCache::kRetention).time_since_epoch().count();
            for (auto it = records_.begin(); it != records_.end();) {
                const auto& row = *it->second;
                if (!row.claimed.load(std::memory_order_acquire) && row.session.expired() &&
                    row.last_seen.load(std::memory_order_relaxed) < expiry)
                    it = records_.erase(it);
                else ++it;
            }
            if (records_.size() >= ss::Ss2022UdpReplayCache::kMaxSessions) return {};
        }
        auto record = std::make_shared<UdpHandoffRecord>();
        record->configuration = std::move(configuration);
        records_.emplace(key, record);
        return record;
    }
private:
    void shutdown() override { records_.clear(); }
    std::unordered_map<UdpHandoffIdentity, std::shared_ptr<UdpHandoffRecord>,
                       UdpHandoffIdentityHash> records_;
};
} // namespace acpp::worker_detail
