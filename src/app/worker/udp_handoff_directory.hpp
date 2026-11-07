#pragma once

#include "udp_ingress.hpp"

#include <atomic>
#include <unordered_map>

namespace acpp::worker_detail {

// Only authenticated identity and execution ownership metadata live here.
// Protocol continuity state is owned, but never interpreted, by this directory.
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
    std::unique_ptr<InboundDatagramAssociation> association;
    std::weak_ptr<UdpIngress::ClientSession> session;
    std::weak_ptr<ExecutionDomain> domain;
    // Coordinator-only fields.
    uint32_t owner = 0;
    std::shared_ptr<const void> configuration;

    explicit UdpHandoffRecord(const InboundDatagramAssociationPolicy& policy)
        : association(policy.create()) {}
};
class UdpHandoffDirectory final : public net::execution_context::service {
public:
    inline static net::execution_context::id id;
    explicit UdpHandoffDirectory(net::execution_context& context) : service(context) {}

    // Called only on GroupCoordinator. A tombstone is retained after its live
    // association ends until the entire timestamp/replay protection expires.
    std::shared_ptr<UdpHandoffRecord> Claim(const UdpHandoffIdentity& key,
                                          std::shared_ptr<const void> configuration,
                                          const InboundDatagramAssociationPolicy& policy) {
        if (auto found = records_.find(key); found != records_.end()) {
            if (&found->second->association->Policy() != &policy ||
                found->second->association->claimed.exchange(true, std::memory_order_acq_rel))
                return {};
            return found->second;
        }
        if (records_.size() >= policy.capacity) {
            const auto now = std::chrono::steady_clock::now();
            for (auto it = records_.begin(); it != records_.end();) {
                const auto& row = *it->second;
                if (!row.association->claimed.load(std::memory_order_acquire) &&
                    row.session.expired() && row.association->ProtectedUntil() < now)
                    it = records_.erase(it);
                else ++it;
            }
            if (records_.size() >= policy.capacity) return {};
        }
        auto record = std::make_shared<UdpHandoffRecord>(policy);
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
