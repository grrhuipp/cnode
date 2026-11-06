#pragma once

#include "acppnode/app/session_group_executor.hpp"
#include <ngtcp2/ngtcp2.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace acpp::transport::internet::hysteria {
class Connection;

struct ConnectionId {
    std::array<uint8_t, NGTCP2_MAX_CIDLEN> bytes{};
    uint8_t size = 0;
    explicit ConnectionId(const ngtcp2_cid& cid) noexcept
        : ConnectionId(cid.data, cid.datalen) {}
    ConnectionId(const uint8_t* data, size_t length) noexcept
        : size(static_cast<uint8_t>(length)) {
        std::copy_n(data, length, bytes.begin());
    }
    bool operator==(const ConnectionId&) const noexcept = default;
};
struct ConnectionIdHash {
    size_t operator()(const ConnectionId& id) const noexcept {
        size_t hash = 1469598103934665603ULL;
        for (size_t i = 0; i < id.size; ++i) {
            hash ^= id.bytes[i];
            hash *= 1099511628211ULL;
        }
        return hash ^ id.size;
    }
};

struct QuicListenerIdentity {};
// Only identity/control metadata is shared. Received bytes always remain in
// the receiving listener; the directory never schedules or forwards a packet.
struct QuicOwnership {
    std::weak_ptr<Connection> connection;
    std::shared_ptr<ExecutionDomain> domain;
    std::atomic<uint32_t> owner{0};
    std::atomic<const QuicListenerIdentity*> listener{nullptr};
    std::atomic<bool> claiming{false};
    std::atomic<bool> retired{false};
    std::atomic<ngtcp2_tstamp> expiry{std::numeric_limits<ngtcp2_tstamp>::max()};
    std::vector<ConnectionId> ids; // directory mutex only
};

class QuicDirectory final : public net::execution_context::service {
public:
    inline static net::execution_context::id id;
    explicit QuicDirectory(net::execution_context& context) : service(context) {}
    bool Publish(const std::string& space, const ConnectionId& cid,
                 const std::shared_ptr<QuicOwnership>& record) {
        std::lock_guard lock(mutex_);
        if (record->retired.load()) return false;
        auto& entries = spaces_[space];
        auto found = entries.find(cid);
        if (found != entries.end()) return found->second == record;
        // Reserve the retirement list before making a CID externally visible.
        record->ids.push_back(cid);
        try { entries.emplace(cid, record); }
        catch (...) { record->ids.pop_back(); throw; }
        return true;
    }
    std::shared_ptr<QuicOwnership> Find(const std::string& space,
                                      const ConnectionId& cid) {
        std::lock_guard lock(mutex_);
        auto ns = spaces_.find(space);
        if (ns == spaces_.end()) return {};
        auto it = ns->second.find(cid);
        return it == ns->second.end() ? nullptr : it->second;
    }
    void Remove(const std::string& space, const ConnectionId& cid,
                const std::shared_ptr<QuicOwnership>& record) noexcept {
        std::lock_guard lock(mutex_);
        auto ns = spaces_.find(space);
        if (ns == spaces_.end()) return;
        auto it = ns->second.find(cid);
        if (it != ns->second.end() && it->second == record) ns->second.erase(it);
        std::erase(record->ids, cid);
        if (ns->second.empty()) spaces_.erase(ns);
    }
    void Retire(const std::string& space,
                const std::shared_ptr<QuicOwnership>& record) noexcept {
        std::lock_guard lock(mutex_);
        record->retired.store(true);
        auto ns = spaces_.find(space);
        if (ns != spaces_.end()) {
            for (const auto& cid : record->ids) {
                auto it = ns->second.find(cid);
                if (it != ns->second.end() && it->second == record) ns->second.erase(it);
            }
            if (ns->second.empty()) spaces_.erase(ns);
        }
        record->ids.clear();
    }
    std::vector<ConnectionId> Snapshot(const std::shared_ptr<QuicOwnership>& record) {
        std::lock_guard lock(mutex_);
        return record->ids;
    }
private:
    void shutdown() override { spaces_.clear(); }
    std::mutex mutex_;
    std::unordered_map<std::string,
        std::unordered_map<ConnectionId, std::shared_ptr<QuicOwnership>, ConnectionIdHash>> spaces_;
};
} // namespace acpp::transport::internet::hysteria
