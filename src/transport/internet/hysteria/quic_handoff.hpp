#pragma once

#include "app/session_group_executor.hpp"
#include <ngtcp2/ngtcp2.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

namespace transport::internet::hysteria {
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
    // Sequential consistency orders claim admission, retirement and the owner
    // change. A successful claim still requires the domain's exclusive lease.
    std::atomic<uint32_t> owner{0};
    std::atomic<const QuicListenerIdentity*> listener{nullptr};
    std::atomic<bool> claiming{false};
    std::atomic<bool> retired{false};
    std::atomic<ngtcp2_tstamp> expiry{std::numeric_limits<ngtcp2_tstamp>::max()};
    // Worker-local, never read by the directory. Prepare/Cancel drain the
    // publishing task before transferring this state or its socket send gate.
    std::vector<ConnectionId> published_ids;
    bool publishing = false;
    bool publication_pending = false;
};

// All methods run on GroupCoordinator::Reactor(), through its bounded mailbox
// or a retirement operation reserved before the connection is published.
// No packet, listener pointer, or Worker allocator enters this control index.
class QuicDirectory final : public net::execution_context::service {
public:
    inline static net::execution_context::id id;
    explicit QuicDirectory(net::execution_context& context) : service(context) {}

    bool Publish(const std::string& space, std::vector<ConnectionId> ids,
                 const std::shared_ptr<QuicOwnership>& owner) {
        if (owner->retired.load()) return false;
        auto& entries = spaces_[space];
        for (const auto& cid : ids) {
            auto found = entries.find(cid);
            if (found != entries.end() && found->second != owner) {
                if (entries.empty()) spaces_.erase(space);
                return false;
            }
        }
        std::unordered_map<QuicOwnership*, std::vector<ConnectionId>>::iterator record;
        bool inserted = false;
        try {
            std::tie(record, inserted) = records_.try_emplace(owner.get());
        } catch (...) {
            if (entries.empty()) spaces_.erase(space);
            throw;
        }
        auto& previous = record->second;
        try {
            for (const auto& cid : ids) entries.emplace(cid, owner);
        } catch (...) {
            for (const auto& cid : ids) {
                if (std::find(previous.begin(), previous.end(), cid) == previous.end())
                    entries.erase(cid);
            }
            if (inserted) records_.erase(record);
            if (entries.empty()) spaces_.erase(space);
            throw;
        }
        for (const auto& cid : previous) {
            if (std::find(ids.begin(), ids.end(), cid) == ids.end()) entries.erase(cid);
        }
        if (entries.empty()) spaces_.erase(space);
        previous.swap(ids);
        return true;
    }
    std::shared_ptr<QuicOwnership> Find(const std::string& space,
                                      const ConnectionId& cid) const {
        auto ns = spaces_.find(space);
        if (ns == spaces_.end()) return {};
        auto it = ns->second.find(cid);
        return it == ns->second.end() || it->second->retired.load() ? nullptr : it->second;
    }
    void Retire(const std::string& space,
                const std::shared_ptr<QuicOwnership>& owner) noexcept {
        auto record = records_.find(owner.get());
        if (record == records_.end()) return;
        auto ns = spaces_.find(space);
        if (ns != spaces_.end()) {
            for (const auto& cid : record->second) {
                auto it = ns->second.find(cid);
                if (it != ns->second.end() && it->second == owner) ns->second.erase(it);
            }
            if (ns->second.empty()) spaces_.erase(ns);
        }
        records_.erase(record);
    }
    struct Retirement final : GroupCoordinator::ReservedOperation {
        QuicDirectory& directory;
        std::string space;
        std::shared_ptr<QuicOwnership> owner;
        Retirement(QuicDirectory& directory_value, std::string space_value,
                   std::shared_ptr<QuicOwnership> owner_value)
            : directory(directory_value), space(std::move(space_value)),
              owner(std::move(owner_value)) {}
        void Invoke() noexcept override { directory.Retire(space, owner); }
    };
private:
    void shutdown() override { records_.clear(); spaces_.clear(); }
    std::unordered_map<QuicOwnership*, std::vector<ConnectionId>> records_;
    std::unordered_map<std::string,
        std::unordered_map<ConnectionId, std::shared_ptr<QuicOwnership>, ConnectionIdHash>> spaces_;
};
} // namespace transport::internet::hysteria
