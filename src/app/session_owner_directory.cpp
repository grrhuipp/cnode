#include "app/session_owner_directory.hpp"

#include "common/allocator.hpp"

#include <cstring>
#include <unordered_map>
#include <utility>

namespace app {
namespace {

struct SessionOwnerKeyHash {
    // Keys are digests: any eight of their bytes are uniformly distributed.
    [[nodiscard]] size_t operator()(const SessionOwnerKey& key) const noexcept {
        size_t hash;
        std::memcpy(&hash, key.data(), sizeof(hash));
        return hash;
    }
};

// Coordinator-owned: which Worker runs each cross-connection session.
class SessionOwnerDirectory final : public net::execution_context::service {
public:
    static net::execution_context::id id;
    explicit SessionOwnerDirectory(net::execution_context& context)
        : net::execution_context::service(context) {}

    // The current owner of `key`, and whether this claim made `candidate` it.
    SessionClaim Claim(const SessionOwnerKey& key, SessionOwner candidate,
                       std::unique_ptr<SessionOwnership::ReleaseOperation> release) {
        if (const auto found = entries_.find(key); found != entries_.end()) {
            return SessionClaim{.owner = found->second, .ownership = {}};
        }
        if (entries_.size() >= kCapacity) return SessionClaim{.owner = candidate, .ownership = {}};
        entries_.emplace(key, candidate);
        // Dropped undelivered, the claim releases what it registered.
        return SessionClaim{.owner = candidate, .ownership = SessionOwnership(std::move(release))};
    }

    void Release(const SessionOwnerKey& key, SessionOwner owner) noexcept {
        const auto found = entries_.find(key);
        if (found == entries_.end() || found->second != owner) return;
        entries_.erase(found);
        common::MaybeShrinkHashContainer(entries_);
    }

private:
    void shutdown() override { entries_.clear(); }

    static constexpr size_t kCapacity = 256 * 1024;
    std::unordered_map<SessionOwnerKey, SessionOwner, SessionOwnerKeyHash> entries_;
};

net::execution_context::id SessionOwnerDirectory::id;

SessionOwnerDirectory& Directory(GroupCoordinator& coordinator) {
    return net::use_service<SessionOwnerDirectory>(coordinator.Services());
}

}  // namespace

void SessionOwnership::ReleaseOperation::Invoke() noexcept {
    Directory(*coordinator).Release(key, owner);
}

void SessionOwnership::Release() noexcept {
    if (!release_) return;
    auto& coordinator = *release_->coordinator;
    coordinator.PostReserved(std::move(release_));
}

net::awaitable<SessionClaim> ClaimSessionOwner(
    GroupCoordinator& coordinator, const SessionOwnerKey& key, SessionOwner candidate) {
    auto release = std::make_unique<SessionOwnership::ReleaseOperation>();
    release->coordinator = &coordinator;
    release->key = key;
    release->owner = candidate;
    co_return co_await coordinator.PostCall(
        [&coordinator, key, candidate, release = std::move(release)]() mutable {
            return Directory(coordinator).Claim(key, candidate, std::move(release));
        });
}

}  // namespace app
