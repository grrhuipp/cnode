#pragma once

#include "app/group_coordinator.hpp"
#include "common/asio_types.hpp"

#include <array>
#include <cstdint>
#include <memory>

namespace app {

// Names one cross-connection session (an SS2022 session ID, an XUDP Global
// ID) process-wide: a digest of its namespace and identity, so the directory
// keeps no credential bytes.
using SessionOwnerKey = std::array<uint8_t, 32>;

// The Worker (mesh index) running a session, and the token naming the session
// in that Worker's mesh messages.
struct SessionOwner {
    uint32_t worker = 0;
    uint64_t token = 0;

    bool operator==(const SessionOwner&) const = default;
};

struct SessionClaim;

// The first Worker to claim `key` owns it until its ownership is released;
// later claims learn that owner. Runs on the coordinator; resumes on the
// caller's executor.
[[nodiscard]] net::awaitable<SessionClaim> ClaimSessionOwner(
    GroupCoordinator& coordinator, const SessionOwnerKey& key, SessionOwner candidate);

// Held by the owning Worker for as long as its session runs. Releasing posts
// the removal reserved at claim time, so it neither allocates nor fails.
class SessionOwnership final {
public:
    // The coordinator outlives every Worker session, as for all reserved
    // operations.
    struct ReleaseOperation final : GroupCoordinator::ReservedOperation {
        GroupCoordinator* coordinator = nullptr;
        SessionOwnerKey key{};
        SessionOwner owner;
        void Invoke() noexcept;
    };

    SessionOwnership() noexcept = default;
    explicit SessionOwnership(std::unique_ptr<ReleaseOperation> release) noexcept
        : release_(std::move(release)) {}
    ~SessionOwnership() { Release(); }
    SessionOwnership(SessionOwnership&& other) noexcept = default;
    SessionOwnership& operator=(SessionOwnership&& other) noexcept {
        if (this != &other) {
            Release();
            release_ = std::move(other.release_);
        }
        return *this;
    }
    SessionOwnership(const SessionOwnership&) = delete;
    SessionOwnership& operator=(const SessionOwnership&) = delete;

    [[nodiscard]] explicit operator bool() const noexcept { return release_ != nullptr; }
    void Release() noexcept;
    // Execution-context shutdown, the directory going with it: drops the
    // ownership without posting its removal.
    void Discard() noexcept { release_.reset(); }

private:
    std::unique_ptr<ReleaseOperation> release_;
};

struct SessionClaim {
    // Who runs the session now.
    SessionOwner owner;
    // Set when this claim made the candidate the owner. Empty with
    // owner == candidate when the directory is full: the session then runs
    // without cross-Worker continuity.
    SessionOwnership ownership;
};

}  // namespace app
