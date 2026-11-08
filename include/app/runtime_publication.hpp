#pragma once

#include "app/proxyman/inbound/user_store.hpp"
#include "common/asio_types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>


class Worker;
struct PreparedInbound;

// ============================================================================
// Worker inbound installation — shared by static startup and panel nodes.
// ============================================================================
enum class InboundInstallFailure : uint8_t {
    None,
    Register,
    TcpListen,
    UdpListen,
};

[[nodiscard]] std::string_view InboundInstallFailureName(InboundInstallFailure failure) noexcept;

// Runs on `worker`'s executor: register the handler, open the TCP listener
// unless the protocol is QUIC-only, then the UDP/QUIC listener. Stops at the
// first failed stage; the caller owns removal of the partially installed tag.
[[nodiscard]] net::awaitable<InboundInstallFailure> InstallInbound(
    Worker& worker, const PreparedInbound& inbound);

// ============================================================================
// User publication — shared by static startup and panel nodes.
// ============================================================================

// Rollback credentials of one publication, allocated before any Worker can
// install the candidate.
struct UserPublicationRollback {
    proxyman::inbound::UserStore::PublishedSnapshot previous;
    std::vector<proxyman::inbound::UserStore::WorkerView> worker_views;
};

// Prepares one candidate and one rollback view per Worker, records the
// rollback in `rollback`, installs the candidate on every Worker (joining every
// started install), commits the candidate and clears `rollback`. A failure
// leaves `rollback` set for RollbackUsers. Workers constructed after the commit
// capture the committed snapshot themselves, so static startup publishes with
// no Workers. `stopping` aborts before each Worker mutation and the commit.
net::awaitable<void> PublishUsers(
    net::any_io_executor executor,
    std::span<const std::unique_ptr<Worker>> workers,
    proxyman::inbound::UserStore::PublishedSnapshot candidate,
    std::optional<UserPublicationRollback>& rollback,
    const bool& stopping);

// Reinstalls and recommits a pending rollback; no-op when none is pending.
net::awaitable<void> RollbackUsers(
    net::any_io_executor executor,
    std::span<const std::unique_ptr<Worker>> workers,
    std::optional<UserPublicationRollback>& rollback,
    const bool& stopping);

