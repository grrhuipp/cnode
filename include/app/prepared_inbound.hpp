#pragma once

#include "app/proxyman/inbound/prepared_config.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "common/asio_types.hpp"
#include "transport/internet/inbound_listen.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>


struct InboundSpec;
struct InboundUserSpec;
struct StaticInboundConfig;
class Worker;

// ============================================================================
// PortBinding - 端口绑定描述（Worker 独立监听时传递）
// ============================================================================
struct PortBinding {
    uint16_t    port     = 0;
    std::string protocol;           // "vmess" / "trojan"
    std::string tag;                // inbound tag
    InboundListen listen;
};

// Cold-path result shared by static and panel sources. Every field is
// immutable after preparation; Workers copy only what they install.
struct PreparedInbound {
    PortBinding binding;
    proxyman::inbound::ReceiverSettings receiver;
    proxyman::inbound::BuildRequest build_request;
    std::shared_ptr<const proxyman::inbound::UserSet> users;
};

// The single inbound builder: protocol settings, users, transport security,
// receiver settings and port binding. Throws std::invalid_argument on any
// invalid field; has no UserStore or Worker side effects.
[[nodiscard]] PreparedInbound PrepareInbound(const InboundSpec& spec);

// Rebuilds only the users of an already prepared inbound. Every user must be
// accepted; a partial authentication snapshot is rejected.
[[nodiscard]] std::shared_ptr<const proxyman::inbound::UserSet> PrepareInboundUsers(
    const proxyman::inbound::BuildRequest& request,
    std::span<const InboundUserSpec> users);

// Map every static source (plus the test inbound) to InboundSpec, validate the
// complete set, then prepare each through the shared inbound builder.
// Preparation has no UserStore or Worker side effects.
[[nodiscard]] std::vector<PreparedInbound> PrepareStartupInbounds(
    std::vector<StaticInboundConfig> sources, bool enable_test_mode);


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
