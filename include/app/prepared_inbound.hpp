#pragma once

#include "app/proxyman/inbound_handler.hpp"
#include "app/proxyman/user_store.hpp"
#include "common/asio_types.hpp"
#include "transport/inbound_listen.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>


namespace infra {

struct InboundSpec;
struct InboundUserSpec;
struct StaticInboundConfig;

}  // namespace infra
namespace app {

class Worker;

// ============================================================================
// PortBinding - 端口绑定描述（Worker 独立监听时传递）
// ============================================================================
struct PortBinding {
    uint16_t    port     = 0;
    std::string protocol;           // "vmess" / "trojan"
    std::string tag;                // inbound tag
    transport::InboundListen listen;
};

// Cold-path result shared by static and panel sources. Every field is
// immutable after preparation; Workers copy only what they install.
struct PreparedInbound {
    PortBinding binding;
    ReceiverSettings receiver;
    BuildRequest build_request;
    std::shared_ptr<const UserSet> users;
};

// The single inbound builder: protocol settings, users, transport security,
// receiver settings and port binding. Throws std::invalid_argument on any
// invalid field; has no UserStore or Worker side effects.
[[nodiscard]] PreparedInbound PrepareInbound(const infra::InboundSpec& spec);

// Rebuilds only the users of an already prepared inbound. Every user must be
// accepted; a partial authentication snapshot is rejected.
[[nodiscard]] std::shared_ptr<const UserSet> PrepareInboundUsers(
    const BuildRequest& request,
    std::span<const infra::InboundUserSpec> users);

// Map every static source (plus the test inbound) to InboundSpec, validate the
// complete set, then prepare each through the shared inbound builder.
// Preparation has no UserStore or Worker side effects.
[[nodiscard]] std::vector<PreparedInbound> PrepareStartupInbounds(
    std::vector<infra::StaticInboundConfig> sources, bool enable_test_mode);


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
// 用户发布：静态启动与面板共用候选准备、提交及回滚凭据。
// ============================================================================

// Rollback credentials of one publication, allocated before any Worker can
// install the candidate.
struct UserPublicationRollback {
    UserStore::PublishedSnapshot previous;
    std::vector<UserStore::WorkerView> worker_views;
};

// 一次发布的候选与回滚凭据。全部在任何 Worker 变更与提交之前分配完成。
struct PreparedUserPublication {
    UserStore::PublishedSnapshot candidate;
    std::vector<UserStore::WorkerView> candidate_views;
    UserPublicationRollback rollback;
    void Commit();
};

// 捕获当前已提交快照作为回滚点，并为候选与回滚各准备 `worker_count` 份 Worker
// 视图；只分配，不改动 UserStore 或任何 Worker。静态启动在 Worker 构造前以
// worker_count = 0 调用并经 Commit 提交候选，之后 Worker 捕获已提交快照；
// 启动失败时由调用方重新提交 `rollback.previous`。
[[nodiscard]] PreparedUserPublication PrepareUserPublication(
    UserStore::PublishedSnapshot candidate, size_t worker_count);

// 面板节点：经 PrepareUserPublication 准备后把回滚凭据记入 `rollback`，在每个
// Worker 安装候选视图（等待全部已启动的安装结束），提交候选并清空 `rollback`。
// 失败时 `rollback` 保持待补偿状态，交给 RollbackUsers。`stopping` 在每次 Worker
// 变更与提交前中止发布。
net::awaitable<void> PublishUsers(
    net::any_io_executor executor,
    std::span<const std::unique_ptr<Worker>> workers,
    UserStore::PublishedSnapshot candidate,
    std::optional<UserPublicationRollback>& rollback,
    const bool& stopping);

// Reinstalls and recommits a pending rollback; no-op when none is pending.
net::awaitable<void> RollbackUsers(
    net::any_io_executor executor,
    std::span<const std::unique_ptr<Worker>> workers,
    std::optional<UserPublicationRollback>& rollback,
    const bool& stopping);

}  // namespace app
