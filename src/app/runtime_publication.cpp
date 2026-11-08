#include "app/runtime_publication.hpp"
#include "../common/awaitable_batch.hpp"

#include "app/prepared_inbound.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "app/worker.hpp"

#include <stdexcept>
#include <utility>


namespace {

using Store = proxyman::inbound::UserStore;

void ThrowIfStopping(const bool& stopping) {
    if (stopping) throw IoSystemError(net::error::operation_aborted);
}

// Leases are copied per Worker so a failed install keeps the source views for
// a later retry.
net::awaitable<void> InstallUserViews(
    net::any_io_executor executor,
    std::span<const std::unique_ptr<Worker>> workers,
    std::span<const Store::WorkerView> views,
    const bool& stopping) {
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers.size());
    for (size_t i = 0; i < workers.size(); ++i) {
        tasks.push_back([](Worker* worker, Store::WorkerView view,
                           const bool* stopping_flag) -> net::awaitable<void> {
            ThrowIfStopping(*stopping_flag);
            co_await worker->PostCall([worker, view = std::move(view)]() mutable {
                worker->InstallUserView(std::move(view));
            });
        }(workers[i].get(), views[i], &stopping));
    }
    co_await RunAwaitableBatch(std::move(executor), std::move(tasks));
}

}  // namespace

std::string_view InboundInstallFailureName(InboundInstallFailure failure) noexcept {
    switch (failure) {
        case InboundInstallFailure::None: return "none";
        case InboundInstallFailure::Register: return "register";
        case InboundInstallFailure::TcpListen: return "tcp-listen";
        case InboundInstallFailure::UdpListen: return "udp-listen";
    }
    return "unknown";
}

net::awaitable<InboundInstallFailure> InstallInbound(
    Worker& worker, const PreparedInbound& inbound) {
    if (!worker.RegisterInbound(inbound.build_request, inbound.receiver)) {
        co_return InboundInstallFailure::Register;
    }
    const bool quic_only =
        proxyman::inbound::RegisteredDatagramTransport(inbound.build_request.protocol) ==
        proxyman::inbound::DatagramTransport::Quic;
    if (!quic_only && !worker.AddListener(inbound.binding)) {
        co_return InboundInstallFailure::TcpListen;
    }
    if (!co_await worker.AddUdpListenerTask(inbound.binding, inbound.build_request)) {
        co_return InboundInstallFailure::UdpListen;
    }
    co_return InboundInstallFailure::None;
}

net::awaitable<void> PublishUsers(
    net::any_io_executor executor,
    std::span<const std::unique_ptr<Worker>> workers,
    Store::PublishedSnapshot candidate,
    std::optional<UserPublicationRollback>& rollback,
    const bool& stopping) {
    ThrowIfStopping(stopping);
    if (rollback) {
        throw std::logic_error("user publication requires completed compensation");
    }
    UserPublicationRollback prepared;
    prepared.previous = Store::CaptureSnapshot();
    prepared.worker_views.reserve(workers.size());
    std::vector<Store::WorkerView> candidate_views;
    candidate_views.reserve(workers.size());
    for (size_t i = 0; i < workers.size(); ++i) {
        prepared.worker_views.push_back(Store::PrepareWorkerView(prepared.previous));
        candidate_views.push_back(Store::PrepareWorkerView(candidate));
    }
    // Retain rollback leases before any mailbox can install a candidate.
    rollback = std::move(prepared);
    co_await InstallUserViews(executor, workers, candidate_views, stopping);
    ThrowIfStopping(stopping);
    Store::CommitSnapshot(std::move(candidate));
    rollback.reset();
}

net::awaitable<void> RollbackUsers(
    net::any_io_executor executor,
    std::span<const std::unique_ptr<Worker>> workers,
    std::optional<UserPublicationRollback>& rollback,
    const bool& stopping) {
    ThrowIfStopping(stopping);
    if (!rollback) co_return;
    co_await InstallUserViews(executor, workers, rollback->worker_views, stopping);
    ThrowIfStopping(stopping);
    Store::CommitSnapshot(rollback->previous);
    rollback.reset();
}

