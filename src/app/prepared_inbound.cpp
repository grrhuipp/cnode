#include "app/prepared_inbound.hpp"

#include "../common/awaitable_batch.hpp"
#include "infra/config.hpp"
#include "app/worker.hpp"
#include "core/constants.hpp"
#include "infra/config_types.hpp"
#include "transport/internet/stream_settings.hpp"

#include <stdexcept>
#include <utility>
#include <variant>


std::shared_ptr<const proxyman::inbound::UserSet> PrepareInboundUsers(
    const proxyman::inbound::BuildRequest& request,
    std::span<const InboundUserSpec> users) {
    auto prepared = proxyman::inbound::BuildUsers(request, users);
    if (!prepared) {
        throw std::invalid_argument(
            "inbound '" + request.tag + "' has invalid users");
    }
    const size_t count = std::visit(
        [](const auto& values) { return values.size(); }, *prepared);
    if (count != users.size()) {
        throw std::invalid_argument(
            "inbound '" + request.tag + "' has an incomplete user snapshot");
    }
    return std::make_shared<const proxyman::inbound::UserSet>(std::move(*prepared));
}

PreparedInbound PrepareInbound(const InboundSpec& spec) {
    if (!proxyman::inbound::HasProxy(spec.protocol)) {
        throw std::invalid_argument(
            "inbound '" + spec.tag + "' has unsupported protocol '" +
            spec.protocol + "'");
    }
    auto build_request = proxyman::inbound::PrepareBuildRequest(
        spec.protocol, spec.tag, spec.settings);
    if (!build_request) {
        throw std::invalid_argument(
            "inbound '" + spec.tag + "' has invalid protocol settings");
    }
    auto users = PrepareInboundUsers(*build_request, spec.users);

    StreamSettings stream_settings = spec.stream_settings;
    TransportSecurity::Prepare(stream_settings, StreamEndpointRole::Inbound);

    return PreparedInbound{
        .binding = PortBinding{
            .port = spec.port,
            .protocol = spec.protocol,
            .tag = spec.tag,
            .listen = spec.listen,
        },
        .receiver = proxyman::inbound::MakeReceiverSettings(
            spec.tag,
            spec.all_tags,
            spec.protocol,
            std::move(stream_settings),
            spec.sniffing,
            spec.proxy_protocol,
            spec.outbound_policy,
            spec.accounting_key),
        .build_request = std::move(*build_request),
        .users = std::move(users),
    };
}

namespace {

StaticInboundConfig MakeTestInboundConfig() {
    StaticInboundConfig source;
    source.protocol = constants::protocol::kDefaultNodeProtocol;
    source.tags.emplace_back(constants::test::kTestInboundTag);
    source.port = constants::test::kTestPort;
    // The ordinary StreamSettings and SniffConfig defaults are already normalized.
    source.users.push_back(InboundUserSpec{
        .user_id = 0,
        .email = "test@example.com",
        .credential = std::string(constants::test::kTestVmessUuid),
        .flow = {},
        .speed_limit = 0,
        .device_limit = 0,
    });
    return source;
}

// Static-only mapping: tag fallback, outbound selection and the per-user
// email default. Everything else passes through unchanged.
InboundSpec StaticInboundSpec(StaticInboundConfig source) {
    std::string tag = source.tags.empty()
        ? naming::BuildProtocolPortTag(source.protocol, source.port)
        : source.tags.front();
    std::vector<std::string> all_tags = source.tags.empty()
        ? std::vector<std::string>{tag}
        : std::move(source.tags);
    routing::OutboundSelectionPolicy outbound_policy = source.outbound_tag
        ? routing::OutboundSelectionPolicy{routing::ForceOutbound(*source.outbound_tag)}
        : (source.routing_enabled
            ? routing::OutboundSelectionPolicy{routing::RouteWithFallback(
                std::string(constants::protocol::kDirect))}
            : routing::OutboundSelectionPolicy{routing::ForceOutbound(
                std::string(constants::protocol::kDirect))});
    if (source.protocol == constants::protocol::kAnyTLS ||
        source.protocol == constants::protocol::kHysteria ||
        source.protocol == constants::protocol::kHysteria2) {
        for (auto& user : source.users) {
            if (user.email.empty()) user.email = tag;
        }
    }
    return InboundSpec{
        .tag = std::move(tag),
        .all_tags = std::move(all_tags),
        .accounting_key = {},
        .protocol = std::move(source.protocol),
        .listen = std::move(source.listen),
        .port = source.port,
        .proxy_protocol = source.proxy_protocol,
        .settings = std::move(source.settings),
        .users = std::move(source.users),
        .stream_settings = std::move(source.stream_settings),
        .sniffing = std::move(source.sniffing),
        .outbound_policy = std::move(outbound_policy),
    };
}

}  // namespace

std::vector<PreparedInbound> PrepareStartupInbounds(
    std::vector<StaticInboundConfig> sources, bool enable_test_mode) {
    if (enable_test_mode) sources.push_back(MakeTestInboundConfig());
    const auto validation = ValidateStaticInboundSemantics(sources);
    if (!validation.Ok()) {
        throw std::invalid_argument("startup inbound " + validation.Message());
    }
    std::vector<PreparedInbound> prepared;
    prepared.reserve(sources.size());
    for (auto& source : sources) {
        auto inbound = PrepareInbound(StaticInboundSpec(std::move(source)));
        if (proxyman::inbound::UserSetEmpty(*inbound.users)) {
            throw std::invalid_argument(
                "static inbound '" + inbound.binding.tag + "' has no valid users");
        }
        prepared.push_back(std::move(inbound));
    }

    return prepared;
}

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
    return RunWorkerBatch(std::move(executor), workers,
        [views, &stopping](Worker& worker, size_t index) {
            return [](Worker* current, Store::WorkerView view,
                      const bool* stopping_flag) -> net::awaitable<void> {
                ThrowIfStopping(*stopping_flag);
                co_await current->PostCall([current, view = std::move(view)]() mutable {
                    current->InstallUserView(std::move(view));
                });
            }(&worker, views[index], &stopping);
        });
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

