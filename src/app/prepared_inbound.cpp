#include "app/prepared_inbound.hpp"

#include "app/worker_batch.hpp"
#include "infra/config.hpp"
#include "app/worker.hpp"
#include "common/constants.hpp"
#include "infra/config_types.hpp"
#include "transport/stream_settings.hpp"
#include "transport/transport_security.hpp"
#include <stdexcept>
#include <utility>
#include <variant>


namespace app {

std::shared_ptr<const UserSet> PrepareInboundUsers(
    const BuildRequest& request,
    std::span<const infra::InboundUserSpec> users) {
    auto prepared = BuildUsers(request, users);
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
    return std::make_shared<const UserSet>(std::move(*prepared));
}

PreparedInbound PrepareInbound(const infra::InboundSpec& spec) {
    if (!HasProxy(spec.protocol)) {
        throw std::invalid_argument(
            "inbound '" + spec.tag + "' has unsupported protocol '" +
            spec.protocol + "'");
    }
    auto build_request = PrepareBuildRequest(
        spec.protocol, spec.tag, spec.settings);
    if (!build_request) {
        throw std::invalid_argument(
            "inbound '" + spec.tag + "' has invalid protocol settings");
    }
    auto users = PrepareInboundUsers(*build_request, spec.users);

    transport::StreamSettings stream_settings = spec.stream_settings;
    transport::TransportSecurity::Prepare(stream_settings, transport::StreamEndpointRole::Inbound);
    // XHTTP 会话命名空间按入站 tag 隔离，配置准备期一次推导，Worker 只读。
    if (stream_settings.IsXHttp()) {
        auto& ns = stream_settings.xhttp.session_namespace;
        std::string prefixed;
        prefixed.reserve(spec.tag.size() + 1 + ns.size());
        prefixed.append(spec.tag);
        prefixed.push_back('\0');
        prefixed.append(ns);
        ns = std::move(prefixed);
    }

    return PreparedInbound{
        .binding = PortBinding{
            .port = spec.port,
            .protocol = spec.protocol,
            .tag = spec.tag,
            .listen = spec.listen,
        },
        .receiver = MakeReceiverSettings(
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

infra::StaticInboundConfig MakeTestInboundConfig() {
    infra::StaticInboundConfig source;
    source.protocol = common::kDefaultNodeProtocol;
    source.tags.emplace_back(common::kTestInboundTag);
    source.port = common::kTestPort;
    // The ordinary StreamSettings and SniffConfig defaults are already normalized.
    source.users.push_back(infra::InboundUserSpec{
        .user_id = 0,
        .email = "test@example.com",
        .credential = std::string(common::kTestVmessUuid),
        .flow = {},
        .speed_limit = 0,
        .device_limit = 0,
    });
    return source;
}

// Static-only mapping: tag fallback, outbound selection and the per-user
// email default. Everything else passes through unchanged.
infra::InboundSpec StaticInboundSpec(infra::StaticInboundConfig source) {
    std::string tag = source.tags.empty()
        ? common::BuildProtocolPortTag(source.protocol, source.port)
        : source.tags.front();
    std::vector<std::string> all_tags = source.tags.empty()
        ? std::vector<std::string>{tag}
        : std::move(source.tags);
    routing::OutboundSelectionPolicy outbound_policy = source.outbound_tag
        ? routing::OutboundSelectionPolicy{routing::ForceOutbound(*source.outbound_tag)}
        : (source.routing_enabled
            ? routing::OutboundSelectionPolicy{routing::RouteWithFallback(
                std::string(common::kDirect))}
            : routing::OutboundSelectionPolicy{routing::ForceOutbound(
                std::string(common::kDirect))});
    if (RegisteredProtocolTraits(source.protocol).mailbox_email_defaults_to_tag) {
        for (auto& user : source.users) {
            if (user.email.empty()) user.email = tag;
        }
    }
    return infra::InboundSpec{
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
    std::vector<infra::StaticInboundConfig> sources, bool enable_test_mode) {
    if (enable_test_mode) sources.push_back(MakeTestInboundConfig());
    const auto validation = infra::ValidateStaticInboundSemantics(sources);
    if (!validation.Ok()) {
        throw std::invalid_argument("startup inbound " + validation.Message());
    }
    std::vector<PreparedInbound> prepared;
    prepared.reserve(sources.size());
    for (auto& source : sources) {
        auto inbound = PrepareInbound(StaticInboundSpec(std::move(source)));
        if (UserSetEmpty(*inbound.users)) {
            throw std::invalid_argument(
                "static inbound '" + inbound.binding.tag + "' has no valid users");
        }
        prepared.push_back(std::move(inbound));
    }

    return prepared;
}

namespace {

using Store = UserStore;

// Leases are copied per Worker so a failed install keeps the source views for
// a later retry.
net::awaitable<void> InstallUserViews(
    net::any_io_executor executor,
    std::span<const std::unique_ptr<Worker>> workers,
    std::span<const Store::WorkerView> views,
    const bool& stopping) {
    co_await PostToEachWorker(std::move(executor), workers, stopping,
        [views](Worker& worker, size_t index) {
            return worker.PostCall([&worker, view = views[index]]() mutable {
                worker.InstallUserView(std::move(view));
            });
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
        RegisteredDatagramTransport(inbound.build_request.protocol) ==
        DatagramTransport::Quic;
    if (!quic_only && !worker.AddListener(inbound.binding)) {
        co_return InboundInstallFailure::TcpListen;
    }
    if (!co_await worker.AddUdpListenerTask(inbound.binding, inbound.build_request)) {
        co_return InboundInstallFailure::UdpListen;
    }
    co_return InboundInstallFailure::None;
}

PreparedUserPublication PrepareUserPublication(
    Store::PublishedSnapshot candidate, size_t worker_count) {
    PreparedUserPublication publication;
    publication.rollback.previous = Store::CaptureSnapshot();
    publication.rollback.worker_views.reserve(worker_count);
    publication.candidate_views.reserve(worker_count);
    for (size_t i = 0; i < worker_count; ++i) {
        publication.rollback.worker_views.push_back(
            Store::PrepareWorkerView(publication.rollback.previous));
        publication.candidate_views.push_back(Store::PrepareWorkerView(candidate));
    }
    publication.candidate = std::move(candidate);
    return publication;
}

void PreparedUserPublication::Commit() {
    Store::CommitSnapshot(std::move(candidate));
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
    auto publication = PrepareUserPublication(std::move(candidate), workers.size());
    // Retain rollback leases before any mailbox can install a candidate.
    rollback = std::move(publication.rollback);
    co_await InstallUserViews(executor, workers, publication.candidate_views, stopping);
    ThrowIfStopping(stopping);
    publication.Commit();
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

}  // namespace app

