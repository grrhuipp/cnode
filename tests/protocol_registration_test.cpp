#include <gtest/gtest.h>

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "registration.hpp"
#include "../src/common/awaitable_task_group.hpp"

#include <iostream>
#include <stdexcept>

namespace {

template <typename Exception, typename Function>
bool Throws(Function&& function) {
    try {
        function();
    } catch (const Exception&) {
        return true;
    } catch (...) {
        return false;
    }
    return false;
}

class DummyRuntime final : public acpp::proxyman::inbound::ProtocolRuntime {
public:
    std::vector<acpp::OnlineDevice>
    GetOnlineDevices(std::string_view) const override {
        return {};
    }
};

class DummyDatagramHandler final : public acpp::Inbound {
public:
    acpp::net::awaitable<acpp::RelayResult> Process(
        std::unique_ptr<acpp::AsyncStream>,
        acpp::routing::Dispatcher&,
        const acpp::proxyman::inbound::ReceiverSettings&,
        acpp::net::io_context&,
        acpp::session::Context&,
        const acpp::TimeoutsConfig&,
        uint32_t) override {
        co_return acpp::RelayResult{};
    }

    tl::expected<
        acpp::InboundDatagramResult,
        acpp::ErrorCode> Process(
        const acpp::InboundDatagramRequest&) override {
        return tl::unexpected(acpp::ErrorCode::PROTOCOL_AUTH_FAILED);
    }
};

class DummyOutbound final : public acpp::Outbound {
public:
    explicit DummyOutbound(std::string created_tag) : tag(std::move(created_tag)) {}

    acpp::net::awaitable<acpp::OutboundProcessResult> Process(
        acpp::session::Context&,
        acpp::transport::Link,
        acpp::OutboundDialer&,
        const acpp::TimeoutsConfig&,
        acpp::StatsShard&,
        const acpp::RelayConfig&,
        acpp::buf::MultiBufferBatch,
        std::chrono::seconds,
        std::chrono::seconds) override {
        co_return acpp::RelayResult{};
    }

    const std::string tag;
};

std::unique_ptr<acpp::proxyman::inbound::ProtocolRuntime>
CreateInboundRuntime() {
    return std::make_unique<DummyRuntime>();
}

std::unique_ptr<acpp::Inbound> CreateInboundHandler(
    acpp::proxyman::inbound::ProtocolRuntime&,
    acpp::StatsShard&,
    acpp::ConnectionLimiter*,
    const acpp::proxyman::inbound::BuildRequest&) {
    return nullptr;
}

std::unique_ptr<acpp::Inbound> FailDatagramHandler(
    acpp::proxyman::inbound::ProtocolRuntime&,
    acpp::StatsShard&,
    acpp::ConnectionLimiter*,
    const acpp::proxyman::inbound::BuildRequest&) {
    return nullptr;
}

std::unique_ptr<acpp::Inbound> CreateDatagramHandler(
    acpp::proxyman::inbound::ProtocolRuntime&,
    acpp::StatsShard&,
    acpp::ConnectionLimiter*,
    const acpp::proxyman::inbound::BuildRequest&) {
    return std::make_unique<DummyDatagramHandler>();
}

std::optional<acpp::proxyman::inbound::UserSet> BuildVmessUsers(
    const acpp::proxyman::inbound::BuildRequest&,
    std::span<const acpp::InboundUserSpec>) {
    return acpp::proxyman::inbound::UserSet{
        acpp::proxyman::inbound::PreparedVmessUsers{
            acpp::proxyman::inbound::PreparedVmessUser{.uuid = "alias-user", .profile = {}}}};
}

std::optional<acpp::proxyman::inbound::UserSet> BuildTrojanUsers(
    const acpp::proxyman::inbound::BuildRequest&,
    std::span<const acpp::InboundUserSpec>) {
    return acpp::proxyman::inbound::UserSet{
        acpp::proxyman::inbound::PreparedTrojanUsers{}};
}

std::optional<acpp::proxyman::outbound::PreparedOutboundProxy>
CreateOutboundConfig(
    const acpp::infra::OutboundSourceConfig&) {
    return acpp::proxyman::outbound::PreparedOutboundProxy{
        .create = acpp::proxyman::outbound::PreparedOutboundCreator{
            [](std::string_view tag,
               acpp::net::io_context&,
               acpp::AwaitableTaskGroup&) -> std::unique_ptr<acpp::Outbound> {
                return std::make_unique<DummyOutbound>(std::string(tag));
            }},
        .sender = {.stream_settings = {}, .send_through = acpp::OutboundBind::Auto()},
    };
}

std::optional<acpp::proxyman::outbound::PreparedOutboundProxy>
CreateNullOutboundConfig(
    const acpp::infra::OutboundSourceConfig&) {
    return acpp::proxyman::outbound::PreparedOutboundProxy{
        .create = acpp::proxyman::outbound::PreparedOutboundCreator{
            [](std::string_view,
               acpp::net::io_context&,
               acpp::AwaitableTaskGroup&) -> std::unique_ptr<acpp::Outbound> {
                return nullptr;
            }},
        .sender = {},
    };
}

std::optional<acpp::proxyman::outbound::PreparedOutboundProxy>
CreateEmptyOutboundConfig(
    const acpp::infra::OutboundSourceConfig&) {
    return acpp::proxyman::outbound::PreparedOutboundProxy{};
}

bool TestInboundRegistration() {
    acpp::proxyman::inbound::ProxyRegistration valid;
    valid.create_runtime = &CreateInboundRuntime;
    valid.create_tcp_handler = &CreateInboundHandler;

    if (!Throws<std::invalid_argument>([&] {
            acpp::proxyman::inbound::RegisterProxy("", valid);
        })) {
        return false;
    }

    auto missing_runtime = valid;
    missing_runtime.create_runtime = nullptr;
    if (!Throws<std::invalid_argument>([&] {
            acpp::proxyman::inbound::RegisterProxy(
                "missing-runtime", missing_runtime);
        })) {
        return false;
    }

    auto missing_handler = valid;
    missing_handler.create_tcp_handler = nullptr;
    if (!Throws<std::invalid_argument>([&] {
            acpp::proxyman::inbound::RegisterProxy(
                "missing-handler", missing_handler);
        })) {
        return false;
    }

    auto missing_user_protocol = valid;
    missing_user_protocol.build_users = &BuildVmessUsers;
    if (!Throws<std::invalid_argument>([&] {
            acpp::proxyman::inbound::RegisterProxy(
                "missing-user-protocol", missing_user_protocol);
        })) {
        return false;
    }

    auto orphan_user_protocol = valid;
    orphan_user_protocol.user_protocol =
        acpp::proxyman::inbound::UserProtocol::Vmess;
    if (!Throws<std::invalid_argument>([&] {
            acpp::proxyman::inbound::RegisterProxy(
                "orphan-user-protocol", orphan_user_protocol);
        })) {
        return false;
    }

    acpp::proxyman::inbound::RegisterProxy("test-inbound", valid);
    if (!Throws<std::logic_error>([&] {
            acpp::proxyman::inbound::RegisterProxy("test-inbound", valid);
        })) {
        return false;
    }
    if (!acpp::proxyman::inbound::HasProxy("test-inbound")) return false;
    if (!acpp::proxyman::inbound::NewProtocolRuntime("test-inbound")) {
        return false;
    }

    const acpp::proxyman::inbound::BuildRequest request;
    DummyRuntime runtime;
    acpp::StatsShard stats;
    auto unknown_udp = acpp::proxyman::inbound::NewDatagramHandler(
        "unknown-udp", runtime, stats, nullptr, request);
    if (unknown_udp.status !=
            acpp::proxyman::inbound::DatagramHandlerBuildStatus::Failed ||
        unknown_udp.handler) {
        return false;
    }

    auto unsupported_udp = acpp::proxyman::inbound::NewDatagramHandler(
        "test-inbound", runtime, stats, nullptr, request);
    if (unsupported_udp.status !=
            acpp::proxyman::inbound::DatagramHandlerBuildStatus::Unsupported ||
        unsupported_udp.handler) {
        return false;
    }

    auto failed_udp_registration = valid;
    failed_udp_registration.create_datagram_handler = &FailDatagramHandler;
    failed_udp_registration.datagram_transport =
        acpp::proxyman::inbound::DatagramTransport::Packet;
    acpp::proxyman::inbound::RegisterProxy(
        "failed-udp", failed_udp_registration);
    auto failed_udp = acpp::proxyman::inbound::NewDatagramHandler(
        "failed-udp", runtime, stats, nullptr, request);
    if (failed_udp.status !=
            acpp::proxyman::inbound::DatagramHandlerBuildStatus::Failed ||
        failed_udp.handler) {
        return false;
    }

    auto ready_udp_registration = valid;
    ready_udp_registration.create_datagram_handler = &CreateDatagramHandler;
    ready_udp_registration.datagram_transport =
        acpp::proxyman::inbound::DatagramTransport::Packet;
    acpp::proxyman::inbound::RegisterProxy(
        "ready-udp", ready_udp_registration);
    auto ready_udp = acpp::proxyman::inbound::NewDatagramHandler(
        "ready-udp", runtime, stats, nullptr, request);
    if (ready_udp.status !=
            acpp::proxyman::inbound::DatagramHandlerBuildStatus::Ready ||
        !ready_udp.handler) {
        return false;
    }

    auto typed_users = valid;
    typed_users.user_protocol =
        acpp::proxyman::inbound::UserProtocol::Vmess;
    typed_users.build_users = &BuildVmessUsers;
    acpp::proxyman::inbound::RegisterProxy("vmess-alias", typed_users);
    if (acpp::proxyman::inbound::RegisteredUserProtocol("vmess-alias") !=
        acpp::proxyman::inbound::UserProtocol::Vmess) {
        return false;
    }
    const acpp::proxyman::inbound::BuildRequest alias_request{
        .tag = "alias-tag", .protocol = "vmess-alias", .settings = {}};
    auto users = acpp::proxyman::inbound::BuildUsers(alias_request, {});
    if (!users || acpp::proxyman::inbound::UserProtocolOf(*users) !=
                      acpp::proxyman::inbound::UserProtocol::Vmess) {
        return false;
    }
    constexpr std::string_view kAliasTag = "alias-tag";
    using acpp::proxyman::inbound::UserStore;
    auto published = UserStore::PrepareUsers(kAliasTag, *users);
    auto view = UserStore::PrepareWorkerView(published);
    UserStore::CommitSnapshot(std::move(published));
    UserStore::InstallWorkerView(std::move(view));
    auto cleared = UserStore::PrepareClearUsers(
        *acpp::proxyman::inbound::RegisteredUserProtocol("vmess-alias"), kAliasTag);
    view = UserStore::PrepareWorkerView(cleared);
    UserStore::CommitSnapshot(std::move(cleared));
    UserStore::InstallWorkerView(std::move(view));
    if (!UserStore::VmessUsers(kAliasTag).empty()) {
        return false;
    }

    auto mismatched_users = typed_users;
    mismatched_users.build_users = &BuildTrojanUsers;
    acpp::proxyman::inbound::RegisterProxy(
        "mismatched-users", mismatched_users);
    const acpp::proxyman::inbound::BuildRequest mismatched_request{
        .tag = "mismatched-tag", .protocol = "mismatched-users", .settings = {}};
    return !acpp::proxyman::inbound::BuildUsers(mismatched_request, {});
}

bool TestOutboundRegistration() {
    if (!Throws<std::invalid_argument>([] {
            acpp::proxyman::outbound::RegisterProxy(
                "", &CreateOutboundConfig);
        })) {
        return false;
    }
    if (!Throws<std::invalid_argument>([] {
            acpp::proxyman::outbound::RegisterProxy(
                "missing-creator", nullptr);
        })) {
        return false;
    }
    acpp::proxyman::outbound::RegisterProxy(
        "test-outbound", &CreateOutboundConfig);
    if (!Throws<std::logic_error>([] {
            acpp::proxyman::outbound::RegisterProxy(
                "test-outbound", &CreateOutboundConfig);
        })) {
        return false;
    }
    if (!acpp::proxyman::outbound::HasProxy("test-outbound")) {
        return false;
    }

    acpp::infra::OutboundSourceConfig source;
    source.tag = "source-owned-tag";
    source.protocol = "test-outbound";
    auto prepared = acpp::proxyman::outbound::PrepareOutboundConfig(source);
    if (!prepared || prepared->tag != source.tag ||
        prepared->protocol != source.protocol || !prepared->create) {
        return false;
    }
    // Without a handler-level sendThrough the protocol default stands.
    if (prepared->sender.send_through.GetMode() != acpp::OutboundBind::Mode::Auto) {
        return false;
    }
    acpp::net::io_context io_context;
    acpp::ResidentTaskGroup tasks(io_context.get_executor());
    auto proxy = acpp::proxyman::outbound::NewProxy(
        *prepared, io_context, tasks.Tasks());
    if (!proxy || static_cast<DummyOutbound&>(*proxy).tag != source.tag) {
        return false;
    }
    // The handler-level sendThrough overrides the protocol default.
    source.send_through = acpp::OutboundBind{};
    prepared = acpp::proxyman::outbound::PrepareOutboundConfig(source);
    if (!prepared ||
        prepared->sender.send_through.GetMode() != acpp::OutboundBind::Mode::None) {
        return false;
    }
    source.send_through.reset();

    acpp::proxyman::outbound::RegisterProxy(
        "null-outbound", &CreateNullOutboundConfig);
    source.protocol = "null-outbound";
    prepared = acpp::proxyman::outbound::PrepareOutboundConfig(source);
    if (!prepared || !Throws<std::logic_error>([&] {
            (void)acpp::proxyman::outbound::NewProxy(
                *prepared, io_context, tasks.Tasks());
        })) {
        return false;
    }

    acpp::proxyman::outbound::PreparedOutboundConfig missing_creator;
    missing_creator.tag = "missing-runtime-creator";
    if (!Throws<std::logic_error>([&] {
            (void)acpp::proxyman::outbound::NewProxy(
                missing_creator, io_context, tasks.Tasks());
        })) {
        return false;
    }

    acpp::proxyman::outbound::RegisterProxy(
        "empty-outbound", &CreateEmptyOutboundConfig);
    source.protocol = "empty-outbound";
    return !acpp::proxyman::outbound::PrepareOutboundConfig(source);
}

}  // namespace

TEST(ProtocolRegistration, Contract) {
    ASSERT_TRUE(TestInboundRegistration())
        << "inbound protocol registration accepted invalid state";
    ASSERT_TRUE(TestOutboundRegistration())
        << "outbound protocol registration accepted invalid state";
}
