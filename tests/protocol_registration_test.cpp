#include <gtest/gtest.h>

#include "app/proxyman/inbound/factory.hpp"
#include "app/stats.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"
#include "transport/async_stream.hpp"
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

class DummyRuntime final : public ::proxyman::inbound::ProtocolRuntime {
public:
    std::vector<::OnlineDevice>
    GetOnlineDevices(std::string_view) const override {
        return {};
    }
};

class DummyDatagramHandler final : public ::Inbound {
public:
    ::net::awaitable<::RelayResult> Process(
        std::unique_ptr<::AsyncStream>,
        ::routing::Dispatcher&,
        const ::proxyman::inbound::ReceiverSettings&,
        ::net::io_context&,
        ::session::Context&,
        const ::TimeoutsConfig&,
        uint32_t) override {
        co_return ::RelayResult{};
    }

    tl::expected<
        ::InboundDatagramResult,
        ::ErrorCode> Process(
        const ::InboundDatagramRequest&) override {
        return tl::unexpected(::ErrorCode::PROTOCOL_AUTH_FAILED);
    }
};

class DummyOutbound final : public ::Outbound {
public:
    explicit DummyOutbound(std::string created_tag) : tag(std::move(created_tag)) {}

    ::net::awaitable<::OutboundProcessResult> Process(
        ::session::Context&,
        ::transport::Link,
        ::OutboundDialer&,
        const ::TimeoutsConfig&,
        ::StatsShard&,
        const ::RelayConfig&,
        ::buf::MultiBufferBatch,
        std::chrono::seconds,
        std::chrono::seconds) override {
        co_return ::RelayResult{};
    }

    const std::string tag;
};

std::unique_ptr<::proxyman::inbound::ProtocolRuntime>
CreateInboundRuntime() {
    return std::make_unique<DummyRuntime>();
}

std::unique_ptr<::Inbound> CreateInboundHandler(
    ::proxyman::inbound::ProtocolRuntime&,
    ::StatsShard&,
    ::ConnectionLimiter*,
    const ::proxyman::inbound::BuildRequest&) {
    return nullptr;
}

std::unique_ptr<::Inbound> FailDatagramHandler(
    ::proxyman::inbound::ProtocolRuntime&,
    ::StatsShard&,
    ::ConnectionLimiter*,
    const ::proxyman::inbound::BuildRequest&) {
    return nullptr;
}

std::unique_ptr<::Inbound> CreateDatagramHandler(
    ::proxyman::inbound::ProtocolRuntime&,
    ::StatsShard&,
    ::ConnectionLimiter*,
    const ::proxyman::inbound::BuildRequest&) {
    return std::make_unique<DummyDatagramHandler>();
}

std::optional<::proxyman::inbound::UserSet> BuildVmessUsers(
    const ::proxyman::inbound::BuildRequest&,
    std::span<const ::InboundUserSpec>) {
    return ::proxyman::inbound::UserSet{
        ::proxyman::inbound::PreparedVmessUsers{
            ::proxyman::inbound::PreparedVmessUser{.uuid = "alias-user", .profile = {}}}};
}

std::optional<::proxyman::inbound::UserSet> BuildTrojanUsers(
    const ::proxyman::inbound::BuildRequest&,
    std::span<const ::InboundUserSpec>) {
    return ::proxyman::inbound::UserSet{
        ::proxyman::inbound::PreparedTrojanUsers{}};
}

std::optional<::proxyman::outbound::PreparedOutboundProxy>
CreateOutboundConfig(
    const ::infra::OutboundSourceConfig&) {
    return ::proxyman::outbound::PreparedOutboundProxy{
        .create = ::proxyman::outbound::PreparedOutboundCreator{
            [](std::string_view tag,
               ::net::io_context&,
               ::AwaitableTaskGroup&) -> std::unique_ptr<::Outbound> {
                return std::make_unique<DummyOutbound>(std::string(tag));
            }},
        .sender = {.stream_settings = {}, .send_through = ::OutboundBind::Auto()},
    };
}

std::optional<::proxyman::outbound::PreparedOutboundProxy>
CreateNullOutboundConfig(
    const ::infra::OutboundSourceConfig&) {
    return ::proxyman::outbound::PreparedOutboundProxy{
        .create = ::proxyman::outbound::PreparedOutboundCreator{
            [](std::string_view,
               ::net::io_context&,
               ::AwaitableTaskGroup&) -> std::unique_ptr<::Outbound> {
                return nullptr;
            }},
        .sender = {},
    };
}

std::optional<::proxyman::outbound::PreparedOutboundProxy>
CreateEmptyOutboundConfig(
    const ::infra::OutboundSourceConfig&) {
    return ::proxyman::outbound::PreparedOutboundProxy{};
}

bool TestInboundRegistration() {
    ::proxyman::inbound::ProxyRegistration valid;
    valid.create_runtime = &CreateInboundRuntime;
    valid.create_tcp_handler = &CreateInboundHandler;

    if (!Throws<std::invalid_argument>([&] {
            ::proxyman::inbound::RegisterProxy("", valid);
        })) {
        return false;
    }

    auto missing_runtime = valid;
    missing_runtime.create_runtime = nullptr;
    if (!Throws<std::invalid_argument>([&] {
            ::proxyman::inbound::RegisterProxy(
                "missing-runtime", missing_runtime);
        })) {
        return false;
    }

    auto missing_handler = valid;
    missing_handler.create_tcp_handler = nullptr;
    if (!Throws<std::invalid_argument>([&] {
            ::proxyman::inbound::RegisterProxy(
                "missing-handler", missing_handler);
        })) {
        return false;
    }

    auto missing_user_protocol = valid;
    missing_user_protocol.build_users = &BuildVmessUsers;
    if (!Throws<std::invalid_argument>([&] {
            ::proxyman::inbound::RegisterProxy(
                "missing-user-protocol", missing_user_protocol);
        })) {
        return false;
    }

    auto orphan_user_protocol = valid;
    orphan_user_protocol.user_protocol =
        ::proxyman::inbound::UserProtocol::Vmess;
    if (!Throws<std::invalid_argument>([&] {
            ::proxyman::inbound::RegisterProxy(
                "orphan-user-protocol", orphan_user_protocol);
        })) {
        return false;
    }

    ::proxyman::inbound::RegisterProxy("test-inbound", valid);
    if (!Throws<std::logic_error>([&] {
            ::proxyman::inbound::RegisterProxy("test-inbound", valid);
        })) {
        return false;
    }
    if (!::proxyman::inbound::HasProxy("test-inbound")) return false;
    if (!::proxyman::inbound::NewProtocolRuntime("test-inbound")) {
        return false;
    }

    const ::proxyman::inbound::BuildRequest request;
    DummyRuntime runtime;
    ::StatsShard stats;
    auto unknown_udp = ::proxyman::inbound::NewDatagramHandler(
        "unknown-udp", runtime, stats, nullptr, request);
    if (unknown_udp.status !=
            ::proxyman::inbound::DatagramHandlerBuildStatus::Failed ||
        unknown_udp.handler) {
        return false;
    }

    auto unsupported_udp = ::proxyman::inbound::NewDatagramHandler(
        "test-inbound", runtime, stats, nullptr, request);
    if (unsupported_udp.status !=
            ::proxyman::inbound::DatagramHandlerBuildStatus::Unsupported ||
        unsupported_udp.handler) {
        return false;
    }

    auto failed_udp_registration = valid;
    failed_udp_registration.create_datagram_handler = &FailDatagramHandler;
    failed_udp_registration.datagram_transport =
        ::proxyman::inbound::DatagramTransport::Packet;
    ::proxyman::inbound::RegisterProxy(
        "failed-udp", failed_udp_registration);
    auto failed_udp = ::proxyman::inbound::NewDatagramHandler(
        "failed-udp", runtime, stats, nullptr, request);
    if (failed_udp.status !=
            ::proxyman::inbound::DatagramHandlerBuildStatus::Failed ||
        failed_udp.handler) {
        return false;
    }

    auto ready_udp_registration = valid;
    ready_udp_registration.create_datagram_handler = &CreateDatagramHandler;
    ready_udp_registration.datagram_transport =
        ::proxyman::inbound::DatagramTransport::Packet;
    ::proxyman::inbound::RegisterProxy(
        "ready-udp", ready_udp_registration);
    auto ready_udp = ::proxyman::inbound::NewDatagramHandler(
        "ready-udp", runtime, stats, nullptr, request);
    if (ready_udp.status !=
            ::proxyman::inbound::DatagramHandlerBuildStatus::Ready ||
        !ready_udp.handler) {
        return false;
    }

    auto typed_users = valid;
    typed_users.user_protocol =
        ::proxyman::inbound::UserProtocol::Vmess;
    typed_users.build_users = &BuildVmessUsers;
    ::proxyman::inbound::RegisterProxy("vmess-alias", typed_users);
    if (::proxyman::inbound::RegisteredUserProtocol("vmess-alias") !=
        ::proxyman::inbound::UserProtocol::Vmess) {
        return false;
    }
    const ::proxyman::inbound::BuildRequest alias_request{
        .tag = "alias-tag", .protocol = "vmess-alias", .settings = {}};
    auto users = ::proxyman::inbound::BuildUsers(alias_request, {});
    if (!users || ::proxyman::inbound::UserProtocolOf(*users) !=
                      ::proxyman::inbound::UserProtocol::Vmess) {
        return false;
    }
    constexpr std::string_view kAliasTag = "alias-tag";
    using ::proxyman::inbound::UserStore;
    auto published = UserStore::PrepareUsers(kAliasTag, *users);
    auto view = UserStore::PrepareWorkerView(published);
    UserStore::CommitSnapshot(std::move(published));
    UserStore::InstallWorkerView(std::move(view));
    auto cleared = UserStore::PrepareClearUsers(
        *::proxyman::inbound::RegisteredUserProtocol("vmess-alias"), kAliasTag);
    view = UserStore::PrepareWorkerView(cleared);
    UserStore::CommitSnapshot(std::move(cleared));
    UserStore::InstallWorkerView(std::move(view));
    if (!UserStore::VmessUsers(kAliasTag).empty()) {
        return false;
    }

    auto mismatched_users = typed_users;
    mismatched_users.build_users = &BuildTrojanUsers;
    ::proxyman::inbound::RegisterProxy(
        "mismatched-users", mismatched_users);
    const ::proxyman::inbound::BuildRequest mismatched_request{
        .tag = "mismatched-tag", .protocol = "mismatched-users", .settings = {}};
    return !::proxyman::inbound::BuildUsers(mismatched_request, {});
}

bool TestOutboundRegistration() {
    if (!Throws<std::invalid_argument>([] {
            ::proxyman::outbound::RegisterProxy(
                "", &CreateOutboundConfig);
        })) {
        return false;
    }
    if (!Throws<std::invalid_argument>([] {
            ::proxyman::outbound::RegisterProxy(
                "missing-creator", nullptr);
        })) {
        return false;
    }
    ::proxyman::outbound::RegisterProxy(
        "test-outbound", &CreateOutboundConfig);
    if (!Throws<std::logic_error>([] {
            ::proxyman::outbound::RegisterProxy(
                "test-outbound", &CreateOutboundConfig);
        })) {
        return false;
    }
    if (!::proxyman::outbound::HasProxy("test-outbound")) {
        return false;
    }

    ::infra::OutboundSourceConfig source;
    source.tag = "source-owned-tag";
    source.protocol = "test-outbound";
    auto prepared = ::proxyman::outbound::PrepareOutboundConfig(source);
    if (!prepared || prepared->tag != source.tag ||
        prepared->protocol != source.protocol || !prepared->create) {
        return false;
    }
    // Without a handler-level sendThrough the protocol default stands.
    if (prepared->sender.send_through.GetMode() != ::OutboundBind::Mode::Auto) {
        return false;
    }
    ::net::io_context io_context;
    ::ResidentTaskGroup tasks(io_context.get_executor());
    auto proxy = ::proxyman::outbound::NewProxy(
        *prepared, io_context, tasks.Tasks());
    if (!proxy || static_cast<DummyOutbound&>(*proxy).tag != source.tag) {
        return false;
    }
    // The handler-level sendThrough overrides the protocol default.
    source.send_through = ::OutboundBind{};
    prepared = ::proxyman::outbound::PrepareOutboundConfig(source);
    if (!prepared ||
        prepared->sender.send_through.GetMode() != ::OutboundBind::Mode::None) {
        return false;
    }
    source.send_through.reset();

    ::proxyman::outbound::RegisterProxy(
        "null-outbound", &CreateNullOutboundConfig);
    source.protocol = "null-outbound";
    prepared = ::proxyman::outbound::PrepareOutboundConfig(source);
    if (!prepared || !Throws<std::logic_error>([&] {
            (void)::proxyman::outbound::NewProxy(
                *prepared, io_context, tasks.Tasks());
        })) {
        return false;
    }

    ::proxyman::outbound::PreparedOutboundConfig missing_creator;
    missing_creator.tag = "missing-runtime-creator";
    if (!Throws<std::logic_error>([&] {
            (void)::proxyman::outbound::NewProxy(
                missing_creator, io_context, tasks.Tasks());
        })) {
        return false;
    }

    ::proxyman::outbound::RegisterProxy(
        "empty-outbound", &CreateEmptyOutboundConfig);
    source.protocol = "empty-outbound";
    return !::proxyman::outbound::PrepareOutboundConfig(source);
}

}  // namespace

TEST(ProtocolRegistration, Contract) {
    ASSERT_TRUE(TestInboundRegistration())
        << "inbound protocol registration accepted invalid state";
    ASSERT_TRUE(TestOutboundRegistration())
        << "outbound protocol registration accepted invalid state";
}
