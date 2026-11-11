#include <gtest/gtest.h>

#include "app/proxyman/inbound/handler.hpp"
#include "app/relay.hpp"
#include "app/stats.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/proxyman/outbound/handler.hpp"
#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"
#include "transport/async_stream.hpp"
#include "common/awaitable_task_group.hpp"
#include "worker_coordinator_fixture.hpp"

#include <stdexcept>
#include <tuple>

namespace {



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
    ::net::awaitable<::OutboundProcessResult> Process(
        ::session::Context&,
        ::transport::Link,
        ::OutboundDialer&,
        const ::TimeoutsConfig&,
        ::StatsShard&,
        const ::RelayConfig&,
        ::buf::MultiBufferBatch) override {
        co_return ::RelayResult{};
    }
};

std::unique_ptr<::Inbound> CreateInboundHandler(
    const ::proxyman::inbound::AdmissionEnvironment&,
    const ::proxyman::inbound::BuildRequest&) {
    return std::make_unique<DummyDatagramHandler>();
}

std::unique_ptr<::Inbound> FailDatagramHandler(
    const ::proxyman::inbound::AdmissionEnvironment&,
    const ::proxyman::inbound::BuildRequest&) {
    return nullptr;
}

std::unique_ptr<::Inbound> CreateDatagramHandler(
    const ::proxyman::inbound::AdmissionEnvironment&,
    const ::proxyman::inbound::BuildRequest&) {
    return std::make_unique<DummyDatagramHandler>();
}

std::optional<::proxyman::inbound::UserSet> BuildVmessUsers(
    const ::proxyman::inbound::BuildRequest&,
    std::span<const ::InboundUserSpec>) {
    return ::proxyman::inbound::UserSet{
        ::proxyman::inbound::PreparedVmessUsers{
            ::proxyman::inbound::PreparedVmessUser{.profile = {}}}};
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
            {},
            [](std::string_view,
               const std::shared_ptr<const ::proxyman::outbound::OutboundProtocolSettings>&,
               ::net::io_context&,
               ::AwaitableTaskGroup&) -> std::unique_ptr<::Outbound> {
                return std::make_unique<DummyOutbound>();
            }},
        .sender = {.stream_settings = {}, .send_through = ::OutboundBind::Auto()},
    };
}

std::optional<::proxyman::outbound::PreparedOutboundProxy>
CreateNullOutboundConfig(
    const ::infra::OutboundSourceConfig&) {
    return ::proxyman::outbound::PreparedOutboundProxy{
        .create = ::proxyman::outbound::PreparedOutboundCreator{
            {},
            [](std::string_view,
               const std::shared_ptr<const ::proxyman::outbound::OutboundProtocolSettings>&,
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

::proxyman::inbound::ProxyRegistration InboundRegistration() {
    ::proxyman::inbound::ProxyRegistration registration;
    registration.create_tcp_handler = &CreateInboundHandler;
    return registration;
}

enum class InvalidInbound { EmptyName, MissingQuicFactory, MissingHandler,
                            MissingUserProtocol, OrphanUserProtocol,
                            OrphanQuicFactory, MissingPacketFactory, OrphanPacketFactory };
class InvalidInboundRegistration : public ::testing::TestWithParam<InvalidInbound> {};

TEST_P(InvalidInboundRegistration, RejectsIncompleteRegistration) {
    auto registration = InboundRegistration();
    std::string protocol = "invalid-lifecycle-registration";
    switch (GetParam()) {
        case InvalidInbound::EmptyName: protocol.clear(); break;
        case InvalidInbound::MissingQuicFactory:
            registration.datagram_transport = ::proxyman::inbound::DatagramTransport::Quic;
            break;
        case InvalidInbound::OrphanQuicFactory:
            registration.create_quic_listener = [](uint32_t, uint32_t, ::net::io_context&,
                ::app::DatagramSessionEnvironment) -> std::unique_ptr<::transport::internet::QuicListener> {
                return {};
            };
            break;
        case InvalidInbound::MissingPacketFactory:
            registration.datagram_transport = ::proxyman::inbound::DatagramTransport::Packet;
            break;
        case InvalidInbound::OrphanPacketFactory:
            registration.create_datagram_handler = &CreateDatagramHandler;
            break;
        case InvalidInbound::MissingHandler: registration.create_tcp_handler = nullptr; break;
        case InvalidInbound::MissingUserProtocol: registration.build_users = &BuildVmessUsers; break;
        case InvalidInbound::OrphanUserProtocol:
            registration.user_protocol = ::proxyman::inbound::UserProtocol::Vmess;
            break;
    }
    EXPECT_THROW(::proxyman::inbound::RegisterProxy(protocol, registration), std::invalid_argument);
}

INSTANTIATE_TEST_SUITE_P(RequiredCapabilities, InvalidInboundRegistration, ::testing::Values(InvalidInbound::EmptyName, InvalidInbound::MissingQuicFactory,
    InvalidInbound::OrphanQuicFactory, InvalidInbound::MissingPacketFactory,
    InvalidInbound::OrphanPacketFactory, InvalidInbound::MissingHandler, InvalidInbound::MissingUserProtocol,
    InvalidInbound::OrphanUserProtocol), ([](const ::testing::TestParamInfo<InvalidInbound>& info) { switch (info.param) {
    case InvalidInbound::EmptyName: return "EmptyName";
    case InvalidInbound::MissingQuicFactory: return "MissingQuicFactory";
    case InvalidInbound::OrphanQuicFactory: return "OrphanQuicFactory";
    case InvalidInbound::MissingPacketFactory: return "MissingPacketFactory";
    case InvalidInbound::OrphanPacketFactory: return "OrphanPacketFactory";
    case InvalidInbound::MissingHandler: return "MissingHandler";
    case InvalidInbound::MissingUserProtocol: return "MissingUserProtocol";
    case InvalidInbound::OrphanUserProtocol: return "OrphanUserProtocol";
}
return "Unknown"; }));

TEST(ProtocolRegistration, DuplicateInboundDoesNotReplacePublishedFactory) {
    const auto registration = InboundRegistration();
    ::proxyman::inbound::RegisterProxy("lifecycle-inbound", registration);
    EXPECT_THROW(::proxyman::inbound::RegisterProxy("lifecycle-inbound", registration),
                 std::logic_error);
    ::net::io_context io;
    ::WorkerCoordinatorFixture coordinator(io);
    auto limiter = ::ConnectionLimiter::Acquire({}, coordinator.Get());
    ::UserOnlineTracker tracker(*coordinator.Get());
    ::StatsShard stats;
    const ::proxyman::inbound::AdmissionEnvironment environment{
        *coordinator.Get(), *limiter, tracker, stats};
    ::proxyman::inbound::HandlerRegistry registry(environment);
    EXPECT_TRUE(registry.NewHandler({.tag = "lifecycle-inbound", .protocol = "lifecycle-inbound", .settings = {}}));
}

TEST(ProtocolRegistration, PreservesRegisteredTraitsAndQuicFactoryCapability) {
    using namespace ::proxyman::inbound;
    auto registration = InboundRegistration();
    registration.datagram_transport = DatagramTransport::Quic;
    registration.traits = {.mailbox_email_defaults_to_tag = true, .requires_tls = true};
    registration.create_quic_listener = [](uint32_t, uint32_t, ::net::io_context&,
        ::app::DatagramSessionEnvironment) -> std::unique_ptr<::transport::internet::QuicListener> {
        return {};
    };
    EXPECT_NO_THROW(RegisterProxy("lifecycle-quic-traits", registration));
    EXPECT_EQ(RegisteredDatagramTransport("lifecycle-quic-traits"), DatagramTransport::Quic);
    const auto traits = RegisteredProtocolTraits("lifecycle-quic-traits");
    EXPECT_TRUE(traits.mailbox_email_defaults_to_tag);
    EXPECT_TRUE(traits.requires_tls);
    RegisterProxy("lifecycle-default-traits", InboundRegistration());
    const auto defaults = RegisteredProtocolTraits("lifecycle-default-traits");
    EXPECT_FALSE(defaults.mailbox_email_defaults_to_tag);
    EXPECT_FALSE(defaults.requires_tls);
    const auto unknown = RegisteredProtocolTraits("lifecycle-unknown-traits");
    EXPECT_FALSE(unknown.mailbox_email_defaults_to_tag);
    EXPECT_FALSE(unknown.requires_tls);
}

enum class DatagramBuild { Unknown, Unsupported, Failed, Ready };
class DatagramRegistration : public ::testing::TestWithParam<DatagramBuild> {};

TEST_P(DatagramRegistration, ReportsCapabilityAndConstructionOutcome) {
    using namespace ::proxyman::inbound;
    auto registration = InboundRegistration();
    std::string protocol;
    auto expected = DatagramHandlerBuildStatus::Failed;
    switch (GetParam()) {
        case DatagramBuild::Unknown: protocol = "lifecycle-unknown-udp"; break;
        case DatagramBuild::Unsupported:
            protocol = "lifecycle-unsupported-udp";
            expected = DatagramHandlerBuildStatus::Unsupported;
            break;
        case DatagramBuild::Failed:
            protocol = "lifecycle-failed-udp";
            registration.create_datagram_handler = &FailDatagramHandler;
            registration.datagram_transport = DatagramTransport::Packet;
            break;
        case DatagramBuild::Ready:
            protocol = "lifecycle-ready-udp";
            registration.create_datagram_handler = &CreateDatagramHandler;
            registration.datagram_transport = DatagramTransport::Packet;
            expected = DatagramHandlerBuildStatus::Ready;
            break;
    }
    if (GetParam() != DatagramBuild::Unknown) RegisterProxy(protocol, registration);
    ::net::io_context io;
    ::WorkerCoordinatorFixture coordinator(io);
    auto limiter = ::ConnectionLimiter::Acquire({}, coordinator.Get());
    ::UserOnlineTracker tracker(*coordinator.Get());
    ::StatsShard stats;
    const AdmissionEnvironment environment{*coordinator.Get(), *limiter, tracker, stats};
    HandlerRegistry registry(environment);
    const BuildRequest request{.tag = {}, .protocol = protocol, .settings = {}};
    auto result = registry.NewDatagramHandler(request);
    EXPECT_EQ(result.status, expected);
    EXPECT_EQ(bool(result.handler), GetParam() == DatagramBuild::Ready);
}

INSTANTIATE_TEST_SUITE_P(Capabilities, DatagramRegistration, ::testing::Values(DatagramBuild::Unknown, DatagramBuild::Unsupported,
                  DatagramBuild::Failed, DatagramBuild::Ready), ([](const ::testing::TestParamInfo<DatagramBuild>& info) { switch (info.param) {
    case DatagramBuild::Unknown: return "UnknownProtocol";
    case DatagramBuild::Unsupported: return "UnsupportedDatagrams";
    case DatagramBuild::Failed: return "ConstructionFailed";
    case DatagramBuild::Ready: return "Ready";
}
return "Unknown"; }));

TEST(ProtocolRegistration, AliasUsesRegisteredCredentialTypeForPublicationAndRemoval) {
    using namespace ::proxyman::inbound;
    auto registration = InboundRegistration();
    registration.user_protocol = UserProtocol::Vmess;
    registration.build_users = &BuildVmessUsers;
    RegisterProxy("lifecycle-vmess-alias", registration);
    const BuildRequest request{
        .tag = "lifecycle-alias-users", .protocol = "lifecycle-vmess-alias", .settings = {}};
    auto users = BuildUsers(request, {});
    ASSERT_TRUE(users);
    EXPECT_EQ(UserProtocolOf(*users), UserProtocol::Vmess);
    const auto protocol = RegisteredUserProtocol(request.protocol);
    ASSERT_TRUE(protocol);
    struct ClearUsers {
        ~ClearUsers() {
            auto empty = UserStore::PrepareClearUsers(UserProtocol::Vmess, "lifecycle-alias-users");
            UserStore::CommitSnapshot(std::move(empty));
            UserStore::ClearWorkerView();
        }
    } cleanup;
    auto published = UserStore::PrepareUsers(request.tag, *users);
    auto view = UserStore::PrepareWorkerView(published);
    UserStore::CommitSnapshot(std::move(published));
    UserStore::InstallWorkerView(std::move(view));
    EXPECT_FALSE(UserStore::VmessUsers(request.tag).empty());
    auto cleared = UserStore::PrepareClearUsers(*protocol, request.tag);
    view = UserStore::PrepareWorkerView(cleared);
    UserStore::CommitSnapshot(std::move(cleared));
    UserStore::InstallWorkerView(std::move(view));
    EXPECT_TRUE(UserStore::VmessUsers(request.tag).empty());
}

TEST(ProtocolRegistration, RejectsCredentialBuilderReturningDifferentProtocol) {
    using namespace ::proxyman::inbound;
    auto registration = InboundRegistration();
    registration.user_protocol = UserProtocol::Vmess;
    registration.build_users = &BuildTrojanUsers;
    RegisterProxy("lifecycle-mismatched-users", registration);
    const BuildRequest request{
        .tag = "lifecycle-mismatched-tag", .protocol = "lifecycle-mismatched-users", .settings = {}};
    EXPECT_FALSE(BuildUsers(request, {}));
}

class InvalidOutboundRegistration : public ::testing::TestWithParam<bool> {};

TEST_P(InvalidOutboundRegistration, RejectsMissingNameOrCreator) {
    EXPECT_THROW(::proxyman::outbound::RegisterProxy(
        GetParam() ? "" : "lifecycle-missing-creator",
        GetParam() ? &CreateOutboundConfig : nullptr), std::invalid_argument);
}

INSTANTIATE_TEST_SUITE_P(RequiredCapabilities, InvalidOutboundRegistration, ::testing::Bool(), ([](const ::testing::TestParamInfo<bool>& info) { return info.param ? "EmptyName" : "MissingCreator"; }));

TEST(ProtocolRegistration, DuplicateOutboundDoesNotReplacePublishedCreator) {
    using namespace ::proxyman::outbound;
    RegisterProxy("lifecycle-outbound", &CreateOutboundConfig);
    EXPECT_THROW(RegisterProxy("lifecycle-outbound", &CreateNullOutboundConfig), std::logic_error);
    ::infra::OutboundSourceConfig source;
    source.tag = "lifecycle-outbound-tag";
    source.protocol = "lifecycle-outbound";
    auto prepared = PrepareOutboundConfig(source);
    ASSERT_TRUE(prepared);
    ::net::io_context io;
    ::ResidentTaskGroup tasks(io.get_executor());
    EXPECT_TRUE(NewProxy(*prepared, io, tasks.Tasks()));
}

TEST(ProtocolRegistration, ExplicitSendThroughOverridesProtocolBinding) {
    using namespace ::proxyman::outbound;
    RegisterProxy("lifecycle-bound-outbound", &CreateOutboundConfig);
    ::infra::OutboundSourceConfig source;
    source.tag = "lifecycle-bound-tag";
    source.protocol = "lifecycle-bound-outbound";
    source.send_through = ::OutboundBind{};
    const auto prepared = PrepareOutboundConfig(source);
    ASSERT_TRUE(prepared);
    EXPECT_EQ(prepared->sender.send_through.GetMode(), ::OutboundBind::Mode::None);
}

class InvalidRuntimeCreator : public ::testing::TestWithParam<bool> {};

TEST_P(InvalidRuntimeCreator, RejectsMissingOrNullRuntimeCreator) {
    using namespace ::proxyman::outbound;
    ::net::io_context io;
    ::ResidentTaskGroup tasks(io.get_executor());
    PreparedOutboundConfig config;
    config.tag = "lifecycle-invalid-runtime";
    if (GetParam()) {
        RegisterProxy("lifecycle-null-outbound", &CreateNullOutboundConfig);
        ::infra::OutboundSourceConfig source;
        source.tag = config.tag;
        source.protocol = "lifecycle-null-outbound";
        auto prepared = PrepareOutboundConfig(source);
        ASSERT_TRUE(prepared);
        config = std::move(*prepared);
    }
    EXPECT_THROW((void)NewProxy(config, io, tasks.Tasks()), std::logic_error);
}

INSTANTIATE_TEST_SUITE_P(RuntimeCreation, InvalidRuntimeCreator, ::testing::Bool(), ([](const ::testing::TestParamInfo<bool>& info) { return info.param ? "NullRuntime" : "MissingCreator"; }));

TEST(ProtocolRegistration, RejectsPreparedOutboundWithoutCreator) {
    using namespace ::proxyman::outbound;
    RegisterProxy("lifecycle-empty-outbound", &CreateEmptyOutboundConfig);
    ::infra::OutboundSourceConfig source;
    source.protocol = "lifecycle-empty-outbound";
    EXPECT_FALSE(PrepareOutboundConfig(source));
}

}  // namespace

class BuiltinOutboundSettings
    : public ::testing::TestWithParam<std::tuple<bool, bool>> {};

TEST_P(BuiltinOutboundSettings, CreatesOnlyProtocolMatchingTypedSettings) {
    const auto [freedom_protocol, freedom_settings] = GetParam();
    infra::OutboundSourceConfig source{
        .tag = "typed-outbound",
        .protocol = freedom_protocol ? "freedom" : "blackhole",
        .settings = infra::FreedomSettings{
            .domain_strategy = proxy::freedom::outbound::DomainStrategy::UseIPv6v4},
        .stream_settings = {},
        .send_through = {},
        .passthrough = false,
    };
    if (!freedom_settings) source.settings = infra::BlackholeSettings{.http_response = true};
    auto prepared = proxyman::outbound::PrepareOutboundConfig(source);
    if (freedom_protocol != freedom_settings) {
        EXPECT_FALSE(prepared);
        return;
    }
    ASSERT_TRUE(prepared);
    net::io_context io;
    ResidentTaskGroup tasks(io.get_executor());
    EXPECT_TRUE(proxyman::outbound::NewProxy(*prepared, io, tasks.Tasks()));
}

INSTANTIATE_TEST_SUITE_P(ProtocolsAndSettings, BuiltinOutboundSettings, ::testing::Combine(::testing::Bool(), ::testing::Bool()), ([](const ::testing::TestParamInfo<BuiltinOutboundSettings::ParamType>& info) { const auto [freedom_protocol, freedom_settings] = info.param;
return std::string(freedom_protocol ? "FreedomProtocol" : "BlackholeProtocol") +
    (freedom_settings ? "FreedomSettings" : "BlackholeSettings"); }));
