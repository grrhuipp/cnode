#include <gtest/gtest.h>

#include "app/prepared_inbound.hpp"
#include "app/inbound_handler.hpp"
#include "app/user_store.hpp"
#include "common/constants.hpp"
#include "infra/config_types.hpp"
#include "routing/dispatcher.hpp"
#include "proxy/inbound.hpp"
#include "transport/stream_settings.hpp"
#include <algorithm>
#include <array>
#include <span>
#include <stdexcept>


namespace {
using namespace ::app;
size_t user_builds = 0;

// Marks a prepared user with the credential text it was built from.
std::array<uint8_t, 16> CredentialMarker(std::string_view credential) {
    std::array<uint8_t, 16> marker{};
    std::copy_n(credential.begin(), std::min(credential.size(), marker.size()), marker.begin());
    return marker;
}

std::optional<UserSet> FakeBuildUsers(const BuildRequest&, std::span<const infra::InboundUserSpec> specs) {
    ++user_builds;
    PreparedVmessUsers users;
    for (const auto& spec : specs) {
        if (spec.credential == "reject") return std::nullopt;
        users.push_back(PreparedVmessUser{.uuid_bytes = CredentialMarker(spec.credential), .profile = {}});
    }
    return users;
}

infra::StaticInboundConfig Source(std::string tag, uint16_t port, std::string user = "static-user") {
    infra::StaticInboundConfig source;
    source.protocol = "vmess";
    source.tags.push_back(std::move(tag));
    source.port = port;
    source.listen = *transport::InboundListen::Parse("127.0.0.1");
    source.users.push_back(infra::InboundUserSpec{.user_id = 0, .email = {}, .credential = std::move(user), .flow = {}, .speed_limit = 0, .device_limit = 0});
    return source;
}

class StartupInboundTest : public ::testing::Test {
protected:
    void SetUp() override {
        static const bool registered = [] {
            ProxyRegistration registration;
            registration.user_protocol = UserProtocol::Vmess;
            registration.create_tcp_handler = [](const AdmissionEnvironment&,
                const BuildRequest&) -> std::unique_ptr<proxy::Inbound> { return {}; };
            registration.build_users = &FakeBuildUsers;
            RegisterProxy("vmess", registration);
            return true;
        }();
        (void)registered;
        user_builds = 0;
        auto snapshot = UserStore::PrepareUsers(
            "static-owner", UserSet{PreparedVmessUsers{PreparedVmessUser{.profile = {}}}});
        auto view = UserStore::PrepareWorkerView(snapshot);
        UserStore::CommitSnapshot(std::move(snapshot));
        UserStore::InstallWorkerView(std::move(view));
    }

    void TearDown() override {
        for (const auto tag : {std::string_view("static-owner"),
                               std::string_view(common::kTestInboundTag)}) {
            auto snapshot = UserStore::PrepareClearUsers(UserProtocol::Vmess, tag);
            UserStore::CommitSnapshot(std::move(snapshot));
        }
        UserStore::ClearWorkerView();
        user_builds = 0;
    }
};

class StartupReservedBinding : public StartupInboundTest,
                               public ::testing::WithParamInterface<bool> {};

TEST_P(StartupReservedBinding, RejectsCollisionBeforeBuildingCredentials) {
    auto source = GetParam()
        ? Source(std::string(common::kTestInboundTag), 12000)
        : Source("static-owner", common::kTestPort);
    EXPECT_THROW((void)app::PrepareStartupInbounds({source}, true), std::invalid_argument);
    EXPECT_EQ(user_builds, 0u);
}

INSTANTIATE_TEST_SUITE_P(TestMode, StartupReservedBinding, ::testing::Bool(),
    [](const ::testing::TestParamInfo<bool>& info) {
        return info.param ? "ReservedTag" : "ReservedPort";
    });

TEST_F(StartupInboundTest, PreparationAddsTestInboundWithoutPublishingUsers) {
    const auto old = UserStore::VmessUsers("static-owner").users;
    const auto prepared = app::PrepareStartupInbounds({Source("static-owner", 12000)}, true);
    ASSERT_EQ(prepared.size(), 2u);
    EXPECT_EQ(prepared[1].binding.tag, common::kTestInboundTag);
    EXPECT_EQ(prepared[1].binding.port, common::kTestPort);
    EXPECT_EQ(UserStore::VmessUsers("static-owner").users, old);
    EXPECT_TRUE(UserStore::VmessUsers(common::kTestInboundTag).empty());
}

TEST_F(StartupInboundTest, InvalidCredentialsLeavePublishedUsersUntouched) {
    const auto old = UserStore::VmessUsers("static-owner").users;
    EXPECT_THROW((void)app::PrepareStartupInbounds(
        {Source("static-owner", 12000), Source("invalid-users", 12001, "reject")}, false),
        std::invalid_argument);
    EXPECT_EQ(UserStore::VmessUsers("static-owner").users, old);
}

enum class StartupPolicy { Routed, Forced, ForcedOverridesRouting };
class StartupDispatchPolicy : public StartupInboundTest,
                              public ::testing::WithParamInterface<StartupPolicy> {};

TEST_P(StartupDispatchPolicy, PreservesExplicitRoutingAndOutboundSelection) {
    auto source = Source("configured", 12002);
    source.routing_enabled = GetParam() != StartupPolicy::Forced;
    source.proxy_protocol = transport::ProxyProtocolMode::On;
    if (GetParam() != StartupPolicy::Routed) source.outbound_tag = "custom-out";
    const auto prepared = app::PrepareStartupInbounds({source}, false);
    ASSERT_EQ(prepared.size(), 1u);
    EXPECT_EQ(prepared[0].receiver.proxy_protocol, transport::ProxyProtocolMode::On);
    const auto& policy = prepared[0].receiver.dispatch_policy.outbound;
    if (GetParam() == StartupPolicy::Routed) {
        EXPECT_TRUE(std::holds_alternative<routing::RouteWithFallback>(policy));
    } else {
        ASSERT_TRUE(std::holds_alternative<routing::ForceOutbound>(policy));
        EXPECT_EQ(std::get<routing::ForceOutbound>(policy).outbound_tag, "custom-out");
    }
}

INSTANTIATE_TEST_SUITE_P(ExplicitConfiguration, StartupDispatchPolicy,
    ::testing::Values(StartupPolicy::Routed, StartupPolicy::Forced,
                      StartupPolicy::ForcedOverridesRouting),
    [](const ::testing::TestParamInfo<StartupPolicy>& info) {
        switch (info.param) {
            case StartupPolicy::Routed: return "RoutingEnabled";
            case StartupPolicy::Forced: return "ForcedOutbound";
            case StartupPolicy::ForcedOverridesRouting: return "ForcedOverridesRouting";
        }
        return "Unknown";
    });
}
