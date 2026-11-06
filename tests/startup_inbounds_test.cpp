#include "startup_inbounds.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/features/routing/dispatch_policy.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/transport/internet/transport_security.hpp"

#include <iostream>
#include <span>
#include <stdexcept>

namespace acpp {
void TransportSecurity::Prepare(StreamSettings& settings, StreamEndpointRole) {
    if (settings.IsTlsLike()) throw std::logic_error("unexpected TLS in plaintext startup fixture");
}
}

namespace {
using namespace acpp;
using namespace acpp::proxyman::inbound;
size_t user_builds = 0;

std::optional<UserSet> FakeBuildUsers(const BuildRequest&, std::span<const InboundUserSpec> specs) {
    ++user_builds;
    PreparedVmessUsers users;
    for (const auto& spec : specs) {
        if (spec.credential == "reject") return std::nullopt;
        users.push_back(PreparedVmessUser{.uuid = spec.credential, .profile = {}});
    }
    return users;
}

StaticInboundConfig Source(std::string tag, uint16_t port, std::string user = "static-user") {
    StaticInboundConfig source;
    source.protocol = "vmess";
    source.tags.push_back(std::move(tag));
    source.port = port;
    source.listen = *InboundListen::Parse("127.0.0.1");
    source.users.push_back(InboundUserSpec{.user_id = 0, .email = {}, .credential = std::move(user), .flow = {}, .speed_limit = 0, .device_limit = 0});
    return source;
}

bool Rejected(std::vector<StaticInboundConfig> sources, bool test_mode) {
    try { (void)PrepareStartupInbounds(std::move(sources), test_mode); }
    catch (const std::invalid_argument&) { return true; }
    return false;
}
}

int main() {
    // Use the production registry and startup preparation with a narrow fake
    // credential builder. Actual VMess startup is covered by process tests.
    ProxyRegistration registration;
    registration.user_protocol = UserProtocol::Vmess;
    registration.create_runtime = []() -> std::unique_ptr<ProtocolRuntime> { return {}; };
    registration.create_tcp_handler = [](ProtocolRuntime&, StatsShard&, ConnectionLimiter*,
                                          const BuildRequest&) -> std::unique_ptr<Inbound> { return {}; };
    registration.build_users = &FakeBuildUsers;
    RegisterProxy("vmess", registration);

    {
        auto snapshot = UserStore::PrepareUsers(
            "static-owner", UserSet{PreparedVmessUsers{
                PreparedVmessUser{.uuid = "sentinel", .profile = {}}}});
        auto view = UserStore::PrepareWorkerView(snapshot);
        UserStore::CommitSnapshot(std::move(snapshot));
        UserStore::InstallWorkerView(std::move(view));
    }
    const auto old = UserStore::VmessUsers("static-owner").users;
    if (!Rejected({Source(std::string(constants::test::kTestInboundTag), 12000)}, true) || user_builds != 0 ||
        !Rejected({Source("static-owner", constants::test::kTestPort)}, true) || user_builds != 0) return 1;

    const auto prepared = PrepareStartupInbounds({Source("static-owner", 12000)}, true);
    if (prepared.size() != 2 || prepared[0].receiver.proxy_protocol != ProxyProtocolMode::Auto ||
        prepared[1].receiver.proxy_protocol != ProxyProtocolMode::Auto) return 6;
    if (user_builds != 2 || prepared.size() != 2 ||
        prepared[0].binding.tag != "static-owner" || prepared[0].build_request.tag != "static-owner" ||
        prepared[1].binding.tag != constants::test::kTestInboundTag ||
        prepared[1].build_request.tag != constants::test::kTestInboundTag ||
        prepared[1].binding.port != constants::test::kTestPort ||
        prepared[1].receiver.stream_settings.network != "tcp" ||
        prepared[1].receiver.stream_settings.security != "none" ||
        prepared[1].receiver.stream_settings.network_mode != NetworkMode::Tcp ||
        prepared[1].receiver.stream_settings.security_mode != SecurityMode::None ||
        !prepared[1].receiver.dispatch_policy.sniffing.enabled || !prepared[1].binding.listen.IsAuto() ||
        std::get<PreparedVmessUsers>(*prepared[1].users).front().uuid != constants::test::kTestVmessUuid ||
        UserStore::VmessUsers("static-owner").users != old ||
        !UserStore::VmessUsers(constants::test::kTestInboundTag).empty()) return 2;

    user_builds = 0;
    if (!Rejected({Source("static-owner", 12000), Source("invalid-users", 12001, "reject")}, false) ||
        user_builds != 2 || UserStore::VmessUsers("static-owner").users != old) return 3;
    if (!PrepareStartupInbounds({}, false).empty() || PrepareStartupInbounds({}, true).size() != 1) return 4;

    auto routed = Source("routed", 12002);
    routed.routing_enabled = true;
    routed.proxy_protocol = ProxyProtocolMode::On;
    auto forced = Source("forced", 12001);
    forced.outbound_tag = "custom-out";
    auto forced_override = Source("forced-override", 12003);
    forced_override.routing_enabled = true;
    forced_override.outbound_tag = "custom-out";
    const auto policies = PrepareStartupInbounds(
        {Source("default-direct", 12000), routed, forced, forced_override}, false);
    if (policies.size() != 4 || policies[1].receiver.proxy_protocol != ProxyProtocolMode::On ||
        policies[0].receiver.proxy_protocol != ProxyProtocolMode::Auto) return 7;
    if (policies.size() != 4 ||
        !std::holds_alternative<routing::ForceOutbound>(policies[0].receiver.dispatch_policy.outbound) ||
        std::get<routing::ForceOutbound>(policies[0].receiver.dispatch_policy.outbound).outbound_tag != "direct" ||
        !std::holds_alternative<routing::RouteWithFallback>(policies[1].receiver.dispatch_policy.outbound) ||
        std::get<routing::RouteWithFallback>(policies[1].receiver.dispatch_policy.outbound).outbound_tag != "direct" ||
        !std::holds_alternative<routing::ForceOutbound>(policies[2].receiver.dispatch_policy.outbound) ||
        std::get<routing::ForceOutbound>(policies[2].receiver.dispatch_policy.outbound).outbound_tag != "custom-out" ||
        !std::holds_alternative<routing::ForceOutbound>(policies[3].receiver.dispatch_policy.outbound) ||
        std::get<routing::ForceOutbound>(policies[3].receiver.dispatch_policy.outbound).outbound_tag != "custom-out") return 5;
    std::cout << "startup sources share validation and preparation without user publication\n";
}
