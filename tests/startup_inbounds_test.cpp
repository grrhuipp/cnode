#include "startup_inbounds.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/features/routing/dispatch_policy.hpp"
#include "acppnode/proxy/inbound.hpp"

#include <iostream>
#include <stdexcept>

namespace {
using namespace acpp;
using namespace acpp::proxyman::inbound;
size_t user_builds = 0;

std::optional<UserSet> BuildUsers(std::string_view, const StaticUserConfig& source) {
    ++user_builds;
    PreparedVmessUsers users;
    for (const auto& client : source.clients) {
        if (client.id == "reject") return std::nullopt;
        users.push_back(PreparedVmessUser{.uuid = client.id});
    }
    return users;
}

StaticInboundConfig Source(std::string tag, uint16_t port, std::string user = "static-user") {
    StaticInboundConfig source;
    source.protocol = "vmess";
    source.tags.push_back(std::move(tag));
    source.port = port;
    source.listen = *InboundListen::Parse("127.0.0.1");
    source.static_users.clients.push_back(StaticUser{.id = std::move(user)});
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
    registration.create_tcp_handler = [](ProtocolRuntime&, StatsShard&, ConnectionLimiterPtr,
                                          const BuildRequest&) -> std::unique_ptr<Inbound> { return {}; };
    registration.build_static_users = &BuildUsers;
    RegisterProxy("vmess", registration);

    UserStore::ApplyUsers("static-owner", UserSet{PreparedVmessUsers{PreparedVmessUser{.uuid = "sentinel"}}});
    const auto old = UserStore::VmessUsers("static-owner").users;
    if (!Rejected({Source(std::string(constants::test::kTestInboundTag), 12000)}, true) || user_builds != 0 ||
        !Rejected({Source("static-owner", constants::test::kTestPort)}, true) || user_builds != 0) return 1;

    const auto prepared = PrepareStartupInbounds({Source("static-owner", 12000)}, true);
    if (user_builds != 2 || prepared.size() != 2 ||
        prepared[0].runtime.tag != "static-owner" || prepared[0].runtime.build_request.tag != "static-owner" ||
        prepared[1].runtime.tag != constants::test::kTestInboundTag ||
        prepared[1].runtime.build_request.tag != constants::test::kTestInboundTag ||
        prepared[1].runtime.port != constants::test::kTestPort ||
        prepared[1].runtime.stream_settings.network != "tcp" ||
        prepared[1].runtime.stream_settings.security != "none" ||
        prepared[1].runtime.stream_settings.network_mode != NetworkMode::Tcp ||
        prepared[1].runtime.stream_settings.security_mode != SecurityMode::None ||
        !prepared[1].runtime.sniffing.enabled || !prepared[1].runtime.listen.IsAuto() ||
        std::get<PreparedVmessUsers>(prepared[1].users).front().uuid != constants::test::kTestVmessUuid ||
        UserStore::VmessUsers("static-owner").users != old ||
        !UserStore::VmessUsers(constants::test::kTestInboundTag).empty()) return 2;

    user_builds = 0;
    if (!Rejected({Source("static-owner", 12000), Source("invalid-users", 12001, "reject")}, false) ||
        user_builds != 2 || UserStore::VmessUsers("static-owner").users != old) return 3;
    if (!PrepareStartupInbounds({}, false).empty() || PrepareStartupInbounds({}, true).size() != 1) return 4;

    auto forced = Source("forced", 12001);
    forced.outbound_tag = "custom-out";
    const auto policies = PrepareStartupInbounds({Source("routed", 12002), forced}, false);
    if (policies.size() != 2 ||
        !std::holds_alternative<routing::RouteWithFallback>(policies[0].runtime.outbound_policy) ||
        std::get<routing::RouteWithFallback>(policies[0].runtime.outbound_policy).outbound_tag != "direct" ||
        !std::holds_alternative<routing::ForceOutbound>(policies[1].runtime.outbound_policy) ||
        std::get<routing::ForceOutbound>(policies[1].runtime.outbound_policy).outbound_tag != "custom-out") return 5;

    std::cout << "startup sources share validation and preparation without user publication\n";
}
