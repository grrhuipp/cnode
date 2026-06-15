#include "acppnode/app/bootstrap_inbounds.hpp"

#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/static_inbound_prepared_config.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/api/api.hpp"

#include <utility>

namespace acpp {

std::vector<std::string> SetupStaticInbounds(
    const std::vector<StaticInboundRuntimeEntry>& runtime_inbounds,
    std::vector<std::unique_ptr<Worker>>& workers,
    const std::vector<std::unique_ptr<ConnectionLimiter>>& connection_limiters) {
    std::vector<std::string> static_inbound_tags;

    if (runtime_inbounds.empty()) {
        return static_inbound_tags;
    }

    for (const auto& inbound : runtime_inbounds) {
        if (!proxyman::inbound::HasProxy(inbound.protocol)) {
            LOG_WARN("static_inbound skipped tag={} protocol={} reason=unsupported",
                     inbound.tag, inbound.protocol);
            continue;
        }

        for (const auto& worker : workers) {
            auto* connection_limiter = connection_limiters[worker->Id()].get();

            auto route_policy = inbound.routing_enabled
                ? proxyman::inbound::RoutePolicy::RouteWithFallback(
                      std::string(constants::protocol::kDirect))
                : proxyman::inbound::RoutePolicy::Fixed(
                      std::string(constants::protocol::kDirect));
            auto receiver = proxyman::inbound::MakeReceiverSettings(
                inbound.tag,
                inbound.all_tags,
                inbound.protocol,
                inbound.stream_settings,
                inbound.sniffing,
                connection_limiter,
                ProxyProtocolMode::Auto,
                std::move(route_policy));
            worker->RegisterInboundAsync(
                inbound.protocol,
                connection_limiter,
                inbound.build_request,
                std::move(receiver),
                true);
        }

        auto binding = MakePortBinding(
            inbound.port,
            inbound.protocol,
            inbound.tag,
            inbound.listen);
        for (const auto& worker : workers) {
            worker->AddListenerAsync(binding);
            auto* connection_limiter = connection_limiters[worker->Id()].get();
            worker->AddUdpListenerAsync(
                binding,
                inbound.protocol,
                connection_limiter,
                inbound.build_request,
                true);
        }
        static_inbound_tags.push_back(inbound.tag);
        LOG_CONSOLE("static_inbound ready tag={} port={} protocol={} network={}",
                    inbound.tag,
                    inbound.port,
                    inbound.protocol,
                    inbound.stream_settings.network);
    }

    return static_inbound_tags;
}

void SetupTestMode(
    std::vector<std::unique_ptr<Worker>>& workers,
    const std::vector<std::unique_ptr<ConnectionLimiter>>& connection_limiters) {
    const std::string protocol = std::string(constants::protocol::kDefaultNodeProtocol);

    LOG_CONSOLE("");
    LOG_CONSOLE("test_mode enabled port={} uuid={}",
                constants::test::kTestPort,
                constants::test::kTestVmessUuid);

    constexpr const char* kTestTag = constants::test::kTestInboundTag.data();

    StreamSettings ss;
    ss.network  = std::string(constants::protocol::kTcp);
    ss.security = std::string(constants::protocol::kNone);
    ss.RecomputeModes();

    SniffConfig sniff;
    sniff.enabled      = true;
    sniff.dest_override = {
        std::string(constants::protocol::kTls),
        std::string(constants::protocol::kHttp),
    };

    StaticUserConfig test_user_config;
    test_user_config.clients.push_back(StaticUser{
        .id = std::string(constants::test::kTestVmessUuid),
        .password = {},
        .email = "test@example.com",
    });
    auto test_users =
        proxyman::inbound::BuildStaticUsers(protocol, kTestTag, test_user_config);
    if (!test_users) {
        LOG_WARN("test_mode failed reason=build_vmess_test_user");
        return;
    }
    proxyman::inbound::UserStore::ApplyUsers(protocol, kTestTag, *test_users);

    proxyman::inbound::BuildRequest req;
    req.tag = kTestTag;
    req.protocol = protocol;

    for (const auto& worker : workers) {
        auto* connection_limiter = connection_limiters[worker->Id()].get();

        auto receiver = proxyman::inbound::MakeReceiverSettings(
            kTestTag,
            std::vector<std::string>{kTestTag},
            protocol,
            ss,
            sniff,
            connection_limiter);

        worker->RegisterInboundAsync(
            protocol,
            connection_limiter,
            req,
            std::move(receiver),
            true);
    }

    auto test_binding = MakePortBinding(
        constants::test::kTestPort,
        protocol,
        kTestTag);

    for (const auto& worker : workers) {
        // AddListenerAsync：post 到 Worker 线程，在 run() 启动后 SO_REUSEPORT bind
        worker->AddListenerAsync(test_binding);
    }
}

}  // namespace acpp
