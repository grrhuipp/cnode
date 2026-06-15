#include "acppnode/app/bootstrap_inbounds.hpp"

#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/proxyman/inbound/udp_handler.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/static_inbound_prepared_config.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/api/api.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/proxy/vmess/account.hpp"

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

    LOG_CONSOLE("Static Inbounds:");

    for (const auto& inbound : runtime_inbounds) {
        bool register_failed = false;
        for (const auto& worker : workers) {
            auto* connection_limiter = connection_limiters[worker->Id()].get();

            auto handler = worker->NewInboundHandler(
                inbound.protocol, connection_limiter, inbound.build_request);
            if (!handler) {
                LOG_WARN("Static inbound '{}': create handler failed, skipped", inbound.tag);
                register_failed = true;
                break;
            }
            handler->SetBanTrackingEnabled(true);

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
            worker->RegisterListenerAsync(std::move(receiver), std::move(handler));
        }

        if (register_failed) {
            for (const auto& worker : workers) {
                worker->UnregisterListenerAsync(inbound.tag);
            }
            continue;
        }

        auto binding = MakePortBinding(
            inbound.port,
            inbound.protocol,
            inbound.tag,
            inbound.listen);
        for (const auto& worker : workers) {
            worker->AddListenerAsync(binding);
            auto* connection_limiter = connection_limiters[worker->Id()].get();

            auto udp_handler = worker->NewUdpInboundHandler(
                inbound.protocol,
                connection_limiter,
                inbound.build_request);
            if (udp_handler) {
                udp_handler->SetBanTrackingEnabled(true);
                worker->AddUdpListenerAsync(binding, std::move(udp_handler));
            }
        }
        static_inbound_tags.push_back(inbound.tag);
        LOG_CONSOLE("  - {} port={} protocol={} network={}",
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
    LOG_CONSOLE("Test mode: port={}, UUID={}",
                constants::test::kTestPort,
                constants::test::kTestVmessUuid);

    auto test_user = vmess::MemoryAccount::FromUUID(
        std::string(constants::test::kTestVmessUuid), 1, "test@example.com");

    if (!test_user) {
        return;
    }

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

    proxyman::inbound::UserSet test_users;
    test_users.vmess_accounts.push_back(*test_user);
    proxyman::inbound::UserStore::ApplyUsers(protocol, kTestTag, test_users);

    proxyman::inbound::BuildRequest req;
    req.tag = kTestTag;
    req.protocol = protocol;

    for (const auto& worker : workers) {
        auto* connection_limiter = connection_limiters[worker->Id()].get();

        auto handler = worker->NewInboundHandler(
            protocol, connection_limiter, req);
        if (!handler) {
            LOG_WARN("Test mode: failed to create vmess inbound handler on worker {}", worker->Id());
            continue;
        }
        handler->SetBanTrackingEnabled(true);

        auto receiver = proxyman::inbound::MakeReceiverSettings(
            kTestTag,
            std::vector<std::string>{kTestTag},
            protocol,
            ss,
            sniff,
            connection_limiter);

        // RegisterListenerAsync：post 到 Worker 线程，在 run() 启动后执行
        worker->RegisterListenerAsync(std::move(receiver), std::move(handler));
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
