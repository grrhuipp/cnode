#include "acppnode/app/bootstrap_inbounds.hpp"

#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/session_handler.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/panel/v2board_panel.hpp"
#include "acppnode/protocol/inbound_registry.hpp"
#include "acppnode/protocol/vmess/vmess_protocol.hpp"

#include <utility>

namespace acpp {

std::vector<std::string> SetupStaticInbounds(
    const Config& config,
    std::vector<std::unique_ptr<Worker>>& workers,
    std::shared_ptr<ConnectionLimiter> connection_limiter) {
    std::vector<std::string> static_inbound_tags;
    auto& inbound_factory = InboundFactory::Instance();

    if (config.GetInbounds().empty()) {
        return static_inbound_tags;
    }

    LOG_CONSOLE("Static Inbounds:");
    for (const auto& inbound : config.GetInbounds()) {
        const std::string& protocol = inbound.protocol;
        const std::string tag = inbound.tags.empty()
            ? naming::BuildProtocolPortTag(protocol, inbound.port)
            : inbound.tags.front();
        std::vector<std::string> all_tags = inbound.tags.empty()
            ? std::vector<std::string>{tag}
            : inbound.tags;

        if (!inbound_factory.Has(protocol)) {
            LOG_WARN("Static inbound '{}': unsupported protocol '{}', skipped", tag, protocol);
            continue;
        }

        InboundBuildRequest req;
        req.tag = tag;
        req.protocol = protocol;
        req.cipher_method = std::string(constants::protocol::kAes256Gcm);
        if (const auto* method = inbound.settings.if_contains("method");
                method && method->is_string()) {
            req.cipher_method = std::string(method->as_string());
        }

        if (!inbound_factory.LoadStaticUsers(protocol, tag, inbound.settings)) {
            LOG_WARN("Static inbound '{}': load users failed, skipped", tag);
            continue;
        }

        bool register_failed = false;
        for (const auto& worker : workers) {
            auto deps = worker->GetInboundProtocolDeps();

            inbound_factory.SyncWorkerUsers(protocol, deps, tag);
            auto handler = inbound_factory.CreateTcpHandler(
                protocol, deps, connection_limiter, req);
            if (!handler) {
                LOG_WARN("Static inbound '{}': create handler failed, skipped", tag);
                register_failed = true;
                break;
            }

            auto lc = MakeListenerContext(
                tag,
                all_tags,
                protocol,
                inbound.stream_settings,
                inbound.sniffing,
                connection_limiter,
                inbound.outbound_tag.empty()
                    ? std::string(constants::protocol::kDirect)
                    : inbound.outbound_tag);
            worker->RegisterListenerAsync(std::move(lc), std::move(handler));
        }

        if (register_failed) {
            for (const auto& worker : workers) {
                worker->UnregisterListenerAsync(tag);
            }
            continue;
        }

        auto binding = MakePortBinding(inbound.port, protocol, tag, inbound.listen);
        for (const auto& worker : workers) {
            worker->AddListenerAsync(binding);
            auto deps = worker->GetInboundProtocolDeps();

            auto udp_handler = inbound_factory.CreateUdpHandler(
                protocol, deps, connection_limiter, req);
            if (udp_handler) {
                worker->AddUdpListenerAsync(binding, std::move(udp_handler));
            }
        }
        static_inbound_tags.push_back(tag);
        LOG_CONSOLE("  - {} port={} protocol={} network={}",
                    tag, inbound.port, protocol, inbound.stream_settings.network);
    }

    return static_inbound_tags;
}

void SetupTestMode(
    std::vector<std::unique_ptr<Worker>>& workers,
    std::shared_ptr<ConnectionLimiter> connection_limiter) {
    auto& inbound_factory = InboundFactory::Instance();
    const std::string protocol = std::string(constants::protocol::kDefaultNodeProtocol);

    LOG_CONSOLE("");
    LOG_CONSOLE("Test mode: port={}, UUID={}",
                constants::test::kTestPort,
                constants::test::kTestVmessUuid);

    auto test_user = vmess::VMessUser::FromUUID(
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

    std::vector<vmess::VMessUser> users = {*test_user};
    vmess::VMessUserManager::UpdateSharedUsersForTag(kTestTag, std::move(users));

    InboundBuildRequest req;
    req.tag = kTestTag;
    req.protocol = protocol;

    for (const auto& worker : workers) {
        auto deps = worker->GetInboundProtocolDeps();

        inbound_factory.SyncWorkerUsers(protocol, deps, kTestTag);
        auto handler = inbound_factory.CreateTcpHandler(
            protocol, deps, connection_limiter, req);
        if (!handler) {
            LOG_WARN("Test mode: failed to create vmess inbound handler on worker {}", worker->Id());
            continue;
        }

        auto lc = MakeListenerContext(
            kTestTag,
            std::vector<std::string>{kTestTag},
            protocol,
            ss,
            sniff,
            connection_limiter);

        // RegisterListenerAsync：post 到 Worker 线程，在 run() 启动后执行
        worker->RegisterListenerAsync(std::move(lc), std::move(handler));
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
