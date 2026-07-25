#include "acppnode/app/bootstrap_inbounds.hpp"

#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"

#include <asio/use_future.hpp>

#include <stdexcept>
#include <string_view>
#include <utility>

namespace acpp {

namespace {

StaticInboundRuntimeEntry BuildTestModeInbound() {
    const std::string protocol = std::string(constants::protocol::kDefaultNodeProtocol);
    constexpr std::string_view kTestTag = constants::test::kTestInboundTag;

    StreamSettings stream_settings;
    stream_settings.network = std::string(constants::protocol::kTcp);
    stream_settings.security = std::string(constants::protocol::kNone);
    stream_settings.RecomputeModes();

    SniffConfig sniffing;
    sniffing.enabled = true;
    sniffing.dest_override = {
        std::string(constants::protocol::kTls),
        std::string(constants::protocol::kHttp),
    };

    StaticUserConfig user_config;
    user_config.clients.push_back(StaticUser{
        .id = std::string(constants::test::kTestVmessUuid),
        .password = {},
        .email = "test@example.com",
        .flow = {},
    });
    auto users = proxyman::inbound::BuildStaticUsers(protocol, kTestTag, user_config);
    if (!users) {
        throw std::runtime_error("test mode VMess user preparation failed");
    }
    proxyman::inbound::UserStore::ApplyUsers(kTestTag, *users);

    StaticInboundRuntimeEntry entry;
    entry.protocol = protocol;
    entry.tag = kTestTag;
    entry.all_tags = {entry.tag};
    entry.port = constants::test::kTestPort;
    entry.stream_settings = std::move(stream_settings);
    entry.sniffing = std::move(sniffing);
    entry.build_request.tag = entry.tag;
    entry.build_request.protocol = protocol;
    return entry;
}

net::awaitable<void> RemoveInstalledInbounds(
    Worker& worker,
    const std::vector<std::string>& installed,
    std::string_view current_tag) {
    if (!current_tag.empty()) {
        co_await worker.UnregisterListenerTask(std::string(current_tag));
    }
    for (auto it = installed.rbegin(); it != installed.rend(); ++it) {
        co_await worker.UnregisterListenerTask(*it);
    }
}

net::awaitable<bool> SetupWorkerInbounds(
    Worker& worker,
    std::vector<StaticInboundRuntimeEntry> inbounds,
    ConnectionLimiterPtr connection_limiter) {
    co_await worker.StartRuntimeTask();

    std::vector<std::string> installed;
    installed.reserve(inbounds.size());

    for (const auto& inbound : inbounds) {
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
            std::move(route_policy),
            0);  // Custom/static inbounds never enter centralized access logs.

        if (!co_await worker.RegisterInboundTask(
                connection_limiter,
                inbound.build_request,
                std::move(receiver))) {
            co_await RemoveInstalledInbounds(worker, installed, inbound.tag);
            co_return false;
        }

        auto binding = MakePortBinding(
            inbound.port,
            inbound.protocol,
            inbound.tag,
            inbound.listen);
        if (!co_await worker.AddListenerTask(binding)) {
            co_await RemoveInstalledInbounds(worker, installed, inbound.tag);
            co_return false;
        }

        if (!co_await worker.AddUdpListenerTask(
                binding,
                connection_limiter,
                inbound.build_request)) {
            co_await RemoveInstalledInbounds(worker, installed, inbound.tag);
            co_return false;
        }

        installed.push_back(inbound.tag);
    }

    co_return true;
}

}  // namespace

InboundStartup QueueInboundStartup(
    const std::vector<StaticInboundRuntimeEntry>& runtime_inbounds,
    std::vector<std::unique_ptr<Worker>>& workers,
    const std::vector<std::unique_ptr<ConnectionLimiter>>& connection_limiters,
    bool enable_test_mode) {
    InboundStartup startup;
    startup.entries = runtime_inbounds;
    if (enable_test_mode) {
        LOG_CONSOLE("");
        LOG_CONSOLE("test_mode enabled port={} uuid={}",
                    constants::test::kTestPort,
                    constants::test::kTestVmessUuid);
        startup.entries.push_back(BuildTestModeInbound());
    }

    startup.tags.reserve(startup.entries.size());
    for (const auto& inbound : startup.entries) {
        startup.tags.push_back(inbound.tag);
    }

    startup.worker_results.reserve(workers.size());
    for (const auto& worker : workers) {
        if (worker->Id() >= connection_limiters.size()) {
            throw std::runtime_error("worker has no matching connection limiter");
        }
        auto* limiter = connection_limiters[worker->Id()].get();
        startup.worker_results.push_back(net::co_spawn(
            worker->GetExecutor(),
            SetupWorkerInbounds(*worker, startup.entries, limiter),
            net::use_future));
    }
    return startup;
}

}  // namespace acpp
