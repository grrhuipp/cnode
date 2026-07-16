#include "acppnode/app/proxyman/inbound/manager.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/handler.hpp"
#include "acppnode/app/proxyman/inbound/udp_handler.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/common/string_hash.hpp"

namespace acpp::proxyman::inbound {

struct Manager::Impl {
    using HandlerMap = memory::ThreadLocalUnorderedMap<
        std::string,
        std::unique_ptr<Handler>,
        TransparentStringHash,
        TransparentStringEq>;
    using RuntimeMap = memory::ThreadLocalUnorderedMap<
        std::string,
        std::unique_ptr<ProtocolRuntime>,
        TransparentStringHash,
        TransparentStringEq>;

    explicit Impl(StatsShard& stats) noexcept
        : stats(stats) {}

    [[nodiscard]] ProtocolRuntime* EnsureRuntime(std::string_view protocol) {
        if (auto it = runtimes.find(protocol); it != runtimes.end()) {
            return it->second.get();
        }
        auto runtime = NewProtocolRuntime(protocol);
        if (!runtime) return nullptr;
        auto result = runtimes.emplace(
            std::string(protocol), std::move(runtime));
        return result.first->second.get();
    }

    [[nodiscard]] ProtocolDeps Deps(std::string_view protocol) {
        return ProtocolDeps{
            .runtime = EnsureRuntime(protocol),
            .stats = &stats,
        };
    }

    StatsShard& stats;
    RuntimeMap runtimes;
    HandlerMap handlers;
    memory::ThreadLocalVector<std::unique_ptr<Handler>> retired_handlers;
};

Manager::Manager(StatsShard& stats)
    : impl_(std::make_unique<Impl>(stats)) {}

Manager::~Manager() noexcept = default;

Handler* Manager::GetHandler(std::string_view tag) noexcept {
    auto it = impl_->handlers.find(tag);
    return it == impl_->handlers.end() ? nullptr : it->second.get();
}

const Handler* Manager::GetHandler(std::string_view tag) const noexcept {
    auto it = impl_->handlers.find(tag);
    return it == impl_->handlers.end() ? nullptr : it->second.get();
}

std::unique_ptr<::acpp::Inbound> Manager::NewHandler(
    std::string_view protocol,
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req) {
    return ::acpp::proxyman::inbound::NewHandler(
        protocol, impl_->Deps(protocol), std::move(limiter), req);
}

UdpHandlerBuildResult Manager::NewUdpHandler(
    std::string_view protocol,
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req) {
    return ::acpp::proxyman::inbound::NewUdpHandler(
        protocol, impl_->Deps(protocol), std::move(limiter), req);
}

Handler* Manager::ReplaceHandler(std::unique_ptr<Handler> handler) {
    if (!handler) {
        return nullptr;
    }

    std::string tag(handler->Tag());
    auto it = impl_->handlers.find(tag);
    if (it == impl_->handlers.end()) {
        auto [inserted_it, inserted] = impl_->handlers.try_emplace(
            std::move(tag), std::move(handler));
        return inserted ? inserted_it->second.get() : nullptr;
    }

    impl_->retired_handlers.push_back(std::move(it->second));
    it->second = std::move(handler);
    return it->second.get();
}

void Manager::RemoveHandler(std::string_view tag) {
    auto it = impl_->handlers.find(tag);
    if (it == impl_->handlers.end()) {
        return;
    }

    impl_->retired_handlers.push_back(std::move(it->second));
    impl_->handlers.erase(it);
}

void Manager::DrainRetiredHandlers() {
    impl_->retired_handlers.clear();
    TryShrinkSequence(impl_->retired_handlers);
}

std::vector<::acpp::OnlineDevice>
Manager::GetOnlineDevices(std::string_view protocol, std::string_view tag) const {
    if (auto it = impl_->runtimes.find(protocol); it != impl_->runtimes.end()) {
        return it->second->GetOnlineDevices(tag);
    }
    return {};
}

Manager::UserMemoryStats Manager::GetUserMemoryStats() const noexcept {
    const auto stats = UserStore::GetStats();
    return UserMemoryStats{
        stats.vmess_accounts,
        stats.vless_users,
        stats.trojan_users,
        stats.shadowsocks_users,
        stats.anytls_users,
    };
}

}  // namespace acpp::proxyman::inbound
