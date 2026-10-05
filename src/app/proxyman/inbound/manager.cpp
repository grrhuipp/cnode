#include "acppnode/app/proxyman/inbound/manager.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/handler.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/common/string_hash.hpp"

#include <asio/strand.hpp>

namespace acpp::proxyman::inbound {

struct Manager::Impl {
    using HandlerMap = memory::DataUnorderedMap<
        std::string,
        std::shared_ptr<Handler>,
        TransparentStringHash,
        TransparentStringEq>;
    using RuntimeMap = memory::DataUnorderedMap<
        std::string,
        std::unique_ptr<ProtocolRuntime>,
        TransparentStringHash,
        TransparentStringEq>;

    Impl(net::any_io_executor owner_executor,
         net::any_io_executor shared_executor)
        : owner_executor(std::move(owner_executor)),
          shared_executor(std::move(shared_executor)),
          online(net::make_strand(this->shared_executor), 65536) {}

    [[nodiscard]] ProtocolRuntime* EnsureRuntime(std::string_view protocol) {
        if (auto it = runtimes.find(protocol); it != runtimes.end()) {
            return it->second.get();
        }
        auto runtime = NewProtocolRuntime(
            protocol, net::make_strand(shared_executor));
        if (!runtime) return nullptr;
        auto result = runtimes.emplace(
            std::string(protocol), std::move(runtime));
        return result.first->second.get();
    }

    net::any_io_executor owner_executor;
    net::any_io_executor shared_executor;
    UserOnlineTracker online;
    RuntimeMap runtimes;
    HandlerMap handlers;
};

Manager::Manager(net::any_io_executor owner_executor,
                 net::any_io_executor shared_executor)
    : impl_(std::make_unique<Impl>(
          std::move(owner_executor), std::move(shared_executor))) {}

Manager::~Manager() noexcept = default;

Manager::HandlerPtr Manager::GetHandler(std::string_view tag) noexcept {
    auto it = impl_->handlers.find(tag);
    return it == impl_->handlers.end() ? nullptr : it->second;
}

std::shared_ptr<const Handler>
Manager::GetHandler(std::string_view tag) const noexcept {
    auto it = impl_->handlers.find(tag);
    return it == impl_->handlers.end() ? nullptr : it->second;
}

std::unique_ptr<::acpp::Inbound> Manager::NewHandler(
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req) {
    auto* runtime = impl_->EnsureRuntime(req.protocol);
    if (!runtime) {
        return nullptr;
    }
    return ::acpp::proxyman::inbound::NewHandler(
        req.protocol, *runtime, impl_->online, std::move(limiter), req);
}

DatagramHandlerBuildResult Manager::NewDatagramHandler(
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req) {
    auto* runtime = impl_->EnsureRuntime(req.protocol);
    if (!runtime) {
        return {DatagramHandlerBuildStatus::Failed, nullptr};
    }
    return ::acpp::proxyman::inbound::NewDatagramHandler(
        req.protocol, *runtime, impl_->online, std::move(limiter), req);
}

Manager::HandlerPtr Manager::ReplaceHandler(std::unique_ptr<Handler> handler) {
    if (!handler) {
        return nullptr;
    }

    std::string tag(handler->Tag());
    auto shared_handler = std::shared_ptr<Handler>(std::move(handler));
    auto it = impl_->handlers.find(tag);
    if (it == impl_->handlers.end()) {
        auto [inserted_it, inserted] = impl_->handlers.try_emplace(
            std::move(tag), std::move(shared_handler));
        return inserted ? inserted_it->second : nullptr;
    }

    it->second = std::move(shared_handler);
    return it->second;
}

void Manager::RemoveHandler(std::string_view tag) {
    auto it = impl_->handlers.find(tag);
    if (it == impl_->handlers.end()) {
        return;
    }

    impl_->handlers.erase(it);
}

net::awaitable<std::vector<::acpp::OnlineDevice>>
Manager::GetOnlineDevices(std::string tag) {
    return impl_->online.GetOnlineDevices(std::move(tag));
}

}  // namespace acpp::proxyman::inbound
