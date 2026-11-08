#include "app/proxyman/inbound/handler_registry.hpp"

#include "app/proxyman/inbound/factory.hpp"
#include "app/proxyman/inbound/handler.hpp"
#include "common/allocator.hpp"
#include "common/online_device.hpp"
#include "common/string_hash.hpp"

namespace proxyman::inbound {

struct HandlerRegistry::Impl : memory::ThreadAllocated {
    using HandlerMap = memory::ThreadLocalUnorderedMap<
        memory::ThreadLocalString,
        std::shared_ptr<Handler>,
        TransparentStringHash,
        TransparentStringEq>;
    using RuntimeMap = memory::ThreadLocalUnorderedMap<
        memory::ThreadLocalString,
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
            memory::ThreadLocalString(protocol), std::move(runtime));
        return result.first->second.get();
    }

    StatsShard& stats;
    RuntimeMap runtimes;
    HandlerMap handlers;
};

HandlerRegistry::HandlerRegistry(StatsShard& stats)
    : impl_(std::make_unique<Impl>(stats)) {}

HandlerRegistry::~HandlerRegistry() noexcept = default;

HandlerRegistry::HandlerPtr HandlerRegistry::GetHandler(std::string_view tag) noexcept {
    auto it = impl_->handlers.find(tag);
    return it == impl_->handlers.end() ? nullptr : it->second;
}

std::shared_ptr<const Handler>
HandlerRegistry::GetHandler(std::string_view tag) const noexcept {
    auto it = impl_->handlers.find(tag);
    return it == impl_->handlers.end() ? nullptr : it->second;
}

std::unique_ptr<::Inbound> HandlerRegistry::NewHandler(
    ::ConnectionLimiter* limiter,
    const BuildRequest& req) {
    auto* runtime = impl_->EnsureRuntime(req.protocol);
    if (!runtime) {
        return nullptr;
    }
    return ::proxyman::inbound::NewHandler(
        req.protocol, *runtime, impl_->stats, std::move(limiter), req);
}

DatagramHandlerBuildResult HandlerRegistry::NewDatagramHandler(
    ::ConnectionLimiter* limiter,
    const BuildRequest& req) {
    auto* runtime = impl_->EnsureRuntime(req.protocol);
    if (!runtime) {
        return {DatagramHandlerBuildStatus::Failed, nullptr};
    }
    return ::proxyman::inbound::NewDatagramHandler(
        req.protocol, *runtime, impl_->stats, std::move(limiter), req);
}

ProtocolRuntime* HandlerRegistry::GetOrCreateRuntime(
    std::string_view protocol) {
    return impl_->EnsureRuntime(protocol);
}

HandlerRegistry::HandlerPtr HandlerRegistry::ReplaceHandler(std::unique_ptr<Handler> handler) {
    if (!handler) {
        return nullptr;
    }

    memory::ThreadLocalString tag(handler->Tag());
    auto shared_handler = std::shared_ptr<Handler>(
        handler.release(), std::default_delete<Handler>{},
        memory::ThreadLocalAllocator<Handler>{});
    auto it = impl_->handlers.find(tag);
    if (it == impl_->handlers.end()) {
        auto [inserted_it, inserted] = impl_->handlers.try_emplace(
            std::move(tag), std::move(shared_handler));
        return inserted ? inserted_it->second : nullptr;
    }

    it->second = std::move(shared_handler);
    return it->second;
}

void HandlerRegistry::RemoveHandler(std::string_view tag) {
    auto it = impl_->handlers.find(tag);
    if (it == impl_->handlers.end()) {
        return;
    }

    impl_->handlers.erase(it);
}

std::vector<::OnlineDevice>
HandlerRegistry::GetOnlineDevices(std::string_view protocol, std::string_view tag) const {
    if (auto it = impl_->runtimes.find(protocol); it != impl_->runtimes.end()) {
        return it->second->GetOnlineDevices(tag);
    }
    return {};
}

}  // namespace proxyman::inbound
