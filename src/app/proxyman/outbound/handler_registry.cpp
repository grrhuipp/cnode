#include "acppnode/app/proxyman/outbound/handler_registry.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/proxy/outbound.hpp"

namespace acpp::proxyman::outbound {

HandlerRegistry::HandlerRegistry() = default;

HandlerRegistry::~HandlerRegistry() noexcept = default;

HandlerRegistry::HandlerPtr HandlerRegistry::GetHandler(std::string_view tag) noexcept {
    auto it = handlers_.find(tag);
    return it == handlers_.end() ? nullptr : it->second;
}

HandlerRegistry::HandlerPtr HandlerRegistry::AddHandler(std::unique_ptr<Outbound> handler) {
    if (!handler) {
        return nullptr;
    }

    memory::ThreadLocalString tag(handler->Tag());
    auto shared_handler = std::shared_ptr<Outbound>(
        handler.release(), std::default_delete<Outbound>{},
        memory::ThreadLocalAllocator<Outbound>{});
    auto [it, inserted] = handlers_.try_emplace(
        std::move(tag), std::move(shared_handler));
    if (!inserted) {
        return nullptr;
    }

    return it->second;
}

HandlerRegistry::HandlerPtr HandlerRegistry::ReplaceHandler(std::unique_ptr<Outbound> handler) {
    if (!handler) {
        return nullptr;
    }

    auto it = handlers_.find(handler->Tag());
    if (it == handlers_.end()) {
        return AddHandler(std::move(handler));
    }

    it->second = std::shared_ptr<Outbound>(
        handler.release(), std::default_delete<Outbound>{},
        memory::ThreadLocalAllocator<Outbound>{});
    return it->second;
}

bool HandlerRegistry::RestoreHandler(HandlerPtr handler) {
    if (!handler) {
        return false;
    }

    auto it = handlers_.find(handler->Tag());
    if (it == handlers_.end()) {
        memory::ThreadLocalString tag(handler->Tag());
        return handlers_.try_emplace(std::move(tag), std::move(handler)).second;
    }

    it->second = std::move(handler);
    return true;
}

void HandlerRegistry::RemoveHandler(std::string_view tag) {
    auto it = handlers_.find(tag);
    if (it == handlers_.end()) {
        return;
    }

    handlers_.erase(it);
}

}  // namespace acpp::proxyman::outbound
