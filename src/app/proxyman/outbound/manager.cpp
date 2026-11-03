#include "acppnode/app/proxyman/outbound/manager.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/proxy/outbound.hpp"

namespace acpp::proxyman::outbound {

Manager::Manager() = default;

Manager::~Manager() noexcept {
    Clear();
}

Manager::HandlerPtr Manager::GetHandler(std::string_view tag) noexcept {
    auto it = handlers_.find(tag);
    return it == handlers_.end() ? nullptr : it->second;
}

Manager::HandlerPtr Manager::AddHandler(std::unique_ptr<Outbound> handler) {
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

Manager::HandlerPtr Manager::ReplaceHandler(std::unique_ptr<Outbound> handler) {
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

void Manager::RemoveHandler(std::string_view tag) {
    auto it = handlers_.find(tag);
    if (it == handlers_.end()) {
        return;
    }

    handlers_.erase(it);
}

void Manager::Clear() noexcept {
    handlers_.clear();
    MaybeShrinkHashContainer(handlers_, 8);
}

}  // namespace acpp::proxyman::outbound
