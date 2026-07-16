#include "acppnode/app/proxyman/outbound/manager.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/proxy/outbound.hpp"

namespace acpp::proxyman::outbound {

struct Manager::Impl {
    using HandlerMap = memory::ThreadLocalUnorderedMap<
        std::string,
        std::shared_ptr<Outbound>,
        TransparentStringHash,
        TransparentStringEq>;

    HandlerMap handlers;
    std::shared_ptr<Outbound> default_handler;
};

Manager::Manager()
    : impl_(std::make_unique<Impl>()) {}

Manager::~Manager() noexcept {
    Clear();
}

Manager::HandlerPtr Manager::GetHandler(std::string_view tag) noexcept {
    auto it = impl_->handlers.find(tag);
    return it == impl_->handlers.end() ? nullptr : it->second;
}

Manager::HandlerPtr Manager::GetDefaultHandler() noexcept {
    return impl_->default_handler;
}

Manager::HandlerPtr Manager::AddHandler(std::unique_ptr<Outbound> handler) {
    if (!handler) {
        return nullptr;
    }

    std::string tag(handler->Tag());
    auto shared_handler = std::shared_ptr<Outbound>(std::move(handler));
    auto [it, inserted] = impl_->handlers.try_emplace(
        std::move(tag), std::move(shared_handler));
    if (!inserted) {
        return nullptr;
    }

    if (!impl_->default_handler) {
        impl_->default_handler = it->second;
    }
    return it->second;
}

Manager::HandlerPtr Manager::ReplaceHandler(std::unique_ptr<Outbound> handler) {
    if (!handler) {
        return nullptr;
    }

    std::string tag(handler->Tag());
    auto it = impl_->handlers.find(tag);
    if (it == impl_->handlers.end()) {
        return AddHandler(std::move(handler));
    }

    const bool replacing_default = impl_->default_handler == it->second;
    it->second = std::shared_ptr<Outbound>(std::move(handler));
    if (replacing_default) {
        impl_->default_handler = it->second;
    }
    return it->second;
}

void Manager::RemoveHandler(std::string_view tag) {
    auto it = impl_->handlers.find(tag);
    if (it == impl_->handlers.end()) {
        return;
    }

    const bool removing_default = impl_->default_handler == it->second;
    impl_->handlers.erase(it);

    if (removing_default) {
        impl_->default_handler = impl_->handlers.empty()
            ? nullptr
            : impl_->handlers.begin()->second;
    }
}

void Manager::Clear() noexcept {
    impl_->handlers.clear();
    MaybeShrinkHashContainer(impl_->handlers, 8);
    impl_->default_handler.reset();
}

}  // namespace acpp::proxyman::outbound
