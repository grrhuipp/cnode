#include "acppnode/app/proxyman/outbound/manager.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/proxy/outbound.hpp"

namespace acpp::proxyman::outbound {

struct Manager::Impl {
    using HandlerMap = memory::ThreadLocalUnorderedMap<
        std::string,
        std::unique_ptr<Outbound>,
        TransparentStringHash,
        TransparentStringEq>;

    HandlerMap handlers;
    memory::ThreadLocalVector<std::unique_ptr<Outbound>> retired_handlers;
    Outbound* default_handler = nullptr;
};

Manager::Manager()
    : impl_(std::make_unique<Impl>()) {}

Manager::~Manager() noexcept {
    Clear();
}

Outbound* Manager::GetHandler(std::string_view tag) noexcept {
    auto it = impl_->handlers.find(tag);
    return it == impl_->handlers.end() ? nullptr : it->second.get();
}

Outbound* Manager::GetDefaultHandler() noexcept {
    return impl_->default_handler;
}

Outbound* Manager::AddHandler(std::unique_ptr<Outbound> handler) noexcept {
    if (!handler) {
        return nullptr;
    }

    std::string tag(handler->Tag());
    if (impl_->handlers.contains(tag)) {
        return nullptr;
    }

    Outbound* raw = handler.get();
    if (!impl_->default_handler) {
        impl_->default_handler = raw;
    }
    impl_->handlers.emplace(std::move(tag), std::move(handler));
    return raw;
}

Outbound* Manager::ReplaceHandler(std::unique_ptr<Outbound> handler) noexcept {
    if (!handler) {
        return nullptr;
    }

    std::string tag(handler->Tag());
    auto it = impl_->handlers.find(tag);
    if (it == impl_->handlers.end()) {
        return AddHandler(std::move(handler));
    }

    Outbound* raw = handler.get();
    const bool replacing_default = impl_->default_handler == it->second.get();
    impl_->retired_handlers.push_back(std::move(it->second));
    it->second = std::move(handler);
    if (replacing_default) {
        impl_->default_handler = raw;
    }
    return raw;
}

void Manager::RemoveHandler(std::string_view tag) noexcept {
    auto it = impl_->handlers.find(tag);
    if (it == impl_->handlers.end()) {
        return;
    }

    if (impl_->default_handler == it->second.get()) {
        impl_->default_handler = nullptr;
    }

    impl_->retired_handlers.push_back(std::move(it->second));
    impl_->handlers.erase(it);

    if (!impl_->default_handler && !impl_->handlers.empty()) {
        impl_->default_handler = impl_->handlers.begin()->second.get();
    }
}

void Manager::Clear() noexcept {
    impl_->handlers.clear();
    impl_->retired_handlers.clear();
    MaybeShrinkHashContainer(impl_->handlers, 8);
    TryShrinkSequence(impl_->retired_handlers);
    impl_->default_handler = nullptr;
}

void Manager::DrainRetiredHandlers() noexcept {
    impl_->retired_handlers.clear();
    TryShrinkSequence(impl_->retired_handlers);
}

}  // namespace acpp::proxyman::outbound
