#include "acppnode/app/proxyman/outbound/manager.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/runtime/channel.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/proxy/outbound.hpp"

#include <asio/strand.hpp>
#include <atomic>
#include <exception>
#include <stdexcept>

namespace acpp::proxyman::outbound {

struct Manager::Impl {
    using HandlerMap = memory::DataUnorderedMap<std::string, HandlerPtr,
        TransparentStringHash, TransparentStringEq>;

    explicit Impl(net::any_io_executor executor)
        : channel(net::make_strand(std::move(executor)), 65),
          shutdown_ticket(channel.TryReserve()), empty(memory::AllocateShared<const HandlerMap>()),
          table(empty) {}

    struct Change {
        Impl& owner;
        explicit Change(Impl& owner, bool shutdown = false) : owner(owner) {
            if (owner.changing || (owner.stopping && !shutdown)) throw ServiceChannelFull();
            owner.changing = true;
        }
        ~Change() { owner.changing = false; }
    };
    net::awaitable<HandlerPtr> Install(std::unique_ptr<Outbound> handler, bool replace) {
        Change change(*this);
        if (!handler) co_return HandlerPtr{};
        const std::string tag(handler->Tag());
        if (tag.empty()) throw std::invalid_argument("outbound tag is empty");
        const auto previous = table.load(std::memory_order_acquire);
        const auto found = previous->find(tag);
        if (!replace && found != previous->end()) co_return HandlerPtr{};
        const auto retired = found == previous->end() ? HandlerPtr{} : found->second;
        auto candidate = memory::AllocateShared<HandlerMap>(*previous);
        HandlerPtr current(std::move(handler));
        candidate->insert_or_assign(tag, current);
        table.store(std::move(candidate), std::memory_order_release);
        if (retired) co_await retired->Stop();
        co_return current;
    }
    net::awaitable<void> Remove(std::string tag) {
        Change change(*this);
        const auto previous = table.load(std::memory_order_acquire);
        const auto found = previous->find(tag);
        if (found == previous->end()) co_return;
        const auto retired = found->second;
        auto candidate = memory::AllocateShared<HandlerMap>(*previous);
        candidate->erase(tag);
        table.store(std::move(candidate), std::memory_order_release);
        co_await retired->Stop();
    }
    net::awaitable<void> Stop() {
        Change change(*this, true);
        stopping = true;
        const auto retired = table.exchange(empty, std::memory_order_acq_rel);
        std::exception_ptr failure;
        for (const auto& [tag, handler] : *retired) {
            (void)tag;
            try { co_await handler->Stop(); }
            catch (...) { if (!failure) failure = std::current_exception(); }
        }
        if (failure) std::rethrow_exception(failure);
    }

    ServiceChannel channel;
    ServiceChannel::Reservation shutdown_ticket;
    const std::shared_ptr<const HandlerMap> empty;
    std::atomic<std::shared_ptr<const HandlerMap>> table;
    bool changing = false;
    bool stopping = false;
};

Manager::Manager(net::any_io_executor executor)
    : impl_(std::make_unique<Impl>(std::move(executor))) {}
Manager::~Manager() noexcept = default;

Manager::HandlerPtr Manager::GetHandler(std::string_view tag) const noexcept {
    const auto table = impl_->table.load(std::memory_order_acquire);
    const auto found = table->find(tag);
    return found == table->end() ? nullptr : found->second;
}
net::awaitable<Manager::HandlerPtr> Manager::AddHandler(std::unique_ptr<Outbound> handler) {
    co_return co_await impl_->channel.PostCommitted(impl_->Install(std::move(handler), false));
}
net::awaitable<Manager::HandlerPtr> Manager::ReplaceHandler(std::unique_ptr<Outbound> handler) {
    co_return co_await impl_->channel.PostCommitted(impl_->Install(std::move(handler), true));
}
net::awaitable<void> Manager::RemoveHandler(std::string tag) {
    co_await impl_->channel.PostCommitted(impl_->Remove(std::move(tag)));
}
net::awaitable<void> Manager::Clear() {
    co_await impl_->channel.PostReserved(impl_->shutdown_ticket, impl_->Stop());
}

} // namespace acpp::proxyman::outbound
