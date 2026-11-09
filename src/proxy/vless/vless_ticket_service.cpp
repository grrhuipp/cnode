#include "vless_ticket_service.hpp"

#include "app/session_group_executor.hpp"
#include "infra/log.hpp"

#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <string>
#include <unordered_map>

namespace vless {
namespace {
using Clock = std::chrono::steady_clock;
using Ticket = std::array<uint8_t, kVlessEncryptionTicketSize>;
using Resumed = VlessEncryptionServerTicketStore::ResumedSession;

struct StoreKey {
    const VlessEncryptionConfig* config = nullptr;
    std::string tag;
    bool operator==(const StoreKey&) const = default;
};

struct StoreKeyHash {
    size_t operator()(const StoreKey& key) const noexcept {
        return std::hash<const void*>{}(key.config) ^ std::hash<std::string>{}(key.tag);
    }
};

struct StoreEntry {
    std::shared_ptr<const VlessEncryptionConfig> config;
    VlessEncryptionServerTicketStore tickets;
};

class TicketDirectoryService final : public net::execution_context::service {
public:
    inline static net::execution_context::id id;
    explicit TicketDirectoryService(net::execution_context& context) : service(context) {}

    VlessEncryptionServerTicketStore& GetOrCreate(
        std::shared_ptr<const VlessEncryptionConfig> config, std::string_view tag) {
        StoreKey key{config.get(), std::string(tag)};
        auto [it, inserted] = stores_.try_emplace(std::move(key));
        if (inserted) it->second.config = std::move(config);
        return it->second.tickets;
    }

    VlessEncryptionServerTicketStore* Find(
        const VlessEncryptionConfig* config, std::string_view tag) {
        auto it = stores_.find(StoreKey{config, std::string(tag)});
        return it == stores_.end() ? nullptr : &it->second.tickets;
    }

private:
    void shutdown() override { stores_.clear(); }
    std::unordered_map<StoreKey, StoreEntry, StoreKeyHash> stores_;
};

} // namespace

net::awaitable<bool> AuthenticateVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config, std::string_view tag,
    VlessEncryptionIssuedTicket ticket, std::array<uint8_t, 16> identity) {
    if (!config) co_return false;
    auto executor = co_await net::this_coro::executor;
    auto* coordinator = GroupCoordinator::ForContext(
        net::query(executor, net::execution::context));
    if (!coordinator) co_return false;
    std::string owned_tag(tag);
    co_return co_await coordinator->PostCall(
        [coordinator, config = std::move(config), tag = std::move(owned_tag),
         ticket = std::move(ticket), identity]() mutable -> bool {
            const auto now = Clock::now();
            const auto expires = ticket.issued_at + std::chrono::seconds(ticket.seconds);
            if (ticket.seconds == 0 || expires <= now) return false;
            auto& store = net::use_service<TicketDirectoryService>(
                coordinator->Services()).GetOrCreate(std::move(config), tag);
            store.Store(ticket.ticket, ticket.pfs_key, ticket.seconds, ticket.issued_at);
            return store.BindIdentity(ticket.ticket, identity, now);
        });
}

net::awaitable<std::optional<Resumed>> LookupVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config, std::string_view tag,
    Ticket ticket, VlessEncryptionNfsKey nfs) {
    if (!config) co_return std::nullopt;
    auto executor = co_await net::this_coro::executor;
    auto& context = net::query(executor, net::execution::context);
    auto* coordinator = GroupCoordinator::ForContext(context);
    if (!coordinator) co_return std::nullopt;
    const auto receiver = GroupCoordinator::WorkerIdForContext(context).value_or(0);
    std::string owned_tag(tag);
    co_return co_await coordinator->PostCall(
        [coordinator, config = std::move(config), tag = std::move(owned_tag),
         ticket, nfs = std::move(nfs), receiver]() -> std::optional<Resumed> {
            auto* store = net::use_service<TicketDirectoryService>(
                coordinator->Services()).Find(config.get(), tag);
            auto result = store ? store->Lookup(ticket, nfs, Clock::now()) : std::nullopt;
            LOG_NET_DEBUG("inbound '{}' ticket lookup receiver={} accepted={}",
                          tag, receiver, result.has_value());
            return result;
        });
}

} // namespace vless
