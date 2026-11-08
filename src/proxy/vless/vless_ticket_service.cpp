#include "vless_ticket_service.hpp"

#include "app/session_group_executor.hpp"
#include "infra/log.hpp"

#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <openssl/rand.h>
#include <map>
#include <string>
#include <unordered_map>

namespace vless {
namespace {
using Clock = std::chrono::steady_clock;
using Ticket = std::array<uint8_t, kVlessEncryptionTicketSize>;
using Resumed = VlessEncryptionServerTicketStore::ResumedSession;

class TicketActorHooks final : public ExecutionDomain::Hooks {
public:
    void Enter() noexcept override {}
    void Leave() noexcept override {}
    void OnFailure(std::exception_ptr) noexcept override { std::terminate(); }
};

struct ActorKey {
    const VlessEncryptionConfig* config;
    std::string tag;
    uint32_t worker;
    bool operator==(const ActorKey&) const = default;
};
struct ActorHash {
    size_t operator()(const ActorKey& key) const noexcept {
        return std::hash<const void*>{}(key.config) ^ std::hash<std::string>{}(key.tag) ^
            std::hash<uint32_t>{}(key.worker);
    }
};

class LocalTicketService final : public net::execution_context::service {
public:
    inline static net::execution_context::id id;
    explicit LocalTicketService(net::execution_context& context) : service(context) {}
    VlessEncryptionServerTicketStore* Get(
        const std::shared_ptr<const VlessEncryptionConfig>& config, std::string_view tag) {
        if (!config_) {
            config_ = config;
            tag_ = tag;
        }
        return config_ == config && tag_ == tag ? &tickets_ : nullptr;
    }
private:
    void shutdown() override {}
    std::shared_ptr<const VlessEncryptionConfig> config_;
    std::string tag_;
    VlessEncryptionServerTicketStore tickets_;
};

struct DirectoryKey {
    const VlessEncryptionConfig* config;
    std::string tag;
    Ticket ticket;
    bool operator==(const DirectoryKey& other) const noexcept {
        return config == other.config && tag == other.tag &&
            CRYPTO_memcmp(ticket.data(), other.ticket.data(), ticket.size()) == 0;
    }
};
struct DirectoryHash {
    std::array<uint64_t, 2> key{};
    size_t operator()(const DirectoryKey& value) const noexcept {
        return static_cast<size_t>(SIPHASH_24(key.data(), value.ticket.data(), value.ticket.size())) ^
            std::hash<const void*>{}(value.config) ^ std::hash<std::string>{}(value.tag);
    }
};
struct DirectoryEntry {
    std::shared_ptr<const VlessEncryptionConfig> config;
    std::shared_ptr<ExecutionDomain> owner;
    Clock::time_point expires;
};

// All fields are confined to the coordinator executor. Timer callbacks retain
// State, never a service pointer, so cancellation cannot outlive a destroyed
// service. Entries contain no PFS secret or mutable replay state.
struct DirectoryState final : std::enable_shared_from_this<DirectoryState> {
    explicit DirectoryState(net::io_context& reactor) : timer(reactor), entries(0, MakeHash()) {}
    static DirectoryHash MakeHash() {
        DirectoryHash hash;
        if (RAND_bytes(reinterpret_cast<uint8_t*>(hash.key.data()), sizeof(hash.key)) != 1)
            throw IoSystemError(io_error::fault, "VLESS ticket directory randomness failed");
        return hash;
    }
    static void ReleaseActor(std::shared_ptr<ExecutionDomain> actor) noexcept {
        if (!actor || actor->CanExecuteInline()) return;
        auto* raw = actor.get();
        try {
            raw->Execute([actor = std::move(actor)]() mutable { actor.reset(); });
        } catch (...) {}
    }
    void Prune(Clock::time_point now) {
        while (!expiry.empty() && expiry.begin()->first <= now) {
            if (auto it = entries.find(expiry.begin()->second); it != entries.end()) {
                ReleaseActor(std::move(it->second.owner));
                entries.erase(it);
            }
            expiry.erase(expiry.begin());
        }
    }
    void Arm() {
        if (closed || expiry.empty()) return;
        const auto deadline = expiry.begin()->first;
        if (armed && *armed <= deadline) return;
        armed = deadline;
        timer.expires_at(deadline);
        timer.async_wait([self = shared_from_this()](const IoErrorCode& error) {
            if (error || self->closed) return;
            self->armed.reset();
            self->Prune(Clock::now());
            self->Arm();
        });
    }
    void Stop() noexcept {
        closed = true;
        timer.cancel();
        expiry.clear();
        for (auto& [key, entry] : entries) {
            (void)key;
            ReleaseActor(std::move(entry.owner));
        }
        entries.clear();
        actors.clear();
    }
    bool Publish(DirectoryKey key, DirectoryEntry entry) {
        Prune(Clock::now());
        if (closed || entry.expires <= Clock::now() || entries.contains(key)) {
            ReleaseActor(std::move(entry.owner));
            return false;
        }
        while (entries.size() >= 65536 && !expiry.empty()) {
            if (auto it = entries.find(expiry.begin()->second); it != entries.end()) {
                ReleaseActor(std::move(it->second.owner));
                entries.erase(it);
            }
            expiry.erase(expiry.begin());
        }
        if (entries.size() >= 65536) {
            ReleaseActor(std::move(entry.owner));
            return false;
        }
        auto event = expiry.emplace(entry.expires, key);
        try {
            entries.emplace(std::move(key), std::move(entry));
        } catch (...) {
            expiry.erase(event);
            throw;
        }
        Arm();
        return true;
    }
    std::shared_ptr<ExecutionDomain> Find(const DirectoryKey& key) {
        Prune(Clock::now());
        if (closed) return {};
        const auto it = entries.find(key);
        return it == entries.end() ? nullptr : it->second.owner;
    }
    std::shared_ptr<ExecutionDomain> FindActor(const ActorKey& key) {
        const auto it = actors.find(key);
        if (closed || it == actors.end()) return {};
        auto actor = it->second.lock();
        if (!actor) actors.erase(it);
        return actor;
    }
    std::shared_ptr<ExecutionDomain> RememberActor(
        ActorKey key, std::shared_ptr<ExecutionDomain> candidate) {
        if (auto actor = FindActor(key)) {
            ReleaseActor(std::move(candidate));
            return actor;
        }
        if (closed) {
            ReleaseActor(std::move(candidate));
            return {};
        }
        if (actors.size() >= 65536) {
            std::erase_if(actors, [](const auto& entry) { return entry.second.expired(); });
            if (actors.size() >= 65536) {
                ReleaseActor(std::move(candidate));
                return {};
            }
        }
        actors.insert_or_assign(std::move(key), candidate);
        return candidate;
    }
    net::steady_timer timer;
    std::unordered_map<DirectoryKey, DirectoryEntry, DirectoryHash> entries;
    std::multimap<Clock::time_point, DirectoryKey> expiry;
    std::unordered_map<ActorKey, std::weak_ptr<ExecutionDomain>, ActorHash> actors;
    std::optional<Clock::time_point> armed;
    bool closed = false;
};
class TicketDirectoryService final : public net::execution_context::service {
public:
    inline static net::execution_context::id id;
    explicit TicketDirectoryService(net::execution_context& context) : service(context) {}
    DirectoryState& Get(net::io_context& reactor) {
        if (!state_) state_ = std::make_shared<DirectoryState>(reactor);
        return *state_;
    }
private:
    void shutdown() override { if (state_) state_->Stop(); }
    std::shared_ptr<DirectoryState> state_;
};
DirectoryState& Directory(GroupCoordinator& coordinator) {
    return net::use_service<TicketDirectoryService>(coordinator.Services()).Get(coordinator.Reactor());
}

net::awaitable<std::optional<Resumed>> LookupOnOwner(
    std::shared_ptr<ExecutionDomain> owner,
    std::shared_ptr<const VlessEncryptionConfig> config,
    std::string tag, Ticket ticket, VlessEncryptionNfsKey nfs, uint32_t receiver) {
    if (ExecutionDomain::Current() != owner) {
        throw IoSystemError(io_error::operation_aborted, "VLESS ticket owner executor mismatch");
    }
    auto* store = net::use_service<LocalTicketService>(owner->Services()).Get(config, tag);
    auto result = store ? store->Lookup(ticket, nfs, Clock::now()) : std::nullopt;
    LOG_NET_DEBUG("inbound '{}' ticket lookup owner={} receiver={} accepted={}",
                  tag, owner->OwnerId(), receiver, result.has_value());
    co_return result;
}
net::awaitable<std::optional<Resumed>> ResolveAndLookup(
    GroupCoordinator* coordinator,
    std::shared_ptr<const VlessEncryptionConfig> config,
    std::string tag, Ticket ticket, VlessEncryptionNfsKey nfs, uint32_t receiver) {
    auto owner = Directory(*coordinator).Find(DirectoryKey{config.get(), tag, ticket});
    if (!owner) co_return std::nullopt;
    // Only authentication values cross this boundary. Neither the socket nor
    // early/application data is sent to the owner or forwarded afterward.
    co_return co_await net::co_spawn(owner->Executor(),
        LookupOnOwner(owner, std::move(config), std::move(tag), ticket, std::move(nfs), receiver),
        net::use_awaitable);
}

net::awaitable<std::shared_ptr<ExecutionDomain>> CreateTicketActor(
    std::shared_ptr<ExecutionDomain> origin) {
    // No PhysicalSessionCapabilities, transport, user view, dispatcher, or
    // outbound pool is retained by this actor. Its storage uses process malloc.
    static const auto hooks = std::make_shared<TicketActorHooks>();
    auto sibling = origin->CreateSibling(hooks);
    origin.reset();
    co_return sibling;
}
net::awaitable<bool> StoreOnActor(
    std::shared_ptr<ExecutionDomain> actor,
    std::shared_ptr<const VlessEncryptionConfig> config, std::string tag,
    VlessEncryptionIssuedTicket issued, std::array<uint8_t, 16> identity) {
    if (ExecutionDomain::Current() != actor) co_return false;
    auto* store = net::use_service<LocalTicketService>(actor->Services()).Get(config, tag);
    if (!store) co_return false;
    store->Store(issued.ticket, issued.pfs_key, issued.seconds, issued.issued_at);
    co_return store->BindIdentity(issued.ticket, identity, Clock::now());
}
net::awaitable<bool> RegisterTicket(
    GroupCoordinator* coordinator, std::shared_ptr<ExecutionDomain> origin,
    std::shared_ptr<const VlessEncryptionConfig> config, std::string tag,
    VlessEncryptionIssuedTicket issued, std::array<uint8_t, 16> identity) {
    const auto expires = issued.issued_at + std::chrono::seconds(issued.seconds);
    const auto now = Clock::now();
    if (issued.seconds == 0 || expires <= now) co_return false;
    auto& directory = Directory(*coordinator);
    directory.Prune(now);
    if (directory.closed ||
        directory.entries.contains(DirectoryKey{config.get(), tag, issued.ticket})) {
        co_return false;
    }
    ActorKey actor_key{config.get(), tag, origin->OwnerId()};
    auto actor = directory.FindActor(actor_key);
    if (!actor) {
        auto candidate = co_await net::co_spawn(origin->Executor(),
            CreateTicketActor(origin), net::use_awaitable);
        actor_key.worker = candidate->OwnerId();
        actor = directory.RememberActor(std::move(actor_key), std::move(candidate));
        if (!actor) co_return false;
        directory.Prune(Clock::now());
        if (directory.closed ||
            directory.entries.contains(DirectoryKey{config.get(), tag, issued.ticket})) {
            co_return false;
        }
    }
    // Release the physical domain as soon as its narrow actor is resolved.
    origin.reset();
    const auto ticket = issued.ticket;
    if (!co_await net::co_spawn(actor->Executor(),
            StoreOnActor(actor, config, tag, std::move(issued), identity), net::use_awaitable)) {
        DirectoryState::ReleaseActor(std::move(actor));
        co_return false;
    }
    auto rollback_actor = actor;
    auto rollback_config = config;
    auto rollback_tag = tag;
    auto key = DirectoryKey{config.get(), std::move(tag), ticket};
    if (!directory.Publish(std::move(key),
            DirectoryEntry{std::move(config), std::move(actor), expires})) {
        auto* raw = rollback_actor.get();
        try {
            raw->Execute([actor = std::move(rollback_actor),
                          cfg = std::move(rollback_config),
                          t = std::move(rollback_tag),
                          ticket]() mutable {
                if (auto* store = net::use_service<LocalTicketService>(actor->Services()).Get(cfg, t)) {
                    store->Erase(ticket);
                }
            });
        } catch (...) {}
        co_return false;
    }
    DirectoryState::ReleaseActor(std::move(rollback_actor));
    co_return true;
}
} // namespace


net::awaitable<bool> AuthenticateVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config, std::string_view tag,
    VlessEncryptionIssuedTicket ticket, std::array<uint8_t, 16> identity) {
    auto origin = ExecutionDomain::Current();
    if (!origin) co_return false;
    auto* coordinator = &origin->Coordinator();
    co_return co_await coordinator->Post(RegisterTicket(coordinator, std::move(origin),
        std::move(config), std::string(tag), std::move(ticket), identity));
}

net::awaitable<std::optional<Resumed>> LookupVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config, std::string_view tag,
    Ticket ticket, VlessEncryptionNfsKey nfs) {
    const auto receiver = ExecutionDomain::Current();
    if (!receiver) co_return std::nullopt;
    auto* coordinator = &receiver->Coordinator();
    co_return co_await coordinator->Post(ResolveAndLookup(coordinator,
        std::move(config), std::string(tag), ticket, std::move(nfs), receiver->OwnerId()));
}
} // namespace vless
