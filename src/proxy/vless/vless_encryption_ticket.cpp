#include "proxy/vless/vless_encryption.hpp"
#include "app/session_group_executor.hpp"
#include "infra/log.hpp"

#include <blake3.h>

#include <algorithm>
#include <chrono>
#include <string>
#include <unordered_map>
#include <utility>
namespace proxy::vless {
namespace {
[[nodiscard]] std::array<uint8_t, 32> DigestNfsKey(
    const VlessEncryptionNfsKey& nfs_key) noexcept {
    std::array<uint8_t, 32> out{};
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, nfs_key.bytes.data(), nfs_key.bytes.size());
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    OPENSSL_cleanse(&hasher, sizeof(hasher));
    return out;
}
}  // namespace
bool VlessEncryptionClientTicketCache::Valid(
    std::chrono::steady_clock::time_point now) const noexcept {
    return expires_at > now;
}

void VlessEncryptionClientTicketCache::Store(
    const VlessEncryptionClientPfsOpenResult& open,
    std::chrono::steady_clock::time_point now) noexcept {
    if (open.ticket_seconds == 0) {
        Clear();
        return;
    }
    pfs_key = open.pfs_key;
    ticket = open.ticket;
    expires_at = now + std::chrono::seconds(open.ticket_seconds);
}

VlessEncryptionServerTicketStore::VlessEncryptionServerTicketStore()
    : sessions_(kMaxSessions) {}

void VlessEncryptionServerTicketStore::EraseOldest() {
    sessions_.EvictOldest([this](auto& entry) noexcept {
        seen_nfs_keys_ -= entry.value.seen_nfs_keys.size();
    });
}

void VlessEncryptionServerTicketStore::Prune(std::chrono::steady_clock::time_point now) {
    sessions_.Prune(now, [this](auto& entry) noexcept {
        seen_nfs_keys_ -= entry.value.seen_nfs_keys.size();
    });
}

std::optional<VlessEncryptionServerTicketStore::ResumedSession>
VlessEncryptionServerTicketStore::Lookup(
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    const VlessEncryptionNfsKey& nfs_key, std::chrono::steady_clock::time_point now) {
    Prune(now);
    while (seen_nfs_keys_ >= kMaxSeenNfsKeys && !sessions_.empty()) EraseOldest();
    TicketArray key{};
    std::copy(ticket.begin(), ticket.end(), key.begin());
    auto* entry = sessions_.Find(key);
    if (!entry || entry->expires_at <= now || !entry->value.identity ||
        entry->value.seen_nfs_keys.size() >= kMaxSeenNfsKeysPerSession) return std::nullopt;
    auto& session = entry->value;
    if (!session.seen_nfs_keys.insert(DigestNfsKey(nfs_key)).second) return std::nullopt;
    ++seen_nfs_keys_;
    return ResumedSession{session.pfs_key, *session.identity};
}

bool VlessEncryptionServerTicketStore::BindIdentity(
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    const std::array<uint8_t, 16>& identity, std::chrono::steady_clock::time_point now) {
    TicketArray key{};
    std::copy(ticket.begin(), ticket.end(), key.begin());
    auto* entry = sessions_.Find(key);
    if (!entry || entry->expires_at <= now) return false;
    auto& bound = entry->value.identity;
    if (bound) return CRYPTO_memcmp(bound->data(), identity.data(), identity.size()) == 0;
    bound = identity;
    return true;
}

void VlessEncryptionServerTicketStore::Erase(
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket) noexcept {
    TicketArray key{};
    std::copy(ticket.begin(), ticket.end(), key.begin());
    sessions_.Erase(key, [this](auto& entry) noexcept {
        seen_nfs_keys_ -= entry.value.seen_nfs_keys.size();
    });
}

void VlessEncryptionServerTicketStore::Store(
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    const VlessEncryptionPfsKey& pfs_key, uint16_t seconds,
    std::chrono::steady_clock::time_point now) {
    if (seconds == 0) return;
    Prune(now);
    TicketArray key{};
    std::copy(ticket.begin(), ticket.end(), key.begin());
    // 重复票据不得覆盖身份、密钥或防重放历史。
    if (sessions_.Find(key)) return;
    sessions_.Insert(key, now + std::chrono::seconds(seconds), Session{
        .pfs_key = pfs_key, .identity = std::nullopt,
        .seen_nfs_keys = decltype(Session::seen_nfs_keys)(
            0, sessions_.hash_function(), proxy::TimingSafeEqual{}, memory::process_resource()),
    }, [this](auto& entry) noexcept {
        seen_nfs_keys_ -= entry.value.seen_nfs_keys.size();
    });
}
namespace {
using Clock = std::chrono::steady_clock;
using Ticket = std::array<uint8_t, kVlessEncryptionTicketSize>;
using Resumed = VlessEncryptionServerTicketStore::ResumedSession;

struct StoreKey {
    const VlessEncryptionConfig* config = nullptr;
    std::string tag;
    bool operator==(const StoreKey&) const = default;
};

struct StoreKeyView {
    const VlessEncryptionConfig* config = nullptr;
    std::string_view tag;
};

struct StoreKeyHash {
    using is_transparent = void;

    size_t operator()(const StoreKey& key) const noexcept {
        return (*this)(StoreKeyView{key.config, key.tag});
    }
    size_t operator()(const StoreKeyView& key) const noexcept {
        return std::hash<const void*>{}(key.config) ^
               std::hash<std::string_view>{}(key.tag);
    }
};

struct StoreKeyEqual {
    using is_transparent = void;

    bool operator()(const StoreKey& a, const StoreKey& b) const noexcept {
        return a == b;
    }
    bool operator()(const StoreKey& a, const StoreKeyView& b) const noexcept {
        return a.config == b.config && std::string_view(a.tag) == b.tag;
    }
    bool operator()(const StoreKeyView& a, const StoreKey& b) const noexcept {
        return a.config == b.config && a.tag == std::string_view(b.tag);
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
        if (auto it = stores_.find(StoreKeyView{config.get(), tag}); it != stores_.end()) {
            return it->second.tickets;
        }
        StoreKey key{config.get(), std::string(tag)};
        auto [it, inserted] = stores_.try_emplace(std::move(key));
        if (inserted) it->second.config = std::move(config);
        return it->second.tickets;
    }

    VlessEncryptionServerTicketStore* Find(
        const VlessEncryptionConfig* config, std::string_view tag) {
        auto it = stores_.find(StoreKeyView{config, tag});
        return it == stores_.end() ? nullptr : &it->second.tickets;
    }

private:
    void shutdown() override { stores_.clear(); }
    std::unordered_map<StoreKey, StoreEntry, StoreKeyHash, StoreKeyEqual> stores_;
};

} // namespace

net::awaitable<bool> AuthenticateVlessTicket(
    app::GroupCoordinator& coordinator,
    std::shared_ptr<const VlessEncryptionConfig> config, std::string_view tag,
    VlessEncryptionIssuedTicket ticket, std::array<uint8_t, 16> identity) {
    if (!config) co_return false;
    std::string owned_tag(tag);
    co_return co_await coordinator.PostCall(
        [&coordinator, config = std::move(config), tag = std::move(owned_tag),
         ticket = std::move(ticket), identity]() mutable -> bool {
            const auto now = Clock::now();
            const auto expires = ticket.issued_at + std::chrono::seconds(ticket.seconds);
            if (ticket.seconds == 0 || expires <= now) return false;
            auto& store = net::use_service<TicketDirectoryService>(
                coordinator.Services()).GetOrCreate(std::move(config), tag);
            store.Store(ticket.ticket, ticket.pfs_key, ticket.seconds, ticket.issued_at);
            return store.BindIdentity(ticket.ticket, identity, now);
        });
}

net::awaitable<std::optional<Resumed>> LookupVlessTicket(
    app::GroupCoordinator& coordinator,
    std::shared_ptr<const VlessEncryptionConfig> config, std::string_view tag,
    Ticket ticket, VlessEncryptionNfsKey nfs) {
    if (!config) co_return std::nullopt;
    std::string owned_tag(tag);
    co_return co_await coordinator.PostCall(
        [&coordinator, config = std::move(config), tag = std::move(owned_tag),
         ticket, nfs = std::move(nfs)]() -> std::optional<Resumed> {
            auto* store = net::use_service<TicketDirectoryService>(
                coordinator.Services()).Find(config.get(), tag);
            auto result = store ? store->Lookup(ticket, nfs, Clock::now()) : std::nullopt;
            LOG_NET_DEBUG("inbound '{}' ticket lookup accepted={}",
                          tag, result.has_value());
            return result;
        });
}
}  // namespace proxy::vless
