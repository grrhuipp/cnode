#include "validator.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "common/allocator.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/string_hash.hpp"
#include "common/container_util.hpp"
#include "vmess_crypto.hpp"
#include "vmess_request.hpp"
#include "app/session_group_executor.hpp"

#include <algorithm>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/siphash.h>
#include <cstdlib>
#include <array>
#include <chrono>
#include <cstring>
#include <utility>

namespace vmess {

namespace {

using SessionKey = std::array<uint8_t, 32>;

struct SessionKeyEqual {
    [[nodiscard]] bool operator()(const SessionKey& a, const SessionKey& b) const noexcept {
        return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
    }
};

struct SessionKeyHash {
    std::array<uint64_t, 2> key{};

    [[nodiscard]] size_t operator()(const SessionKey& value) const noexcept {
        return static_cast<size_t>(SIPHASH_24(key.data(), value.data(), value.size()));
    }
};

    struct SessionHistory {
        static constexpr int64_t kTtlSeconds = 180;
        static constexpr int64_t kCleanupIntervalSeconds = 30;
        static constexpr size_t kMaxEntries = 65536;

        memory::ThreadLocalUnorderedMap<SessionKey, int64_t, SessionKeyHash, SessionKeyEqual> entries;
        memory::ThreadLocalDeque<std::pair<const SessionKey*, int64_t>> order;
        int64_t last_cleanup = 0;

        SessionHistory()
            : entries(0, [] {
                  SessionKeyHash hash;
                  if (RAND_bytes(reinterpret_cast<uint8_t*>(hash.key.data()),
                                 sizeof(hash.key)) != 1) {
                      std::abort();
                  }
                  return hash;
              }()) {}
        void Cleanup(int64_t now) {
            if (now - last_cleanup < kCleanupIntervalSeconds &&
                entries.size() < kMaxEntries) {
                return;
            }
            last_cleanup = now;
            while (!order.empty()) {
                const auto [key_ptr, expires_at] = order.front();
                auto it = entries.find(*key_ptr);
                if (it == entries.end() || it->second != expires_at) {
                    order.pop_front();
                    continue;
                }
                if (expires_at > now) {
                    break;
                }
                entries.erase(it);
                order.pop_front();
            }
            MaybeShrinkHashContainer(entries);
            order.shrink_to_fit();
        }

        bool AddIfNew(SessionKey key, int64_t now) {
            Cleanup(now);
            auto it = entries.find(key);
            if (it != entries.end() && it->second > now) {
                return false;
            }
            const int64_t expires_at = now + kTtlSeconds;
            if (it != entries.end()) {
                order.emplace_back(&it->first, expires_at);
                it->second = expires_at;
                return true;
            }
            while (entries.size() >= kMaxEntries && !order.empty()) {
                const auto [oldest_key_ptr, oldest_expires] = order.front();
                order.pop_front();
                if (auto oldest_it = entries.find(*oldest_key_ptr);
                    oldest_it != entries.end() && oldest_it->second == oldest_expires) {
                    entries.erase(oldest_it);
                }
            }
            auto [inserted_it, inserted] = entries.emplace(std::move(key), expires_at);
            try {
                order.emplace_back(&inserted_it->first, expires_at);
            } catch (...) {
                if (inserted) {
                    entries.erase(inserted_it);
                }
                throw;
            }
            return true;
        }

    };

    struct alignas(64) HotUserCache {
        static constexpr size_t kMaxHotUsers = 32;
        static constexpr int64_t kWindowSeconds = 300;
        using Credential = proxyman::inbound::UserStore::VmessCredential;
        using AuthIDLookupTable = proxyman::inbound::UserStore::VmessUserMap;

        struct HotEntry {
            const Credential* user = nullptr;
            const AuthIDLookupTable* table = nullptr;
            int64_t last_seen = 0;
        };

        std::array<HotEntry, kMaxHotUsers> entries{};
        size_t size = 0;
        uint64_t view_revision = 0;
        int64_t last_cleanup = 0;

        void Touch(const Credential* user,
                   const AuthIDLookupTable* table,
                   int64_t now) noexcept {
            const auto begin = entries.begin();
            const auto end = begin + size;
            for (auto it = begin; it != end; ++it) {
                if (it->user == user) {
                    HotEntry entry = *it;
                    entry.table = table;
                    entry.last_seen = now;
                    if (it != begin) {
                        std::move_backward(begin, it, it + 1);
                        entries.front() = entry;
                    } else {
                        *it = entry;
                    }
                    return;
                }
            }

            const size_t shift = std::min(size, kMaxHotUsers - 1);
            if (shift > 0) {
                std::move_backward(begin, begin + shift, begin + shift + 1);
            }
            entries.front() = HotEntry{user, table, now};
            if (size < kMaxHotUsers) {
                ++size;
            }
        }

        void Cleanup(int64_t now) noexcept {
            size_t write = 0;
            for (size_t read = 0; read < size; ++read) {
                if (entries[read].last_seen + kWindowSeconds >= now) {
                    if (write != read) {
                        entries[write] = entries[read];
                    }
                    ++write;
                }
            }
            size = write;
        }

        void Clear() noexcept {
            size = 0;
        }
    };
    static HotUserCache& ThreadHotCache() noexcept {
        thread_local HotUserCache cache;
        return cache;
    }

    struct HistoryService final : net::execution_context::service {
        inline static net::execution_context::id id;
        explicit HistoryService(net::execution_context& context) : service(context) {}
        void shutdown() override {}
        SessionHistory history;
    };
}  // namespace

TimedUserValidator::TimedUserValidator() = default;

TimedUserValidator::~TimedUserValidator() = default;

std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential>
TimedUserValidator::FindByAuthIDForTag(
    std::string_view tag,
    const uint8_t* auth_id,
    int64_t& out_timestamp) const {

    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto tryUser = [&](const proxyman::inbound::UserStore::VmessCredential& user) -> bool {
        std::array<uint8_t, 16> plaintext{};
        AES_decrypt(auth_id, plaintext.data(), &user.auth_id_key);

        int64_t timestamp = 0;
        for (int i = 0; i < 8; i++) {
            timestamp = (timestamp << 8) | plaintext[i];
        }

        if (timestamp > now + TIMESTAMP_TOLERANCE || timestamp < now - TIMESTAMP_TOLERANCE) {
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
            return false;
        }

        uint32_t crc = CRC32(plaintext.data(), 12);
        uint32_t expected_crc = (static_cast<uint32_t>(plaintext[12]) << 24) |
                                (static_cast<uint32_t>(plaintext[13]) << 16) |
                                (static_cast<uint32_t>(plaintext[14]) << 8) |
                                plaintext[15];
        OPENSSL_cleanse(plaintext.data(), plaintext.size());

        if (crc == expected_crc) {
            out_timestamp = timestamp;
            return true;
        }
        return false;
    };

    auto view = proxyman::inbound::UserStore::VmessUsers(tag);
    const uint64_t revision = proxyman::inbound::UserStore::WorkerViewRevision();
    auto& tls_hot_cache = ThreadHotCache();
    if (revision == 0 || tls_hot_cache.view_revision != revision) {
        tls_hot_cache.Clear();
        tls_hot_cache.view_revision = revision;
    }

    if (revision != 0 && now - tls_hot_cache.last_cleanup > 60) {
        tls_hot_cache.last_cleanup = now;
        tls_hot_cache.Cleanup(now);
    }

    if (!view.users) {
        return {};
    }

    if (revision != 0) {
        for (auto it = tls_hot_cache.entries.begin();
             it != tls_hot_cache.entries.begin() + tls_hot_cache.size;
             ++it) {
            if (it->table == view.users.get() &&
                it->last_seen + HotUserCache::kWindowSeconds >= now) {
                const auto* user = it->user;
                if (tryUser(*user)) {
                    tls_hot_cache.Touch(user, view.users.get(), now);
                    return view.Share(*user);
                }
            }
        }
    }

    for (const auto& user : *view.users) {
        if (tryUser(user)) {
            if (revision != 0) {
                tls_hot_cache.Touch(&user, view.users.get(), now);
            }
            return view.Share(user);
        }
    }

    return {};
}

net::awaitable<bool> TimedUserValidator::RegisterSessionIfNew(
    const proxyman::inbound::UserStore::VmessCredential& user,
    const std::array<uint8_t, 16>& body_key,
    const std::array<uint8_t, 16>& body_iv) const {
    auto domain = ExecutionDomain::Current();
    if (!domain) throw std::logic_error("VMess replay admission requires an execution domain");
    std::array<uint8_t, 48> material{};
    std::memcpy(material.data(), user.uuid_bytes.data(), 16);
    std::memcpy(material.data() + 16, body_key.data(), 16);
    std::memcpy(material.data() + 32, body_iv.data(), 16);
    const SessionKey key = SHA256Hash(material.data(), material.size());
    OPENSSL_cleanse(material.data(), material.size());
    auto* coordinator = &domain->Coordinator();
    return coordinator->PostCall([coordinator, key] {
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return net::use_service<HistoryService>(
            coordinator->Services()).history.AddIfNew(key, now);
    });
}


}  // namespace vmess
