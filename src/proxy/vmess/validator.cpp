#include "validator.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/common/string_hash.hpp"
#include "vmess_crypto.hpp"
#include "vmess_request.hpp"
#include "acppnode/app/session_group_executor.hpp"

#include <algorithm>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/siphash.h>
#include <cstdlib>
#include <array>
#include <chrono>
#include <cstring>
#include <utility>
#include <deque>
#include <unordered_map>

namespace acpp {
namespace vmess {

struct TimedUserValidator::Impl : memory::ThreadAllocated {
    struct SessionKey {
        std::array<uint8_t, 16> user{};
        std::array<uint8_t, 16> key{};
        std::array<uint8_t, 16> iv{};

        [[nodiscard]] bool operator==(const SessionKey& other) const noexcept {
            return CRYPTO_memcmp(user.data(), other.user.data(), user.size()) == 0 &&
                   CRYPTO_memcmp(key.data(), other.key.data(), key.size()) == 0 &&
                   CRYPTO_memcmp(iv.data(), other.iv.data(), iv.size()) == 0;
        }
    };

    struct SessionKeyHash {
        std::array<uint64_t, 2> key{};

        [[nodiscard]] size_t operator()(const SessionKey& value) const noexcept {
            std::array<uint8_t, 48> bytes{};
            std::memcpy(bytes.data(), value.user.data(), 16);
            std::memcpy(bytes.data() + 16, value.key.data(), 16);
            std::memcpy(bytes.data() + 32, value.iv.data(), 16);
            return static_cast<size_t>(SIPHASH_24(key.data(), bytes.data(), bytes.size()));
        }
    };

    struct SessionHistory {
        static constexpr int64_t kTtlSeconds = 180;
        static constexpr int64_t kCleanupIntervalSeconds = 30;
        static constexpr size_t kMaxEntries = 65536;

        std::unordered_map<SessionKey, int64_t, SessionKeyHash> entries;
        std::deque<std::pair<SessionKey, int64_t>> order;
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
                const auto& [key, expires_at] = order.front();
                auto it = entries.find(key);
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
        }

        bool AddIfNew(SessionKey key, int64_t now) {
            Cleanup(now);
            auto it = entries.find(key);
            if (it != entries.end() && it->second > now) {
                return false;
            }
            if (it == entries.end()) {
                while (entries.size() >= kMaxEntries && !order.empty()) {
                    const auto& [oldest_key, oldest_expires] = order.front();
                    if (auto oldest_it = entries.find(oldest_key);
                        oldest_it != entries.end() && oldest_it->second == oldest_expires) {
                        entries.erase(oldest_it);
                    }
                    order.pop_front();
                }
                if (entries.size() >= kMaxEntries) {
                    entries.erase(entries.begin());
                }
            }
            const int64_t expires_at = now + kTtlSeconds;
            order.emplace_back(key, expires_at);
            try { entries.insert_or_assign(std::move(key), expires_at); }
            catch (...) { order.pop_back(); throw; }
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
};

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
        std::array<uint8_t, 16> plaintext;
        AES_decrypt(auth_id, plaintext.data(), &user.auth_id_key);

        int64_t timestamp = 0;
        for (int i = 0; i < 8; i++) {
            timestamp = (timestamp << 8) | plaintext[i];
        }

        if (timestamp > now + TIMESTAMP_TOLERANCE || timestamp < now - TIMESTAMP_TOLERANCE) {
            return false;
        }

        uint32_t crc = CRC32(plaintext.data(), 12);
        uint32_t expected_crc = (static_cast<uint32_t>(plaintext[12]) << 24) |
                                (static_cast<uint32_t>(plaintext[13]) << 16) |
                                (static_cast<uint32_t>(plaintext[14]) << 8) |
                                plaintext[15];

        if (crc == expected_crc) {
            out_timestamp = timestamp;
            return true;
        }
        return false;
    };

    auto view = proxyman::inbound::UserStore::VmessUsers(tag);
    const uint64_t revision = proxyman::inbound::UserStore::WorkerViewRevision();
    auto& tls_hot_cache = Impl::ThreadHotCache();
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
                it->last_seen + Impl::HotUserCache::kWindowSeconds >= now) {
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
    Impl::SessionKey key;
    key.user = user.uuid_bytes;
    key.key = body_key;
    key.iv = body_iv;
    auto* coordinator = &domain->Coordinator();
    return coordinator->PostCall([coordinator, key] {
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return net::use_service<Impl::HistoryService>(
            coordinator->Services()).history.AddIfNew(key, now);
    });
}


}  // namespace vmess
}  // namespace acpp
