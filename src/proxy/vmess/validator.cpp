#include "validator.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/common/string_hash.hpp"
#include "vmess_crypto.hpp"
#include "vmess_request.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <utility>

namespace acpp {
namespace vmess {

struct TimedUserValidator::Impl : memory::ThreadAllocated {
    struct SessionKey {
        std::array<uint8_t, 16> user{};
        std::array<uint8_t, 16> key{};
        std::array<uint8_t, 16> iv{};

        [[nodiscard]] bool operator==(const SessionKey& other) const noexcept {
            return user == other.user && key == other.key && iv == other.iv;
        }
    };

    struct SessionKeyHash {
        [[nodiscard]] size_t operator()(const SessionKey& value) const noexcept {
            uint64_t words[6]{};
            std::memcpy(&words[0], value.user.data(), 16);
            std::memcpy(&words[2], value.key.data(), 16);
            std::memcpy(&words[4], value.iv.data(), 16);
            uint64_t h = 1469598103934665603ull;
            for (uint64_t word : words) {
                h ^= word;
                h *= 1099511628211ull;
            }
            return static_cast<size_t>(h);
        }
    };

    struct SessionHistory {
        static constexpr int64_t kTtlSeconds = 180;
        static constexpr int64_t kCleanupIntervalSeconds = 30;
        static constexpr size_t kMaxEntries = 65536;

        memory::ThreadLocalUnorderedMap<SessionKey, int64_t, SessionKeyHash> entries;
        memory::ThreadLocalDeque<std::pair<SessionKey, int64_t>> order;
        int64_t last_cleanup = 0;

        void Cleanup(int64_t now) {
            if (now - last_cleanup < kCleanupIntervalSeconds &&
                entries.size() <= kMaxEntries) {
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
                if (expires_at > now && entries.size() <= kMaxEntries) {
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
            const int64_t expires_at = now + kTtlSeconds;
            entries[key] = expires_at;
            order.emplace_back(std::move(key), expires_at);
            return true;
        }

        void Clear() {
            entries.clear();
            order.clear();
            last_cleanup = 0;
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

        memory::ThreadLocalVector<HotEntry> entries;

        HotUserCache() {
            entries.reserve(kMaxHotUsers);
        }

        void Touch(const Credential* user,
                   const AuthIDLookupTable* table,
                   int64_t now) {
            for (auto it = entries.begin(); it != entries.end(); ++it) {
                if (it->user == user) {
                    HotEntry entry = *it;
                    entry.table = table;
                    entry.last_seen = now;
                    if (it != entries.begin()) {
                        std::move_backward(entries.begin(), it, it + 1);
                        entries.front() = entry;
                    } else {
                        *it = entry;
                    }
                    return;
                }
            }

            if (entries.size() < kMaxHotUsers) {
                entries.reserve(kMaxHotUsers);
                entries.insert(entries.begin(), HotEntry{user, table, now});
            } else if (!entries.empty()) {
                std::move_backward(entries.begin(), entries.end() - 1, entries.end());
                entries.front() = HotEntry{user, table, now};
            }
        }

        void Cleanup(int64_t now) {
            std::erase_if(entries, [now](const HotEntry& entry) {
                return entry.last_seen + kWindowSeconds < now;
            });
        }

        void Clear() {
            entries.clear();
        }
    };

    mutable HotUserCache hot_cache;
    // Borrowed entries are invalidated on cold Worker publication, not when
    // requests alternate between tags sharing this validator.
    mutable uint64_t view_revision = 0;
    mutable int64_t last_hot_cache_cleanup = 0;
    mutable SessionHistory session_history;
};

TimedUserValidator::TimedUserValidator()
    : impl_(std::make_unique<Impl>()) {}

TimedUserValidator::~TimedUserValidator() = default;
TimedUserValidator::TimedUserValidator(TimedUserValidator&&) noexcept = default;
TimedUserValidator& TimedUserValidator::operator=(TimedUserValidator&&) noexcept = default;

std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential>
TimedUserValidator::FindByAuthIDForTag(
    std::string_view tag,
    const uint8_t* auth_id,
    int64_t& out_timestamp) const {

    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto tryUser = [&](const proxyman::inbound::UserStore::VmessCredential& user) -> bool {
        std::array<uint8_t, 16> plaintext;
        AES128ECBDecrypt(user.cached_auth_aes_key.data(), auth_id, plaintext.data());

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
    if (impl_->view_revision != revision) {
        impl_->hot_cache.Clear();
        impl_->view_revision = revision;
    }

    if (now - impl_->last_hot_cache_cleanup > 60) {
        impl_->last_hot_cache_cleanup = now;
        impl_->hot_cache.Cleanup(now);
    }

    if (!view.users) {
        return {};
    }

    for (auto it = impl_->hot_cache.entries.begin();
         it != impl_->hot_cache.entries.end();
         ++it) {
        if (it->table == view.users.get() &&
            it->last_seen + Impl::HotUserCache::kWindowSeconds >= now) {
            const auto* user = it->user;
            if (tryUser(*user)) {
                impl_->hot_cache.Touch(user, view.users.get(), now);
                return view.Share(*user);
            }
        }
    }

    for (const auto& user : *view.users) {
        if (tryUser(user)) {
            impl_->hot_cache.Touch(&user, view.users.get(), now);
            return view.Share(user);
        }
    }

    return {};
}

bool TimedUserValidator::RegisterSessionIfNew(
    const proxyman::inbound::UserStore::VmessCredential& user,
    const std::array<uint8_t, 16>& body_key,
    const std::array<uint8_t, 16>& body_iv) const {
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    Impl::SessionKey key;
    key.user = user.uuid_bytes;
    key.key = body_key;
    key.iv = body_iv;
    return impl_->session_history.AddIfNew(std::move(key), now);
}


}  // namespace vmess
}  // namespace acpp
