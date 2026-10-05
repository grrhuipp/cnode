#include "validator.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/string_hash.hpp"
#include "vmess_crypto.hpp"
#include "vmess_request.hpp"

#include <array>
#include <chrono>
#include <cstring>
#include <utility>

namespace acpp {
namespace vmess {

struct TimedUserValidator::Impl : memory::DataAllocated {
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
            size_t h = 1469598103934665603ull;
            auto mix = [&h](uint8_t byte) noexcept {
                h ^= static_cast<size_t>(byte);
                h *= 1099511628211ull;
            };
            for (uint8_t byte : value.user) mix(byte);
            for (uint8_t byte : value.key) mix(byte);
            for (uint8_t byte : value.iv) mix(byte);
            return h;
        }
    };

    struct SessionHistory {
        static constexpr int64_t kTtlSeconds = 180;
        static constexpr int64_t kCleanupIntervalSeconds = 30;
        static constexpr size_t kMaxEntries = 65536;

        memory::DataUnorderedMap<SessionKey, int64_t, SessionKeyHash> entries;
        memory::DataDeque<std::pair<SessionKey, int64_t>> order;
        int64_t last_cleanup = 0;

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
            if (it == entries.end() && entries.size() >= kMaxEntries) return false;
            const int64_t expires_at = now + kTtlSeconds;
            // Prepare the cleanup index before publishing the replay entry.
            order.emplace_back(key, expires_at);
            try { entries[key] = expires_at; }
            catch (...) { order.pop_back(); throw; }
            Cleanup(now);
            return true;
        }

        void Clear() {
            entries.clear();
            order.clear();
            last_cleanup = 0;
        }
    };

    explicit Impl(net::any_io_executor executor) : channel(std::move(executor), 4096) {}
    ServiceChannel channel;
    SessionHistory session_history;

};

TimedUserValidator::TimedUserValidator(net::any_io_executor executor)
    : impl_(std::make_unique<Impl>(std::move(executor))) {}

TimedUserValidator::~TimedUserValidator() = default;
TimedUserValidator::TimedUserValidator(TimedUserValidator&&) noexcept = default;
TimedUserValidator& TimedUserValidator::operator=(TimedUserValidator&&) noexcept = default;

size_t TimedUserValidator::Size() const {
    return proxyman::inbound::UserStore::GetStats().vmess_accounts;
}

size_t TimedUserValidator::SizeForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::SizeForProtocolTag(
        proxyman::inbound::UserProtocol::Vmess, tag);
}

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
    if (!view.users) {
        return {};
    }

    for (const auto& [uuid, user] : *view.users) {
        if (tryUser(user)) {
            return view.Share(user);
        }
    }

    return {};
}

net::awaitable<bool> TimedUserValidator::RegisterSessionIfNew(
    std::array<uint8_t, 16> user,
    std::array<uint8_t, 16> body_key,
    std::array<uint8_t, 16> body_iv) {
    return impl_->channel.Call([this, user, body_key, body_iv] {
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return impl_->session_history.AddIfNew(Impl::SessionKey{
            .user = user, .key = body_key, .iv = body_iv}, now);
    });
}

}  // namespace vmess
}  // namespace acpp
