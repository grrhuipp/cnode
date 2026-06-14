#include "acppnode/proxy/vmess/validator.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/common/string_hash.hpp"
#include "vmess_crypto.hpp"
#include "vmess_request.hpp"

#include <array>
#include <chrono>
#include <cstring>

namespace acpp {
namespace vmess {

struct TimedUserValidator::Impl {
    using UserMap = memory::ThreadLocalUnorderedMap<std::string,
                                                    MemoryAccount,
                                                    TransparentStringHash,
                                                    TransparentStringEq>;

    struct alignas(64) HotUserCache {
        static constexpr size_t kMaxEntries = 8192;
        static constexpr int64_t kWindowSeconds = 300;
        using ActiveList = memory::ThreadLocalList<const MemoryAccount*>;

        struct Entry {
            memory::ThreadLocalString tag;
            int64_t timestamp;
            ActiveList::iterator order_it;
        };

        memory::ThreadLocalUnorderedMap<const MemoryAccount*, Entry> entries;
        ActiveList active_order;

        void Touch(const MemoryAccount* user, std::string_view tag, int64_t now) {
            auto it = entries.find(user);
            if (it != entries.end()) {
                it->second.tag.assign(tag.data(), tag.size());
                it->second.timestamp = now;
                if (it->second.order_it != active_order.begin()) {
                    active_order.splice(active_order.begin(), active_order, it->second.order_it);
                }
                return;
            }

            active_order.push_front(user);
            Entry entry;
            entry.tag.assign(tag.data(), tag.size());
            entry.timestamp = now;
            entry.order_it = active_order.begin();
            entries.emplace(user, std::move(entry));
            if (entries.size() > kMaxEntries && !active_order.empty()) {
                const auto* tail = active_order.back();
                active_order.pop_back();
                entries.erase(tail);
            }
        }

        void Cleanup(int64_t now) {
            for (auto it = entries.begin(); it != entries.end(); ) {
                if (it->second.timestamp + kWindowSeconds < now) {
                    active_order.erase(it->second.order_it);
                    it = entries.erase(it);
                } else {
                    ++it;
                }
            }
        }

        void Clear() {
            entries.clear();
            active_order.clear();
        }

        void UpdateTime(const MemoryAccount* user, int64_t now) {
            auto it = entries.find(user);
            if (it != entries.end()) {
                it->second.timestamp = now;
            }
        }
    };

    memory::ThreadLocalUnorderedMap<std::string,
                                    UserMap,
                                    TransparentStringHash,
                                    TransparentStringEq> users_by_tag;
    mutable HotUserCache hot_cache;
    mutable int64_t last_hot_cache_cleanup = 0;
    UserOnlineTracker stats;
};

TimedUserValidator::TimedUserValidator()
    : impl_(std::make_unique<Impl>()) {}

TimedUserValidator::~TimedUserValidator() = default;
TimedUserValidator::TimedUserValidator(TimedUserValidator&&) noexcept = default;
TimedUserValidator& TimedUserValidator::operator=(TimedUserValidator&&) noexcept = default;

void TimedUserValidator::UpdateUsersForTag(const std::string& tag, const std::vector<MemoryAccount>& users) {
    // 获取或创建该 tag 的用户 map
    auto& tag_users = impl_->users_by_tag[tag];
    tag_users.reserve(users.size());

    // 构建新用户集合
    memory::ThreadLocalUnorderedSet<std::string, TransparentStringHash, TransparentStringEq> new_uuids;
    new_uuids.reserve(users.size());
    for (const auto& user : users) {
        new_uuids.insert(user.uuid);
    }

    // 删除不在新列表中的用户
    for (auto it = tag_users.begin(); it != tag_users.end(); ) {
        if (new_uuids.find(it->first) == new_uuids.end()) {
            it = tag_users.erase(it);
        } else {
            ++it;
        }
    }

    // 添加或更新用户
    for (const auto& user : users) {
        tag_users[user.uuid] = user;
    }

    // 清空热点缓存（用户指针可能已失效）
    impl_->hot_cache.Clear();
}

void TimedUserValidator::AddUsersForTag(const std::string& tag, const std::vector<MemoryAccount>& users) {
    auto& tag_users = impl_->users_by_tag[tag];
    tag_users.reserve(tag_users.size() + users.size());
    for (const auto& user : users) {
        tag_users[user.uuid] = user;
    }
    impl_->hot_cache.Clear();
}

void TimedUserValidator::RemoveUsersForTag(const std::string& tag, const std::vector<MemoryAccount>& users) {
    auto it = impl_->users_by_tag.find(tag);
    if (it == impl_->users_by_tag.end()) {
        return;
    }
    for (const auto& user : users) {
        it->second.erase(user.uuid);
    }
    if (it->second.empty()) {
        impl_->users_by_tag.erase(it);
    }
    impl_->hot_cache.Clear();
}

void TimedUserValidator::ClearTag(const std::string& tag) {
    impl_->users_by_tag.erase(tag);
    impl_->hot_cache.Clear();
}

void TimedUserValidator::Clear() {
    impl_->users_by_tag.clear();
    impl_->hot_cache.Clear();
}

size_t TimedUserValidator::Size() const {
    size_t total = 0;
    for (const auto& [tag, users] : impl_->users_by_tag) {
        total += users.size();
    }
    return total;
}

size_t TimedUserValidator::SizeForTag(std::string_view tag) const {
    auto it = impl_->users_by_tag.find(tag);
    if (it != impl_->users_by_tag.end()) {
        return it->second.size();
    }
    return 0;
}

const MemoryAccount* TimedUserValidator::FindByAuthIDForTag(
    std::string_view tag,
    const uint8_t* auth_id,
    int64_t& out_timestamp) const {

    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto tryUser = [&](const MemoryAccount& user) -> bool {
        std::array<uint8_t, 16> plaintext;
        user.cached_auth_aes_key.ECBDecrypt(auth_id, plaintext.data());

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

    if (now - impl_->last_hot_cache_cleanup > 60) {
        impl_->last_hot_cache_cleanup = now;
        impl_->hot_cache.Cleanup(now);
    }

    {
        std::array<const MemoryAccount*, 32> candidates{};
        size_t candidate_count = 0;
        for (const auto* user : impl_->hot_cache.active_order) {
            auto it = impl_->hot_cache.entries.find(user);
            if (it != impl_->hot_cache.entries.end() &&
                std::string_view(it->second.tag.data(), it->second.tag.size()) == tag &&
                it->second.timestamp + Impl::HotUserCache::kWindowSeconds >= now) {
                candidates[candidate_count++] = user;
                if (candidate_count == candidates.size()) {
                    break;
                }
            }
        }

        for (size_t i = 0; i < candidate_count; ++i) {
            const auto* user = candidates[i];
            if (tryUser(*user)) {
                impl_->hot_cache.UpdateTime(user, now);
                return user;
            }
        }
    }

    auto tag_it = impl_->users_by_tag.find(tag);
    if (tag_it == impl_->users_by_tag.end()) {
        return nullptr;
    }

    for (const auto& [uuid, user] : tag_it->second) {
        if (tryUser(user)) {
            impl_->hot_cache.Touch(&user, tag, now);
            return &user;
        }
    }

    return nullptr;
}

void TimedUserValidator::OnUserConnected(std::string_view tag,
                                         uint64_t user_id,
                                         std::string_view client_ip) {
    impl_->stats.OnUserConnected(tag, user_id, client_ip);
}

void TimedUserValidator::OnUserDisconnected(std::string_view tag,
                                            uint64_t user_id,
                                            std::string_view client_ip) {
    impl_->stats.OnUserDisconnected(tag, user_id, client_ip);
}

bool TimedUserValidator::CanAcceptDevice(std::string_view tag,
                                         uint64_t user_id,
                                         std::string_view client_ip,
                                         uint32_t device_limit) const {
    return impl_->stats.CanAcceptDevice(tag, user_id, client_ip, device_limit);
}

size_t TimedUserValidator::OnlineDeviceCount(std::string_view tag,
                                             uint64_t user_id) const {
    return impl_->stats.OnlineDeviceCount(tag, user_id);
}

std::vector<OnlineDevice>
TimedUserValidator::GetOnlineDevices(std::string_view tag) const {
    return impl_->stats.GetOnlineDevices(tag);
}

}  // namespace vmess
}  // namespace acpp
