#include "acppnode/app/proxyman/inbound/user_store.hpp"

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/core/constants.hpp"

#include <algorithm>
#include <atomic>
#include <utility>

namespace acpp::proxyman::inbound {

namespace {

using VmessTagMap =
    std::unordered_map<std::string,
                       std::shared_ptr<const UserStore::VmessUserMap>,
                       TransparentStringHash,
                       TransparentStringEq>;
using VlessTagMap =
    std::unordered_map<std::string,
                       std::shared_ptr<const UserStore::VlessUserMap>,
                       TransparentStringHash,
                       TransparentStringEq>;
using TrojanTagMap =
    std::unordered_map<std::string,
                       std::shared_ptr<const UserStore::TrojanUserMap>,
                       TransparentStringHash,
                       TransparentStringEq>;
using ShadowsocksTagMap =
    std::unordered_map<std::string,
                       std::shared_ptr<const UserStore::ShadowsocksUserList>,
                       TransparentStringHash,
                       TransparentStringEq>;
using AnyTlsTagMap =
    std::unordered_map<std::string,
                       std::shared_ptr<const UserStore::AnyTlsUserMap>,
                       TransparentStringHash,
                       TransparentStringEq>;

struct Snapshot {
    VmessTagMap vmess;
    VlessTagMap vless;
    TrojanTagMap trojan;
    ShadowsocksTagMap shadowsocks;
    AnyTlsTagMap anytls;
    uint64_t generation = 0;
};

std::atomic<std::shared_ptr<const Snapshot>>& GlobalSnapshot() {
    static std::atomic<std::shared_ptr<const Snapshot>> snapshot{
        std::make_shared<const Snapshot>()};
    return snapshot;
}

std::shared_ptr<const Snapshot> LoadSnapshot() {
    return GlobalSnapshot().load(std::memory_order_acquire);
}

template <typename Mutator>
void Publish(Mutator&& mutator) {
    auto& global = GlobalSnapshot();
    for (;;) {
        auto current = global.load(std::memory_order_acquire);
        auto next = std::make_shared<Snapshot>(*current);
        mutator(*next);
        next->generation = current->generation + 1;
        std::shared_ptr<const Snapshot> published = std::move(next);
        if (global.compare_exchange_weak(
                current,
                published,
                std::memory_order_release,
                std::memory_order_acquire)) {
            return;
        }
    }
}

std::shared_ptr<const UserStore::Profile> ShareProfile(const ::acpp::UserProfile& profile) {
    return std::make_shared<UserStore::Profile>(profile);
}

UserStore::VmessCredential
BuildVmessCredential(const PreparedVmessUser& user) {
    return UserStore::VmessCredential{
        .uuid = user.uuid,
        .uuid_bytes = user.uuid_bytes,
        .cmd_key = user.cmd_key,
        .auth_key = user.auth_key,
        .cached_auth_aes_key = user.cached_auth_aes_key,
        .profile = ShareProfile(user.profile),
    };
}

std::shared_ptr<const UserStore::VmessUserMap>
BuildVmessUsers(const std::vector<PreparedVmessUser>& users) {
    auto map = std::make_shared<UserStore::VmessUserMap>();
    map->reserve(users.size());
    for (const auto& user : users) {
        (*map)[user.uuid] = BuildVmessCredential(user);
    }
    return map;
}

UserStore::VlessCredential
BuildVlessCredential(const PreparedVlessUser& user) {
    return UserStore::VlessCredential{
        .uuid = user.uuid,
        .uuid_bytes = user.uuid_bytes,
        .flow = user.flow,
        .profile = ShareProfile(user.profile),
    };
}

std::shared_ptr<const UserStore::VlessUserMap>
BuildVlessUsers(const std::vector<PreparedVlessUser>& users) {
    auto map = std::make_shared<UserStore::VlessUserMap>();
    map->reserve(users.size());
    for (const auto& user : users) {
        (*map)[user.uuid_bytes] = BuildVlessCredential(user);
    }
    return map;
}

UserStore::TrojanCredential
BuildTrojanCredential(const PreparedTrojanUser& user) {
    return UserStore::TrojanCredential{
        .password_hash = user.password_hash,
        .profile = ShareProfile(user.profile),
    };
}

std::shared_ptr<const UserStore::TrojanUserMap>
BuildTrojanUsers(const std::vector<PreparedTrojanUser>& users) {
    auto map = std::make_shared<UserStore::TrojanUserMap>();
    map->reserve(users.size());
    for (const auto& user : users) {
        (*map)[user.password_hash] = BuildTrojanCredential(user);
    }
    return map;
}

UserStore::ShadowsocksCredential
BuildShadowsocksCredential(const PreparedShadowsocksUser& user) {
    return UserStore::ShadowsocksCredential{
        .password = user.password,
        .derived_key = user.derived_key,
        .identity_key = user.identity_key,
        .cipher_type = user.cipher_type,
        .key_size = user.key_size,
        .salt_size = user.salt_size,
        .profile = ShareProfile(user.profile),
    };
}

std::shared_ptr<const UserStore::ShadowsocksUserList>
BuildShadowsocksUsers(const std::vector<PreparedShadowsocksUser>& users) {
    auto list = std::make_shared<UserStore::ShadowsocksUserList>();
    list->reserve(users.size());
    for (const auto& user : users) {
        list->push_back(BuildShadowsocksCredential(user));
    }
    return list;
}

UserStore::AnyTlsCredential
BuildAnyTlsCredential(const PreparedAnyTlsUser& user) {
    return UserStore::AnyTlsCredential{
        .password_hash = user.password_hash,
        .profile = ShareProfile(user.profile),
    };
}

std::shared_ptr<const UserStore::AnyTlsUserMap>
BuildAnyTlsUsers(const std::vector<PreparedAnyTlsUser>& users) {
    auto map = std::make_shared<UserStore::AnyTlsUserMap>();
    map->reserve(users.size());
    for (const auto& user : users) {
        (*map)[user.password_hash] = BuildAnyTlsCredential(user);
    }
    return map;
}

template <typename TagMap, typename ContainerPtr>
void SetOrErase(TagMap& map, std::string_view tag, ContainerPtr users) {
    if (!users || users->empty()) {
        map.erase(std::string(tag));
        return;
    }
    map[std::string(tag)] = std::move(users);
}

template <typename TagMap>
size_t TagSize(const TagMap& map, std::string_view tag) {
    auto it = map.find(tag);
    return it == map.end() || !it->second ? 0 : it->second->size();
}

bool SameShadowsocksIdentity(const UserStore::ShadowsocksCredential& a,
                             const PreparedShadowsocksUser& b) noexcept {
    if (a.profile && a.profile->user_id != 0 && b.profile.user_id != 0) {
        return a.profile->user_id == b.profile.user_id;
    }
    return a.password == b.password;
}

}  // namespace

size_t UserStore::Array16Hash::operator()(const std::array<uint8_t, 16>& value) const noexcept {
    size_t out = 1469598103934665603ull;
    for (uint8_t byte : value) {
        out ^= byte;
        out *= 1099511628211ull;
    }
    return out;
}

size_t UserStore::Array32Hash::operator()(const std::array<uint8_t, 32>& value) const noexcept {
    size_t out = 1469598103934665603ull;
    for (uint8_t byte : value) {
        out ^= byte;
        out *= 1099511628211ull;
    }
    return out;
}

void UserStore::ApplyUsers(std::string_view protocol,
                           std::string_view tag,
                           const UserSet& users) {
    Publish([&](Snapshot& snapshot) {
        if (protocol == constants::protocol::kVmess) {
            SetOrErase(snapshot.vmess, tag, BuildVmessUsers(users.vmess_accounts));
        } else if (protocol == constants::protocol::kVless) {
            SetOrErase(snapshot.vless, tag, BuildVlessUsers(users.vless_users));
        } else if (protocol == constants::protocol::kTrojan) {
            SetOrErase(snapshot.trojan, tag, BuildTrojanUsers(users.trojan_users));
        } else if (protocol == constants::protocol::kShadowsocks) {
            SetOrErase(snapshot.shadowsocks, tag, BuildShadowsocksUsers(users.ss_users));
        } else if (protocol == constants::protocol::kAnyTLS) {
            SetOrErase(snapshot.anytls, tag, BuildAnyTlsUsers(users.anytls_users));
        }
    });
}

void UserStore::AddUsers(std::string_view protocol,
                         std::string_view tag,
                         const UserSet& users) {
    Publish([&](Snapshot& snapshot) {
        if (protocol == constants::protocol::kVmess) {
            auto next = std::make_shared<VmessUserMap>();
            if (auto it = snapshot.vmess.find(tag); it != snapshot.vmess.end() && it->second) {
                *next = *it->second;
            }
            next->reserve(next->size() + users.vmess_accounts.size());
            for (const auto& user : users.vmess_accounts) {
                (*next)[user.uuid] = BuildVmessCredential(user);
            }
            SetOrErase(snapshot.vmess, tag, std::move(next));
        } else if (protocol == constants::protocol::kVless) {
            auto next = std::make_shared<VlessUserMap>();
            if (auto it = snapshot.vless.find(tag); it != snapshot.vless.end() && it->second) {
                *next = *it->second;
            }
            next->reserve(next->size() + users.vless_users.size());
            for (const auto& user : users.vless_users) {
                (*next)[user.uuid_bytes] = BuildVlessCredential(user);
            }
            SetOrErase(snapshot.vless, tag, std::move(next));
        } else if (protocol == constants::protocol::kTrojan) {
            auto next = std::make_shared<TrojanUserMap>();
            if (auto it = snapshot.trojan.find(tag); it != snapshot.trojan.end() && it->second) {
                *next = *it->second;
            }
            next->reserve(next->size() + users.trojan_users.size());
            for (const auto& user : users.trojan_users) {
                (*next)[user.password_hash] = BuildTrojanCredential(user);
            }
            SetOrErase(snapshot.trojan, tag, std::move(next));
        } else if (protocol == constants::protocol::kShadowsocks) {
            auto next = std::make_shared<ShadowsocksUserList>();
            if (auto it = snapshot.shadowsocks.find(tag);
                    it != snapshot.shadowsocks.end() && it->second) {
                *next = *it->second;
            }
            next->reserve(next->size() + users.ss_users.size());
            for (const auto& user : users.ss_users) {
                auto it = std::find_if(
                    next->begin(), next->end(),
                    [&](const auto& existing) {
                        return SameShadowsocksIdentity(existing, user);
                    });
                if (it != next->end()) {
                    *it = BuildShadowsocksCredential(user);
                } else {
                    next->push_back(BuildShadowsocksCredential(user));
                }
            }
            SetOrErase(snapshot.shadowsocks, tag, std::move(next));
        } else if (protocol == constants::protocol::kAnyTLS) {
            auto next = std::make_shared<AnyTlsUserMap>();
            if (auto it = snapshot.anytls.find(tag); it != snapshot.anytls.end() && it->second) {
                *next = *it->second;
            }
            next->reserve(next->size() + users.anytls_users.size());
            for (const auto& user : users.anytls_users) {
                (*next)[user.password_hash] = BuildAnyTlsCredential(user);
            }
            SetOrErase(snapshot.anytls, tag, std::move(next));
        }
    });
}

void UserStore::RemoveUsers(std::string_view protocol,
                            std::string_view tag,
                            const UserSet& users) {
    Publish([&](Snapshot& snapshot) {
        if (protocol == constants::protocol::kVmess) {
            auto it = snapshot.vmess.find(tag);
            if (it == snapshot.vmess.end() || !it->second) return;
            auto next = std::make_shared<VmessUserMap>(*it->second);
            for (const auto& user : users.vmess_accounts) {
                next->erase(user.uuid);
            }
            SetOrErase(snapshot.vmess, tag, std::move(next));
        } else if (protocol == constants::protocol::kVless) {
            auto it = snapshot.vless.find(tag);
            if (it == snapshot.vless.end() || !it->second) return;
            auto next = std::make_shared<VlessUserMap>(*it->second);
            for (const auto& user : users.vless_users) {
                next->erase(user.uuid_bytes);
            }
            SetOrErase(snapshot.vless, tag, std::move(next));
        } else if (protocol == constants::protocol::kTrojan) {
            auto it = snapshot.trojan.find(tag);
            if (it == snapshot.trojan.end() || !it->second) return;
            auto next = std::make_shared<TrojanUserMap>(*it->second);
            for (const auto& user : users.trojan_users) {
                next->erase(user.password_hash);
            }
            SetOrErase(snapshot.trojan, tag, std::move(next));
        } else if (protocol == constants::protocol::kShadowsocks) {
            auto it = snapshot.shadowsocks.find(tag);
            if (it == snapshot.shadowsocks.end() || !it->second) return;
            auto next = std::make_shared<ShadowsocksUserList>(*it->second);
            auto should_remove = [&](const auto& existing) {
                return std::any_of(
                    users.ss_users.begin(), users.ss_users.end(),
                    [&](const auto& user) {
                        return SameShadowsocksIdentity(existing, user);
                    });
            };
            next->erase(std::remove_if(next->begin(), next->end(), should_remove), next->end());
            SetOrErase(snapshot.shadowsocks, tag, std::move(next));
        } else if (protocol == constants::protocol::kAnyTLS) {
            auto it = snapshot.anytls.find(tag);
            if (it == snapshot.anytls.end() || !it->second) return;
            auto next = std::make_shared<AnyTlsUserMap>(*it->second);
            for (const auto& user : users.anytls_users) {
                next->erase(user.password_hash);
            }
            SetOrErase(snapshot.anytls, tag, std::move(next));
        }
    });
}

void UserStore::ClearUsers(std::string_view protocol,
                           std::string_view tag) {
    Publish([&](Snapshot& snapshot) {
        if (protocol == constants::protocol::kVmess) {
            snapshot.vmess.erase(std::string(tag));
        } else if (protocol == constants::protocol::kVless) {
            snapshot.vless.erase(std::string(tag));
        } else if (protocol == constants::protocol::kTrojan) {
            snapshot.trojan.erase(std::string(tag));
        } else if (protocol == constants::protocol::kShadowsocks) {
            snapshot.shadowsocks.erase(std::string(tag));
        } else if (protocol == constants::protocol::kAnyTLS) {
            snapshot.anytls.erase(std::string(tag));
        }
    });
}

void UserStore::ClearProtocol(std::string_view protocol) {
    Publish([&](Snapshot& snapshot) {
        if (protocol == constants::protocol::kVmess) {
            snapshot.vmess.clear();
        } else if (protocol == constants::protocol::kVless) {
            snapshot.vless.clear();
        } else if (protocol == constants::protocol::kTrojan) {
            snapshot.trojan.clear();
        } else if (protocol == constants::protocol::kShadowsocks) {
            snapshot.shadowsocks.clear();
        } else if (protocol == constants::protocol::kAnyTLS) {
            snapshot.anytls.clear();
        }
    });
}

void UserStore::ClearAll() {
    std::shared_ptr<const Snapshot> empty = std::make_shared<const Snapshot>();
    GlobalSnapshot().store(std::move(empty), std::memory_order_release);
}

UserStore::VmessUsersView UserStore::VmessUsers(std::string_view tag) {
    auto snapshot = LoadSnapshot();
    auto it = snapshot->vmess.find(tag);
    return {it == snapshot->vmess.end() ? nullptr : it->second};
}

UserStore::VlessUsersView UserStore::VlessUsers(std::string_view tag) {
    auto snapshot = LoadSnapshot();
    auto it = snapshot->vless.find(tag);
    return {it == snapshot->vless.end() ? nullptr : it->second};
}

std::shared_ptr<const UserStore::VlessCredential>
UserStore::FindVlessUser(std::string_view tag,
                         const std::array<uint8_t, 16>& uuid_bytes) {
    auto view = VlessUsers(tag);
    if (!view.users) {
        return nullptr;
    }
    auto it = view.users->find(uuid_bytes);
    if (it == view.users->end()) {
        return nullptr;
    }
    return view.Share(it->second);
}

std::shared_ptr<const UserStore::TrojanCredential>
UserStore::FindTrojanUser(std::string_view tag, std::string_view password_hash) {
    auto snapshot = LoadSnapshot();
    auto tag_it = snapshot->trojan.find(tag);
    if (tag_it == snapshot->trojan.end() || !tag_it->second) {
        return nullptr;
    }
    auto user_it = tag_it->second->find(password_hash);
    if (user_it == tag_it->second->end()) {
        return nullptr;
    }
    return std::shared_ptr<const TrojanCredential>(tag_it->second, &user_it->second);
}

bool UserStore::HasTrojanUser(std::string_view tag,
                              std::string_view password_hash) {
    return FindTrojanUser(tag, password_hash) != nullptr;
}

UserStore::ShadowsocksUsersView UserStore::ShadowsocksUsers(std::string_view tag) {
    auto snapshot = LoadSnapshot();
    auto it = snapshot->shadowsocks.find(tag);
    return {it == snapshot->shadowsocks.end() ? nullptr : it->second};
}

std::shared_ptr<const UserStore::ShadowsocksCredential>
UserStore::FindShadowsocksUserById(std::string_view tag, int64_t user_id) {
    auto view = ShadowsocksUsers(tag);
    if (!view.users) {
        return nullptr;
    }
    for (const auto& user : *view.users) {
        if (user.profile && user.profile->user_id == user_id) {
            return view.Share(user);
        }
    }
    return nullptr;
}

std::shared_ptr<const UserStore::AnyTlsCredential>
UserStore::FindAnyTlsUser(std::string_view tag,
                          const std::array<uint8_t, 32>& password_hash) {
    auto snapshot = LoadSnapshot();
    auto tag_it = snapshot->anytls.find(tag);
    if (tag_it == snapshot->anytls.end() || !tag_it->second) {
        return nullptr;
    }
    auto user_it = tag_it->second->find(password_hash);
    if (user_it == tag_it->second->end()) {
        return nullptr;
    }
    return std::shared_ptr<const AnyTlsCredential>(tag_it->second, &user_it->second);
}

UserStore::Stats UserStore::GetStats() {
    Stats stats;
    auto snapshot = LoadSnapshot();
    for (const auto& [tag, users] : snapshot->vmess) {
        (void)tag;
        if (users) stats.vmess_accounts += users->size();
    }
    for (const auto& [tag, users] : snapshot->vless) {
        (void)tag;
        if (users) stats.vless_users += users->size();
    }
    for (const auto& [tag, users] : snapshot->trojan) {
        (void)tag;
        if (users) stats.trojan_users += users->size();
    }
    for (const auto& [tag, users] : snapshot->shadowsocks) {
        (void)tag;
        if (users) stats.shadowsocks_users += users->size();
    }
    for (const auto& [tag, users] : snapshot->anytls) {
        (void)tag;
        if (users) stats.anytls_users += users->size();
    }
    return stats;
}

size_t UserStore::SizeForProtocolTag(std::string_view protocol,
                                     std::string_view tag) {
    auto snapshot = LoadSnapshot();
    if (protocol == constants::protocol::kVmess) {
        return TagSize(snapshot->vmess, tag);
    }
    if (protocol == constants::protocol::kVless) {
        return TagSize(snapshot->vless, tag);
    }
    if (protocol == constants::protocol::kTrojan) {
        return TagSize(snapshot->trojan, tag);
    }
    if (protocol == constants::protocol::kShadowsocks) {
        return TagSize(snapshot->shadowsocks, tag);
    }
    if (protocol == constants::protocol::kAnyTLS) {
        return TagSize(snapshot->anytls, tag);
    }
    return 0;
}

}  // namespace acpp::proxyman::inbound
