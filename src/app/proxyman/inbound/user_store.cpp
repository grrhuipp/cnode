#include "app/proxyman/inbound/user_store.hpp"

#include "app/proxyman/inbound/prepared_config.hpp"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <format>
#include <stdexcept>
#include <limits>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace proxyman::inbound {

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
using HysteriaTagMap =
    std::unordered_map<std::string,
                       std::shared_ptr<const UserStore::HysteriaUserMap>,
                       TransparentStringHash,
                       TransparentStringEq>;

}  // namespace

struct UserStore::Snapshot {
    VmessTagMap vmess;
    VlessTagMap vless;
    TrojanTagMap trojan;
    ShadowsocksTagMap shadowsocks;
    AnyTlsTagMap anytls;
    HysteriaTagMap hysteria;
    std::array<std::unordered_map<std::string, uint64_t,
                                  TransparentStringHash, TransparentStringEq>,
               std::variant_size_v<UserSet>> credential_revisions;
};

struct UserStore::WorkerLease {
    PublishedSnapshot snapshot;
    uint64_t revision;
};

namespace {

std::atomic<UserStore::PublishedSnapshot>& GlobalSnapshot() {
    static std::atomic<UserStore::PublishedSnapshot> snapshot{
        std::make_shared<const UserStore::Snapshot>()};
    return snapshot;
}

UserStore::WorkerView& LocalView() {
    static thread_local UserStore::WorkerView view;
    return view;
}


// Two users deriving one credential would let authentication pick an
// arbitrary owner for traffic, limits and online devices; reject the update.
[[noreturn]] void ThrowAmbiguousCredential(std::string_view protocol) {
    throw std::invalid_argument(std::format("{} users share one credential", protocol));
}

UserStore::VmessCredential
BuildVmessCredential(const PreparedVmessUser& user) {
    UserStore::VmessCredential credential{
        .uuid_bytes = user.uuid_bytes,
        .cmd_key = user.cmd_key,
        .auth_id_key = {},
        .profile = user.profile,
    };
    if (AES_set_decrypt_key(user.auth_key.data(), 128, &credential.auth_id_key) != 0) {
        throw std::logic_error("VMess AuthID key schedule rejected a 128-bit key");
    }
    return credential;
}

std::shared_ptr<const UserStore::VmessUserMap>
BuildVmessUsers(const std::vector<PreparedVmessUser>& users) {
    auto list = std::make_shared<UserStore::VmessUserMap>();
    list->reserve(users.size());
    std::unordered_set<std::array<uint8_t, 16>, UserStore::Array16Hash> seen;
    seen.reserve(users.size());
    for (const auto& user : users) {
        if (!seen.insert(user.uuid_bytes).second) ThrowAmbiguousCredential("VMess");
        list->push_back(BuildVmessCredential(user));
    }
    return list;
}

UserStore::VlessCredential
BuildVlessCredential(const PreparedVlessUser& user) {
    return UserStore::VlessCredential{
        .uuid_bytes = user.uuid_bytes,
        .flow = user.flow,
        .profile = user.profile,
    };
}

std::shared_ptr<const UserStore::VlessUserMap>
BuildVlessUsers(const std::vector<PreparedVlessUser>& users) {
    auto map = std::make_shared<UserStore::VlessUserMap>();
    map->reserve(users.size());
    for (const auto& user : users) {
        if (!map->try_emplace(user.uuid_bytes, BuildVlessCredential(user)).second) {
            ThrowAmbiguousCredential("VLESS");
        }
    }
    return map;
}

UserStore::TrojanCredential
BuildTrojanCredential(const PreparedTrojanUser& user) {
    return UserStore::TrojanCredential{
        .profile = user.profile,
    };
}

std::shared_ptr<const UserStore::TrojanUserMap>
BuildTrojanUsers(const std::vector<PreparedTrojanUser>& users) {
    auto map = std::make_shared<UserStore::TrojanUserMap>();
    map->reserve(users.size());
    for (const auto& user : users) {
        if (!map->try_emplace(user.password_hash, BuildTrojanCredential(user)).second) {
            ThrowAmbiguousCredential("Trojan");
        }
    }
    return map;
}

UserStore::ShadowsocksCredential
BuildShadowsocksCredential(const PreparedShadowsocksUser& user) {
    return UserStore::ShadowsocksCredential{
        .derived_key = user.derived_key,
        .identity_key = user.identity_key,
        .psk_hash = user.psk_hash,
        .key_size = user.key_size,
        .salt_size = user.salt_size,
        .profile = user.profile,
    };
}

std::shared_ptr<const UserStore::ShadowsocksUserList>
BuildShadowsocksUsers(const std::vector<PreparedShadowsocksUser>& users) {
    auto list = std::make_shared<UserStore::ShadowsocksUserList>();
    list->reserve(users.size());
    std::unordered_set<std::string_view> seen;
    seen.reserve(users.size());
    for (const auto& user : users) {
        const std::string_view key(
            reinterpret_cast<const char*>(user.derived_key.data()), user.derived_key.size);
        if (!seen.insert(key).second) ThrowAmbiguousCredential("Shadowsocks");
        list->push_back(BuildShadowsocksCredential(user));
    }
    return list;
}

UserStore::AnyTlsCredential
BuildAnyTlsCredential(const PreparedAnyTlsUser& user) {
    return UserStore::AnyTlsCredential{
        .password_hash = user.password_hash,
        .profile = user.profile,
    };
}

std::shared_ptr<const UserStore::AnyTlsUserMap>
BuildAnyTlsUsers(const std::vector<PreparedAnyTlsUser>& users) {
    auto map = std::make_shared<UserStore::AnyTlsUserMap>();
    map->reserve(users.size());
    for (const auto& user : users) {
        if (!map->try_emplace(user.password_hash, BuildAnyTlsCredential(user)).second) {
            ThrowAmbiguousCredential("AnyTLS");
        }
    }
    return map;
}

UserStore::HysteriaCredential
BuildHysteriaCredential(const PreparedHysteriaUser& user) {
    return UserStore::HysteriaCredential{
        .credential_hash = user.credential_hash,
        .profile = user.profile,
    };
}

std::shared_ptr<const UserStore::HysteriaUserMap>
BuildHysteriaUsers(const std::vector<PreparedHysteriaUser>& users) {
    auto map = std::make_shared<UserStore::HysteriaUserMap>();
    map->reserve(users.size());
    for (const auto& user : users) {
        if (!map->try_emplace(
                user.credential_hash, BuildHysteriaCredential(user)).second) {
            ThrowAmbiguousCredential("Hysteria");
        }
    }
    return map;
}

template <typename TagMap>
void EraseByTag(TagMap& map, std::string_view tag) {
    if (auto it = map.find(tag); it != map.end()) {
        map.erase(it);
    }
}

template <typename TagMap, typename ContainerPtr>
void SetOrErase(TagMap& map, std::string_view tag, ContainerPtr users) {
    if (!users || users->empty()) {
        EraseByTag(map, tag);
        return;
    }
    if (auto it = map.find(tag); it != map.end()) {
        it->second = std::move(users);
        return;
    }
    map.emplace(std::string(tag), std::move(users));
}

}  // namespace

size_t UserStore::Array16Hash::operator()(const std::array<uint8_t, 16>& value) const noexcept {
    uint64_t lo = 0;
    uint64_t hi = 0;
    std::memcpy(&lo, value.data(), sizeof(lo));
    std::memcpy(&hi, value.data() + sizeof(lo), sizeof(hi));
    uint64_t h = lo ^ (hi + 0x9e3779b97f4a7c15ull + (lo << 6) + (lo >> 2));
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33;
    return static_cast<size_t>(h);
}

size_t UserStore::Array32Hash::operator()(const std::array<uint8_t, 32>& value) const noexcept {
    uint64_t w0 = 0, w1 = 0, w2 = 0, w3 = 0;
    std::memcpy(&w0, value.data(), 8);
    std::memcpy(&w1, value.data() + 8, 8);
    std::memcpy(&w2, value.data() + 16, 8);
    std::memcpy(&w3, value.data() + 24, 8);
    uint64_t h = w0 ^ (w1 * 0x9e3779b97f4a7c15ull) ^ (w2 * 0xbf58476d1ce4e5b9ull) ^ (w3 * 0x94d049bb133111ebull);
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33;
    return static_cast<size_t>(h);
}

UserStore::PublishedSnapshot UserStore::CaptureSnapshot() {
    return GlobalSnapshot().load(std::memory_order_acquire);
}

UserStore::WorkerView UserStore::PrepareWorkerView(PublishedSnapshot snapshot) {
    static std::atomic<uint64_t> next_revision{1};
    return std::make_shared<const WorkerLease>(WorkerLease{
        std::move(snapshot), next_revision.fetch_add(1, std::memory_order_relaxed)});
}

void UserStore::InstallWorkerView(WorkerView view) noexcept {
    LocalView() = std::move(view);
}

UserStore::WorkerView UserStore::ExchangeWorkerView(WorkerView view) noexcept {
    LocalView().swap(view);
    return view;
}

UserStore::WorkerView UserStore::CaptureWorkerView() noexcept {
    return LocalView();
}

void UserStore::ClearWorkerView() noexcept {
    InstallWorkerView({});
}

uint64_t UserStore::WorkerViewRevision() noexcept {
    const auto& view = LocalView();
    return view ? view->revision : 0;
}

uint64_t UserStore::CredentialRevision(
    UserProtocol protocol, std::string_view tag) noexcept {
    const auto& view = LocalView();
    if (!view || !view->snapshot) return 0;
    const auto& revisions = view->snapshot->credential_revisions[static_cast<size_t>(protocol)];
    const auto found = revisions.find(tag);
    return found == revisions.end() ? 0 : found->second;
}

void UserStore::CommitSnapshot(PublishedSnapshot snapshot) noexcept {
    GlobalSnapshot().store(std::move(snapshot), std::memory_order_release);
}

UserStore::PublishedSnapshot UserStore::PrepareUsers(
    std::string_view tag, const UserSet& users) {
    const UserUpdate update{tag, users};
    return PrepareUsers(std::span(&update, 1));
}

UserStore::PublishedSnapshot UserStore::PrepareUsers(
    std::span<const UserUpdate> updates) {
    auto next = std::make_shared<Snapshot>(*CaptureSnapshot());
    for (const auto& [tag, users] : updates) {
        if (const auto* vmess = std::get_if<PreparedVmessUsers>(&users)) {
            SetOrErase(next->vmess, tag, BuildVmessUsers(*vmess));
        } else if (const auto* vless = std::get_if<PreparedVlessUsers>(&users)) {
            SetOrErase(next->vless, tag, BuildVlessUsers(*vless));
        } else if (const auto* trojan = std::get_if<PreparedTrojanUsers>(&users)) {
            SetOrErase(next->trojan, tag, BuildTrojanUsers(*trojan));
        } else if (const auto* shadowsocks = std::get_if<PreparedShadowsocksUsers>(&users)) {
            SetOrErase(next->shadowsocks, tag, BuildShadowsocksUsers(*shadowsocks));
        } else if (const auto* anytls = std::get_if<PreparedAnyTlsUsers>(&users)) {
            SetOrErase(next->anytls, tag, BuildAnyTlsUsers(*anytls));
        } else if (const auto* hysteria = std::get_if<PreparedHysteriaUsers>(&users)) {
            SetOrErase(next->hysteria, tag, BuildHysteriaUsers(*hysteria));
        }
        const auto protocol = UserProtocolOf(users);
        if (protocol == UserProtocol::Vmess || protocol == UserProtocol::Shadowsocks) continue;
        auto& revisions = next->credential_revisions[static_cast<size_t>(protocol)];
        if (std::visit([](const auto& entries) { return entries.empty(); }, users)) {
            EraseByTag(revisions, tag);
        } else {
            // Prepare operations are serialized by the control-plane gate.
            static uint64_t next_revision = 1;
            if (next_revision == std::numeric_limits<uint64_t>::max()) {
                throw std::overflow_error("credential revision exhausted");
            }
            revisions.insert_or_assign(std::string(tag), next_revision++);
        }
    }
    return next;
}


UserStore::PublishedSnapshot UserStore::PrepareClearUsers(
    UserProtocol protocol, std::string_view tag) {
    auto next = std::make_shared<Snapshot>(*CaptureSnapshot());
    switch (protocol) {
        case UserProtocol::Vmess: EraseByTag(next->vmess, tag); break;
        case UserProtocol::Vless: EraseByTag(next->vless, tag); break;
        case UserProtocol::Trojan: EraseByTag(next->trojan, tag); break;
        case UserProtocol::Shadowsocks: EraseByTag(next->shadowsocks, tag); break;
        case UserProtocol::AnyTls: EraseByTag(next->anytls, tag); break;
        case UserProtocol::Hysteria: EraseByTag(next->hysteria, tag); break;
    }
    EraseByTag(next->credential_revisions[static_cast<size_t>(protocol)], tag);
    return next;
}

UserStore::VmessUsersView UserStore::VmessUsers(std::string_view tag) {
    const auto& view = LocalView();
    if (!view || !view->snapshot) return {};
    auto it = view->snapshot->vmess.find(tag);
    return {it == view->snapshot->vmess.end()
        ? nullptr : std::shared_ptr<const VmessUserMap>(view, it->second.get())};
}

UserStore::VlessUsersView UserStore::VlessUsers(std::string_view tag) {
    const auto& view = LocalView();
    if (!view || !view->snapshot) return {};
    auto it = view->snapshot->vless.find(tag);
    return {it == view->snapshot->vless.end()
        ? nullptr : std::shared_ptr<const VlessUserMap>(view, it->second.get())};
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
    const auto& view = LocalView();
    if (!view || !view->snapshot) return nullptr;
    auto tag_it = view->snapshot->trojan.find(tag);
    if (tag_it == view->snapshot->trojan.end()) return nullptr;
    auto user_it = tag_it->second->find(password_hash);
    if (user_it == tag_it->second->end()) return nullptr;
    return std::shared_ptr<const TrojanCredential>(view, &user_it->second);
}

UserStore::ShadowsocksUsersView UserStore::ShadowsocksUsers(std::string_view tag) {
    const auto& view = LocalView();
    if (!view || !view->snapshot) return {};
    auto it = view->snapshot->shadowsocks.find(tag);
    return {it == view->snapshot->shadowsocks.end()
        ? nullptr : std::shared_ptr<const ShadowsocksUserList>(view, it->second.get())};
}

std::shared_ptr<const UserStore::AnyTlsCredential>
UserStore::FindAnyTlsUser(std::string_view tag,
                          const std::array<uint8_t, 32>& password_hash) {
    const auto& view = LocalView();
    if (!view || !view->snapshot) return nullptr;
    auto tag_it = view->snapshot->anytls.find(tag);
    if (tag_it == view->snapshot->anytls.end()) return nullptr;
    auto user_it = tag_it->second->find(password_hash);
    if (user_it == tag_it->second->end()) return nullptr;
    return std::shared_ptr<const AnyTlsCredential>(view, &user_it->second);
}

std::shared_ptr<const UserStore::HysteriaCredential>
UserStore::FindHysteriaUser(
    std::string_view tag,
    const std::array<uint8_t, 32>& credential_hash) {
    const auto& view = LocalView();
    if (!view || !view->snapshot) return nullptr;
    auto tag_it = view->snapshot->hysteria.find(tag);
    if (tag_it == view->snapshot->hysteria.end()) return nullptr;
    auto user_it = tag_it->second->find(credential_hash);
    if (user_it == tag_it->second->end()) return nullptr;
    return std::shared_ptr<const HysteriaCredential>(view, &user_it->second);
}

size_t UserStore::TotalUsers() {
    auto snapshot = CaptureSnapshot();
    size_t total = 0;
    const auto count = [&](const auto& tags) {
        for (const auto& [tag, users] : tags) {
            (void)tag;
            total += users->size();
        }
    };
    count(snapshot->vmess);
    count(snapshot->vless);
    count(snapshot->trojan);
    count(snapshot->shadowsocks);
    count(snapshot->anytls);
    count(snapshot->hysteria);
    return total;
}

}  // namespace proxyman::inbound
