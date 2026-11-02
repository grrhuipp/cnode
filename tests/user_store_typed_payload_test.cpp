#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include <iostream>
#include <type_traits>
#include <variant>

namespace {
using namespace acpp::proxyman::inbound;
static_assert(std::variant_size_v<UserSet> == 5);
static_assert(std::is_same_v<std::variant_alternative_t<0, UserSet>, PreparedVmessUsers>);

void Commit(UserStore::PublishedSnapshot snapshot) {
    auto view = UserStore::PrepareWorkerView(snapshot);
    UserStore::CommitSnapshot(std::move(snapshot));
    UserStore::InstallWorkerView(std::move(view));
}

PreparedVmessUser Vmess(std::string uuid, int64_t id) {
    PreparedVmessUser user;
    user.uuid = std::move(uuid);
    user.profile.user_id = id;
    return user;
}
PreparedTrojanUser Trojan(std::string hash, int64_t id) {
    PreparedTrojanUser user;
    user.password_hash = std::move(hash);
    user.profile.user_id = id;
    return user;
}

bool TestTypedUpdatesStayProtocolLocal() {
    constexpr std::string_view tag = "shared-tag";
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{Vmess("vmess-1", 1)}}));
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedTrojanUsers{Trojan("hash-1", 2)}}));
    if (UserStore::VmessUsers(tag).size() != 1 || !UserStore::FindTrojanUser(tag, "hash-1")) return false;

    auto old = UserStore::VmessUsers(tag);
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{Vmess("vmess-2", 3)}}));
    if (UserStore::VmessUsers(tag).users->contains("vmess-1") ||
        !UserStore::VmessUsers(tag).users->contains("vmess-2") ||
        !old.users->contains("vmess-1") || !UserStore::FindTrojanUser(tag, "hash-1")) return false;

    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedTrojanUsers{}}));
    if (UserStore::FindTrojanUser(tag, "hash-1") || UserStore::VmessUsers(tag).size() != 1) return false;
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{}}));
    return UserStore::VmessUsers(tag).empty();
}

bool TestTypedClearStaysProtocolLocal() {
    constexpr std::string_view tag = "clear-tag";
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{Vmess("vmess", 1)}}));
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedTrojanUsers{Trojan("hash", 2)}}));
    Commit(UserStore::PrepareClearUsers(UserProtocol::Vmess, tag));
    return UserStore::VmessUsers(tag).empty() && UserStore::FindTrojanUser(tag, "hash");
}
}  // namespace

int main() {
    if (!TestTypedUpdatesStayProtocolLocal() || !TestTypedClearStaysProtocolLocal()) {
        std::cerr << "typed replacement/clear crossed protocol storage boundaries\n";
        return 1;
    }
    UserStore::ClearWorkerView();
}
