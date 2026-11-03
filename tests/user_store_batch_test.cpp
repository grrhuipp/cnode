#include "acppnode/app/proxyman/inbound/user_store.hpp"

#include <array>
#include <cstdlib>
#include <iostream>
#include <new>

namespace {
thread_local std::ptrdiff_t fail_after = -1;
using namespace acpp::proxyman::inbound;

void Commit(UserStore::PublishedSnapshot snapshot) {
    auto view = UserStore::PrepareWorkerView(snapshot);
    UserStore::CommitSnapshot(std::move(snapshot));
    UserStore::InstallWorkerView(std::move(view));
}
}

// Inject at the real cold snapshot and Worker-lease allocation boundaries.
void* operator new(std::size_t size) {
    if (fail_after == 0) throw std::bad_alloc();
    if (fail_after > 0) --fail_after;
    if (void* memory = std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete[](void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, std::size_t) noexcept { std::free(memory); }
void operator delete[](void* memory, std::size_t) noexcept { std::free(memory); }

int main() {
    const UserSet first_old = PreparedVmessUsers{PreparedVmessUser{
        .uuid = "old-first",
        .profile = {.user_id = 101, .email = {}}}};
    const UserSet second_old = PreparedTrojanUsers{PreparedTrojanUser{
        .password_hash = "old-second",
        .profile = {.user_id = 102, .email = {}}}};
    const UserSet unrelated = PreparedVmessUsers{PreparedVmessUser{.uuid = "unrelated", .profile = {}}};
    const std::array initial{
        UserStore::UserUpdate{"first", first_old}, UserStore::UserUpdate{"second", second_old},
        UserStore::UserUpdate{"unrelated", unrelated}};
    Commit(UserStore::PrepareUsers(initial));
    const auto old_snapshot = UserStore::CaptureSnapshot();
    const auto first_view = UserStore::VmessUsers("first").users;
    const auto second_view = UserStore::FindTrojanUser("second", "old-second");
    const auto unrelated_view = UserStore::VmessUsers("unrelated").users;
    const UserSet first_new = PreparedVmessUsers{
        PreparedVmessUser{
            .uuid = "new-first-1",
            .profile = {.user_id = 201, .email = {}}},
        PreparedVmessUser{
            .uuid = "new-first-2",
            .profile = {.user_id = 202, .email = {}}}};
    const UserSet second_new = PreparedTrojanUsers{PreparedTrojanUser{
        .password_hash = "new-second",
        .profile = {.user_id = 203, .email = {}}}};
    const UserSet third_new = PreparedVlessUsers{PreparedVlessUser{}};
    const std::array updates{
        UserStore::UserUpdate{"first", first_new}, UserStore::UserUpdate{"second", second_new},
        UserStore::UserUpdate{"third", third_new}};

    bool completed = false;
    std::ptrdiff_t failures = 0;
    for (std::ptrdiff_t limit = 0; limit < 512; ++limit) {
        fail_after = limit;
        try {
            Commit(UserStore::PrepareUsers(updates));
            completed = true;
        } catch (const std::bad_alloc&) { ++failures; }
        fail_after = -1;
        if (completed) break;
        if (UserStore::CaptureSnapshot() != old_snapshot ||
            UserStore::VmessUsers("first").users != first_view ||
            UserStore::FindTrojanUser("second", "old-second") != second_view ||
            UserStore::FindTrojanUser("second", "new-second") || !UserStore::VlessUsers("third").empty()) {
            std::cerr << "allocation failure changed a committed snapshot or Worker view\n";
            return 1;
        }
    }
    if (!completed || failures < 5 || UserStore::VmessUsers("first").size() != 2 ||
        !UserStore::FindTrojanUser("second", "new-second") ||
        UserStore::FindTrojanUser("second", "old-second") ||
        UserStore::VlessUsers("third").size() != 1 ||
        UserStore::VmessUsers("unrelated").users != unrelated_view ||
        first_view->size() != 1 || (*first_view)[0].profile.user_id != 101 || second_view->profile.user_id != 102) return 2;

    auto current = UserStore::CaptureSnapshot();
    auto worker_one = UserStore::PrepareWorkerView(current);
    auto worker_two = UserStore::PrepareWorkerView(current);
    UserStore::InstallWorkerView(std::move(worker_one));
    auto first_lease_user = UserStore::FindTrojanUser("second", "new-second");
    UserStore::InstallWorkerView(std::move(worker_two));
    auto second_lease_user = UserStore::FindTrojanUser("second", "new-second");
    if (first_lease_user.get() != second_lease_user.get() ||
        (!first_lease_user.owner_before(second_lease_user) &&
         !second_lease_user.owner_before(first_lease_user))) return 3;
    // A shared table has distinct per-Worker control blocks. Lookup does not
    // allocate, and retiring a Worker leaves already authenticated users alive.
    fail_after = 0;
    auto hot_user = UserStore::FindTrojanUser("second", "new-second");
    fail_after = -1;
    UserStore::ClearWorkerView();
    if (UserStore::FindTrojanUser("second", "new-second") ||
        hot_user->profile.user_id != 203 || first_lease_user->profile.user_id != 203) return 4;
    std::weak_ptr<const UserStore::TrojanCredential> retired_lease = hot_user;
    hot_user.reset();
    second_lease_user.reset();
    if (!retired_lease.expired()) return 5;
    UserStore::InstallWorkerView(UserStore::PrepareWorkerView(current));

    PreparedShadowsocksUser ss_user;
    ss_user.password = "identity-user";
    ss_user.profile.user_id = 7;
    ss_user.psk_hash.fill(0x11);
    Commit(UserStore::PrepareUsers("ss-hash", UserSet{PreparedShadowsocksUsers{ss_user}}));
    const auto ss_view = UserStore::ShadowsocksUsers("ss-hash");
    ss_user.psk_hash.fill(0x22);
    Commit(UserStore::PrepareUsers("ss-hash", UserSet{PreparedShadowsocksUsers{ss_user}}));
    if (ss_view[0].psk_hash[0] != 0x11 || UserStore::ShadowsocksUsers("ss-hash")[0].psk_hash[0] != 0x22) return 6;
    Commit(UserStore::PrepareClearUsers(UserProtocol::Shadowsocks, "ss-hash"));
    if (!UserStore::ShadowsocksUsers("ss-hash").empty() || ss_view[0].psk_hash[0] != 0x11) return 7;
    UserStore::ClearWorkerView();
    std::cout << "snapshot/Worker-lease atomicity preserved across " << failures << " allocation failures\n";
}
