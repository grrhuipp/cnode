#include "acppnode/app/proxyman/inbound/user_store.hpp"

#include <array>
#include <cstdlib>
#include <iostream>
#include <new>

namespace {
thread_local std::ptrdiff_t fail_after = -1;
}

// Inject at every real allocation boundary in the production RCU publisher.
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
    using namespace acpp::proxyman::inbound;
    const UserSet first_old = PreparedVmessUsers{PreparedVmessUser{.uuid = "old-first"}};
    const UserSet second_old = PreparedTrojanUsers{PreparedTrojanUser{.password_hash = "old-second"}};
    const UserSet unrelated = PreparedVmessUsers{PreparedVmessUser{.uuid = "unrelated"}};
    const std::array initial{
        UserStore::UserUpdate{"first", first_old},
        UserStore::UserUpdate{"second", second_old},
        UserStore::UserUpdate{"unrelated", unrelated}};
    UserStore::ApplyUsers(initial);
    const auto first_view = UserStore::VmessUsers("first").users;
    const auto second_view = UserStore::FindTrojanUser("second", "old-second");
    const auto unrelated_view = UserStore::VmessUsers("unrelated").users;

    const UserSet first_new = PreparedVmessUsers{
        PreparedVmessUser{.uuid = "new-first-1"}, PreparedVmessUser{.uuid = "new-first-2"}};
    const UserSet second_new = PreparedTrojanUsers{PreparedTrojanUser{.password_hash = "new-second"}};
    const UserSet third_new = PreparedVlessUsers{PreparedVlessUser{}};
    const std::array updates{
        UserStore::UserUpdate{"first", first_new},
        UserStore::UserUpdate{"second", second_new},
        UserStore::UserUpdate{"third", third_new}};

    bool completed = false;
    std::ptrdiff_t failures = 0;
    for (std::ptrdiff_t limit = 0; limit < 512; ++limit) {
        fail_after = limit;
        try {
            UserStore::ApplyUsers(updates);
            completed = true;
        } catch (const std::bad_alloc&) {
            ++failures;
        }
        fail_after = -1;
        if (completed) break;
        if (UserStore::VmessUsers("first").users != first_view ||
            UserStore::FindTrojanUser("second", "old-second") != second_view ||
            UserStore::FindTrojanUser("second", "new-second") ||
            !UserStore::VlessUsers("third").empty()) {
            std::cerr << "allocation failure published a partial batch at boundary " << limit << '\n';
            return 1;
        }
    }
    if (!completed || failures < 10 || UserStore::VmessUsers("first").size() != 2 ||
        !UserStore::FindTrojanUser("second", "new-second") ||
        UserStore::FindTrojanUser("second", "old-second") ||
        UserStore::VlessUsers("third").size() != 1 ||
        UserStore::VmessUsers("unrelated").users != unrelated_view ||
        first_view->size() != 1 || !first_view->contains(std::string_view("old-first")) ||
        second_view->password_hash != "old-second") return 2;

    const UserSet empty_vmess = PreparedVmessUsers{};
    const UserSet empty_trojan = PreparedTrojanUsers{};
    const std::array removals{
        UserStore::UserUpdate{"first", empty_vmess}, UserStore::UserUpdate{"second", empty_trojan}};
    UserStore::ApplyUsers(removals);
    if (!UserStore::VmessUsers("first").empty() ||
        UserStore::FindTrojanUser("second", "new-second") ||
        UserStore::VmessUsers("unrelated").users != unrelated_view) return 3;
    std::cout << "batch publication preserved old snapshot across " << failures << " allocation failures\n";
}
