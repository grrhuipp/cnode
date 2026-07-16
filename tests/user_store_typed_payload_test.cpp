#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/core/constants.hpp"

#include <iostream>
#include <type_traits>
#include <variant>

namespace {

using namespace acpp::proxyman::inbound;

static_assert(std::variant_size_v<UserSet> == 5);
static_assert(std::is_same_v<
              std::variant_alternative_t<0, UserSet>,
              PreparedVmessUsers>);

PreparedVmessUser Vmess(std::string uuid, int64_t user_id) {
    PreparedVmessUser user;
    user.uuid = std::move(uuid);
    user.profile.user_id = user_id;
    return user;
}

PreparedTrojanUser Trojan(std::string hash, int64_t user_id) {
    PreparedTrojanUser user;
    user.password_hash = std::move(hash);
    user.profile.user_id = user_id;
    return user;
}

bool TestTypedUpdatesStayProtocolLocal() {
    constexpr std::string_view kTag = "shared-tag";
    UserStore::ClearAll();

    UserStore::ApplyUsers(kTag, UserSet{PreparedVmessUsers{Vmess("vmess-1", 1)}});
    UserStore::ApplyUsers(kTag, UserSet{PreparedTrojanUsers{Trojan("hash-1", 2)}});

    if (UserStore::SizeForProtocolTag(acpp::constants::protocol::kVmess, kTag) != 1 ||
        UserStore::SizeForProtocolTag(acpp::constants::protocol::kTrojan, kTag) != 1) {
        return false;
    }

    UserStore::AddUsers(kTag, UserSet{PreparedVmessUsers{Vmess("vmess-2", 3)}});
    if (UserStore::SizeForProtocolTag(acpp::constants::protocol::kVmess, kTag) != 2 ||
        UserStore::SizeForProtocolTag(acpp::constants::protocol::kTrojan, kTag) != 1) {
        return false;
    }

    UserStore::RemoveUsers(kTag, UserSet{PreparedTrojanUsers{Trojan("hash-1", 2)}});
    if (UserStore::SizeForProtocolTag(acpp::constants::protocol::kVmess, kTag) != 2 ||
        UserStore::SizeForProtocolTag(acpp::constants::protocol::kTrojan, kTag) != 0) {
        return false;
    }

    UserStore::ApplyUsers(kTag, UserSet{PreparedVmessUsers{}});
    return UserStore::SizeForProtocolTag(acpp::constants::protocol::kVmess, kTag) == 0;
}

}  // namespace

int main() {
    if (!TestTypedUpdatesStayProtocolLocal()) {
        std::cerr << "typed user updates crossed protocol storage boundaries\n";
        return 1;
    }
    return 0;
}
