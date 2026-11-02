#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
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

    UserStore::ApplyUsers(kTag, UserSet{PreparedVmessUsers{Vmess("vmess-1", 1)}});
    UserStore::ApplyUsers(kTag, UserSet{PreparedTrojanUsers{Trojan("hash-1", 2)}});

    if (UserStore::SizeForProtocolTag(UserProtocol::Vmess, kTag) != 1 ||
        UserStore::SizeForProtocolTag(UserProtocol::Trojan, kTag) != 1) {
        return false;
    }

    UserStore::AddUsers(kTag, UserSet{PreparedVmessUsers{Vmess("vmess-2", 3)}});
    if (UserStore::SizeForProtocolTag(UserProtocol::Vmess, kTag) != 2 ||
        UserStore::SizeForProtocolTag(UserProtocol::Trojan, kTag) != 1) {
        return false;
    }

    UserStore::RemoveUsers(kTag, UserSet{PreparedTrojanUsers{Trojan("hash-1", 2)}});
    if (UserStore::SizeForProtocolTag(UserProtocol::Vmess, kTag) != 2 ||
        UserStore::SizeForProtocolTag(UserProtocol::Trojan, kTag) != 0) {
        return false;
    }

    UserStore::ApplyUsers(kTag, UserSet{PreparedVmessUsers{}});
    return UserStore::SizeForProtocolTag(UserProtocol::Vmess, kTag) == 0;
}

bool TestTypedClearStaysProtocolLocal() {
    constexpr std::string_view kTag = "clear-tag";
    UserStore::ApplyUsers(kTag, UserSet{PreparedVmessUsers{Vmess("vmess", 1)}});
    UserStore::ApplyUsers(kTag, UserSet{PreparedTrojanUsers{Trojan("hash", 2)}});

    UserStore::ClearUsers(UserProtocol::Vmess, kTag);
    return UserStore::SizeForProtocolTag(UserProtocol::Vmess, kTag) == 0 &&
           UserStore::SizeForProtocolTag(UserProtocol::Trojan, kTag) == 1;
}

}  // namespace

int main() {
    if (!TestTypedUpdatesStayProtocolLocal()) {
        std::cerr << "typed user updates crossed protocol storage boundaries\n";
        return 1;
    }
    if (!TestTypedClearStaysProtocolLocal()) {
        std::cerr << "typed user clear crossed protocol storage boundaries\n";
        return 2;
    }
    return 0;
}
