#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "validator.hpp"
#include "vmess_crypto.hpp"
#include <chrono>
#include <iostream>
#include <stdexcept>

int main() {
    using namespace acpp::proxyman::inbound;
    try {
        PreparedVmessUser user;
        user.uuid = "11111111-1111-1111-1111-111111111111";
        user.cached_auth_aes_key.fill(0x19);
        user.profile.user_id = 1;
        constexpr auto tag = "snapshot-lifetime";
        const UserSet users = PreparedVmessUsers{user};
        UserStore::ApplyUsers(tag, users);
        acpp::vmess::TimedUserValidator validator;
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::array<uint8_t, 16> auth;
        acpp::vmess::GenerateAuthID(user.cached_auth_aes_key.data(), now, auth.data());
        int64_t timestamp = 0;
        auto authenticated = validator.FindByAuthIDForTag(tag, auth.data(), timestamp);
        if (!authenticated || timestamp != now) throw std::runtime_error("authentication failed");
        std::weak_ptr<const UserStore::VmessCredential> old_table = authenticated;
        authenticated.reset();
        UserStore::ApplyUsers(tag, users);
        if (!old_table.expired()) throw std::runtime_error("idle validator pinned a replaced table");
        authenticated = validator.FindByAuthIDForTag(tag, auth.data(), timestamp);
        if (!authenticated) throw std::runtime_error("replacement table failed authentication");
        old_table = authenticated;
        authenticated.reset();
        UserStore::ClearUsers(UserProtocol::Vmess, tag);
        if (!old_table.expired()) throw std::runtime_error("idle validator pinned a removed table");
        if (validator.FindByAuthIDForTag(tag, auth.data(), timestamp))
            throw std::runtime_error("expired hot-cache credentials must never authenticate");
        UserStore::ApplyUsers(tag, users);
        if (!validator.FindByAuthIDForTag(tag, auth.data(), timestamp))
            throw std::runtime_error("validator must recover after table removal");
        UserStore::ClearUsers(UserProtocol::Vmess, tag);
        std::cout << "VMess hot cache: replaced/removed table released, stale pointers invalidated PASS\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
