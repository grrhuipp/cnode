#include <gtest/gtest.h>

#include "app/proxyman/inbound/user_store.hpp"
#include "app/proxyman/inbound/prepared_config.hpp"
#include "validator.hpp"
#include "vmess_crypto.hpp"
#include <chrono>
#include <iostream>
#include <stdexcept>

namespace {
using namespace ::proxyman::inbound;
void Commit(UserStore::PublishedSnapshot snapshot) {
    auto view = UserStore::PrepareWorkerView(snapshot);
    UserStore::CommitSnapshot(std::move(snapshot));
    UserStore::InstallWorkerView(std::move(view));
}
void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
}

TEST(VmessAuthSnapshot, Contract) {
    using namespace ::proxyman::inbound;
    try {
        PreparedVmessUser user;
        user.uuid = "11111111-1111-1111-1111-111111111111";
        user.auth_key.fill(0x19);
        user.profile.user_id = 1;
        constexpr auto tag = "snapshot-lifetime";
        const UserSet users = PreparedVmessUsers{user};
        Commit(UserStore::PrepareUsers(tag, users));
        ::vmess::TimedUserValidator validator;
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::array<uint8_t, 16> auth;
        ::vmess::GenerateAuthID(
            ::vmess::ExpandAuthIDEncryptKey(user.auth_key), now, auth.data());
        int64_t timestamp = 0;
        auto authenticated = validator.FindByAuthIDForTag(tag, auth.data(), timestamp);
        Check(authenticated && timestamp == now, "authentication failed");
        std::weak_ptr<const UserStore::VmessCredential> old_lease = authenticated;
        authenticated.reset();
        Commit(UserStore::PrepareUsers(tag, users));
        Check(old_lease.expired(), "idle validator pinned a replaced Worker lease");
        authenticated = validator.FindByAuthIDForTag(tag, auth.data(), timestamp);
        Check(bool(authenticated), "replacement table failed authentication");
        old_lease = authenticated;
        authenticated.reset();
        Commit(UserStore::PrepareClearUsers(UserProtocol::Vmess, tag));
        Check(old_lease.expired(), "idle validator pinned a removed Worker lease");
        Check(!validator.FindByAuthIDForTag(tag, auth.data(), timestamp),
              "expired hot-cache credentials authenticated");

        PreparedVmessUser other = user;
        other.uuid = "22222222-2222-2222-2222-222222222222";
        other.auth_key.fill(0x27);
        other.profile.user_id = 2;
        const UserSet other_users = PreparedVmessUsers{other};
        const std::array updates{
            UserStore::UserUpdate{tag, users}, UserStore::UserUpdate{"other-tag", other_users}};
        auto prepared = UserStore::PrepareUsers(updates);
        Check(!validator.FindByAuthIDForTag(tag, auth.data(), timestamp),
              "preparation changed an installed Worker view");
        Commit(std::move(prepared));
        std::array<uint8_t, 16> other_auth;
        ::vmess::GenerateAuthID(
            ::vmess::ExpandAuthIDEncryptKey(other.auth_key), now, other_auth.data());
        for (int round = 0; round < 64; ++round) {
            auto first = validator.FindByAuthIDForTag(tag, auth.data(), timestamp);
            auto second = validator.FindByAuthIDForTag("other-tag", other_auth.data(), timestamp);
            Check(first && second && first->profile.user_id == 1 && second->profile.user_id == 2,
                  "alternating tag hot-cache lookup lost credential isolation");
            Check(!validator.FindByAuthIDForTag(tag, other_auth.data(), timestamp),
                  "hot-cache credential crossed tags");
        }
        authenticated = validator.FindByAuthIDForTag(tag, auth.data(), timestamp);
        UserStore::ClearWorkerView();
        Check(authenticated && authenticated->profile.user_id == 1,
              "Worker shutdown invalidated an authenticated session lease");
        Check(!validator.FindByAuthIDForTag(tag, auth.data(), timestamp),
              "cleared Worker view accepted stale hot-cache credentials");
        std::cout << "VMess replacement, removal, tag isolation and Worker shutdown lifetime passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        FAIL() << error.what();
    }
}
