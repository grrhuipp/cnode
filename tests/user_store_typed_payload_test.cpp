#include <gtest/gtest.h>

#include "app/proxyman/inbound/prepared_config.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
#include <type_traits>
#include <variant>

namespace {
using namespace ::proxyman::inbound;

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
PreparedHysteriaUser Hysteria(uint8_t hash_byte, int64_t id) {
    PreparedHysteriaUser user;
    user.credential_hash.fill(hash_byte);
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
    if (UserStore::VmessUsers(tag).size() != 1 ||
        UserStore::VmessUsers(tag)[0].profile.user_id != 3 ||
        old.size() != 1 || old[0].profile.user_id != 1 || !UserStore::FindTrojanUser(tag, "hash-1")) return false;

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

// Two users deriving the same credential are ambiguous even when their source
// text differs (VMess/VLESS parse UUIDs case- and hyphen-insensitively); the
// update must fail before any snapshot is published.
bool TestAmbiguousCredentialsRejected() {
    constexpr std::string_view tag = "ambiguous-tag";
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{Vmess("kept", 1)}}));
    const auto before = UserStore::CaptureSnapshot();
    auto upper = Vmess("6BA7B810-9DAD-11D1-80B4-00C04FD430C8", 2);
    auto lower = Vmess("6ba7b8109dad11d180b400c04fd430c8", 3);
    upper.uuid_bytes.fill(0x6b);
    lower.uuid_bytes.fill(0x6b);
    PreparedVlessUser vless_a;
    PreparedVlessUser vless_b;
    const std::array<UserSet, 4> ambiguous{
        UserSet{PreparedVmessUsers{upper, lower}},
        UserSet{PreparedVlessUsers{vless_a, vless_b}},
        UserSet{PreparedTrojanUsers{
            Trojan("same-hash", 4), Trojan("same-hash", 5)}},
        UserSet{PreparedHysteriaUsers{
            Hysteria(0x42, 6), Hysteria(0x42, 7)}}};
    for (const auto& users : ambiguous) {
        try {
            static_cast<void>(UserStore::PrepareUsers(tag, users));
            return false;
        } catch (const std::invalid_argument&) {
        }
    }
    return UserStore::CaptureSnapshot() == before &&
           UserStore::VmessUsers(tag).size() == 1 &&
           UserStore::VmessUsers(tag)[0].profile.user_id == 1 &&
           [&] {
               const auto credential =
                   UserStore::FindHysteriaUser(
                       tag, Hysteria(0x42, 0).credential_hash);
               return !credential;
           }();
}
}  // namespace

TEST(UserStoreTypedPayload, Contract) {
    if (!TestTypedUpdatesStayProtocolLocal() || !TestTypedClearStaysProtocolLocal()) {
        std::cerr << "typed replacement/clear crossed protocol storage boundaries\n";
        FAIL() << "typed replacement/clear crossed protocol storage boundaries";
    }
    if (!TestAmbiguousCredentialsRejected()) {
        std::cerr << "ambiguous credentials were published or silently merged\n";
        FAIL() << "ambiguous credentials were published or silently merged";
    }
    UserStore::ClearWorkerView();
}
