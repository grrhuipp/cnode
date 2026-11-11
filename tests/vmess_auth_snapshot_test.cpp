#include <gtest/gtest.h>
#include "app/proxyman/inbound/user_store.hpp"
#include "proxy/vmess/encoding/body.hpp"
#include "proxy/vmess/vmess_crypto.hpp"
#include <chrono>

namespace {
using namespace ::proxyman::inbound;
void Commit(UserStore::PublishedSnapshot snapshot) {
    auto view = UserStore::PrepareWorkerView(snapshot);
    UserStore::CommitSnapshot(std::move(snapshot));
    UserStore::InstallWorkerView(std::move(view));
}
class VmessSnapshot : public testing::Test {
protected:
    static constexpr auto tag = "snapshot-lifetime";
    static constexpr auto other_tag = "snapshot-other-tag";
    PreparedVmessUser user;
    std::array<uint8_t, 16> auth;
    int64_t now = 0, timestamp = 0;
    void SetUp() override {
        user.auth_key.fill(0x19);
        user.profile.user_id = 1;
        Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{user}}));
        now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        ::vmess::GenerateAuthID(::vmess::ExpandAuthIDEncryptKey(user.auth_key), now, auth.data());
    }
    void TearDown() override {
        Commit(UserStore::PrepareClearUsers(UserProtocol::Vmess, tag));
        Commit(UserStore::PrepareClearUsers(UserProtocol::Vmess, other_tag));
        UserStore::ClearWorkerView();
    }
};

TEST_F(VmessSnapshot, ReplacingUsersReleasesIdleCredentialLeaseAndAuthenticatesNewView) {
    auto credential = ::vmess::FindByAuthIDForTag(tag, auth.data(), &timestamp);
    ASSERT_TRUE(credential);
    EXPECT_EQ(timestamp, now);
    std::weak_ptr<const UserStore::VmessCredential> old = credential;
    credential.reset();
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{user}}));
    EXPECT_TRUE(old.expired());
    EXPECT_TRUE(::vmess::FindByAuthIDForTag(tag, auth.data(), &timestamp));
}

TEST_F(VmessSnapshot, RemovingUsersReleasesIdleLeaseAndRejectsCachedAuthentication) {
    auto credential = ::vmess::FindByAuthIDForTag(tag, auth.data(), &timestamp);
    ASSERT_TRUE(credential);
    std::weak_ptr<const UserStore::VmessCredential> old = credential;
    credential.reset();
    Commit(UserStore::PrepareClearUsers(UserProtocol::Vmess, tag));
    EXPECT_TRUE(old.expired());
    EXPECT_FALSE(::vmess::FindByAuthIDForTag(tag, auth.data(), &timestamp));
}

TEST_F(VmessSnapshot, PreparingReplacementDoesNotChangeInstalledView) {
    Commit(UserStore::PrepareClearUsers(UserProtocol::Vmess, tag));
    auto prepared = UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{user}});
    EXPECT_FALSE(::vmess::FindByAuthIDForTag(tag, auth.data(), &timestamp));
    Commit(std::move(prepared));
    EXPECT_TRUE(::vmess::FindByAuthIDForTag(tag, auth.data(), &timestamp));
}

TEST_F(VmessSnapshot, AlternatingHotCacheLookupsRemainIsolatedByInboundTag) {
    auto other = user;
    other.auth_key.fill(0x27);
    other.profile.user_id = 2;
    // UserUpdate borrows its UserSet; keep both sets alive through preparation.
    const UserSet first_users{PreparedVmessUsers{user}};
    const UserSet second_users{PreparedVmessUsers{other}};
    const std::array updates{
        UserStore::UserUpdate{tag, first_users},
        UserStore::UserUpdate{other_tag, second_users}};
    Commit(UserStore::PrepareUsers(updates));
    std::array<uint8_t, 16> other_auth;
    ::vmess::GenerateAuthID(::vmess::ExpandAuthIDEncryptKey(other.auth_key), now, other_auth.data());
    for (int round = 0; round < 2; ++round) {
        const auto first = ::vmess::FindByAuthIDForTag(tag, auth.data(), &timestamp);
        const auto second = ::vmess::FindByAuthIDForTag(other_tag, other_auth.data(), &timestamp);
        ASSERT_TRUE(first);
        ASSERT_TRUE(second);
        EXPECT_EQ(first->profile.user_id, 1);
        EXPECT_EQ(second->profile.user_id, 2);
        EXPECT_FALSE(::vmess::FindByAuthIDForTag(tag, other_auth.data(), &timestamp));
        EXPECT_FALSE(::vmess::FindByAuthIDForTag(other_tag, auth.data(), &timestamp));
    }
}

TEST_F(VmessSnapshot, WorkerShutdownPreservesSessionLeaseButRejectsNewAuthentication) {
    const auto credential = ::vmess::FindByAuthIDForTag(tag, auth.data(), &timestamp);
    ASSERT_TRUE(credential);
    UserStore::ClearWorkerView();
    EXPECT_EQ(credential->profile.user_id, 1);
    EXPECT_FALSE(::vmess::FindByAuthIDForTag(tag, auth.data(), &timestamp));
}
}  // namespace
