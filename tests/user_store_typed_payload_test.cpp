#include <gtest/gtest.h>

#include "app/user_store.hpp"
#include <stdexcept>

namespace {
using namespace ::app;

void Commit(UserStore::PublishedSnapshot snapshot) {
    auto view = UserStore::PrepareWorkerView(snapshot);
    UserStore::CommitSnapshot(std::move(snapshot));
    UserStore::InstallWorkerView(std::move(view));
}

PreparedVmessUser Vmess(int64_t id) {
    PreparedVmessUser user;
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

class UserStoreTypedPayload : public ::testing::Test {
protected:
    void SetUp() override { previous_ = UserStore::CaptureSnapshot(); }
    void TearDown() override {
        UserStore::ClearWorkerView();
        UserStore::CommitSnapshot(std::move(previous_));
    }
private:
    UserStore::PublishedSnapshot previous_;
};

TEST_F(UserStoreTypedPayload, ReplacingOneProtocolPreservesOtherProtocolAndOldView) {
    constexpr std::string_view tag = "shared-tag";
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{Vmess(1)}}));
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedTrojanUsers{Trojan("hash-1", 2)}}));
    ASSERT_EQ(UserStore::VmessUsers(tag).size(), 1);
    ASSERT_TRUE(UserStore::FindTrojanUser(tag, "hash-1"));
    const auto old = UserStore::VmessUsers(tag);
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{Vmess(3)}}));
    const auto current = UserStore::VmessUsers(tag);
    ASSERT_EQ(current.size(), 1);
    EXPECT_EQ(current[0].profile.user_id, 3);
    ASSERT_EQ(old.size(), 1);
    EXPECT_EQ(old[0].profile.user_id, 1);
    const auto trojan = UserStore::FindTrojanUser(tag, "hash-1");
    ASSERT_TRUE(trojan);
    EXPECT_EQ(trojan->profile.user_id, 2);
}

TEST_F(UserStoreTypedPayload, EmptyReplacementClearsOnlyItsProtocol) {
    constexpr std::string_view tag = "empty-tag";
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{Vmess(1)}}));
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedTrojanUsers{Trojan("hash-1", 2)}}));
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedTrojanUsers{}}));
    EXPECT_FALSE(UserStore::FindTrojanUser(tag, "hash-1"));
    EXPECT_EQ(UserStore::VmessUsers(tag).size(), 1);
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{}}));
    EXPECT_TRUE(UserStore::VmessUsers(tag).empty());
}

TEST_F(UserStoreTypedPayload, TypedClearPreservesOtherProtocol) {
    constexpr std::string_view tag = "clear-tag";
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{Vmess(1)}}));
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedTrojanUsers{Trojan("hash", 2)}}));
    Commit(UserStore::PrepareClearUsers(UserProtocol::Vmess, tag));
    EXPECT_TRUE(UserStore::VmessUsers(tag).empty());
    const auto other = UserStore::FindTrojanUser(tag, "hash");
    ASSERT_TRUE(other);
    EXPECT_EQ(other->profile.user_id, 2);
}

class AmbiguousUserCredentials : public UserStoreTypedPayload,
                                 public ::testing::WithParamInterface<int> {};
TEST_P(AmbiguousUserCredentials, RejectsBeforePublishingAnyState) {
    constexpr std::string_view tag = "ambiguous-tag";
    Commit(UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{Vmess(1)}}));
    const auto before = UserStore::CaptureSnapshot();
    UserSet users;
    switch (GetParam()) {
    case 0: {
        auto first = Vmess(2);
        auto second = Vmess(3);
        first.uuid_bytes.fill(0x6b);
        second.uuid_bytes.fill(0x6b);
        users = PreparedVmessUsers{first, second};
        break;
    }
    case 1: users = PreparedVlessUsers{PreparedVlessUser{}, PreparedVlessUser{}}; break;
    case 2: users = PreparedTrojanUsers{Trojan("same-hash", 4), Trojan("same-hash", 5)}; break;
    case 3: users = PreparedHysteriaUsers{Hysteria(0x42, 6), Hysteria(0x42, 7)}; break;
    }
    EXPECT_THROW(static_cast<void>(UserStore::PrepareUsers(tag, users)), std::invalid_argument);
    EXPECT_EQ(UserStore::CaptureSnapshot(), before);
    const auto existing = UserStore::VmessUsers(tag);
    ASSERT_EQ(existing.size(), 1);
    EXPECT_EQ(existing[0].profile.user_id, 1);
    EXPECT_FALSE(UserStore::FindHysteriaUser(tag, Hysteria(0x42, 0).credential_hash));
}
INSTANTIATE_TEST_SUITE_P(Authentication, AmbiguousUserCredentials,
    ::testing::Values(0, 1, 2, 3), ([](const ::testing::TestParamInfo<int>& info) {
        constexpr const char* names[]{"Vmess", "Vless", "Trojan", "Hysteria"};
        return names[info.param];
    }));
}  // namespace
