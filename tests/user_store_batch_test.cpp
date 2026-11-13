#include <gtest/gtest.h>

#include "allocation_hook.hpp"
#include "app/proxyman/user_store.hpp"
#include <array>
#include <new>

namespace {
thread_local std::ptrdiff_t fail_after = -1;
using namespace ::app;

template <typename Users>
concept BorrowableUserUpdate = requires(Users&& users) {
    UserStore::UserUpdate{"borrowed", std::forward<Users>(users)};
};
static_assert(BorrowableUserUpdate<UserSet&>);
static_assert(BorrowableUserUpdate<const UserSet&>);
static_assert(!BorrowableUserUpdate<UserSet>);
static_assert(!BorrowableUserUpdate<const UserSet>);

void Commit(UserStore::PublishedSnapshot snapshot) {
    auto view = UserStore::PrepareWorkerView(snapshot);
    UserStore::CommitSnapshot(std::move(snapshot));
    UserStore::InstallWorkerView(std::move(view));
}

void FailAfterCount(std::size_t) {
    if (fail_after == 0) throw std::bad_alloc();
    if (fail_after > 0) --fail_after;
}

class UserStoreBatch : public ::testing::Test {
protected:
    void SetUp() override { previous_ = UserStore::CaptureSnapshot(); }
    void TearDown() override {
        fail_after = -1;
        UserStore::ClearWorkerView();
        UserStore::CommitSnapshot(std::move(previous_));
    }
private:
    UserStore::PublishedSnapshot previous_;
};
}  // namespace

constinit allocation_hook::Hooks allocation_hook::hooks{.before_new = FailAfterCount};

namespace {
TEST_F(UserStoreBatch, AllocationFailureLeavesWholeBatchAndWorkerViewUnchanged) {
    const UserSet first_old = PreparedVmessUsers{PreparedVmessUser{
        .profile = {.user_id = 101, .email = {}}}};
    const UserSet second_old = PreparedTrojanUsers{PreparedTrojanUser{
        .password_hash = "old-second",
        .profile = {.user_id = 102, .email = {}}}};
    const UserSet unrelated = PreparedVmessUsers{PreparedVmessUser{
        .profile = {.user_id = 103, .email = {}}}};
    const std::array initial{
        UserStore::UserUpdate{"first", first_old}, UserStore::UserUpdate{"second", second_old},
        UserStore::UserUpdate{"unrelated", unrelated}};
    Commit(UserStore::PrepareUsers(initial));
    const auto old_snapshot = UserStore::CaptureSnapshot();
    const auto first_view = UserStore::VmessUsers("first").users;
    const auto second_view = UserStore::FindTrojanUser("second", "old-second");
    ASSERT_TRUE(first_view);
    ASSERT_TRUE(second_view);
    const UserSet first_new = PreparedVmessUsers{
        PreparedVmessUser{.uuid_bytes = {1}, .profile = {.user_id = 201, .email = {}}},
        PreparedVmessUser{.uuid_bytes = {2}, .profile = {.user_id = 202, .email = {}}}};
    const UserSet second_new = PreparedTrojanUsers{PreparedTrojanUser{
        .password_hash = "new-second", .profile = {.user_id = 203, .email = {}}}};
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
        } catch (const std::bad_alloc&) {
            ++failures;
        }
        fail_after = -1;
        if (completed) break;
        SCOPED_TRACE(limit);
        EXPECT_EQ(UserStore::CaptureSnapshot(), old_snapshot);
        EXPECT_EQ(UserStore::VmessUsers("first").users, first_view);
        EXPECT_EQ(UserStore::FindTrojanUser("second", "old-second"), second_view);
        EXPECT_FALSE(UserStore::FindTrojanUser("second", "new-second"));
        EXPECT_FALSE(UserStore::FindVlessUser("third", {}));
    }
    ASSERT_TRUE(completed);
    EXPECT_GT(failures, 0);
    EXPECT_EQ(UserStore::VmessUsers("first").size(), 2);
    EXPECT_TRUE(UserStore::FindTrojanUser("second", "new-second"));
    EXPECT_FALSE(UserStore::FindTrojanUser("second", "old-second"));
    EXPECT_TRUE(UserStore::FindVlessUser("third", {}));
    const auto untouched = UserStore::VmessUsers("unrelated");
    ASSERT_EQ(untouched.size(), 1);
    EXPECT_EQ(untouched[0].profile.user_id, 103);
    ASSERT_EQ(first_view->size(), 1);
    EXPECT_EQ((*first_view)[0].profile.user_id, 101);
    EXPECT_EQ(second_view->profile.user_id, 102);
}

TEST_F(UserStoreBatch, WorkerRetirementPreservesAuthenticatedUsersUntilLastReference) {
    const UserSet users = PreparedTrojanUsers{PreparedTrojanUser{
        .password_hash = "credential", .profile = {.user_id = 203, .email = {}}}};
    Commit(UserStore::PrepareUsers("leases", users));
    const auto snapshot = UserStore::CaptureSnapshot();
    auto worker_one = UserStore::PrepareWorkerView(snapshot);
    auto worker_two = UserStore::PrepareWorkerView(snapshot);
    UserStore::InstallWorkerView(std::move(worker_one));
    const auto first_user = UserStore::FindTrojanUser("leases", "credential");
    UserStore::InstallWorkerView(std::move(worker_two));
    auto second_user = UserStore::FindTrojanUser("leases", "credential");
    ASSERT_TRUE(first_user);
    ASSERT_TRUE(second_user);
    const std::weak_ptr<const UserStore::TrojanCredential> retired = second_user;
    UserStore::ClearWorkerView();
    EXPECT_FALSE(UserStore::FindTrojanUser("leases", "credential"));
    EXPECT_EQ(first_user->profile.user_id, 203);
    EXPECT_EQ(second_user->profile.user_id, 203);
    second_user.reset();
    EXPECT_TRUE(retired.expired());
    EXPECT_EQ(first_user->profile.user_id, 203);
}

TEST_F(UserStoreBatch, CredentialLookupDoesNotAllocate) {
    const UserSet users = PreparedTrojanUsers{PreparedTrojanUser{
        .password_hash = "credential", .profile = {.user_id = 203, .email = {}}}};
    Commit(UserStore::PrepareUsers("lookup", users));
    fail_after = 0;
    const auto user = UserStore::FindTrojanUser("lookup", "credential");
    fail_after = -1;
    ASSERT_TRUE(user);
    EXPECT_EQ(user->profile.user_id, 203);
}

TEST_F(UserStoreBatch, ShadowsocksReplacementAndClearPreserveRetiredCredentials) {
    PreparedShadowsocksUser user;
    user.profile.user_id = 7;
    user.psk_hash.fill(0x11);
    Commit(UserStore::PrepareUsers("ss-hash", UserSet{PreparedShadowsocksUsers{user}}));
    const auto old = UserStore::ShadowsocksUsers("ss-hash");
    ASSERT_EQ(old.size(), 1);
    user.psk_hash.fill(0x22);
    Commit(UserStore::PrepareUsers("ss-hash", UserSet{PreparedShadowsocksUsers{user}}));
    EXPECT_EQ(old[0].psk_hash[0], 0x11);
    const auto current = UserStore::ShadowsocksUsers("ss-hash");
    ASSERT_EQ(current.size(), 1);
    EXPECT_EQ(current[0].psk_hash[0], 0x22);
    Commit(UserStore::PrepareClearUsers(UserProtocol::Shadowsocks, "ss-hash"));
    EXPECT_TRUE(UserStore::ShadowsocksUsers("ss-hash").empty());
    EXPECT_EQ(old[0].psk_hash[0], 0x11);
}
}  // namespace
