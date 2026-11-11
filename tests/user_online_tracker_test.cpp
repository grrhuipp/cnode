#include <gtest/gtest.h>

#include "common/sharded_user_stats.hpp"
#include "transport_coordinator_fixture.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>

namespace {
std::optional<UserOnlineSessionGuard> RunDeviceAdmission(
    net::io_context& worker, net::awaitable<std::optional<UserOnlineSessionGuard>> task) {
    worker.restart();
    auto result = net::co_spawn(worker, std::move(task), net::use_future);
    worker.run();
    return result.get();
}

TEST(UserOnlineTracker, ExplicitCoordinatorSharesDeviceQuotaAndReturnsReservationsAcrossWorkers) {
    net::io_context first, second;
    TransportCoordinatorFixture control(first);
    control.Coordinator().RegisterWorker(second);
    UserOnlineTracker first_users(control.Coordinator()), second_users(control.Coordinator());
    auto first_lease = RunDeviceAdmission(first, first_users.TryConnectSession("tag", 42, "192.0.2.1", 1));
    ASSERT_TRUE(first_lease);
    auto same_device = RunDeviceAdmission(second, second_users.TryConnectSession("tag", 42, "192.0.2.1", 1));
    ASSERT_TRUE(same_device);
    EXPECT_FALSE(RunDeviceAdmission(second, second_users.TryConnectSession("tag", 42, "192.0.2.2", 1)));
    EXPECT_EQ(first_users.OnlineDeviceCount("tag", 42), 1u);
    EXPECT_EQ(second_users.OnlineDeviceCount("tag", 42), 1u);
    first_lease.reset();
    EXPECT_FALSE(RunDeviceAdmission(first, first_users.TryConnectSession("tag", 42, "192.0.2.2", 1)));
    same_device.reset();
    auto new_device = RunDeviceAdmission(second, second_users.TryConnectSession("tag", 42, "192.0.2.2", 1));
    EXPECT_TRUE(new_device);
    EXPECT_EQ(first_users.OnlineDeviceCount("tag", 42), 0u);
    EXPECT_EQ(second_users.GetOnlineDevices("tag"), (std::vector<OnlineDevice>{{42, "192.0.2.2"}}));
}

TEST(UserOnlineTracker, ClosedCoordinatorDoesNotBecomeDeviceLimitRejection) {
    net::io_context worker;
    TransportCoordinatorFixture control(worker);
    UserOnlineTracker users(control.Coordinator());
    control.Coordinator().CloseAdmission();
    try {
        (void)RunDeviceAdmission(worker, users.TryConnectSession("tag", 42, "192.0.2.1", 1));
        ADD_FAILURE() << "closed coordinator admitted a tracked session";
    } catch (const IoSystemError& error) {
        EXPECT_EQ(error.code(), net::error::operation_aborted);
    }
    EXPECT_EQ(users.OnlineDeviceCount("tag", 42), 0u);
}
}  // namespace
