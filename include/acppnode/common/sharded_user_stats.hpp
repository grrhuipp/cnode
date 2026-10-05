#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/runtime/channel.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace acpp {

// Cross-session device admission belongs to this service owner, never to a
// protocol validator or an execution thread. A successful check reserves the
// device in the same synchronous service operation.
class UserOnlineTracker {
public:
    explicit UserOnlineTracker(net::any_io_executor executor, size_t capacity = 4096);
    ~UserOnlineTracker();
    UserOnlineTracker(const UserOnlineTracker&) = delete;
    UserOnlineTracker& operator=(const UserOnlineTracker&) = delete;

    struct Permit {
        ServiceChannel::Reservation reservation;
        std::string tag;
        uint64_t user_id = 0;
        std::string client_ip;
    };
    net::awaitable<std::optional<Permit>> TryAcquire(std::string tag, uint64_t user_id,
                                    std::string client_ip, uint32_t device_limit);
    net::awaitable<void> Release(Permit permit);
    net::awaitable<size_t> OnlineDeviceCount(std::string tag, uint64_t user_id);
    net::awaitable<std::vector<OnlineDevice>> GetOnlineDevices(std::string tag);
    [[nodiscard]] net::any_io_executor Executor() const { return channel_.Executor(); }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    ServiceChannel channel_;
};

// A session owns this reservation and explicitly awaits Release after all its
// child operations have joined. The destructor never schedules work.
class UserOnlineLease {
public:
    explicit UserOnlineLease(UserOnlineTracker& owner) noexcept : owner_(owner) {}
    UserOnlineLease(const UserOnlineLease&) = delete;
    UserOnlineLease& operator=(const UserOnlineLease&) = delete;
    net::awaitable<bool> Acquire(std::string tag, uint64_t user_id,
                                 std::string ip, uint32_t limit);
    net::awaitable<void> Release();
private:
    UserOnlineTracker& owner_;
    std::optional<UserOnlineTracker::Permit> permit_;
};

}  // namespace acpp
