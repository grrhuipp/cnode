#pragma once

// ============================================================================
// Session-domain online tracking with process-wide device admission.
// Protocol caches remain private to the domain; the bounded control coordinator
// owns device admission across all Workers and domains. Preallocated return
// notices release quotas without blocking. Reporting reads domain-local leases.
// ============================================================================

#include "common/asio_types.hpp"
#include "common/string_hash.hpp"

#include <compare>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <unordered_map>

namespace common {

struct OnlineDevice {
    int64_t user_id = 0;
    std::string ip;

    OnlineDevice() = default;
    OnlineDevice(int64_t user_id_value, std::string ip_value)
        : user_id(user_id_value), ip(std::move(ip_value)) {}

    friend auto operator<=>(const OnlineDevice&, const OnlineDevice&) = default;
};

class UserOnlineSessionGuard;

}  // namespace common
namespace app {

class GroupCoordinator;

}  // namespace app

namespace common {

class UserOnlineTracker {
public:
    explicit UserOnlineTracker(app::GroupCoordinator& coordinator) noexcept : coordinator_(coordinator) {}
    ~UserOnlineTracker() = default;
    // UserOnlineSessionGuard 借用本对象地址：禁止拷贝，且不声明移动。
    UserOnlineTracker(const UserOnlineTracker&) = delete;
    UserOnlineTracker& operator=(const UserOnlineTracker&) = delete;
    // Process-wide device quota belongs to the explicitly supplied coordinator;
    // anonymous sessions (user_id <= 0) are admitted without a reservation.
    [[nodiscard]] net::awaitable<std::optional<UserOnlineSessionGuard>> TryConnectSession(
        std::string_view tag,
        int64_t user_id,
        std::string_view client_ip,
        uint32_t device_limit);

    // 只做查找与摘除，不分配。
    void OnUserDisconnected(std::string_view tag,
                            uint64_t user_id,
                            std::string_view client_ip) noexcept;

    [[nodiscard]] size_t OnlineDeviceCount(std::string_view tag,
                                           uint64_t user_id) const;

    std::vector<OnlineDevice> GetOnlineDevices(std::string_view tag) const;
private:
    friend class UserOnlineSessionGuard;
    struct DeviceReservation;
    using DeviceIpMap =
        std::unordered_map<std::string,
                           uint32_t,
                           TransparentStringHash,
                           TransparentStringEq>;
    using UserDeviceMap = std::unordered_map<uint64_t, DeviceIpMap>;
    using TagDeviceMap =
        std::unordered_map<std::string,
                           UserDeviceMap,
                           TransparentStringHash,
                           TransparentStringEq>;

    app::GroupCoordinator& coordinator_;
    TagDeviceMap devices_;
};

class UserOnlineSessionGuard {
public:
    UserOnlineSessionGuard() noexcept = default;

    ~UserOnlineSessionGuard() noexcept {
        Reset();
    }

    UserOnlineSessionGuard(const UserOnlineSessionGuard&) = delete;
    UserOnlineSessionGuard& operator=(const UserOnlineSessionGuard&) = delete;

    UserOnlineSessionGuard(UserOnlineSessionGuard&& other) noexcept
        : tracker_(std::exchange(other.tracker_, nullptr))
        , quota_reservation_(std::move(other.quota_reservation_)) {}

    UserOnlineSessionGuard& operator=(UserOnlineSessionGuard&& other) noexcept {
        if (this == &other) {
            return *this;
        }
        Reset();
        tracker_ = std::exchange(other.tracker_, nullptr);
        quota_reservation_ = std::move(other.quota_reservation_);
        return *this;
    }

private:
    friend class UserOnlineTracker;
    void Arm(UserOnlineTracker& tracker) noexcept { tracker_ = &tracker; }
    void Reset() noexcept;

    UserOnlineTracker* tracker_ = nullptr;
    std::shared_ptr<UserOnlineTracker::DeviceReservation> quota_reservation_;
};

}  // namespace common

