#pragma once

// ============================================================================
// Session-domain online tracking with process-wide device admission.
// Protocol caches remain private to the domain; the bounded control coordinator
// owns device admission across all Workers and domains. Preallocated return
// notices release quotas without blocking. Reporting reads domain-local leases.
// ============================================================================

#include "common/online_device.hpp"
#include "common/allocator.hpp"
#include "common/asio_types.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>


class GroupCoordinator;

class UserOnlineSessionGuard;

class UserOnlineTracker {
public:
    UserOnlineTracker();
    ~UserOnlineTracker();

    // UserOnlineSessionGuard 借用本对象地址：禁止拷贝，且不声明移动。
    UserOnlineTracker(const UserOnlineTracker&) = delete;
    UserOnlineTracker& operator=(const UserOnlineTracker&) = delete;
    // The only device-admission implementation; `coordinator` owns the
    // process-wide quota. Anonymous sessions (user_id <= 0) are admitted
    // without a reservation.
    [[nodiscard]] net::awaitable<std::optional<UserOnlineSessionGuard>> TryConnectSession(
        GroupCoordinator& coordinator,
        std::string_view tag,
        int64_t user_id,
        std::string_view client_ip,
        uint32_t device_limit);
    // Forwards with the current execution domain's coordinator; registered
    // users require one.
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
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class UserOnlineSessionGuard {
public:
    UserOnlineSessionGuard() noexcept = default;

    UserOnlineSessionGuard(std::string_view tag,
                           uint64_t user_id,
                           std::string_view client_ip)
        : tag_(tag)
        , user_id_(user_id)
        , client_ip_(client_ip) {}

    ~UserOnlineSessionGuard() noexcept {
        Reset();
    }

    UserOnlineSessionGuard(const UserOnlineSessionGuard&) = delete;
    UserOnlineSessionGuard& operator=(const UserOnlineSessionGuard&) = delete;

    UserOnlineSessionGuard(UserOnlineSessionGuard&& other) noexcept
        : tracker_(std::exchange(other.tracker_, nullptr))
        , tag_(std::move(other.tag_))
        , user_id_(std::exchange(other.user_id_, 0))
        , client_ip_(std::move(other.client_ip_))
        , quota_reservation_(std::move(other.quota_reservation_)) {}

    UserOnlineSessionGuard& operator=(UserOnlineSessionGuard&& other) noexcept {
        if (this == &other) {
            return *this;
        }
        Reset();
        tracker_ = std::exchange(other.tracker_, nullptr);
        tag_ = std::move(other.tag_);
        user_id_ = std::exchange(other.user_id_, 0);
        client_ip_ = std::move(other.client_ip_);
        quota_reservation_ = std::move(other.quota_reservation_);
        return *this;
    }

private:
    friend class UserOnlineTracker;
    void Arm(UserOnlineTracker& tracker) noexcept { tracker_ = &tracker; }
    void Reset() noexcept {
        if (tracker_ && user_id_ != 0) {
            auto* tracker = std::exchange(tracker_, nullptr);
            tracker->OnUserDisconnected(tag_, std::exchange(user_id_, 0), client_ip_);
        } else {
            tracker_ = nullptr;
            user_id_ = 0;
        }
        quota_reservation_.reset();
    }

    UserOnlineTracker* tracker_ = nullptr;
    memory::ThreadLocalString tag_;
    uint64_t user_id_ = 0;
    memory::ThreadLocalString client_ip_;
    std::shared_ptr<void> quota_reservation_;
};

