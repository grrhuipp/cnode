#pragma once

// ============================================================================
// sharded_user_stats.hpp — Worker 私有在线用户追踪
//
// 从 TimedUserValidator / Validator 中提取的公共逻辑。
// 协议特有内容（用户存储、认证、HotCache、IP 封禁）各自保留在协议 manager 中。
//
// 在线状态归属 Worker 线程：连接建立、断开和面板在线采集都通过
// 对应 Worker executor 执行，因此无需锁、原子或跨线程协调。
// ============================================================================

#include "acppnode/common/online_device.hpp"
#include "acppnode/common/allocator.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace acpp {

class UserOnlineSessionGuard;

class UserOnlineTracker {
public:
    using OnlineDevice = ::acpp::OnlineDevice;

    UserOnlineTracker();
    ~UserOnlineTracker();

    UserOnlineTracker(const UserOnlineTracker&) = delete;
    UserOnlineTracker& operator=(const UserOnlineTracker&) = delete;
    UserOnlineTracker(UserOnlineTracker&&) noexcept;
    UserOnlineTracker& operator=(UserOnlineTracker&&) noexcept;
    [[nodiscard]] std::optional<UserOnlineSessionGuard> TryConnectSession(
        std::string_view tag,
        int64_t user_id,
        std::string_view client_ip,
        uint32_t device_limit);

    void OnUserConnected(std::string_view tag,
                         uint64_t user_id,
                         std::string_view client_ip);

    void OnUserDisconnected(std::string_view tag,
                            uint64_t user_id,
                            std::string_view client_ip);

    [[nodiscard]] bool CanAcceptDevice(std::string_view tag,
                                       uint64_t user_id,
                                       std::string_view client_ip,
                                       uint32_t device_limit) const;

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

    UserOnlineSessionGuard(UserOnlineTracker& tracker,
                           std::string_view tag,
                           uint64_t user_id,
                           std::string_view client_ip)
        : tracker_(&tracker)
        , tag_(tag)
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
        , client_ip_(std::move(other.client_ip_)) {}

    UserOnlineSessionGuard& operator=(UserOnlineSessionGuard&& other) noexcept {
        if (this == &other) {
            return *this;
        }
        Reset();
        tracker_ = std::exchange(other.tracker_, nullptr);
        tag_ = std::move(other.tag_);
        user_id_ = std::exchange(other.user_id_, 0);
        client_ip_ = std::move(other.client_ip_);
        return *this;
    }

private:
    void Reset() noexcept {
        if (!tracker_ || user_id_ == 0) {
            return;
        }
        auto* tracker = std::exchange(tracker_, nullptr);
        const auto user_id = std::exchange(user_id_, 0);
        try {
            tracker->OnUserDisconnected(tag_, user_id, client_ip_);
        } catch (...) {
        }
    }

    UserOnlineTracker* tracker_ = nullptr;
    memory::ThreadLocalString tag_;
    uint64_t user_id_ = 0;
    memory::ThreadLocalString client_ip_;
};

}  // namespace acpp
