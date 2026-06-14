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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

class UserOnlineTracker {
public:
    using OnlineDevice = ::acpp::OnlineDevice;

    UserOnlineTracker();
    ~UserOnlineTracker();

    UserOnlineTracker(const UserOnlineTracker&) = delete;
    UserOnlineTracker& operator=(const UserOnlineTracker&) = delete;
    UserOnlineTracker(UserOnlineTracker&&) noexcept;
    UserOnlineTracker& operator=(UserOnlineTracker&&) noexcept;

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

    void ClearTag(std::string_view tag);

    void Clear();

    std::vector<OnlineDevice> GetOnlineDevices(std::string_view tag) const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp
