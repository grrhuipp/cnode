#pragma once

#include "acppnode/proxy/shadowsocks/user_info.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
struct OnlineDevice;
}  // namespace acpp

namespace acpp::ss {

// ============================================================================
// Validator - Shadowsocks Worker 本地用户表
//
// 对齐 xray-core proxy/shadowsocks/validator.go：
//   - 按 tag 维护用户快照
//   - 提供按 tag / user_id 查找
//   - 承载 Worker 本地在线设备追踪
// ============================================================================
class Validator {
public:
    Validator();
    ~Validator();

    Validator(const Validator&) = delete;
    Validator& operator=(const Validator&) = delete;
    Validator(Validator&&) noexcept;
    Validator& operator=(Validator&&) noexcept;

    void UpdateUsersForTag(const std::string& tag,
                           const std::vector<SsUserInfo>& users);
    void AddUsersForTag(const std::string& tag, const std::vector<SsUserInfo>& users);
    void RemoveUsersForTag(const std::string& tag, const std::vector<SsUserInfo>& users);

    [[nodiscard]] std::span<const SsUserInfo> FindUsersForTag(std::string_view tag) const;
    [[nodiscard]] std::vector<SsUserInfo> GetUsersForTag(std::string_view tag) const;

    [[nodiscard]] std::optional<SsUserInfo> FindUserById(std::string_view tag,
                                                         int64_t user_id) const;

    [[nodiscard]] size_t Size() const;

    void OnUserConnected(std::string_view tag,
                         int64_t user_id,
                         std::string_view client_ip);

    void OnUserDisconnected(std::string_view tag,
                            uint64_t user_id,
                            std::string_view client_ip);

    [[nodiscard]] bool CanAcceptDevice(std::string_view tag,
                                       int64_t user_id,
                                       std::string_view client_ip,
                                       uint32_t device_limit) const;

    [[nodiscard]] size_t OnlineDeviceCount(std::string_view tag,
                                           int64_t user_id) const;

    [[nodiscard]] std::vector<OnlineDevice>
    GetOnlineDevices(std::string_view tag) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::ss
