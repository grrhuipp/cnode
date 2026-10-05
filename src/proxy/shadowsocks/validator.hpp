#pragma once

#include "acppnode/app/proxyman/inbound/user_store.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
struct OnlineDevice;
}  // namespace acpp

namespace acpp::ss {

// ============================================================================
// Validator - Shadowsocks user validator
//
// 对齐 xray-core proxy/shadowsocks/validator.go：
//   - 认证用户读取全局 RCU 快照
//   - 提供按 tag / user_id 查找
//   - 在线设备由独立服务管理，不进入认证快照
// ============================================================================
class Validator {
public:
    Validator() = default;
    ~Validator() = default;

    Validator(const Validator&) = delete;
    Validator& operator=(const Validator&) = delete;
    Validator(Validator&&) noexcept = default;
    Validator& operator=(Validator&&) noexcept = default;

    [[nodiscard]] proxyman::inbound::UserStore::ShadowsocksUsersView
    FindUsersForTag(std::string_view tag) const;

    [[nodiscard]] size_t Size() const;
    [[nodiscard]] size_t SizeForTag(std::string_view tag) const;


};

}  // namespace acpp::ss
