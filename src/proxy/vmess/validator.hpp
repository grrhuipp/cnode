#pragma once

// ============================================================================
// validator.hpp — VMess TimedUserValidator
//
// 职责（协议特有）：
//   - 全局 RCU 账户快照
//   - 热点账户缓存
//
// 通用能力：
//   - 在线用户追踪
// ============================================================================

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/sharded_user_stats.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

namespace vmess {

// ============================================================================
// TimedUserValidator — 用户验证器
//
// 线程模型：
//   - 认证用户表为进程级唯一只读快照；热路径仅借 Worker 独立 lease
//   - 面板/静态更新在有界冷入口安装 Worker view 后发布
//   - 在线追踪与热点凭据指针缓存均为 Worker 私有状态
// ============================================================================
class TimedUserValidator : public UserOnlineTracker {
public:
    TimedUserValidator();
    ~TimedUserValidator();

    TimedUserValidator(const TimedUserValidator&) = delete;
    TimedUserValidator& operator=(const TimedUserValidator&) = delete;
    TimedUserValidator(TimedUserValidator&&) noexcept;
    TimedUserValidator& operator=(TimedUserValidator&&) noexcept;

    // 通过 AuthID 查找用户，限定 tag（优化：O(N_tag) 而非 O(N_total)）
    std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential>
    FindByAuthIDForTag(std::string_view tag,
                       const uint8_t* auth_id,
                       int64_t& out_timestamp) const;

    // Records AEAD request body key/IV for replay protection.
    // Returns false if the same user/key/IV tuple is still inside the replay window.
    [[nodiscard]] bool RegisterSessionIfNew(
        const proxyman::inbound::UserStore::VmessCredential& user,
        const std::array<uint8_t, 16>& body_key,
        const std::array<uint8_t, 16>& body_iv) const;


private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace vmess
}  // namespace acpp
