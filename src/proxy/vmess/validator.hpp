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

#include "app/proxyman/inbound/user_store.hpp"
#include "common/sharded_user_stats.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>


namespace vmess {

// ============================================================================
// TimedUserValidator — 用户验证器
//
// 线程模型：
//   - Credentials are immutable snapshots leased by the current session domain.
//   - Online leases and hot credential caches stay in that stable domain.
//   - Replay admission runs on the bounded process control coordinator.
// ============================================================================
class TimedUserValidator : public UserOnlineTracker {
public:
    TimedUserValidator();
    ~TimedUserValidator();

    TimedUserValidator(const TimedUserValidator&) = delete;
    TimedUserValidator& operator=(const TimedUserValidator&) = delete;

    // 通过 AuthID 查找用户，限定 tag（优化：O(N_tag) 而非 O(N_total)）
    std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential>
    FindByAuthIDForTag(std::string_view tag,
                       const uint8_t* auth_id,
                       int64_t& out_timestamp) const;

    // Records AEAD request body key/IV for replay protection.
    // Returns false if the same user/key/IV tuple is still inside the replay window.
    [[nodiscard]] net::awaitable<bool> RegisterSessionIfNew(
        const proxyman::inbound::UserStore::VmessCredential& user,
        const std::array<uint8_t, 16>& body_key,
        const std::array<uint8_t, 16>& body_iv) const;
};

}  // namespace vmess
