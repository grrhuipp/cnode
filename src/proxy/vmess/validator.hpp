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
#include "acppnode/runtime/channel.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
struct OnlineDevice;

namespace vmess {

// ============================================================================
// TimedUserValidator — 用户验证器
//
// 线程模型：
//   - 认证用户表为进程级单份 RCU 快照，认证路径只做 atomic load
//   - 面板/静态更新在冷路径构建新快照后无锁发布
//   - 在线追踪由独立服务持有
// ============================================================================
class TimedUserValidator {
public:
    explicit TimedUserValidator(net::any_io_executor executor);
    ~TimedUserValidator();

    TimedUserValidator(const TimedUserValidator&) = delete;
    TimedUserValidator& operator=(const TimedUserValidator&) = delete;
    TimedUserValidator(TimedUserValidator&&) noexcept;
    TimedUserValidator& operator=(TimedUserValidator&&) noexcept;

    size_t Size() const;
    size_t SizeForTag(std::string_view tag) const;

    // 通过 AuthID 查找用户，限定 tag（优化：O(N_tag) 而非 O(N_total)）
    std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential>
    FindByAuthIDForTag(std::string_view tag,
                       const uint8_t* auth_id,
                       int64_t& out_timestamp) const;

    // Records AEAD request body key/IV for replay protection.
    // Returns false if the same user/key/IV tuple is still inside the replay window.
    [[nodiscard]] net::awaitable<bool> RegisterSessionIfNew(
        std::array<uint8_t, 16> user,
        std::array<uint8_t, 16> body_key,
        std::array<uint8_t, 16> body_iv);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace vmess
}  // namespace acpp
