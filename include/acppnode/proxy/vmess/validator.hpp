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
#include "acppnode/proxy/vmess/account.hpp"

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
//   - 在线追踪为 Worker 私有状态
// ============================================================================
class TimedUserValidator {
public:
    TimedUserValidator();
    ~TimedUserValidator();

    TimedUserValidator(const TimedUserValidator&) = delete;
    TimedUserValidator& operator=(const TimedUserValidator&) = delete;
    TimedUserValidator(TimedUserValidator&&) noexcept;
    TimedUserValidator& operator=(TimedUserValidator&&) noexcept;

    // ── 用户存储 ─────────────────────────────────────────────────────────────

    void ApplyUsers(std::string_view tag, const std::vector<MemoryAccount>& users);
    void AddUsers(std::string_view tag, const std::vector<MemoryAccount>& users);
    void RemoveUsers(std::string_view tag, const std::vector<MemoryAccount>& users);
    void ClearUsers(std::string_view tag);
    void Clear();

    size_t Size() const;
    size_t SizeForTag(std::string_view tag) const;

    // 通过 AuthID 查找用户，限定 tag（优化：O(N_tag) 而非 O(N_total)）
    std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential>
    FindByAuthIDForTag(std::string_view tag,
                       const uint8_t* auth_id,
                       int64_t& out_timestamp) const;

    // ── 在线追踪 ─────────────────────────────────────────────────────────────

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

    [[nodiscard]] std::vector<OnlineDevice>
    GetOnlineDevices(std::string_view tag) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace vmess
}  // namespace acpp
