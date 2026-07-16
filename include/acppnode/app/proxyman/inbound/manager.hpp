#pragma once

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/rate_limiter_fwd.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
class Inbound;
struct OnlineDevice;
struct StatsShard;
}  // namespace acpp

namespace acpp::proxyman::inbound {

class Handler;
struct UdpHandlerBuildResult;
// ============================================================================
// Manager - per-Worker inbound handler manager
//
// 对齐 xray-core features/inbound.Manager 的职责边界。它只在 Worker 线程访问，
// 不加锁；跨线程入口仍由 Worker 的 *Async 方法 post 到 io_context。
// ============================================================================
class Manager final {
public:
    explicit Manager(StatsShard& stats);
    ~Manager() noexcept;

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    using HandlerPtr = std::shared_ptr<Handler>;

    [[nodiscard]] HandlerPtr GetHandler(std::string_view tag) noexcept;
    [[nodiscard]] std::shared_ptr<const Handler>
    GetHandler(std::string_view tag) const noexcept;

    [[nodiscard]] std::unique_ptr<::acpp::Inbound> NewHandler(
        std::string_view protocol,
        ::acpp::ConnectionLimiterPtr limiter,
        const BuildRequest& req);

    [[nodiscard]] UdpHandlerBuildResult NewUdpHandler(
        std::string_view protocol,
        ::acpp::ConnectionLimiterPtr limiter,
        const BuildRequest& req);

    // ReplaceHandler 原子替换同 tag handler。调用方持有的 shared_ptr 让在途
    // 物理连接和 detached 逻辑子流继续使用原 handler。
    [[nodiscard]] HandlerPtr ReplaceHandler(std::unique_ptr<Handler> handler);

    // RemoveHandler 只撤销 manager 所有权；在途请求按 shared_ptr 自然收尾。
    void RemoveHandler(std::string_view tag);

    [[nodiscard]] std::vector<::acpp::OnlineDevice>
    GetOnlineDevices(std::string_view protocol, std::string_view tag) const;

    struct UserMemoryStats {
        size_t vmess_accounts = 0;
        size_t vless_users = 0;
        size_t trojan_users = 0;
        size_t shadowsocks_users = 0;
        size_t anytls_users = 0;
    };

    [[nodiscard]] UserMemoryStats GetUserMemoryStats() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::proxyman::inbound
