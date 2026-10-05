#pragma once

#include "acppnode/app/rate_limiter_fwd.hpp"
#include "acppnode/common/asio_types.hpp"

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
struct BuildRequest;
struct DatagramHandlerBuildResult;
// ============================================================================
// Manager - runtime inbound handler manager
//
// 对齐 xray-core features/inbound.Manager 的职责边界。可变状态只在 owner
// strand 访问；其他执行域只能经有界入口投递。
// ============================================================================
class Manager final {
public:
    Manager(net::any_io_executor owner_executor,
            net::any_io_executor shared_executor);
    ~Manager() noexcept;

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    using HandlerPtr = std::shared_ptr<Handler>;

    [[nodiscard]] HandlerPtr GetHandler(std::string_view tag) noexcept;
    [[nodiscard]] std::shared_ptr<const Handler>
    GetHandler(std::string_view tag) const noexcept;

    [[nodiscard]] std::unique_ptr<::acpp::Inbound> NewHandler(
        ::acpp::ConnectionLimiterPtr limiter,
        const BuildRequest& req);

    [[nodiscard]] DatagramHandlerBuildResult NewDatagramHandler(
        ::acpp::ConnectionLimiterPtr limiter,
        const BuildRequest& req);

    // ReplaceHandler 在 owner strand 上替换同 tag handler。调用方持有的
    // shared_ptr 让在途物理连接及其任务组持有的逻辑子任务继续使用原 handler。
    [[nodiscard]] HandlerPtr ReplaceHandler(std::unique_ptr<Handler> handler);

    // RemoveHandler 只撤销 manager 所有权；在途请求按 shared_ptr 自然收尾。
    void RemoveHandler(std::string_view tag);

    [[nodiscard]] net::awaitable<std::vector<::acpp::OnlineDevice>>
    GetOnlineDevices(std::string tag);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::proxyman::inbound
