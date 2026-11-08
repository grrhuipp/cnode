#pragma once

#include "app/rate_limiter_fwd.hpp"
#include "common/allocator.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

class Inbound;
struct OnlineDevice;
struct StatsShard;

namespace proxyman::inbound {

class Handler;
struct BuildRequest;
struct DatagramHandlerBuildResult;
class ProtocolRuntime;
// ============================================================================
// HandlerRegistry - per-Worker inbound handler registry
//
// 对齐 xray-core features/inbound.Manager 的职责边界。它只在 Worker 线程访问，
// 不加锁；跨线程控制面操作只能经所属 Worker 的有界 mailbox 投递。
// ============================================================================
class HandlerRegistry final : public memory::ThreadAllocated {
public:
    explicit HandlerRegistry(StatsShard& stats);
    ~HandlerRegistry() noexcept;

    HandlerRegistry(const HandlerRegistry&) = delete;
    HandlerRegistry& operator=(const HandlerRegistry&) = delete;

    using HandlerPtr = std::shared_ptr<Handler>;

    [[nodiscard]] HandlerPtr GetHandler(std::string_view tag) noexcept;
    [[nodiscard]] std::shared_ptr<const Handler>
    GetHandler(std::string_view tag) const noexcept;

    [[nodiscard]] std::unique_ptr<::Inbound> NewHandler(
        ::ConnectionLimiter* limiter,
        const BuildRequest& req);

    [[nodiscard]] DatagramHandlerBuildResult NewDatagramHandler(
        ::ConnectionLimiter* limiter,
        const BuildRequest& req);
    [[nodiscard]] ProtocolRuntime* GetOrCreateRuntime(
        std::string_view protocol);

    // ReplaceHandler 在所属 Worker 上替换同 tag handler。调用方持有的
    // shared_ptr 让在途物理连接及其任务组持有的逻辑子任务继续使用原 handler。
    [[nodiscard]] HandlerPtr ReplaceHandler(std::unique_ptr<Handler> handler);

    // RemoveHandler 只撤销 registry 所有权；在途请求按 shared_ptr 自然收尾。
    void RemoveHandler(std::string_view tag);

    [[nodiscard]] std::vector<::OnlineDevice>
    GetOnlineDevices(std::string_view protocol, std::string_view tag) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace proxyman::inbound
