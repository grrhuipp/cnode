#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/relay_types.hpp"
#include "acppnode/app/rate_limiter_fwd.hpp"
#include "acppnode/proxy/inbound_datagram.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/transport/async_stream.hpp"
#include <asio/this_coro.hpp>
#include <exception>

#include <tl/expected.hpp>
#include <memory>
#include <cstdint>

namespace acpp {

class AsyncStream;
struct TimeoutsConfig;
struct StatsShard;

namespace session {
struct Context;
}

namespace proxyman::inbound {
struct ReceiverSettings;
}

namespace routing {
class Dispatcher;
}

// ============================================================================
// Inbound - 入站协议处理器接口（代理层）
//
// 职责：协议解析、认证和 dispatcher handoff，不涉及传输层（TLS/WS 由 proxyman inbound 负责）。
//
// 协议实现示例：
//   - VMessInbound: Process 解析 AEAD 头后提交 session::Context 给 dispatcher
//   - TrojanInbound: Process 解析 SHA224+目标后提交 session::Context 给 dispatcher
// ============================================================================
class Inbound : public memory::DataAllocated {
public:
    explicit Inbound(UserOnlineTracker& online) noexcept : online_(online) {}
    virtual ~Inbound() noexcept = default;

    // Owner-local protocol state may be transferred during an atomic handler
    // replacement. Live sessions keep the state they already captured.
    virtual void AdoptOwnerStateFrom(Inbound&) noexcept {}

    // -----------------------------------------------------------------------
    // 从已建立的传输流中解析协议头，并移交给 dispatcher。
    //
    // @param stream  已完成 TLS/WS 等传输层握手的字节流
    // @param ctx     会话上下文（用于填充用户信息、错误记录）
    // @param pressure_idle_timeout runtime 当前压力模式的空闲超时秒数；0 表示未启用
    // @return        dispatcher/relay 结果；协议解析失败在进入 dispatcher 前返回错误
    // -----------------------------------------------------------------------
    net::awaitable<RelayResult> Process(
        std::unique_ptr<AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        net::any_io_executor executor,
        session::Context& ctx,
        StatsShard& stats,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) {
        UserOnlineLease online(online_);
        RelayResult result;
        std::exception_ptr failure;
        try {
            result = co_await ProcessSession(std::move(stream), dispatcher, receiver,
                executor, ctx, stats, online, timeouts, pressure_idle_timeout);
        } catch (...) {
            failure = std::current_exception();
        }
        const bool throw_on_cancel = co_await net::this_coro::throw_if_cancelled();
        co_await net::this_coro::throw_if_cancelled(false);
        co_await online.Release();
        co_await net::this_coro::throw_if_cancelled(throw_on_cancel);
        if (failure) std::rethrow_exception(failure);
        co_return result;
    }

    virtual net::awaitable<RelayResult> ProcessSession(
        std::unique_ptr<AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        net::any_io_executor executor,
        session::Context& ctx,
        StatsShard& stats,
        UserOnlineLease& online,
        const TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) = 0;

    // Native datagrams enter through the same protocol handler abstraction.
    // The owning UDP runtime performs the dispatcher handoff after protocol
    // parsing and authentication.
    [[nodiscard]] virtual tl::expected<InboundDatagramResult, ErrorCode>
    Process(const InboundDatagramRequest&) {
        return tl::unexpected(ErrorCode::NOT_SUPPORTED);
    }
private:
    UserOnlineTracker& online_;
};

}  // namespace acpp
