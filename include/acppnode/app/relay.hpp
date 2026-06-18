#pragma once

#include "acppnode/app/relay_types.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/token_bucket.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/experimental/awaitable_operators.hpp>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>

namespace acpp {

// 前向声明
class InitialPayload;
struct Buffer;
class UDPSession;

namespace relay_detail {

inline constexpr uint64_t kRelayStatsFlushBytes = 64 * 1024;
inline constexpr auto kRelayCloseGraceTimeout = std::chrono::seconds(1);
using SteadyClock = std::chrono::steady_clock;

template <typename Endpoint>
void MarkAbortiveCloseIfSupported(Endpoint& endpoint) {
    if constexpr (requires { endpoint.SetAbortiveClose(true); }) {
        endpoint.SetAbortiveClose(true);
    }
}

template <typename Endpoint>
void CloseIfSupported(Endpoint& endpoint) noexcept {
    if constexpr (requires { endpoint.Close(); }) {
        try {
            endpoint.Close();
        } catch (...) {
        }
    }
}

template <typename Endpoint>
void CloseAbortiveIfSupported(Endpoint& endpoint) noexcept {
    if constexpr (requires { endpoint.CloseAbortive(); }) {
        try {
            endpoint.CloseAbortive();
        } catch (...) {
        }
    } else {
        MarkAbortiveCloseIfSupported(endpoint);
        CloseIfSupported(endpoint);
    }
}

template <typename Endpoint>
void CancelIfSupported(Endpoint& endpoint) noexcept {
    if constexpr (requires { endpoint.Cancel(); }) {
        try {
            endpoint.Cancel();
        } catch (...) {
        }
    }
}

template <typename FromControl, typename ToControl>
void CancelRelayControls(FromControl& from, ToControl& to) noexcept {
    CancelIfSupported(from);
    if constexpr (std::is_same_v<std::remove_cvref_t<FromControl>,
                                 std::remove_cvref_t<ToControl>>) {
        if (std::addressof(from) != std::addressof(to)) {
            CancelIfSupported(to);
        }
    } else {
        CancelIfSupported(to);
    }
}

template <typename Endpoint>
net::awaitable<void> ShutdownWriteForClose(Endpoint& endpoint) {
    if constexpr (requires { endpoint.SetWriteTimeout(kRelayCloseGraceTimeout); }) {
        endpoint.SetWriteTimeout(kRelayCloseGraceTimeout);
    }

    if constexpr (requires { endpoint.StartPhaseDeadline(kRelayCloseGraceTimeout); }) {
        (void)endpoint.StartPhaseDeadline(kRelayCloseGraceTimeout);
    }

    try {
        if constexpr (requires { endpoint.AsyncShutdownWrite(); }) {
            co_await endpoint.AsyncShutdownWrite();
        } else if constexpr (requires { endpoint.ShutdownWrite(); }) {
            endpoint.ShutdownWrite();
        }
    } catch (...) {
    }

    if constexpr (requires { endpoint.ClearPhaseDeadline(); }) {
        endpoint.ClearPhaseDeadline();
    }
}

template <typename Writer, typename Control>
net::awaitable<void> ShutdownWriteForClose(Writer& writer, Control& control) {
    if constexpr (requires { control.SetWriteTimeout(kRelayCloseGraceTimeout); }) {
        control.SetWriteTimeout(kRelayCloseGraceTimeout);
    }

    if constexpr (requires { control.StartPhaseDeadline(kRelayCloseGraceTimeout); }) {
        (void)control.StartPhaseDeadline(kRelayCloseGraceTimeout);
    }

    try {
        if constexpr (requires { writer.AsyncShutdownWrite(); }) {
            co_await writer.AsyncShutdownWrite();
        } else if constexpr (requires { ShutdownWrite(writer, control); }) {
            co_await ShutdownWrite(writer, control);
        } else if constexpr (requires { control.AsyncShutdownWrite(); }) {
            co_await control.AsyncShutdownWrite();
        } else if constexpr (requires { control.ShutdownWrite(); }) {
            control.ShutdownWrite();
        }
    } catch (...) {
    }

    if constexpr (requires { control.ClearPhaseDeadline(); }) {
        control.ClearPhaseDeadline();
    }
}

inline ErrorCode SelectRelayError(ErrorCode up, ErrorCode down) noexcept {
    if (up == ErrorCode::OK) {
        return down;
    }
    if (down == ErrorCode::OK) {
        return up;
    }
    if (up == ErrorCode::CANCELLED && down != ErrorCode::CANCELLED) {
        return down;
    }
    return up;
}

inline bool ClientSideErrorFirst(ErrorCode up, ErrorCode down) noexcept {
    if (up == ErrorCode::OK) {
        return false;
    }
    return !(up == ErrorCode::CANCELLED &&
             down != ErrorCode::OK &&
             down != ErrorCode::CANCELLED);
}

inline int64_t ToSteadyNs(SteadyClock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        tp.time_since_epoch()).count();
}

struct RelayDirectionState {
    bool eof = false;
    int64_t half_close_deadline_ns = 0;
};

class RateTimerGuard {
public:
    explicit RateTimerGuard(net::io_context& io_context) noexcept
        : sleep_(io_context) {}

    ~RateTimerGuard() noexcept = default;

    RateTimerGuard(const RateTimerGuard&) = delete;
    RateTimerGuard& operator=(const RateTimerGuard&) = delete;

    [[nodiscard]] net::awaitable<void> WaitFor(std::chrono::nanoseconds delay) {
        return sleep_.WaitFor(
            std::chrono::duration_cast<std::chrono::milliseconds>(delay));
    }

private:
    ScheduledSleep sleep_;
};

struct NoopRateLimiter {
    explicit NoopRateLimiter(uint64_t) noexcept {}
};

struct NoopRateTimer {
    explicit NoopRateTimer(net::io_context&) noexcept {}
};

inline std::optional<std::chrono::seconds> RemainingHalfCloseBudget(int64_t deadline_ns) {
    const int64_t raw = deadline_ns;
    if (raw <= 0) {
        return std::nullopt;
    }

    const auto deadline = SteadyClock::time_point(std::chrono::nanoseconds(raw));
    const auto now = SteadyClock::now();
    if (deadline <= now) {
        return std::chrono::seconds(0);
    }

    auto remaining = std::chrono::duration_cast<std::chrono::seconds>(deadline - now);
    if (remaining.count() == 0) {
        remaining = std::chrono::seconds(1);
    }
    return remaining;
}

inline void FlushRelayStats(StatsShard* stats, LocalStatsAccumulator& acc) {
    if (!stats) {
        acc.Reset();
        return;
    }
    if (acc.bytes_in == 0 && acc.bytes_out == 0) {
        return;
    }
    stats->CommitAccumulator(acc);
    acc.Reset();
}

template <typename Stream>
bool ConsumeReadSideTimeoutSignal(Stream& stream) {
    bool read = stream.ConsumeReadTimeout();
    bool idle = stream.ConsumeIdleTimeout();
    return read || idle;
}

template <typename Stream>
bool ConsumeWriteSideTimeoutSignal(Stream& stream) {
    bool write = stream.ConsumeWriteTimeout();
    bool idle = stream.ConsumeIdleTimeout();
    return write || idle;
}

template <typename FromControl, typename ToControl>
bool ConsumeRelayTimeoutSignals(FromControl& from, ToControl& to) {
    // half-close 的 absolute deadline 会通过 phase deadline 主动 cancel 正在进行的 I/O，
    // 这里统一把 read/write/idle/phase 四类超时信号都折叠成 relay timeout。
    bool timed_out =
        ConsumeReadSideTimeoutSignal(from) || ConsumeWriteSideTimeoutSignal(to);
    bool from_phase = from.ConsumePhaseDeadline();
    bool to_phase = to.ConsumePhaseDeadline();
    return timed_out || from_phase || to_phase;
}

template <typename ClientStream, typename TargetStream>
net::awaitable<std::optional<RelayResult>> WriteFirstPacket(
    ClientStream& client,
    TargetStream& target,
    StatsShard& stats,
    std::span<const uint8_t> first_packet) {

    if (first_packet.empty()) {
        co_return std::nullopt;
    }

    buf::MultiBuffer mb;
    mb.reserve((first_packet.size() + buf::Buffer::kSize - 1) / buf::Buffer::kSize);

    size_t offset = 0;
    while (offset < first_packet.size()) {
        buf::BufferGuard out{buf::Buffer::New()};
        if (!out) {
            throw std::bad_alloc();
        }
        const size_t chunk = std::min(
            first_packet.size() - offset,
            static_cast<size_t>(out->Available()));
        std::memcpy(out->Tail().data(), first_packet.data() + offset, chunk);
        out->Produce(static_cast<uint32_t>(chunk));
        mb.push_back(out.release());
        offset += chunk;
    }

    try {
        co_await target.WriteMultiBuffer(std::move(mb));
        mb.clear();
        stats.AddBytesOut(first_packet.size());
        co_return std::nullopt;

    } catch (const IoSystemError& e) {
        MarkAbortiveCloseIfSupported(client);
        MarkAbortiveCloseIfSupported(target);
        RelayResult result;
        result.error = ConsumeWriteSideTimeoutSignal(target)
            ? ErrorCode::RELAY_TIMEOUT
            : MapAsioError(e.code());
        result.error_msg = std::string("first packet error: ") + e.what();
        co_return result;
    } catch (const std::exception& e) {
        MarkAbortiveCloseIfSupported(client);
        MarkAbortiveCloseIfSupported(target);
        RelayResult result;
        result.error = ErrorCode::RELAY_WRITE_FAILED;
        result.error_msg = std::string("first packet error: ") + e.what();
        co_return result;
    }
}

template <typename ClientStream, typename TargetStream>
net::awaitable<std::optional<RelayResult>> WriteFirstPacketBuffer(
    ClientStream& client,
    TargetStream& target,
    StatsShard& stats,
    buf::Buffer*& first_packet) {

    if (!first_packet || first_packet->IsEmpty()) {
        buf::Buffer::Free(first_packet);
        first_packet = nullptr;
        co_return std::nullopt;
    }

    const size_t first_packet_size = first_packet->Len();
    buf::MultiBuffer mb;
    mb.reserve(1);
    mb.push_back(first_packet);
    first_packet = nullptr;

    try {
        co_await target.WriteMultiBuffer(std::move(mb));
        mb.clear();
        stats.AddBytesOut(first_packet_size);
        co_return std::nullopt;

    } catch (const IoSystemError& e) {
        MarkAbortiveCloseIfSupported(client);
        MarkAbortiveCloseIfSupported(target);
        RelayResult result;
        result.error = ConsumeWriteSideTimeoutSignal(target)
            ? ErrorCode::RELAY_TIMEOUT
            : MapAsioError(e.code());
        result.error_msg = std::string("first packet error: ") + e.what();
        co_return result;
    } catch (const std::exception& e) {
        MarkAbortiveCloseIfSupported(client);
        MarkAbortiveCloseIfSupported(target);
        RelayResult result;
        result.error = ErrorCode::RELAY_WRITE_FAILED;
        result.error_msg = std::string("first packet error: ") + e.what();
        co_return result;
    }
}

template <typename ClientStream, typename TargetStream>
net::awaitable<std::optional<RelayResult>> WriteFirstPacketMultiBuffer(
    ClientStream& client,
    TargetStream& target,
    StatsShard& stats,
    buf::MultiBuffer& first_packet) {

    const size_t first_packet_size = buf::TotalLen(first_packet);
    if (first_packet_size == 0) {
        first_packet.clear();
        co_return std::nullopt;
    }

    buf::MultiBuffer mb = std::move(first_packet);
    first_packet.clear();

    try {
        co_await target.WriteMultiBuffer(std::move(mb));
        mb.clear();
        stats.AddBytesOut(first_packet_size);
        co_return std::nullopt;

    } catch (const IoSystemError& e) {
        MarkAbortiveCloseIfSupported(client);
        MarkAbortiveCloseIfSupported(target);
        RelayResult result;
        result.error = ConsumeWriteSideTimeoutSignal(target)
            ? ErrorCode::RELAY_TIMEOUT
            : MapAsioError(e.code());
        result.error_msg = std::string("first packet error: ") + e.what();
        co_return result;
    } catch (const std::exception& e) {
        MarkAbortiveCloseIfSupported(client);
        MarkAbortiveCloseIfSupported(target);
        RelayResult result;
        result.error = ErrorCode::RELAY_WRITE_FAILED;
        result.error_msg = std::string("first packet error: ") + e.what();
        co_return result;
    }
}

template <bool RateLimited,
          typename FromReader,
          typename FromControl,
          typename ToWriter,
          typename ToControl>
net::awaitable<std::pair<uint64_t, ErrorCode>> RelayOneDirectionImpl(
    net::io_context& io_context,
    FromReader& from_reader,
    FromControl& from_control,
    ToWriter& to_writer,
    ToControl& to_control,
    RelayDirectionState& my_state,
    RelayDirectionState& peer_state,
    std::chrono::seconds half_close_timeout,
    StatsShard* stats,
    bool is_upload,
    uint64_t speed_limit,
    uint64_t* live_bytes_counter,
    const session::Context& ctx) {

    uint64_t total_bytes = 0;
    ErrorCode error = ErrorCode::OK;
    if (live_bytes_counter) {
        *live_bytes_counter = 0;
    }

    using RateLimiter = std::conditional_t<RateLimited, TokenBucket, NoopRateLimiter>;
    using RateTimer = std::conditional_t<RateLimited, RateTimerGuard, NoopRateTimer>;
    [[maybe_unused]] RateLimiter rate_limiter(speed_limit);
    [[maybe_unused]] RateTimer rate_timer(io_context);
    LocalStatsAccumulator stats_acc;

    while (true) {
        if (auto remaining = RemainingHalfCloseBudget(my_state.half_close_deadline_ns)) {
            if (remaining->count() == 0) {
                error = ErrorCode::RELAY_TIMEOUT;
                LOG_CONN_DEBUG(ctx, "[relay] {} absolute half-close timeout, transferred={}B",
                               is_upload ? "up" : "down", total_bytes);
                CancelRelayControls(from_control, to_control);
                break;
            }

            from_control.SetReadTimeout(*remaining);
            to_control.SetWriteTimeout(*remaining);
        }

        // 注意：不在这里检查 peer_eof。
        // TCP 全双工：对端关闭写端（EOF）不代表关闭读端，
        // 本方向应继续转发直到自身 EOF 或半关闭超时到期后被 Cancel。

        try {
            buf::MultiBuffer mb;
            if constexpr (requires { from_reader.ReadMultiBuffer(); }) {
                mb = co_await from_reader.ReadMultiBuffer();
            } else if constexpr (std::is_same_v<
                                     std::remove_cvref_t<FromReader>,
                                     std::remove_cvref_t<FromControl>>) {
                mb = co_await from_reader.ReadMultiBuffer();
            } else {
                mb = co_await ReadMultiBuffer(from_reader, from_control);
            }

            if (mb.empty()) {
                if (ConsumeRelayTimeoutSignals(from_control, to_control)) {
                    error = ErrorCode::RELAY_TIMEOUT;
                    LOG_CONN_DEBUG(ctx, "[relay] {} relay timeout, transferred={}B",
                                   is_upload ? "up" : "down", total_bytes);
                    CancelRelayControls(from_control, to_control);
                    break;
                }

                // 被对端半关闭超时后 Cancel 的情况：对端已 EOF 且超时到期，
                // 主动 Cancel 了我们的 from 流，直接退出即可
                if (peer_state.eof) {
                    LOG_CONN_DEBUG(ctx, "[relay] {} forced exit by peer half-close timeout, transferred={}B",
                                   is_upload ? "up" : "down", total_bytes);
                    break;
                }

                LOG_CONN_DEBUG(ctx, "[relay] {} EOF after {}B", is_upload ? "up" : "down", total_bytes);
                my_state.eof = true;

                // 对齐 Xray：半关闭只切换 idle timer，不发送传输/协议级写关闭。
                // 写关闭由 DoRelay 全关闭阶段统一发送。
                if (!peer_state.eof) {
                    if (half_close_timeout.count() > 0) {
                        const auto deadline = SteadyClock::now() + half_close_timeout;
                        peer_state.half_close_deadline_ns = ToSteadyNs(deadline);

                        LOG_CONN_DEBUG(ctx, "[relay] {} half-close: arming absolute timeout {}s for peer direction",
                                       is_upload ? "up" : "down", half_close_timeout.count());
                        from_control.SetIdleTimeout(half_close_timeout);
                        to_control.SetIdleTimeout(half_close_timeout);
                        // 一侧已经 EOF 后，另一侧最多只允许保留 half_close_timeout。
                        // 当前方向退出后，peer direction 会按共享 absolute deadline 收敛。
                        from_control.SetWriteTimeout(half_close_timeout);
                        to_control.SetWriteTimeout(half_close_timeout);
                        // 仅修改 write timeout 不会缩短已经 arm 的 async_write deadline。
                        // 用 absolute phase deadline 主动取消正在进行的读/写，确保 half-close
                        // 预算对 in-flight I/O 也立即生效。
                        (void)from_control.StartPhaseDeadline(half_close_timeout);
                        (void)to_control.StartPhaseDeadline(half_close_timeout);
                    } else {
                        LOG_CONN_DEBUG(ctx, "[relay] {} half-close: timeout=0, cancel peer immediately",
                                       is_upload ? "up" : "down");
                        // 超时为 0：立即终止对端方向
                        to_control.Cancel();
                    }
                } else {
                    LOG_CONN_DEBUG(ctx, "[relay] {} EOF, peer already EOF, both done",
                                   is_upload ? "up" : "down");
                }
                break;
            }

            size_t n = buf::TotalLen(mb);
            if constexpr (RateLimited) {
                auto wait_time = rate_limiter.Consume(n);
                if (wait_time.count() > 0) {
                    co_await rate_timer.WaitFor(wait_time);
                }
            }

            if constexpr (requires { to_writer.WriteMultiBuffer(std::move(mb)); }) {
                co_await to_writer.WriteMultiBuffer(std::move(mb));
            } else if constexpr (std::is_same_v<
                                     std::remove_cvref_t<ToWriter>,
                                     std::remove_cvref_t<ToControl>>) {
                co_await to_writer.WriteMultiBuffer(std::move(mb));
            } else {
                co_await WriteMultiBuffer(to_writer, to_control, std::move(mb));
            }

            total_bytes += n;
            if (live_bytes_counter) {
                *live_bytes_counter = total_bytes;
            }
            if (stats) {
                if (is_upload) stats_acc.AddBytesOut(n);
                else           stats_acc.AddBytesIn(n);

                if (stats_acc.bytes_in + stats_acc.bytes_out >= kRelayStatsFlushBytes) {
                    FlushRelayStats(stats, stats_acc);
                }
            }

        } catch (const IoSystemError& e) {
            error = MapAsioError(e.code());
            if (error == ErrorCode::CANCELLED &&
                ConsumeRelayTimeoutSignals(from_control, to_control)) {
                error = ErrorCode::RELAY_TIMEOUT;
                LOG_CONN_DEBUG(ctx, "[relay] {} cancelled by timeout, transferred={}B",
                               is_upload ? "up" : "down", total_bytes);
            } else {
                LOG_CONN_DEBUG(ctx, "[relay] {} error: {} ({}), transferred={}B",
                               is_upload ? "up" : "down",
                               ErrorCodeToString(error), e.what(), total_bytes);
            }
            CancelRelayControls(from_control, to_control);
            break;
        } catch (const std::exception& e) {
            error = ErrorCode::RELAY_WRITE_FAILED;
            LOG_CONN_DEBUG(ctx, "[relay] {} exception: {}, transferred={}B",
                           is_upload ? "up" : "down", e.what(), total_bytes);
            CancelRelayControls(from_control, to_control);
            break;
        } catch (...) {
            error = ErrorCode::RELAY_WRITE_FAILED;
            LOG_CONN_DEBUG(ctx, "[relay] {} exception: unknown, transferred={}B",
                           is_upload ? "up" : "down", total_bytes);
            CancelRelayControls(from_control, to_control);
            break;
        }
    }

    FlushRelayStats(stats, stats_acc);
    co_return std::make_pair(total_bytes, error);
}

}  // namespace relay_detail

// ============================================================================
// 低成本 TCP relay 入口
//
// ClientEndpoint / TargetEndpoint are concrete reader/writer states prepared
// by protocol Handler::Process; relay consumes them directly without wrapping
// them as AsyncStream.
// ============================================================================
template <typename ClientEndpoint, typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLink(
    net::io_context& io_context,
    ClientEndpoint& client,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    const RelayConfig& config = RelayConfig{}) {

    using namespace net::experimental::awaitable_operators;

    RelayResult result;
    relay_detail::RelayDirectionState client_state;
    relay_detail::RelayDirectionState target_state;

    LOG_CONN_DEBUG(ctx, "Relay started, speed_limit={}, uplink_only={}s, downlink_only={}s",
                   config.speed_limit > 0 ?
                   std::format("{}MB/s", config.speed_limit / 1024 / 1024) : "unlimited",
                   config.uplink_only.count(),
                   config.downlink_only.count());

    std::pair<uint64_t, ErrorCode> up_result;
    std::pair<uint64_t, ErrorCode> down_result;
    if (config.speed_limit == 0) {
        auto [up, down] = co_await (
            relay_detail::RelayOneDirectionImpl<false>(
                io_context, client, client, target, target, client_state, target_state,
                config.downlink_only,
                &stats, true, config.speed_limit, &ctx.traffic.bytes_up, ctx) &&
            relay_detail::RelayOneDirectionImpl<false>(
                io_context, target, target, client, client, target_state, client_state,
                config.uplink_only,
                &stats, false, config.speed_limit, &ctx.traffic.bytes_down, ctx)
        );
        up_result = up;
        down_result = down;
    } else {
        auto [up, down] = co_await (
            relay_detail::RelayOneDirectionImpl<true>(
                io_context, client, client, target, target, client_state, target_state,
                config.downlink_only,
                &stats, true, config.speed_limit, &ctx.traffic.bytes_up, ctx) &&
            relay_detail::RelayOneDirectionImpl<true>(
                io_context, target, target, client, client, target_state, client_state,
                config.uplink_only,
                &stats, false, config.speed_limit, &ctx.traffic.bytes_down, ctx)
        );
        up_result = up;
        down_result = down;
    }

    auto [bytes_up, error_up] = up_result;
    auto [bytes_down, error_down] = down_result;

    // relay 结束后立刻清掉 half-close phase deadline，
    // 避免后续优雅关闭被残留 absolute deadline 误取消。
    client.ClearPhaseDeadline();
    target.ClearPhaseDeadline();

    result.bytes_up = bytes_up;
    result.bytes_down = bytes_down;

    ctx.traffic.bytes_up = bytes_up;
    ctx.traffic.bytes_down = bytes_down;

    result.error = relay_detail::SelectRelayError(error_up, error_down);
    result.client_closed_first =
        relay_detail::ClientSideErrorFirst(error_up, error_down);

    LOG_CONN_DEBUG(ctx, "Relay CLOSING: up_err={} down_err={} up={}B down={}B closer={}",
                   ErrorCodeToString(error_up), ErrorCodeToString(error_down),
                   bytes_up, bytes_down,
                   result.client_closed_first ? "client" : "target");

    // 错误路径快速关闭：跳过传输/协议级优雅写关闭，
    // 直接 Cancel 所有挂起操作后由析构链关闭 socket。
    // 正常关闭（双方均 EOF）才执行协议级优雅关闭。
    if (error_up != ErrorCode::OK || error_down != ErrorCode::OK) {
        client.Cancel();
        target.Cancel();
        relay_detail::CloseAbortiveIfSupported(client);
        relay_detail::CloseAbortiveIfSupported(target);
    } else {
        // 并行发送双向优雅写关闭，减少 1 次 RTT
        auto shutdown_client = [&]() -> net::awaitable<void> {
            co_await relay_detail::ShutdownWriteForClose(client);
        };
        auto shutdown_target = [&]() -> net::awaitable<void> {
            co_await relay_detail::ShutdownWriteForClose(target);
        };
        co_await (shutdown_client() && shutdown_target());
        client.Cancel();
        target.Cancel();
        relay_detail::CloseIfSupported(client);
        relay_detail::CloseIfSupported(target);
    }

    LOG_CONN_DEBUG(ctx, "Relay finished: up={} down={}", bytes_up, bytes_down);

    co_return result;
}

template <typename ClientReader,
          typename ClientWriter,
          typename ClientControl,
          typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLink(
    net::io_context& io_context,
    ClientReader& client_reader,
    ClientWriter& client_writer,
    ClientControl& client_control,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    const RelayConfig& config = RelayConfig{}) {

    using namespace net::experimental::awaitable_operators;

    RelayResult result;
    relay_detail::RelayDirectionState client_state;
    relay_detail::RelayDirectionState target_state;

    LOG_CONN_DEBUG(ctx, "Relay started, speed_limit={}, uplink_only={}s, downlink_only={}s",
                   config.speed_limit > 0 ?
                   std::format("{}MB/s", config.speed_limit / 1024 / 1024) : "unlimited",
                   config.uplink_only.count(),
                   config.downlink_only.count());

    std::pair<uint64_t, ErrorCode> up_result;
    std::pair<uint64_t, ErrorCode> down_result;
    if (config.speed_limit == 0) {
        auto [up, down] = co_await (
            relay_detail::RelayOneDirectionImpl<false>(
                io_context,
                client_reader,
                client_control,
                target,
                target,
                client_state,
                target_state,
                config.downlink_only,
                &stats,
                true,
                config.speed_limit,
                &ctx.traffic.bytes_up,
                ctx) &&
            relay_detail::RelayOneDirectionImpl<false>(
                io_context,
                target,
                target,
                client_writer,
                client_control,
                target_state,
                client_state,
                config.uplink_only,
                &stats,
                false,
                config.speed_limit,
                &ctx.traffic.bytes_down,
                ctx)
        );
        up_result = up;
        down_result = down;
    } else {
        auto [up, down] = co_await (
            relay_detail::RelayOneDirectionImpl<true>(
                io_context,
                client_reader,
                client_control,
                target,
                target,
                client_state,
                target_state,
                config.downlink_only,
                &stats,
                true,
                config.speed_limit,
                &ctx.traffic.bytes_up,
                ctx) &&
            relay_detail::RelayOneDirectionImpl<true>(
                io_context,
                target,
                target,
                client_writer,
                client_control,
                target_state,
                client_state,
                config.uplink_only,
                &stats,
                false,
                config.speed_limit,
                &ctx.traffic.bytes_down,
                ctx)
        );
        up_result = up;
        down_result = down;
    }

    auto [bytes_up, error_up] = up_result;
    auto [bytes_down, error_down] = down_result;

    client_control.ClearPhaseDeadline();
    target.ClearPhaseDeadline();

    result.bytes_up = bytes_up;
    result.bytes_down = bytes_down;

    ctx.traffic.bytes_up = bytes_up;
    ctx.traffic.bytes_down = bytes_down;

    result.error = relay_detail::SelectRelayError(error_up, error_down);
    result.client_closed_first =
        relay_detail::ClientSideErrorFirst(error_up, error_down);

    LOG_CONN_DEBUG(ctx, "Relay CLOSING: up_err={} down_err={} up={}B down={}B closer={}",
                   ErrorCodeToString(error_up), ErrorCodeToString(error_down),
                   bytes_up, bytes_down,
                   result.client_closed_first ? "client" : "target");

    if (error_up != ErrorCode::OK || error_down != ErrorCode::OK) {
        client_control.Cancel();
        target.Cancel();
        relay_detail::CloseAbortiveIfSupported(client_control);
        relay_detail::CloseAbortiveIfSupported(target);
    } else {
        auto shutdown_client = [&]() -> net::awaitable<void> {
            co_await relay_detail::ShutdownWriteForClose(client_writer, client_control);
        };
        auto shutdown_target = [&]() -> net::awaitable<void> {
            co_await relay_detail::ShutdownWriteForClose(target);
        };
        co_await (shutdown_client() && shutdown_target());
        client_control.Cancel();
        target.Cancel();
        relay_detail::CloseIfSupported(client_control);
        relay_detail::CloseIfSupported(target);
    }

    LOG_CONN_DEBUG(ctx, "Relay finished: up={} down={}", bytes_up, bytes_down);

    co_return result;
}

template <typename ClientReader,
          typename ClientWriter,
          typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLink(
    net::io_context& io_context,
    ClientReader& client_reader,
    ClientWriter& client_writer,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    const RelayConfig& config = RelayConfig{}) {

    (void)io_context;
    (void)config;
    using namespace net::experimental::awaitable_operators;

    LOG_CONN_DEBUG(ctx, "Relay started without client control, speed_limit={}",
                   config.speed_limit > 0 ?
                   std::format("{}MB/s", config.speed_limit / 1024 / 1024) : "unlimited");

    std::pair<uint64_t, ErrorCode> up_result{0, ErrorCode::OK};
    std::pair<uint64_t, ErrorCode> down_result{0, ErrorCode::OK};
    ErrorCode first_error = ErrorCode::OK;
    bool first_error_from_client = false;

    auto remember_error = [&](ErrorCode error, bool from_client) {
        if (error != ErrorCode::OK && first_error == ErrorCode::OK) {
            first_error = error;
            first_error_from_client = from_client;
        }
    };

    auto upload = [&]() -> net::awaitable<std::pair<uint64_t, ErrorCode>> {
        uint64_t bytes = 0;
        LocalStatsAccumulator stats_acc;
        while (true) {
            try {
                buf::MultiBuffer mb = co_await client_reader.ReadMultiBuffer();
                if (mb.empty()) {
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                    co_return std::make_pair(bytes, ErrorCode::OK);
                }
                const size_t n = buf::TotalLen(mb);
                co_await target.WriteMultiBuffer(std::move(mb));
                bytes += n;
                ctx.traffic.bytes_up = bytes;
                stats_acc.AddBytesOut(n);
                if (stats_acc.bytes_in + stats_acc.bytes_out >= relay_detail::kRelayStatsFlushBytes) {
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                }
            } catch (const IoSystemError& e) {
                relay_detail::FlushRelayStats(&stats, stats_acc);
                const ErrorCode error = MapAsioError(e.code());
                up_result = std::make_pair(bytes, error);
                remember_error(error, true);
                relay_detail::CancelIfSupported(target);
                throw;
            } catch (...) {
                relay_detail::FlushRelayStats(&stats, stats_acc);
                up_result = std::make_pair(bytes, ErrorCode::RELAY_WRITE_FAILED);
                remember_error(ErrorCode::RELAY_WRITE_FAILED, true);
                relay_detail::CancelIfSupported(target);
                throw;
            }
        }
    };

    auto download = [&]() -> net::awaitable<std::pair<uint64_t, ErrorCode>> {
        uint64_t bytes = 0;
        LocalStatsAccumulator stats_acc;
        while (true) {
            try {
                buf::MultiBuffer mb = co_await target.ReadMultiBuffer();
                if (mb.empty()) {
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                    co_return std::make_pair(bytes, ErrorCode::OK);
                }
                const size_t n = buf::TotalLen(mb);
                co_await client_writer.WriteMultiBuffer(std::move(mb));
                bytes += n;
                ctx.traffic.bytes_down = bytes;
                stats_acc.AddBytesIn(n);
                if (stats_acc.bytes_in + stats_acc.bytes_out >= relay_detail::kRelayStatsFlushBytes) {
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                }
            } catch (const IoSystemError& e) {
                relay_detail::FlushRelayStats(&stats, stats_acc);
                const ErrorCode error = MapAsioError(e.code());
                down_result = std::make_pair(bytes, error);
                remember_error(error, false);
                relay_detail::CancelIfSupported(target);
                throw;
            } catch (...) {
                relay_detail::FlushRelayStats(&stats, stats_acc);
                down_result = std::make_pair(bytes, ErrorCode::RELAY_WRITE_FAILED);
                remember_error(ErrorCode::RELAY_WRITE_FAILED, false);
                relay_detail::CancelIfSupported(target);
                throw;
            }
        }
    };

    try {
        auto [up, down] = co_await (upload() && download());
        up_result = up;
        down_result = down;
    } catch (...) {
        if (first_error == ErrorCode::OK) {
            first_error = ErrorCode::INTERNAL;
        }
    }

    RelayResult result;
    result.bytes_up = first_error == ErrorCode::OK ? up_result.first : ctx.traffic.bytes_up;
    result.bytes_down = first_error == ErrorCode::OK ? down_result.first : ctx.traffic.bytes_down;
    result.client_closed_first = first_error != ErrorCode::OK
        ? first_error_from_client
        : relay_detail::ClientSideErrorFirst(up_result.second, down_result.second);
    if (first_error != ErrorCode::OK) {
        result.error = first_error;
    } else if (up_result.second != ErrorCode::OK) {
        result.error = up_result.second;
    } else if (down_result.second != ErrorCode::OK) {
        result.error = down_result.second;
    }
    ctx.traffic.bytes_up = result.bytes_up;
    ctx.traffic.bytes_down = result.bytes_down;

    if (result.error != ErrorCode::OK) {
        target.Cancel();
        relay_detail::CloseAbortiveIfSupported(target);
    } else {
        auto shutdown_client = [&]() -> net::awaitable<void> {
            co_await relay_detail::ShutdownWriteForClose(client_writer);
        };
        auto shutdown_target = [&]() -> net::awaitable<void> {
            co_await relay_detail::ShutdownWriteForClose(target);
        };
        co_await (shutdown_client() && shutdown_target());
        target.Cancel();
        relay_detail::CloseIfSupported(target);
    }

    LOG_CONN_DEBUG(ctx, "Relay finished without client control: up={} down={}",
                   result.bytes_up, result.bytes_down);
    co_return result;
}

template <typename ClientEndpoint, typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLinkWithFirstPacket(
    net::io_context& io_context,
    ClientEndpoint& client,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    std::span<const uint8_t> first_packet,
    const RelayConfig& config = RelayConfig{}) {

    const size_t first_packet_size = first_packet.size();

    if (auto error = co_await relay_detail::WriteFirstPacket(client, target, stats, first_packet)) {
        co_return *error;
    }

    auto result = co_await DoRelayLink(io_context, client, target, ctx, stats, config);
    result.bytes_up += first_packet_size;

    co_return result;
}

template <typename ClientReader,
          typename ClientWriter,
          typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLinkWithFirstPacket(
    net::io_context& io_context,
    ClientReader& client_reader,
    ClientWriter& client_writer,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    std::span<const uint8_t> first_packet,
    const RelayConfig& config = RelayConfig{}) {

    const size_t first_packet_size = first_packet.size();

    if (auto error = co_await relay_detail::WriteFirstPacket(
            target, target, stats, first_packet)) {
        co_return *error;
    }

    auto result = co_await DoRelayLink(
        io_context,
        client_reader,
        client_writer,
        target,
        ctx,
        stats,
        config);
    result.bytes_up += first_packet_size;

    co_return result;
}

template <typename ClientReader,
          typename ClientWriter,
          typename ClientControl,
          typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLinkWithFirstPacket(
    net::io_context& io_context,
    ClientReader& client_reader,
    ClientWriter& client_writer,
    ClientControl& client_control,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    std::span<const uint8_t> first_packet,
    const RelayConfig& config = RelayConfig{}) {

    const size_t first_packet_size = first_packet.size();

    if (auto error = co_await relay_detail::WriteFirstPacket(
            client_control, target, stats, first_packet)) {
        co_return *error;
    }

    auto result = co_await DoRelayLink(
        io_context,
        client_reader,
        client_writer,
        client_control,
        target,
        ctx,
        stats,
        config);
    result.bytes_up += first_packet_size;

    co_return result;
}

template <typename ClientEndpoint, typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLinkWithFirstPacket(
    net::io_context& io_context,
    ClientEndpoint& client,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    buf::Buffer*& first_packet,
    const RelayConfig& config = RelayConfig{}) {

    const size_t first_packet_size = first_packet ? first_packet->Len() : 0;

    if (auto error = co_await relay_detail::WriteFirstPacketBuffer(
            client, target, stats, first_packet)) {
        co_return *error;
    }

    auto result = co_await DoRelayLink(io_context, client, target, ctx, stats, config);
    result.bytes_up += first_packet_size;

    co_return result;
}

template <typename ClientReader,
          typename ClientWriter,
          typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLinkWithFirstPacket(
    net::io_context& io_context,
    ClientReader& client_reader,
    ClientWriter& client_writer,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    buf::MultiBuffer& first_packet,
    const RelayConfig& config = RelayConfig{}) {

    const size_t first_packet_size = buf::TotalLen(first_packet);

    if (auto error = co_await relay_detail::WriteFirstPacketMultiBuffer(
            target, target, stats, first_packet)) {
        co_return *error;
    }

    auto result = co_await DoRelayLink(
        io_context,
        client_reader,
        client_writer,
        target,
        ctx,
        stats,
        config);
    result.bytes_up += first_packet_size;

    co_return result;
}

template <typename ClientReader,
          typename ClientWriter,
          typename ClientControl,
          typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLinkWithFirstPacket(
    net::io_context& io_context,
    ClientReader& client_reader,
    ClientWriter& client_writer,
    ClientControl& client_control,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    buf::Buffer*& first_packet,
    const RelayConfig& config = RelayConfig{}) {

    const size_t first_packet_size = first_packet ? first_packet->Len() : 0;

    if (auto error = co_await relay_detail::WriteFirstPacketBuffer(
            client_control, target, stats, first_packet)) {
        co_return *error;
    }

    auto result = co_await DoRelayLink(
        io_context,
        client_reader,
        client_writer,
        client_control,
        target,
        ctx,
        stats,
        config);
    result.bytes_up += first_packet_size;

    co_return result;
}

template <typename ClientEndpoint, typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLinkWithFirstPacket(
    net::io_context& io_context,
    ClientEndpoint& client,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    buf::MultiBuffer& first_packet,
    const RelayConfig& config = RelayConfig{}) {

    const size_t first_packet_size = buf::TotalLen(first_packet);

    if (auto error = co_await relay_detail::WriteFirstPacketMultiBuffer(
            client, target, stats, first_packet)) {
        co_return *error;
    }

    auto result = co_await DoRelayLink(io_context, client, target, ctx, stats, config);
    result.bytes_up += first_packet_size;

    co_return result;
}

template <typename ClientReader,
          typename ClientWriter,
          typename ClientControl,
          typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLinkWithFirstPacket(
    net::io_context& io_context,
    ClientReader& client_reader,
    ClientWriter& client_writer,
    ClientControl& client_control,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    buf::MultiBuffer& first_packet,
    const RelayConfig& config = RelayConfig{}) {

    const size_t first_packet_size = buf::TotalLen(first_packet);

    if (auto error = co_await relay_detail::WriteFirstPacketMultiBuffer(
            client_control, target, stats, first_packet)) {
        co_return *error;
    }

    auto result = co_await DoRelayLink(
        io_context,
        client_reader,
        client_writer,
        client_control,
        target,
        ctx,
        stats,
        config);
    result.bytes_up += first_packet_size;

    co_return result;
}

// ============================================================================
// UDP Relay（Full Cone NAT）— xray-core outbound.Process 数据面
//
// 由 UDP-capable 出站的 Process 在 dispatcher.Dispatch -> outbound.Process
// 链路内调用：client_reader/client_writer 是已准备好的 transport::Link 端点，
// session 是该 Worker 本地的 Full Cone UDP socket。UDP 协议细节由 relay 内部
// 由入站协议 reader/writer helper 完成封帧后以协议无关方式中继，不再走单独的 dispatcher UDP 分支。
// 上行（client->remote）与回包（remote->client）作为同一 Worker 上的两个并发
// 协程运行；client 侧空闲由入站 stream 的 idle timeout 终止读取。
// ============================================================================
net::awaitable<RelayResult> DoUDPRelayLink(
    net::io_context& io_context,
    transport::MultiBufferReader& client_reader,
    transport::MultiBufferWriter& client_writer,
    UDPSession& session,
    session::Context& ctx,
    StatsShard& stats,
    const UDPRelayConfig& config = UDPRelayConfig{});

}  // namespace acpp
