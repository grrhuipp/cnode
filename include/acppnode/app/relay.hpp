#pragma once

#include "acppnode/app/relay_types.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/token_bucket.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/transport/internet/async_delay.hpp"

#include <asio/experimental/awaitable_operators.hpp>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

namespace acpp {

namespace relay_detail {

inline constexpr uint64_t kRelayStatsFlushBytes = 64 * 1024;
inline constexpr auto kRelayCloseGraceTimeout = std::chrono::seconds(1);
using SteadyClock = std::chrono::steady_clock;

// Owned by the joined relay scope, so either direction can end both waits.
struct RelayRateLimits {
    TokenBucket up;
    TokenBucket down;
    AsyncDelay up_wait;
    AsyncDelay down_wait;
    bool cancelled = false;
    ErrorCode cancellation_error = ErrorCode::CANCELLED;

    RelayRateLimits(net::io_context& io, uint64_t rate)
        : up(rate), down(rate), up_wait(io), down_wait(io) {}

    void Cancel(ErrorCode error = ErrorCode::CANCELLED) noexcept {
        cancelled = true;
        if (cancellation_error == ErrorCode::CANCELLED) cancellation_error = error;
        up_wait.Cancel();
        down_wait.Cancel();
    }
};

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
void CancelRelayControls(FromControl& from, ToControl& to, RelayRateLimits* limits) noexcept {
    if (limits) limits->Cancel();
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
        if constexpr (requires { endpoint.ClearPhaseDeadline(); }) endpoint.ClearPhaseDeadline();
        throw;
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
        if constexpr (requires { control.ClearPhaseDeadline(); }) control.ClearPhaseDeadline();
        throw;
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

inline ErrorCode CaptureShutdownFailure(session::Context& ctx) noexcept {
    try {
        throw;
    } catch (const transport::LinkError& error) {
        return error.code();
    } catch (const IoSystemError& error) {
        ctx.outbound.os_error_code = error.code().value();
        return MapAsioError(error.code());
    } catch (const std::bad_alloc&) {
        return ErrorCode::RESOURCE_EXHAUSTED;
    } catch (...) {
        return ErrorCode::RELAY_WRITE_FAILED;
    }
}

struct RelayDirectionState {
    bool eof = false;
    bool half_close_expired = false;
    ErrorCode cancellation_error = ErrorCode::OK;
    std::optional<SteadyClock::time_point> half_close_deadline;
    TimeoutToken half_close_timer;
};

struct RelayCloseState {
    explicit RelayCloseState(net::io_context& io) : wake(io) {}

    void Complete() noexcept {
        complete = true;
        wake.Cancel();
    }

    void Mark(bool client_side) noexcept {
        if (!known && !local_failure) {
            known = true;
            client = client_side;
        }
    }

    void MarkLocalFailure() noexcept {
        local_failure = true;
        known = false;
        client = false;
    }

    bool local_failure = false;
    bool known = false;
    bool client = false;
    bool complete = false;
    AsyncDelay wake;
};

template <typename Reader>
transport::EofAction ReadEofAction(const Reader& reader) noexcept {
    if constexpr (requires { reader.ReadEofAction(); }) return reader.ReadEofAction();
    else return transport::EofAction::WaitForPeer;
}

template <typename Writer>
bool WriteShutdownClosesLink(const Writer& writer) noexcept {
    if constexpr (requires { writer.WriteShutdownClosesLink(); }) return writer.WriteShutdownClosesLink();
    else return false;
}

inline void ObserveUdpRelayTarget(
    session::Context& ctx,
    const buf::MultiBuffer& payload) noexcept {
    if (ctx.content.network != Network::UDP) {
        return;
    }
    const auto datagram = buf::InspectUdpDatagram(payload);
    if (!datagram.Valid()) {
        return;
    }

    const TargetAddress& target = *datagram.target;
    uint64_t hash = 1469598103934665603ULL;
    auto mix = [&](uint8_t value) noexcept {
        hash ^= value;
        hash *= 1099511628211ULL;
    };
    mix(static_cast<uint8_t>(target.type));
    mix(static_cast<uint8_t>(target.port >> 8));
    mix(static_cast<uint8_t>(target.port));
    if (target.IsDomain()) {
        for (const unsigned char ch : target.host) {
            mix(ch);
        }
    } else if (target.resolved_addr) {
        const auto normalized = iputil::NormalizeAddress(*target.resolved_addr);
        if (normalized.is_v4()) {
            for (const auto byte : normalized.to_v4().to_bytes()) mix(byte);
        } else if (normalized.is_v6()) {
            for (const auto byte : normalized.to_v6().to_bytes()) mix(byte);
        }
    }
    if (hash == 0) hash = 1;

    const uint32_t tracked = std::min<uint32_t>(
        ctx.traffic.distinct_target_count,
        static_cast<uint32_t>(ctx.traffic.distinct_target_hashes.size()));
    for (uint32_t i = 0; i < tracked; ++i) {
        if (ctx.traffic.distinct_target_hashes[i] == hash) return;
    }
    if (tracked < ctx.traffic.distinct_target_hashes.size()) {
        ctx.traffic.distinct_target_hashes[tracked] = hash;
        ++ctx.traffic.distinct_target_count;
    } else {
        ctx.traffic.distinct_target_count = static_cast<uint32_t>(
            ctx.traffic.distinct_target_hashes.size());
    }
    if (ctx.traffic.distinct_target_count > 1) {
        ctx.content.multiple_targets = true;
    }
}

inline void ObserveRelayPacket(
    session::Context& ctx,
    bool is_upload,
    bool is_datagram = false) noexcept {
    if (is_upload) {
        ++ctx.traffic.packet_count_up;
    } else {
        ++ctx.traffic.packet_count_down;
    }
    if (is_datagram) {
        ++ctx.traffic.datagram_count;
    }
    if (ctx.traffic.first_byte_ms == 0 && ctx.accept_time_us > 0) {
        const int64_t elapsed_us = std::max<int64_t>(0, NowMicros() - ctx.accept_time_us);
        ctx.traffic.first_byte_ms = static_cast<uint64_t>(
            std::max<int64_t>(1, (elapsed_us + 999) / 1000));
    }
}

inline std::optional<std::chrono::seconds> RemainingHalfCloseBudget(
    std::optional<SteadyClock::time_point> deadline) {
    if (!deadline) return std::nullopt;
    const auto now = SteadyClock::now();
    if (*deadline <= now) return std::chrono::seconds::zero();
    return std::chrono::ceil<std::chrono::seconds>(*deadline - now);
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
    RelayCloseState& close_state,
    std::chrono::seconds half_close_timeout,
    StatsShard* stats,
    bool is_upload,
    RelayRateLimits* limits,
    uint64_t* live_bytes_counter,
    session::Context& ctx,
    buf::MultiBuffer initial_payload = {}) {

    uint64_t total_bytes = 0;
    ErrorCode error = ErrorCode::OK;
    if (live_bytes_counter) {
        *live_bytes_counter = 0;
    }

    LocalStatsAccumulator stats_acc;
    bool operation_side_is_client = is_upload;

    while (true) {
        if (close_state.complete && my_state.cancellation_error == ErrorCode::OK) break;
        if (auto remaining = RemainingHalfCloseBudget(my_state.half_close_deadline)) {
            if (remaining->count() == 0) {
                error = ErrorCode::RELAY_TIMEOUT;
                close_state.Mark(is_upload);
                LOG_CONN_DEBUG(ctx, "[relay] {} absolute half-close timeout, transferred={}B",
                               is_upload ? "up" : "down", total_bytes);
                CancelRelayControls(from_control, to_control, limits);
                break;
            }

            from_control.SetReadTimeout(*remaining);
            to_control.SetWriteTimeout(*remaining);
        }

        // 注意：不在这里检查 peer_eof。
        // TCP 全双工：对端关闭写端（EOF）不代表关闭读端，
        // 本方向应继续转发直到自身 EOF 或半关闭超时到期后被 Cancel。

        try {
            if (my_state.cancellation_error != ErrorCode::OK)
                throw transport::LinkError(my_state.cancellation_error);
            buf::MultiBuffer mb = std::move(initial_payload);
            operation_side_is_client = is_upload;
            if (!buf::HasData(mb)) {
                mb.clear();
                if constexpr (requires { from_reader.ReadMultiBuffer(); }) {
                    mb = co_await from_reader.ReadMultiBuffer();
                } else if constexpr (std::is_same_v<
                                         std::remove_cvref_t<FromReader>,
                                         std::remove_cvref_t<FromControl>>) {
                    mb = co_await from_reader.ReadMultiBuffer();
                } else {
                    mb = co_await ReadMultiBuffer(from_reader, from_control);
                }
            }

            if (my_state.cancellation_error != ErrorCode::OK)
                throw transport::LinkError(my_state.cancellation_error);
            if (close_state.complete) break;
            if (!buf::HasData(mb)) {
                if ((my_state.half_close_expired || ConsumeRelayTimeoutSignals(from_control, to_control))) {
                    close_state.Mark(operation_side_is_client);
                    error = ErrorCode::RELAY_TIMEOUT;
                    LOG_CONN_DEBUG(ctx, "[relay] {} relay timeout, transferred={}B",
                                   is_upload ? "up" : "down", total_bytes);
                    CancelRelayControls(from_control, to_control, limits);
                    break;
                }

                LOG_CONN_DEBUG(ctx, "[relay] {} EOF after {}B", is_upload ? "up" : "down", total_bytes);
                my_state.eof = true;
                close_state.Mark(is_upload);
                const auto action = ReadEofAction(from_reader);
                if (action == transport::EofAction::CloseLink || WriteShutdownClosesLink(to_writer)) {
                    // The parent cancels and joins the remaining direction.
                    // Wire shutdown happens after the join, never while another
                    // direction still borrows this link or writes its frames.
                    close_state.Complete();
                    break;
                }
                if (action == transport::EofAction::ShutdownPeerWrite) {
                    co_await ShutdownWriteForClose(to_writer, to_control);
                }
                if (!peer_state.eof) {
                    if (half_close_timeout.count() > 0) {
                        const auto now = SteadyClock::now();
                        const auto room = std::chrono::duration_cast<std::chrono::seconds>(
                            SteadyClock::time_point::max() - now);
                        const auto deadline = half_close_timeout >= room
                            ? SteadyClock::time_point::max() : now + half_close_timeout;
                        peer_state.half_close_deadline = deadline;
                        peer_state.half_close_timer = TimeoutScheduler::ForIoContext(io_context).ScheduleAfter(
                            std::chrono::ceil<std::chrono::milliseconds>(deadline - now),
                            [&from_control, &to_control, &peer_state, limits] {
                                peer_state.half_close_expired = true;
                                CancelRelayControls(from_control, to_control, limits);
                            });

                        LOG_CONN_DEBUG(ctx, "[relay] {} half-close: arming absolute timeout {}s for peer direction",
                                       is_upload ? "up" : "down", half_close_timeout.count());
                        from_control.SetIdleTimeout(half_close_timeout);
                        to_control.SetIdleTimeout(half_close_timeout);
                        // 一侧已经 EOF 后，另一侧最多只允许保留 half_close_timeout。
                        // 当前方向退出后，peer direction 会按共享 absolute deadline 收敛。
                        from_control.SetWriteTimeout(half_close_timeout);
                        to_control.SetWriteTimeout(half_close_timeout);
                        // The scoped half-close timer cancels both I/O and rate
                        // waits, including writes already in flight. No second
                        // transport phase deadline is needed for this budget.
                    } else {
                        LOG_CONN_DEBUG(ctx, "[relay] {} half-close: timeout=0, cancel peer immediately",
                                       is_upload ? "up" : "down");
                        // 超时为 0：立即终止对端方向
                        peer_state.half_close_expired = true;
                        CancelRelayControls(from_control, to_control, limits);
                    }
                } else {
                    LOG_CONN_DEBUG(ctx, "[relay] {} EOF, peer already EOF, both done",
                                   is_upload ? "up" : "down");
                }
                break;
            }

            if (is_upload) {
                ObserveUdpRelayTarget(ctx, mb);
            }

            size_t n = buf::TotalLen(mb);
            if constexpr (RateLimited) {
                auto& bucket = is_upload ? limits->up : limits->down;
                auto& delay = is_upload ? limits->up_wait : limits->down_wait;
                co_await delay.WaitFor(bucket.Consume(n));
            }
            if (my_state.half_close_expired) throw transport::LinkError(ErrorCode::RELAY_TIMEOUT);
            if (limits && limits->cancelled) throw transport::LinkError(limits->cancellation_error);
            if (close_state.complete) break;

            operation_side_is_client = !is_upload;
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
            ObserveRelayPacket(ctx, is_upload);
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

        } catch (const transport::WriteClosed&) {
            // Do not count an unstarted write or discard the opposite input.
            my_state.eof = true;
            close_state.Mark(operation_side_is_client);
            break;
        } catch (const transport::LinkError& e) {
            close_state.Mark(operation_side_is_client);
            error = e.code();
            if (error == ErrorCode::CANCELLED &&
                (my_state.half_close_expired || ConsumeRelayTimeoutSignals(from_control, to_control))) {
                error = ErrorCode::RELAY_TIMEOUT;
            }
            if (error == ErrorCode::CANCELLED && close_state.complete) {
                error = ErrorCode::OK;
                break;
            }
            ctx.outbound.failure_detail_code = ErrorCodeToString(error);
            CancelRelayControls(from_control, to_control, limits);
            break;
        } catch (const IoSystemError& e) {
            close_state.Mark(operation_side_is_client);
            error = MapAsioError(e.code());
            const bool io_cancelled = error == ErrorCode::CANCELLED;
            if (error == ErrorCode::CANCELLED && close_state.complete &&
                !my_state.half_close_expired && !ConsumeRelayTimeoutSignals(from_control, to_control)) {
                error = ErrorCode::OK;
                break;
            }
            if (!io_cancelled && ctx.outbound.os_error_code == 0) {
                ctx.outbound.os_error_code = e.code().value();
                ctx.outbound.failure_detail_code = ErrorCodeToString(error);
            }
            if (error == ErrorCode::CANCELLED &&
                (my_state.half_close_expired || ConsumeRelayTimeoutSignals(from_control, to_control))) {
                error = ErrorCode::RELAY_TIMEOUT;
                LOG_CONN_DEBUG(ctx, "[relay] {} cancelled by timeout, transferred={}B",
                               is_upload ? "up" : "down", total_bytes);
            } else {
                LOG_CONN_DEBUG(ctx, "[relay] {} error: {} ({}), transferred={}B",
                               is_upload ? "up" : "down",
                               ErrorCodeToString(error), e.what(), total_bytes);
            }
            CancelRelayControls(from_control, to_control, limits);
            break;
        } catch (const std::bad_alloc&) {
            close_state.MarkLocalFailure();
            error = ErrorCode::RESOURCE_EXHAUSTED;
            ctx.outbound.failure_detail_code = ErrorCodeToString(error);
            CancelRelayControls(from_control, to_control, limits);
            break;
        } catch (const std::exception& e) {
            close_state.Mark(operation_side_is_client);
            error = ErrorCode::RELAY_WRITE_FAILED;
            LOG_CONN_DEBUG(ctx, "[relay] {} exception: {}, transferred={}B",
                           is_upload ? "up" : "down", e.what(), total_bytes);
            CancelRelayControls(from_control, to_control, limits);
            break;
        } catch (...) {
            close_state.Mark(operation_side_is_client);
            error = ErrorCode::RELAY_WRITE_FAILED;
            LOG_CONN_DEBUG(ctx, "[relay] {} exception: unknown, transferred={}B",
                           is_upload ? "up" : "down", total_bytes);
            CancelRelayControls(from_control, to_control, limits);
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
    const RelayConfig& config = RelayConfig{},
    buf::MultiBuffer initial_payload = {}) {

    using namespace net::experimental::awaitable_operators;

    RelayResult result;
    relay_detail::RelayDirectionState client_state;
    relay_detail::RelayDirectionState target_state;
    relay_detail::RelayCloseState close_state(io_context);
    const auto parent_cancellation = co_await net::this_coro::cancellation_state;

    LOG_CONN_DEBUG(ctx, "Relay started, speed_limit={}, uplink_only={}s, downlink_only={}s",
                   config.speed_limit > 0 ?
                   std::format("{}MB/s", config.speed_limit / 1024 / 1024) : "unlimited",
                   config.uplink_only.count(),
                   config.downlink_only.count());

    std::unique_ptr<relay_detail::RelayRateLimits> limits;
    if (config.speed_limit != 0)
        limits = std::make_unique<relay_detail::RelayRateLimits>(io_context, config.speed_limit);
    struct CancellationContext {
        ClientControl& client;
        TargetEndpoint& target;
        relay_detail::RelayDirectionState& client_state;
        relay_detail::RelayDirectionState& target_state;
        relay_detail::RelayRateLimits* limits;
        bool notifying = false;

        void Cancel(ErrorCode reason) noexcept {
            if (notifying) return;
            notifying = true;
            if (client_state.half_close_expired || target_state.half_close_expired ||
                relay_detail::ConsumeRelayTimeoutSignals(client, target)) reason = ErrorCode::RELAY_TIMEOUT;
            auto& retained = client_state.cancellation_error;
            if (retained == ErrorCode::OK || retained == ErrorCode::CANCELLED) retained = reason;
            target_state.cancellation_error = retained;
            if (limits) limits->Cancel(retained);
            relay_detail::CancelIfSupported(client);
            relay_detail::CancelIfSupported(target);
            notifying = false;
        }
    } cancellation_context{client_control, target, client_state, target_state, limits.get()};
    const auto cancel = [](void* raw, transport::Cancellation cancellation) noexcept {
        static_cast<CancellationContext*>(raw)->Cancel(cancellation.reason);
    };
    transport::CancellationSubscription client_cancel(client_reader.Cancellation(), cancel, &cancellation_context);
    transport::CancellationSubscription target_cancel(target.Cancellation(), cancel, &cancellation_context);

    std::pair<uint64_t, ErrorCode> up_result;
    std::pair<uint64_t, ErrorCode> down_result;
    auto transfer = [&]() -> net::awaitable<void> {
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
                close_state,
                config.downlink_only,
                &stats,
                true,
                limits.get(),
                &ctx.traffic.bytes_up,
                ctx,
                std::move(initial_payload)) &&
            relay_detail::RelayOneDirectionImpl<false>(
                io_context,
                target,
                target,
                client_writer,
                client_control,
                target_state,
                client_state,
                close_state,
                config.uplink_only,
                &stats,
                false,
                limits.get(),
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
                close_state,
                config.downlink_only,
                &stats,
                true,
                limits.get(),
                &ctx.traffic.bytes_up,
                ctx,
                std::move(initial_payload)) &&
            relay_detail::RelayOneDirectionImpl<true>(
                io_context,
                target,
                target,
                client_writer,
                client_control,
                target_state,
                client_state,
                close_state,
                config.uplink_only,
                &stats,
                false,
                limits.get(),
                &ctx.traffic.bytes_down,
                ctx)
        );
        up_result = up;
        down_result = down;
    }
    };
    auto watch_complete = [&]() -> net::awaitable<void> {
        if (!close_state.complete) co_await close_state.wake.WaitFor(std::chrono::milliseconds::max());
        if (!close_state.complete) throw transport::LinkError(ErrorCode::CANCELLED);
    };
    (void)co_await (transfer() || watch_complete());

    auto [bytes_up, error_up] = up_result;
    auto [bytes_down, error_down] = down_result;

    client_state.half_close_timer = {};
    target_state.half_close_timer = {};
    client_control.ClearPhaseDeadline();
    target.ClearPhaseDeadline();

    result.bytes_up = bytes_up;
    result.bytes_down = bytes_down;

    ctx.traffic.bytes_up = bytes_up;
    ctx.traffic.bytes_down = bytes_down;

    result.error = relay_detail::SelectRelayError(error_up, error_down);
    if (result.error == ErrorCode::OK && parent_cancellation.cancelled() != net::cancellation_type::none)
        result.error = ErrorCode::CANCELLED;
    if (result.error != ErrorCode::OK)
        ctx.outbound.failure_detail_code = ErrorCodeToString(result.error);
    result.client_closed_first = close_state.client;
    result.close_side_known = close_state.known;

    LOG_CONN_DEBUG(ctx, "Relay CLOSING: up_err={} down_err={} up={}B down={}B closer={}",
                   ErrorCodeToString(error_up), ErrorCodeToString(error_down),
                   bytes_up, bytes_down,
                   result.client_closed_first ? "client" : "target");

    if (result.error != ErrorCode::OK) {
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
        try {
            co_await (shutdown_client() && shutdown_target());
        } catch (...) {
            result.error = relay_detail::CaptureShutdownFailure(ctx);
            if (client_state.cancellation_error != ErrorCode::OK &&
                client_state.cancellation_error != ErrorCode::CANCELLED)
                result.error = client_state.cancellation_error;
            ctx.outbound.failure_detail_code = ErrorCodeToString(result.error);
        }
        client_control.Cancel();
        target.Cancel();
        if (result.error == ErrorCode::OK) {
            relay_detail::CloseIfSupported(client_control);
            relay_detail::CloseIfSupported(target);
        } else {
            relay_detail::CloseAbortiveIfSupported(client_control);
            relay_detail::CloseAbortiveIfSupported(target);
        }
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
    const RelayConfig& config = RelayConfig{},
    buf::MultiBuffer initial_payload = {}) {

    using namespace net::experimental::awaitable_operators;

    LOG_CONN_DEBUG(ctx, "Relay started without client control, speed_limit={}",
                   config.speed_limit > 0 ?
                   std::format("{}MB/s", config.speed_limit / 1024 / 1024) : "unlimited");

    std::unique_ptr<relay_detail::RelayRateLimits> limits;
    if (config.speed_limit != 0)
        limits = std::make_unique<relay_detail::RelayRateLimits>(io_context, config.speed_limit);
    relay_detail::RelayCloseState close_state(io_context);
    // The watchdog participates in the same joined coroutine group. Its
    // completion cancels reader/writer awaits even when no client control exists.
    struct StopState {
        relay_detail::RelayRateLimits* limits;
        relay_detail::RelayCloseState& close;
        ErrorCode reason = ErrorCode::OK;

        StopState(relay_detail::RelayCloseState& close, relay_detail::RelayRateLimits* value)
            : limits(value), close(close) {}
        void Request(ErrorCode error) noexcept {
            if (reason == ErrorCode::OK ||
                (reason == ErrorCode::CANCELLED && error != ErrorCode::CANCELLED)) reason = error;
            if (limits) limits->Cancel(error);
            close.wake.Cancel();
        }
    } stop(close_state, limits.get());
    struct CancelContext { StopState& stop; TargetEndpoint& target; } cancel_context{stop, target};
    transport::CancellationSubscription target_cancel(target.Cancellation(), [](void* raw, transport::Cancellation cancellation) noexcept {
        auto& context = *static_cast<CancelContext*>(raw);
        context.stop.Request(relay_detail::ConsumeRelayTimeoutSignals(context.target, context.target)
            ? ErrorCode::RELAY_TIMEOUT : cancellation.reason);
    }, &cancel_context);
    transport::CancellationSubscription client_cancel(client_reader.Cancellation(), [](void* raw, transport::Cancellation cancellation) noexcept {
        auto& context = *static_cast<CancelContext*>(raw);
        context.stop.Request(cancellation.reason);
        relay_detail::CancelIfSupported(context.target);
    }, &cancel_context);

    auto cancel_target = [&]() noexcept {
        stop.Request(ErrorCode::CANCELLED);
        relay_detail::CancelIfSupported(target);
    };

    std::pair<uint64_t, ErrorCode> up_result{0, ErrorCode::OK};
    std::pair<uint64_t, ErrorCode> down_result{0, ErrorCode::OK};
    ErrorCode first_error = ErrorCode::OK;
    bool upload_eof = false;
    bool download_eof = false;
    auto& timeout_scheduler = TimeoutScheduler::ForIoContext(io_context);
    TimeoutToken half_close_token;
    const auto parent_cancellation = co_await net::this_coro::cancellation_state;

    auto remember_error = [&](ErrorCode error) {
        if (error != ErrorCode::OK && (first_error == ErrorCode::OK ||
            (first_error == ErrorCode::CANCELLED && error != ErrorCode::CANCELLED))) first_error = error;
    };

    auto arm_half_close_timeout = [&](std::chrono::seconds timeout) {
        if (half_close_token.Valid()) return;
        if (timeout <= std::chrono::seconds::zero()) {
            stop.Request(ErrorCode::RELAY_TIMEOUT);
            cancel_target();
            return;
        }
        const auto maximum = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::milliseconds::max());
        const auto delay = timeout >= maximum ? std::chrono::milliseconds::max() :
            std::chrono::duration_cast<std::chrono::milliseconds>(timeout);
        half_close_token = timeout_scheduler.ScheduleAfter(delay, [&stop, &cancel_target] {
            stop.Request(ErrorCode::RELAY_TIMEOUT);
            cancel_target();
        });
    };

    auto upload = [&]() -> net::awaitable<std::pair<uint64_t, ErrorCode>> {
        uint64_t bytes = 0;
        bool operation_side_is_client = true;
        LocalStatsAccumulator stats_acc;
        while (true) {
            try {
                if (stop.reason != ErrorCode::OK) throw transport::LinkError(stop.reason);
                if (close_state.complete) {
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                    co_return std::make_pair(bytes, ErrorCode::OK);
                }
                operation_side_is_client = true;
                buf::MultiBuffer mb = std::move(initial_payload);
                if (!buf::HasData(mb)) {
                    mb.clear();
                    mb = co_await client_reader.ReadMultiBuffer();
                }
                if (!buf::HasData(mb)) {
                    upload_eof = true;
                    close_state.Mark(true);
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                    if (relay_detail::ReadEofAction(client_reader) == transport::EofAction::CloseLink ||
                        relay_detail::WriteShutdownClosesLink(target)) {
                        close_state.Complete();
                        co_return std::make_pair(bytes, ErrorCode::OK);
                    }
                    co_await relay_detail::ShutdownWriteForClose(target);
                    if (!download_eof) arm_half_close_timeout(config.downlink_only);
                    co_return std::make_pair(bytes, ErrorCode::OK);
                }
                relay_detail::ObserveUdpRelayTarget(ctx, mb);
                const size_t n = buf::TotalLen(mb);
                if (limits) co_await limits->up_wait.WaitFor(limits->up.Consume(n));
                if (stop.reason != ErrorCode::OK) throw transport::LinkError(stop.reason);
                if (limits && limits->cancelled) throw transport::LinkError(ErrorCode::CANCELLED);
                if (close_state.complete) {
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                    co_return std::make_pair(bytes, ErrorCode::OK);
                }
                operation_side_is_client = false;
                co_await target.WriteMultiBuffer(std::move(mb));
                bytes += n;
                relay_detail::ObserveRelayPacket(ctx, true);
                ctx.traffic.bytes_up = bytes;
                stats_acc.AddBytesOut(n);
                if (stats_acc.bytes_in + stats_acc.bytes_out >= relay_detail::kRelayStatsFlushBytes) {
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                }
            } catch (const transport::WriteClosed&) {
                upload_eof = true;
                close_state.Mark(operation_side_is_client);
                relay_detail::FlushRelayStats(&stats, stats_acc);
                co_return std::make_pair(bytes, ErrorCode::OK);
            } catch (const transport::LinkError& e) {
                close_state.Mark(operation_side_is_client);
                relay_detail::FlushRelayStats(&stats, stats_acc);
                ErrorCode error = e.code();
                if (error == ErrorCode::CANCELLED && close_state.complete && stop.reason == ErrorCode::OK)
                    co_return std::make_pair(bytes, ErrorCode::OK);
                if (error == ErrorCode::CANCELLED &&
                    (stop.reason == ErrorCode::RELAY_TIMEOUT || relay_detail::ConsumeRelayTimeoutSignals(target, target))) {
                    error = ErrorCode::RELAY_TIMEOUT;
                }
                ctx.outbound.failure_detail_code = ErrorCodeToString(error);
                up_result = std::make_pair(bytes, error);
                remember_error(error);
                cancel_target();
                throw;
            } catch (const IoSystemError& e) {
                close_state.Mark(operation_side_is_client);
                relay_detail::FlushRelayStats(&stats, stats_acc);
                ErrorCode error = MapAsioError(e.code());
                const bool io_cancelled = error == ErrorCode::CANCELLED;
                if (error == ErrorCode::CANCELLED && close_state.complete && stop.reason == ErrorCode::OK &&
                    !relay_detail::ConsumeRelayTimeoutSignals(target, target))
                    co_return std::make_pair(bytes, ErrorCode::OK);
                if (error == ErrorCode::CANCELLED && relay_detail::ConsumeRelayTimeoutSignals(target, target)) {
                    error = ErrorCode::RELAY_TIMEOUT;
                }
                if (!io_cancelled && ctx.outbound.os_error_code == 0) {
                    ctx.outbound.os_error_code = e.code().value();
                    ctx.outbound.failure_detail_code = ErrorCodeToString(error);
                }
                up_result = std::make_pair(bytes, error);
                remember_error(error);
                cancel_target();
                throw;
            } catch (const std::bad_alloc&) {
                close_state.MarkLocalFailure();
                relay_detail::FlushRelayStats(&stats, stats_acc);
                ctx.outbound.failure_detail_code = ErrorCodeToString(ErrorCode::RESOURCE_EXHAUSTED);
                up_result = std::make_pair(bytes, ErrorCode::RESOURCE_EXHAUSTED);
                remember_error(ErrorCode::RESOURCE_EXHAUSTED);
                cancel_target();
                throw;
            } catch (...) {
                close_state.Mark(operation_side_is_client);
                relay_detail::FlushRelayStats(&stats, stats_acc);
                up_result = std::make_pair(bytes, ErrorCode::RELAY_WRITE_FAILED);
                remember_error(ErrorCode::RELAY_WRITE_FAILED);
                cancel_target();
                throw;
            }
        }
    };

    auto download = [&]() -> net::awaitable<std::pair<uint64_t, ErrorCode>> {
        uint64_t bytes = 0;
        bool operation_side_is_client = false;
        LocalStatsAccumulator stats_acc;
        while (true) {
            try {
                if (stop.reason != ErrorCode::OK) throw transport::LinkError(stop.reason);
                if (close_state.complete) {
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                    co_return std::make_pair(bytes, ErrorCode::OK);
                }
                operation_side_is_client = false;
                buf::MultiBuffer mb = co_await target.ReadMultiBuffer();
                if (!buf::HasData(mb)) {
                    download_eof = true;
                    close_state.Mark(false);
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                    if (relay_detail::ReadEofAction(target) == transport::EofAction::CloseLink ||
                        relay_detail::WriteShutdownClosesLink(client_writer)) {
                        close_state.Complete();
                        co_return std::make_pair(bytes, ErrorCode::OK);
                    }
                    co_await relay_detail::ShutdownWriteForClose(client_writer);
                    if (!upload_eof) arm_half_close_timeout(config.uplink_only);
                    co_return std::make_pair(bytes, ErrorCode::OK);
                }
                const size_t n = buf::TotalLen(mb);
                if (limits) co_await limits->down_wait.WaitFor(limits->down.Consume(n));
                if (stop.reason != ErrorCode::OK) throw transport::LinkError(stop.reason);
                if (limits && limits->cancelled) throw transport::LinkError(ErrorCode::CANCELLED);
                if (close_state.complete) {
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                    co_return std::make_pair(bytes, ErrorCode::OK);
                }
                operation_side_is_client = true;
                co_await client_writer.WriteMultiBuffer(std::move(mb));
                bytes += n;
                relay_detail::ObserveRelayPacket(ctx, false);
                ctx.traffic.bytes_down = bytes;
                stats_acc.AddBytesIn(n);
                if (stats_acc.bytes_in + stats_acc.bytes_out >= relay_detail::kRelayStatsFlushBytes) {
                    relay_detail::FlushRelayStats(&stats, stats_acc);
                }
            } catch (const transport::WriteClosed&) {
                download_eof = true;
                close_state.Mark(operation_side_is_client);
                relay_detail::FlushRelayStats(&stats, stats_acc);
                co_return std::make_pair(bytes, ErrorCode::OK);
            } catch (const transport::LinkError& e) {
                close_state.Mark(operation_side_is_client);
                relay_detail::FlushRelayStats(&stats, stats_acc);
                ErrorCode error = e.code();
                if (error == ErrorCode::CANCELLED && close_state.complete && stop.reason == ErrorCode::OK)
                    co_return std::make_pair(bytes, ErrorCode::OK);
                if (error == ErrorCode::CANCELLED &&
                    (stop.reason == ErrorCode::RELAY_TIMEOUT || relay_detail::ConsumeRelayTimeoutSignals(target, target))) {
                    error = ErrorCode::RELAY_TIMEOUT;
                }
                ctx.outbound.failure_detail_code = ErrorCodeToString(error);
                down_result = std::make_pair(bytes, error);
                remember_error(error);
                cancel_target();
                throw;
            } catch (const IoSystemError& e) {
                close_state.Mark(operation_side_is_client);
                relay_detail::FlushRelayStats(&stats, stats_acc);
                ErrorCode error = MapAsioError(e.code());
                const bool io_cancelled = error == ErrorCode::CANCELLED;
                if (error == ErrorCode::CANCELLED && close_state.complete && stop.reason == ErrorCode::OK &&
                    !relay_detail::ConsumeRelayTimeoutSignals(target, target))
                    co_return std::make_pair(bytes, ErrorCode::OK);
                if (!io_cancelled && ctx.outbound.os_error_code == 0) {
                    ctx.outbound.os_error_code = e.code().value();
                    ctx.outbound.failure_detail_code = ErrorCodeToString(error);
                }
                if (error == ErrorCode::CANCELLED &&
                    (stop.reason == ErrorCode::RELAY_TIMEOUT || relay_detail::ConsumeRelayTimeoutSignals(target, target))) {
                    error = ErrorCode::RELAY_TIMEOUT;
                }
                down_result = std::make_pair(bytes, error);
                remember_error(error);
                cancel_target();
                throw;
            } catch (const std::bad_alloc&) {
                close_state.MarkLocalFailure();
                relay_detail::FlushRelayStats(&stats, stats_acc);
                ctx.outbound.failure_detail_code = ErrorCodeToString(ErrorCode::RESOURCE_EXHAUSTED);
                down_result = std::make_pair(bytes, ErrorCode::RESOURCE_EXHAUSTED);
                remember_error(ErrorCode::RESOURCE_EXHAUSTED);
                cancel_target();
                throw;
            } catch (...) {
                close_state.Mark(operation_side_is_client);
                relay_detail::FlushRelayStats(&stats, stats_acc);
                down_result = std::make_pair(bytes, ErrorCode::RELAY_WRITE_FAILED);
                remember_error(ErrorCode::RELAY_WRITE_FAILED);
                cancel_target();
                throw;
            }
        }
    };

    auto transfer = [&]() -> net::awaitable<void> {
        auto [up, down] = co_await (upload() && download());
        up_result = up;
        down_result = down;
    };
    auto watch_stop = [&]() -> net::awaitable<void> {
        if (stop.reason == ErrorCode::OK && !close_state.complete)
            co_await close_state.wake.WaitFor(std::chrono::milliseconds::max());
        if (stop.reason == ErrorCode::OK && !close_state.complete) throw transport::LinkError(ErrorCode::CANCELLED);
    };
    try {
        (void)co_await (transfer() || watch_stop());
    } catch (...) {
        if (first_error == ErrorCode::OK) {
            first_error = parent_cancellation.cancelled() != net::cancellation_type::none
                ? ErrorCode::CANCELLED : ErrorCode::INTERNAL;
        }
    }
    remember_error(stop.reason);
    timeout_scheduler.Cancel(half_close_token);

    RelayResult result;
    result.bytes_up = first_error == ErrorCode::OK ? up_result.first : ctx.traffic.bytes_up;
    result.bytes_down = first_error == ErrorCode::OK ? down_result.first : ctx.traffic.bytes_down;
    result.client_closed_first = close_state.client;
    result.close_side_known = close_state.known;
    if (first_error != ErrorCode::OK) {
        result.error = first_error;
    } else if (up_result.second != ErrorCode::OK) {
        result.error = up_result.second;
    } else if (down_result.second != ErrorCode::OK) {
        result.error = down_result.second;
    }
    if (result.error != ErrorCode::OK)
        ctx.outbound.failure_detail_code = ErrorCodeToString(result.error);
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
        try {
            co_await (shutdown_client() && shutdown_target());
        } catch (...) {
            result.error = relay_detail::CaptureShutdownFailure(ctx);
            if (stop.reason != ErrorCode::OK && stop.reason != ErrorCode::CANCELLED)
                result.error = stop.reason;
            ctx.outbound.failure_detail_code = ErrorCodeToString(result.error);
        }
        target.Cancel();
        if (result.error == ErrorCode::OK) relay_detail::CloseIfSupported(target);
        else relay_detail::CloseAbortiveIfSupported(target);
    }

    LOG_CONN_DEBUG(ctx, "Relay finished without client control: up={} down={}",
                   result.bytes_up, result.bytes_down);
    co_return result;
}

}  // namespace acpp
