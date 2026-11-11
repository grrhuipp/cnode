#pragma once

#include "common/allocator.hpp"
#include "common/defaults.hpp"
#include "common/error.hpp"
#include "common/session.hpp"
#include "common/buf/multi_buffer.hpp"
#include "transport/async_stream.hpp"
#include "transport/failure.hpp"
#include "app/stats.hpp"
#include "infra/log.hpp"
#include "transport/internet/async_delay.hpp"

#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>
#include <chrono>
#include <cstdint>
#include <memory>
#include <cstddef>
#include <utility>

// ============================================================================
// Relay 配置
// ============================================================================
struct RelayConfig {
    std::chrono::seconds uplink_only{defaults::kUplinkOnlyTimeout};     // 下行 EOF 后上行最多保留多久
    std::chrono::seconds downlink_only{defaults::kDownlinkOnlyTimeout}; // 上行 EOF 后下行最多保留多久
    uint64_t speed_limit = 0;              // bytes/s，0 = 不限速
};

// ============================================================================
// Relay 结果
// ============================================================================
struct RelayResult : ResultStatus {
    uint64_t bytes_up = 0;
    uint64_t bytes_down = 0;
    bool client_closed_first = false;
    bool close_side_known = false;
};

namespace relay_detail {

inline constexpr uint64_t kRelayStatsFlushBytes = 64 * 1024;
inline constexpr auto kRelayCloseGraceTimeout = std::chrono::seconds(1);

// 两个方向的令牌桶与等待事件；只为限速转发分配，不限速的转发帧不携带它。
// 全部状态与订阅存活到两个方向和看门狗汇合之后。定义见 src/app/relay.cpp。
struct RelayRateLimits;
struct RelayRateLimitsDelete {
    void operator()(RelayRateLimits* limits) const noexcept;
};
using RelayRateLimitsPtr = std::unique_ptr<RelayRateLimits, RelayRateLimitsDelete>;

// rate 为 0（不限速）时返回空指针。
RelayRateLimitsPtr AllocateRelayRateLimits(net::io_context& io, uint64_t rate);
void CancelRelayRateWaits(RelayRateLimits& limits) noexcept;
// 预留本方向的字节额度并返回需要等待的时长；为零时调用方不得发起等待，
// 预算内的包不承担等待协程。
[[nodiscard]] std::chrono::milliseconds ReserveRelayBytes(
    RelayRateLimits& limits, bool upload, size_t bytes) noexcept;
// 每个方向同一时刻至多一个等待；取消经 CancelRelayRateWaits 投递。
[[nodiscard]] net::awaitable<void> WaitRelayRate(
    RelayRateLimits& limits, bool upload, std::chrono::milliseconds delay);

template <typename Endpoint>
void CloseIfSupported(Endpoint& endpoint) noexcept {
    if constexpr (requires { endpoint.Close(); }) {
        try { endpoint.Close(); } catch (...) {}
    }
}

template <typename Endpoint>
void CloseAbortiveIfSupported(Endpoint& endpoint) noexcept {
    if constexpr (requires { endpoint.CloseAbortive(); }) {
        try { endpoint.CloseAbortive(); } catch (...) {}
    } else {
        if constexpr (requires { endpoint.SetAbortiveClose(true); }) endpoint.SetAbortiveClose(true);
        CloseIfSupported(endpoint);
    }
}

template <typename Endpoint>
void CancelIfSupported(Endpoint& endpoint) noexcept {
    if constexpr (requires { endpoint.Cancel(); }) {
        try { endpoint.Cancel(); } catch (...) {}
    }
}

template <typename Writer, typename Control>
net::awaitable<void> ShutdownWriteForClose(
    Writer& writer, Control& control, bool preserve_phase_deadline = false) {
    if constexpr (requires { control.SetWriteTimeout(kRelayCloseGraceTimeout); }) {
        control.SetWriteTimeout(kRelayCloseGraceTimeout);
    }
    if (!preserve_phase_deadline) {
        if constexpr (requires { control.StartPhaseDeadline(kRelayCloseGraceTimeout); }) {
            (void)control.StartPhaseDeadline(kRelayCloseGraceTimeout);
        }
    }
    try {
        if constexpr (requires { writer.AsyncShutdownWrite(); }) {
            co_await writer.AsyncShutdownWrite();
        } else if constexpr (requires { control.AsyncShutdownWrite(); }) {
            co_await control.AsyncShutdownWrite();
        } else if constexpr (requires { control.ShutdownWrite(); }) {
            control.ShutdownWrite();
        }
    } catch (...) {
        if (!preserve_phase_deadline) {
            if constexpr (requires { control.ClearPhaseDeadline(); }) control.ClearPhaseDeadline();
        }
        throw;
    }
    if (!preserve_phase_deadline) {
        if constexpr (requires { control.ClearPhaseDeadline(); }) control.ClearPhaseDeadline();
    }
}

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

void FlushRelayStats(StatsShard& stats, LocalStatsAccumulator& acc);

template <typename Control>
bool ConsumeTimeoutSignals(Control& control) {
    // Consume every flag, including when another flag is already set.
    const bool read = control.ConsumeReadTimeout();
    const bool write = control.ConsumeWriteTimeout();
    const bool idle = control.ConsumeIdleTimeout();
    const bool phase = control.ConsumePhaseDeadline();
    return read || write || idle || phase;
}

enum class RelayPhase { Transferring, HalfClosed, Completing, Stopping, Joined };
struct RelayDirectionState {
    bool eof = false;
    bool write_shutdown = false;
};

struct RelayState {
    explicit RelayState(net::io_context& io);

    void Mark(bool client_side) noexcept;
    void Stop(ErrorCode error) noexcept;
    void Complete() noexcept;
    bool Ending() const noexcept {
        return phase == RelayPhase::Completing || phase == RelayPhase::Stopping;
    }

    RelayPhase phase = RelayPhase::Transferring;
    ErrorCode reason = ErrorCode::OK;
    bool close_side_known = false;
    bool client_closed_first = false;
    bool local_failure = false;
    RelayDirectionState up;
    RelayDirectionState down;
    SignalChannel wake;
};

}  // namespace relay_detail

// A null client control denotes split/logical input. It changes only the
// available transport controls, never EOF, error, accounting or join semantics.
// The reader cancellation source and the joined watchdog cover this case too.
template <typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLink(
    net::io_context& io_context,
    transport::MultiBufferReader& client_reader,
    transport::MultiBufferWriter& client_writer,
    AsyncStream* client_control,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    const RelayConfig& config = RelayConfig{},
    buf::MultiBufferBatch initial_payload = {}) {

    using namespace net::experimental::awaitable_operators;
    using relay_detail::RelayPhase;
    relay_detail::RelayState state(io_context);
    const auto limits = relay_detail::AllocateRelayRateLimits(io_context, config.speed_limit);
    ctx.traffic.bytes_up = ctx.traffic.bytes_down = 0;
    const auto parent_cancellation = co_await net::this_coro::cancellation_state;

    struct CancellationContext {
        struct Subscription final : transport::CancellationSubscription {
            explicit Subscription(CancellationContext& owner) noexcept : owner(owner) {}
            CancellationContext& owner;
        private:
            void OnCancellation(transport::Cancellation cancellation) noexcept override {
                owner.Stop(cancellation.reason);
            }
        };
        AsyncStream* client;
        TargetEndpoint& target;
        relay_detail::RelayState& state;
        relay_detail::RelayRateLimits* limits;
        bool notifying = false;
        Subscription client_cancel{*this};
        Subscription target_cancel{*this};

        CancellationContext(AsyncStream* client, TargetEndpoint& target,
                            relay_detail::RelayState& state, relay_detail::RelayRateLimits* limits)
            : client(client), target(target), state(state), limits(limits) {}

        bool ConsumeTimeout() {
            const bool target_timeout = relay_detail::ConsumeTimeoutSignals(target);
            const bool client_timeout = client && relay_detail::ConsumeTimeoutSignals(*client);
            return target_timeout || client_timeout;
        }
        void Stop(ErrorCode reason) noexcept {
            if (notifying) return;
            notifying = true;
            if (ConsumeTimeout()) reason = ErrorCode::RELAY_TIMEOUT;
            state.Stop(reason);
            if (limits) relay_detail::CancelRelayRateWaits(*limits);
            if (client) relay_detail::CancelIfSupported(*client);
            relay_detail::CancelIfSupported(target);
            notifying = false;
        }
    } cancellation(client_control, target, state, limits.get());
    cancellation.client_cancel.Resubscribe(client_reader.Cancellation());
    cancellation.target_cancel.Resubscribe(target.Cancellation());

    auto arm_half_close = [&](std::chrono::seconds timeout) {
        if (state.phase != RelayPhase::Transferring) return;
        state.phase = RelayPhase::HalfClosed;
        // One absolute budget covers the remaining read, write AND rate wait,
        // whether or not the input owns a physical control. Never renew it on I/O.
        if (timeout <= std::chrono::seconds::zero()) cancellation.Stop(ErrorCode::RELAY_TIMEOUT);
        else if (!target.StartPhaseDeadline(timeout)) cancellation.Stop(ErrorCode::INTERNAL);
    };

    auto direction = [&](auto& reader, auto& writer, auto* control, bool upload)
        -> net::awaitable<void> {
        auto& current = upload ? state.up : state.down;
        const auto& peer = upload ? state.down : state.up;
        auto& bytes = upload ? ctx.traffic.bytes_up : ctx.traffic.bytes_down;
        LocalStatsAccumulator acc;
        bool operation_side_is_client = upload;
        bool writing = false;
        try {
            const auto direction_cancellation = co_await net::this_coro::cancellation_state;
            while (!state.Ending()) {
                operation_side_is_client = upload;
                writing = false;
                buf::MultiBuffer payload;
                if (upload && !initial_payload.empty()) payload = initial_payload.PopFront();
                else payload = co_await reader.ReadMultiBuffer();
                if (state.Ending()) break;
                if (direction_cancellation.cancelled() != net::cancellation_type::none)
                    throw transport::LinkError(ErrorCode::CANCELLED);
                if (payload.byte_size() == 0 && !payload.HasUDP()) {
                    if (cancellation.ConsumeTimeout()) {
                        cancellation.Stop(ErrorCode::RELAY_TIMEOUT);
                        break;
                    }
                    current.eof = true;
                    state.Mark(upload);
                    const auto action = relay_detail::ReadEofAction(reader);
                    if (action == transport::EofAction::CloseLink || relay_detail::WriteShutdownClosesLink(writer)) {
                        // No wire shutdown until both directions release their borrows.
                        state.Complete();
                        break;
                    }
                    if (!peer.eof) {
                        arm_half_close(upload ? config.downlink_only : config.uplink_only);
                        if (state.Ending()) break;
                    }
                    if (action == transport::EofAction::ShutdownPeerWrite) {
                        operation_side_is_client = !upload;
                        writing = true;
                        const bool preserve_phase_deadline =
                            upload && !peer.eof && state.phase == RelayPhase::HalfClosed;
                        if (control) {
                            co_await relay_detail::ShutdownWriteForClose(
                                writer, *control, preserve_phase_deadline);
                        } else {
                            co_await relay_detail::ShutdownWriteForClose(
                                writer, writer, preserve_phase_deadline);
                        }
                        current.write_shutdown = true;
                    }
                    break;
                }
                const auto count = payload.byte_size();
                if (limits) {
                    // An under-budget packet must not pay for a wait coroutine.
                    if (const auto delay = relay_detail::ReserveRelayBytes(*limits, upload, count);
                        delay > std::chrono::milliseconds::zero()) {
                        co_await relay_detail::WaitRelayRate(*limits, upload, delay);
                    }
                }
                if (state.Ending()) break;
                if (direction_cancellation.cancelled() != net::cancellation_type::none)
                    throw transport::LinkError(ErrorCode::CANCELLED);
                operation_side_is_client = !upload;
                writing = true;
                co_await writer.WriteMultiBuffer(std::move(payload));
                bytes += count;
                if (upload) acc.AddBytesOut(count);
                else acc.AddBytesIn(count);
                if (acc.bytes_in + acc.bytes_out >= relay_detail::kRelayStatsFlushBytes)
                    relay_detail::FlushRelayStats(stats, acc);
            }
        } catch (const transport::WriteClosed&) {
            // A rejected, unstarted write must not discard the reverse payload.
            current.eof = true;
            state.Mark(operation_side_is_client);
            if (!peer.eof) arm_half_close(upload ? config.downlink_only : config.uplink_only);
        } catch (...) {
            auto error = transport::ClassifyFailure(std::current_exception(),
                writing ? ErrorCode::RELAY_WRITE_FAILED : ErrorCode::INTERNAL);
            const bool timed_out = cancellation.ConsumeTimeout();
            if (timed_out) error = ErrorCode::RELAY_TIMEOUT;
            // Only cancellation caused by protocol full-close is clean EOF.
            if (!(error == ErrorCode::CANCELLED && state.phase == RelayPhase::Completing)) {
                if (error == ErrorCode::RESOURCE_EXHAUSTED) {
                    state.local_failure = true;
                    state.close_side_known = false;
                    state.client_closed_first = false;
                } else state.Mark(operation_side_is_client);
                cancellation.Stop(error);
            }
        }
        relay_detail::FlushRelayStats(stats, acc);
    };
    auto watch_stop = [&]() -> net::awaitable<void> {
        if (!state.Ending())
            (void)co_await state.wake.async_receive(net::as_tuple(net::use_awaitable));
        if (!state.Ending()) throw transport::LinkError(ErrorCode::CANCELLED);
    };
    try {
        // The winning branch cancels AND joins its sibling, including a split
        // reader that has no control object and a writer blocked by backpressure.
        (void)co_await ((direction(client_reader, target, &target, true) &&
                         direction(target, client_writer, client_control, false)) ||
                        watch_stop());
    } catch (...) {
        cancellation.Stop(transport::ClassifyFailure(std::current_exception(), ErrorCode::INTERNAL));
    }
    if (parent_cancellation.cancelled() != net::cancellation_type::none && state.reason == ErrorCode::OK)
        state.Stop(ErrorCode::CANCELLED);
    state.phase = RelayPhase::Joined;
    if (client_control) client_control->ClearPhaseDeadline();
    target.ClearPhaseDeadline();

    if (state.reason == ErrorCode::OK) {
        bool client_shutdown_timed_out = false;
        auto shutdown = [&](auto& writer, auto* control, bool already_shutdown) -> net::awaitable<void> {
            if (already_shutdown) co_return;
            try {
                if (control) co_await relay_detail::ShutdownWriteForClose(writer, *control);
                else co_await relay_detail::ShutdownWriteForClose(writer, writer);
            } catch (const transport::WriteClosed&) {
            } catch (...) {
                // Capture each child's original cause before the join can wrap
                // simultaneous failures in asio::multiple_exceptions.
                const auto error = transport::ClassifyFailure(
                    std::current_exception(), ErrorCode::RELAY_WRITE_FAILED);
                state.Stop((client_shutdown_timed_out || cancellation.ConsumeTimeout())
                               ? ErrorCode::RELAY_TIMEOUT
                               : error);
            }
        };
        auto shutdown_client = [&]() -> net::awaitable<void> {
            if (!client_control && !state.down.write_shutdown) {
                AsyncDelay delay(io_context);
                auto wait_grace = [&]() -> net::awaitable<void> {
                    co_await delay.WaitFor(relay_detail::kRelayCloseGraceTimeout);
                    const auto cancellation = co_await net::this_coro::cancellation_state;
                    if (cancellation.cancelled() == net::cancellation_type::none) {
                        client_shutdown_timed_out = true;
                    }
                };
                (void)co_await (
                    shutdown(client_writer, client_control, state.down.write_shutdown) ||
                    wait_grace());
                if (client_shutdown_timed_out) {
                    state.Stop(ErrorCode::RELAY_TIMEOUT);
                }
                co_return;
            }
            co_await shutdown(client_writer, client_control, state.down.write_shutdown);
        };
        try {
            co_await (shutdown_client() &&
                      shutdown(target, &target, state.up.write_shutdown));
        } catch (...) {
            const auto error = transport::ClassifyFailure(std::current_exception(), ErrorCode::INTERNAL);
            state.Stop((client_shutdown_timed_out || cancellation.ConsumeTimeout())
                           ? ErrorCode::RELAY_TIMEOUT
                           : error);
        }
    }
    // Both directions and shutdowns are joined. Healthy protocol output may
    // still await transport ACKs; only failure needs an abortive cancellation.
    cancellation.client_cancel.Unsubscribe();
    cancellation.target_cancel.Unsubscribe();
    if (state.reason == ErrorCode::OK) {
        if (client_control) relay_detail::CloseIfSupported(*client_control);
        relay_detail::CloseIfSupported(target);
    } else {
        if (client_control) relay_detail::CancelIfSupported(*client_control);
        relay_detail::CancelIfSupported(target);
        if (client_control) relay_detail::CloseAbortiveIfSupported(*client_control);
        relay_detail::CloseAbortiveIfSupported(target);
    }

    RelayResult result;
    result.bytes_up = ctx.traffic.bytes_up;
    result.bytes_down = ctx.traffic.bytes_down;
    result.error = state.reason;
    result.client_closed_first = state.client_closed_first;
    result.close_side_known = state.close_side_known;
    LOG_CONN_DEBUG(ctx, "relay finished up={}B down={}B error={}", result.bytes_up,
                   result.bytes_down, ErrorCodeToString(result.error));
    co_return result;
}

