#pragma once

#include "common/allocator.hpp"
#include "common/error.hpp"
#include "common/session.hpp"
#include "common/buf/multi_buffer.hpp"
#include "transport/async_stream.hpp"
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
#include <optional>
#include <algorithm>
#include <cstddef>
#include <limits>
#include <utility>

// Worker-local byte reservations. Initial credit is one second of traffic;
// idle credit is capped at two seconds. Waiting cannot earn reserved bytes again.
class TokenBucket {
public:
    using Clock = std::chrono::steady_clock;

    explicit TokenBucket(uint64_t rate, Clock::time_point now = Clock::now()) noexcept
        : rate_(rate), tokens_(rate), last_ms_(Millis(now)) {}

    TokenBucket(const TokenBucket&) = delete;
    TokenBucket& operator=(const TokenBucket&) = delete;

    [[nodiscard]] std::chrono::milliseconds Consume(
        size_t bytes, Clock::time_point now = Clock::now()) noexcept {
        if (rate_ == 0 || bytes == 0) return std::chrono::milliseconds::zero();
        const int64_t now_ms = Millis(now);
        if (now_ms > last_ms_) {
            Refill(static_cast<uint64_t>(now_ms) - static_cast<uint64_t>(last_ms_));
            last_ms_ = now_ms;
        }
        if (tokens_ >= bytes) {
            tokens_ -= bytes;
            return DelayFrom(now_ms);
        }

        const uint64_t deficit = bytes - tokens_;
        // Whole seconds plus a remainder in [1, rate] avoid deficit * 1000.
        const uint64_t seconds = (deficit - 1) / rate_;
        const uint64_t remainder = (deficit - 1) % rate_ + 1;
        uint32_t low = 1, high = 1000;
        while (low < high) {
            const uint32_t mid = low + (high - low) / 2;
            if (Credit(mid) >= remainder) high = mid;
            else low = mid + 1;
        }
        tokens_ = Credit(low) - remainder;
        fraction_ = ((rate_ % 1000) * low + fraction_) % 1000;

        constexpr uint64_t maximum = std::numeric_limits<int64_t>::max();
        const bool overflow = seconds > (maximum - low) / 1000;
        const uint64_t wait = overflow
            ? maximum : seconds * 1000 + low;
        const uint64_t room = maximum - static_cast<uint64_t>(last_ms_);
        if (overflow || wait > room) {
            last_ms_ = std::numeric_limits<int64_t>::max();
            tokens_ = fraction_ = 0;
        } else {
            last_ms_ += static_cast<int64_t>(wait);
        }
        return DelayFrom(now_ms);
    }

private:
    static int64_t Millis(Clock::time_point now) noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    // elapsed <= 1000: the result never exceeds rate_, even at UINT64_MAX.
    uint64_t Credit(uint32_t elapsed) const noexcept {
        return (rate_ / 1000) * elapsed + ((rate_ % 1000) * elapsed + fraction_) / 1000;
    }

    void Refill(uint64_t elapsed) noexcept {
        constexpr uint64_t maximum = std::numeric_limits<uint64_t>::max();
        const uint64_t capacity = rate_ > maximum / 2 ? maximum : rate_ * 2;
        if (elapsed >= 2000) {
            tokens_ = capacity;
            fraction_ = 0;
            return;
        }
        if (elapsed >= 1000) {
            if (rate_ >= capacity - tokens_) {
                tokens_ = capacity;
                fraction_ = 0;
                return;
            }
            tokens_ += rate_;
            elapsed -= 1000;
        }
        const uint64_t credit = Credit(static_cast<uint32_t>(elapsed));
        if (credit >= capacity - tokens_) {
            tokens_ = capacity;
            fraction_ = 0;
        } else {
            tokens_ += credit;
            fraction_ = ((rate_ % 1000) * elapsed + fraction_) % 1000;
        }
    }

    std::chrono::milliseconds DelayFrom(int64_t now) const noexcept {
        if (last_ms_ <= now) return std::chrono::milliseconds::zero();
        const uint64_t delay = static_cast<uint64_t>(last_ms_) - static_cast<uint64_t>(now);
        return std::chrono::milliseconds{static_cast<int64_t>(std::min<uint64_t>(
            delay, std::numeric_limits<int64_t>::max()))};
    }

    uint64_t rate_;
    uint64_t tokens_;
    uint64_t fraction_ = 0; // Thousandths of one byte, not yet spendable.
    int64_t last_ms_;      // Includes credit reserved in future waits.
};

namespace relay_detail {

inline constexpr uint64_t kRelayStatsFlushBytes = 64 * 1024;
inline constexpr auto kRelayCloseGraceTimeout = std::chrono::seconds(1);

// All state and subscriptions live until both directions and the watchdog join.
// Allocated only for speed-limited relays so unlimited frames do not carry it.
struct RelayRateLimits : memory::WorkerAllocated {
    TokenBucket up;
    TokenBucket down;
    AsyncDelay up_wait;
    AsyncDelay down_wait;

    RelayRateLimits(net::io_context& io, uint64_t rate)
        : up(rate), down(rate), up_wait(io), down_wait(io) {}

    void Cancel() noexcept {
        up_wait.Cancel();
        down_wait.Cancel();
    }
};

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

inline ErrorCode CaptureFailure(ErrorCode unknown = ErrorCode::INTERNAL) noexcept {
    try {
        throw;
    } catch (const transport::LinkError& error) {
        return error.code();
    } catch (const IoSystemError& error) {
        return MapAsioError(error.code());
    } catch (const std::bad_alloc&) {
        return ErrorCode::RESOURCE_EXHAUSTED;
    } catch (...) {
        return unknown;
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

inline void FlushRelayStats(StatsShard& stats, LocalStatsAccumulator& acc) {
    if (acc.bytes_in == 0 && acc.bytes_out == 0) return;
    stats.CommitAccumulator(acc);
    acc.Reset();
}

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
    explicit RelayState(net::io_context& io)
        : wake(net::any_io_executor(io.get_executor()), 1) {}

    void Mark(bool client_side) noexcept {
        if (!close_side_known && !local_failure) {
            close_side_known = true;
            client_closed_first = client_side;
        }
    }
    void Stop(ErrorCode error) noexcept {
        if (reason == ErrorCode::OK || (reason == ErrorCode::CANCELLED && error != ErrorCode::CANCELLED))
            reason = error;
        phase = RelayPhase::Stopping;
        wake.close();
    }
    void Complete() noexcept {
        if (reason != ErrorCode::OK) return;
        phase = RelayPhase::Completing;
        wake.close();
    }
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
template <typename ClientReader, typename ClientWriter, typename ClientControl, typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLink(
    net::io_context& io_context,
    ClientReader& client_reader,
    ClientWriter& client_writer,
    ClientControl* client_control,
    TargetEndpoint& target,
    session::Context& ctx,
    StatsShard& stats,
    const RelayConfig& config = RelayConfig{},
    buf::MultiBufferBatch initial_payload = {}) {

    using namespace net::experimental::awaitable_operators;
    using relay_detail::RelayPhase;
    relay_detail::RelayState state(io_context);
    std::unique_ptr<relay_detail::RelayRateLimits> limits;
    if (config.speed_limit != 0) {
        limits = memory::MakeUnique<relay_detail::RelayRateLimits>(
            ctx.pool,
            io_context, config.speed_limit);
    }
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
        ClientControl* client;
        TargetEndpoint& target;
        relay_detail::RelayState& state;
        relay_detail::RelayRateLimits* limits;
        bool notifying = false;
        Subscription client_cancel{*this};
        Subscription target_cancel{*this};

        CancellationContext(ClientControl* client, TargetEndpoint& target,
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
            if (limits) limits->Cancel();
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
                    auto& bucket = upload ? limits->up : limits->down;
                    auto& wait = upload ? limits->up_wait : limits->down_wait;
                    // An under-budget packet must not pay for a wait coroutine.
                    if (const auto delay = bucket.Consume(count);
                        delay > std::chrono::milliseconds::zero()) {
                        co_await wait.WaitFor(delay);
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
            auto error = relay_detail::CaptureFailure(
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
        cancellation.Stop(relay_detail::CaptureFailure());
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
                const auto error = relay_detail::CaptureFailure(ErrorCode::RELAY_WRITE_FAILED);
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
            const auto error = relay_detail::CaptureFailure();
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

