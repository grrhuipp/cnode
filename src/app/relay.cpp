#include "app/relay.hpp"
#include "app/token_bucket.hpp"

#include <algorithm>
#include <limits>

namespace app {

std::chrono::milliseconds TokenBucket::Consume(size_t bytes, Clock::time_point now) noexcept {
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

void TokenBucket::Refill(uint64_t elapsed) noexcept {
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

std::chrono::milliseconds TokenBucket::DelayFrom(int64_t now) const noexcept {
    if (last_ms_ <= now) return std::chrono::milliseconds::zero();
    const uint64_t delay = static_cast<uint64_t>(last_ms_) - static_cast<uint64_t>(now);
    return std::chrono::milliseconds{static_cast<int64_t>(std::min<uint64_t>(
        delay, std::numeric_limits<int64_t>::max()))};
}

struct RelayRateLimits {
    TokenBucket up;
    TokenBucket down;
    transport::AsyncDelay up_wait;
    transport::AsyncDelay down_wait;

    RelayRateLimits(net::io_context& io, uint64_t rate)
        : up(rate), down(rate), up_wait(io), down_wait(io) {}
};

void RelayRateLimitsDelete::operator()(RelayRateLimits* limits) const noexcept {
    delete limits;
}

RelayRateLimitsPtr AllocateRelayRateLimits(net::io_context& io, uint64_t rate) {
    if (rate == 0) return {};
    return RelayRateLimitsPtr(new RelayRateLimits(io, rate));
}

void CancelRelayRateWaits(RelayRateLimits& limits) noexcept {
    limits.up_wait.Cancel();
    limits.down_wait.Cancel();
}

std::chrono::milliseconds ReserveRelayBytes(
    RelayRateLimits& limits, bool upload, size_t bytes) noexcept {
    return (upload ? limits.up : limits.down).Consume(bytes);
}

net::awaitable<void> WaitRelayRate(
    RelayRateLimits& limits, bool upload, std::chrono::milliseconds delay) {
    return (upload ? limits.up_wait : limits.down_wait).WaitFor(delay);
}

void FlushRelayStats(StatsShard& stats, LocalStatsAccumulator& acc) {
    if (acc.bytes_in == 0 && acc.bytes_out == 0) return;
    stats.CommitAccumulator(acc);
    acc.Reset();
}

RelayState::RelayState(net::io_context& io)
    : wake(net::any_io_executor(io.get_executor()), 1) {}

void RelayState::Mark(bool client_side) noexcept {
    if (!close_side_known && !local_failure) {
        close_side_known = true;
        client_closed_first = client_side;
    }
}

void RelayState::Stop(common::ErrorCode error) noexcept {
    if (reason == common::ErrorCode::OK || (reason == common::ErrorCode::CANCELLED && error != common::ErrorCode::CANCELLED))
        reason = error;
    phase = RelayPhase::Stopping;
    wake.close();
}

void RelayState::Complete() noexcept {
    if (reason != common::ErrorCode::OK) return;
    phase = RelayPhase::Completing;
    wake.close();
}


net::awaitable<RelayResult> DoRelayLinkImpl(
    net::io_context& io_context,
    transport::MultiBufferReader& client_reader,
    transport::MultiBufferWriter& client_writer,
    transport::AsyncStream* client_control,
    RelayTargetAdapter target,
    common::Context& ctx,
    StatsShard& stats,
    const RelayConfig& config,
    common::MultiBufferBatch initial_payload) {

    using namespace net::experimental::awaitable_operators;
    RelayState state(io_context);
    const auto limits = AllocateRelayRateLimits(io_context, config.speed_limit);
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
        transport::AsyncStream* client;
        RelayTargetAdapter& target;
        RelayState& state;
        RelayRateLimits* limits;
        bool notifying = false;
        Subscription client_cancel{*this};
        Subscription target_cancel{*this};

        CancellationContext(transport::AsyncStream* client, RelayTargetAdapter& target,
                            RelayState& state, RelayRateLimits* limits)
            : client(client), target(target), state(state), limits(limits) {}

        bool ConsumeTimeout() {
            const bool target_timeout = target.consume_timeouts(target.target);
            const bool client_timeout = client && ConsumeTimeoutSignals(*client);
            return target_timeout || client_timeout;
        }
        void Stop(common::ErrorCode reason) noexcept {
            if (notifying) return;
            notifying = true;
            if (ConsumeTimeout()) reason = common::ErrorCode::RELAY_TIMEOUT;
            state.Stop(reason);
            if (limits) CancelRelayRateWaits(*limits);
            if (client) CancelIfSupported(*client);
            target.cancel(target.target);
            notifying = false;
        }
    } cancellation(client_control, target, state, limits.get());
    cancellation.client_cancel.Resubscribe(client_reader.Cancellation());
    cancellation.target_cancel.Resubscribe(*target.cancellation);

    auto arm_half_close = [&](std::chrono::seconds timeout) {
        if (state.phase != RelayPhase::Transferring) return;
        state.phase = RelayPhase::HalfClosed;
        if (timeout <= std::chrono::seconds::zero()) cancellation.Stop(common::ErrorCode::RELAY_TIMEOUT);
        else if (!target.start_phase_deadline(target.target, timeout)) cancellation.Stop(common::ErrorCode::INTERNAL);
    };

    auto direction = [&](bool upload) -> net::awaitable<void> {
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
                common::MultiBuffer payload;
                if (upload && !initial_payload.empty()) payload = initial_payload.PopFront();
                else if (upload) payload = co_await client_reader.ReadMultiBuffer();
                else payload = co_await target.read(target.target);
                if (state.Ending()) break;
                if (direction_cancellation.cancelled() != net::cancellation_type::none)
                    throw transport::LinkError(common::ErrorCode::CANCELLED);
                if (payload.byte_size() == 0 && !payload.HasUDP()) {
                    if (cancellation.ConsumeTimeout()) {
                        cancellation.Stop(common::ErrorCode::RELAY_TIMEOUT);
                        break;
                    }
                    current.eof = true;
                    state.Mark(upload);
                    const auto action = upload
                        ? ReadEofAction(client_reader)
                        : target.read_eof_action(target.target);
                    const bool write_closes = upload
                        ? target.write_shutdown_closes_link(target.target)
                        : WriteShutdownClosesLink(client_writer);
                    if (action == transport::EofAction::CloseLink || write_closes) {
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
                        if (upload) {
                            co_await target.shutdown_write(target.target, preserve_phase_deadline);
                        } else if (client_control) {
                            co_await ShutdownWriteForClose(client_writer, *client_control, preserve_phase_deadline);
                        } else {
                            co_await ShutdownWriteForClose(client_writer, client_writer, preserve_phase_deadline);
                        }
                        current.write_shutdown = true;
                    }
                    break;
                }
                const auto count = payload.byte_size();
                if (limits) {
                    if (const auto delay = ReserveRelayBytes(*limits, upload, count);
                        delay > std::chrono::milliseconds::zero()) {
                        co_await WaitRelayRate(*limits, upload, delay);
                    }
                }
                if (state.Ending()) break;
                if (direction_cancellation.cancelled() != net::cancellation_type::none)
                    throw transport::LinkError(common::ErrorCode::CANCELLED);
                operation_side_is_client = !upload;
                writing = true;
                if (upload) co_await target.write(target.target, std::move(payload));
                else co_await client_writer.WriteMultiBuffer(std::move(payload));
                bytes += count;
                if (upload) acc.AddBytesOut(count);
                else acc.AddBytesIn(count);
                if (acc.bytes_in + acc.bytes_out >= kRelayStatsFlushBytes)
                    FlushRelayStats(stats, acc);
            }
        } catch (const transport::WriteClosed&) {
            current.eof = true;
            state.Mark(operation_side_is_client);
            if (!peer.eof) arm_half_close(upload ? config.downlink_only : config.uplink_only);
        } catch (...) {
            auto error = transport::ClassifyFailure(std::current_exception(),
                writing ? common::ErrorCode::RELAY_WRITE_FAILED : common::ErrorCode::INTERNAL);
            const bool timed_out = cancellation.ConsumeTimeout();
            if (timed_out) error = common::ErrorCode::RELAY_TIMEOUT;
            if (!(error == common::ErrorCode::CANCELLED && state.phase == RelayPhase::Completing)) {
                if (error == common::ErrorCode::RESOURCE_EXHAUSTED) {
                    state.local_failure = true;
                    state.close_side_known = false;
                    state.client_closed_first = false;
                } else state.Mark(operation_side_is_client);
                cancellation.Stop(error);
            }
        }
        FlushRelayStats(stats, acc);
    };
    auto watch_stop = [&]() -> net::awaitable<void> {
        if (!state.Ending())
            (void)co_await state.wake.async_receive(net::as_tuple(net::use_awaitable));
        if (!state.Ending()) throw transport::LinkError(common::ErrorCode::CANCELLED);
    };
    try {
        (void)co_await ((direction(true) && direction(false)) || watch_stop());
    } catch (...) {
        cancellation.Stop(transport::ClassifyFailure(std::current_exception(), common::ErrorCode::INTERNAL));
    }
    if (parent_cancellation.cancelled() != net::cancellation_type::none && state.reason == common::ErrorCode::OK)
        state.Stop(common::ErrorCode::CANCELLED);
    state.phase = RelayPhase::Joined;
    if (client_control) client_control->ClearPhaseDeadline();
    target.clear_phase_deadline(target.target);

    if (state.reason == common::ErrorCode::OK) {
        bool client_shutdown_timed_out = false;
        auto shutdown_client_once = [&]() -> net::awaitable<void> {
            if (state.down.write_shutdown) co_return;
            try {
                if (client_control) co_await ShutdownWriteForClose(client_writer, *client_control);
                else co_await ShutdownWriteForClose(client_writer, client_writer);
            } catch (const transport::WriteClosed&) {
            } catch (...) {
                const auto error = transport::ClassifyFailure(
                    std::current_exception(), common::ErrorCode::RELAY_WRITE_FAILED);
                state.Stop((client_shutdown_timed_out || cancellation.ConsumeTimeout())
                               ? common::ErrorCode::RELAY_TIMEOUT
                               : error);
            }
        };
        auto shutdown_target_once = [&]() -> net::awaitable<void> {
            if (state.up.write_shutdown) co_return;
            try {
                co_await target.shutdown_write(target.target, false);
            } catch (const transport::WriteClosed&) {
            } catch (...) {
                const auto error = transport::ClassifyFailure(
                    std::current_exception(), common::ErrorCode::RELAY_WRITE_FAILED);
                state.Stop((client_shutdown_timed_out || cancellation.ConsumeTimeout())
                               ? common::ErrorCode::RELAY_TIMEOUT
                               : error);
            }
        };
        auto shutdown_client = [&]() -> net::awaitable<void> {
            if (!client_control && !state.down.write_shutdown) {
                transport::AsyncDelay delay(io_context);
                auto wait_grace = [&]() -> net::awaitable<void> {
                    co_await delay.WaitFor(kRelayCloseGraceTimeout);
                    const auto cancellation_state = co_await net::this_coro::cancellation_state;
                    if (cancellation_state.cancelled() == net::cancellation_type::none) {
                        client_shutdown_timed_out = true;
                    }
                };
                (void)co_await (shutdown_client_once() || wait_grace());
                if (client_shutdown_timed_out) {
                    state.Stop(common::ErrorCode::RELAY_TIMEOUT);
                }
                co_return;
            }
            co_await shutdown_client_once();
        };
        try {
            co_await (shutdown_client() && shutdown_target_once());
        } catch (...) {
            const auto error = transport::ClassifyFailure(std::current_exception(), common::ErrorCode::INTERNAL);
            state.Stop((client_shutdown_timed_out || cancellation.ConsumeTimeout())
                           ? common::ErrorCode::RELAY_TIMEOUT
                           : error);
        }
    }
    cancellation.client_cancel.Unsubscribe();
    cancellation.target_cancel.Unsubscribe();
    if (state.reason == common::ErrorCode::OK) {
        if (client_control) CloseIfSupported(*client_control);
        target.close(target.target);
    } else {
        if (client_control) CancelIfSupported(*client_control);
        target.cancel(target.target);
        if (client_control) CloseAbortiveIfSupported(*client_control);
        target.close_abortive(target.target);
    }

    RelayResult result;
    result.bytes_up = ctx.traffic.bytes_up;
    result.bytes_down = ctx.traffic.bytes_down;
    result.error = state.reason;
    result.client_closed_first = state.client_closed_first;
    result.close_side_known = state.close_side_known;
    LOG_CONN_DEBUG(ctx, "relay finished up={}B down={}B error={}", result.bytes_up,
                   result.bytes_down, common::ErrorCodeToString(result.error));
    co_return result;
}
}  // namespace app
