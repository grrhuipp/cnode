#pragma once

#include "common/defaults.hpp"
#include "common/error.hpp"
#include "common/session.hpp"
#include "common/multi_buffer.hpp"
#include "transport/async_stream.hpp"
#include "transport/failure.hpp"
#include "app/stats.hpp"
#include "infra/log.hpp"
#include "transport/async_delay.hpp"

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
namespace app {

struct RelayConfig {
    std::chrono::seconds uplink_only{common::kUplinkOnlyTimeout};     // 下行 EOF 后上行最多保留多久
    std::chrono::seconds downlink_only{common::kDownlinkOnlyTimeout}; // 上行 EOF 后下行最多保留多久
    std::chrono::seconds idle_timeout{0};
    std::chrono::seconds write_timeout{0};
    uint64_t speed_limit = 0;              // bytes/s，0 = 不限速
};

// ============================================================================
// Relay 结果
// ============================================================================
struct RelayResult : common::ResultStatus {
    uint64_t bytes_up = 0;
    uint64_t bytes_down = 0;
    bool client_closed_first = false;
    bool close_side_known = false;
};


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
decltype(auto) RelayControlOf(Endpoint& endpoint) noexcept {
    if constexpr (requires { endpoint.RelayControl(); }) {
        return RelayControlOf(endpoint.RelayControl());
    } else {
        return (endpoint);
    }
}

template <typename Endpoint>
decltype(auto) RelayControlOf(const Endpoint& endpoint) noexcept {
    if constexpr (requires { endpoint.RelayControl(); }) {
        return RelayControlOf(endpoint.RelayControl());
    } else {
        return (endpoint);
    }
}

template <typename Endpoint>
void CloseIfSupported(Endpoint& endpoint) noexcept {
    if constexpr (requires { endpoint.Close(); }) {
        try { endpoint.Close(); } catch (...) {}
    } else if constexpr (requires { endpoint.RelayControl(); }) {
        CloseIfSupported(endpoint.RelayControl());
    }
}

template <typename Endpoint>
void CloseAbortiveIfSupported(Endpoint& endpoint) noexcept {
    if constexpr (requires { endpoint.CloseAbortive(); }) {
        try { endpoint.CloseAbortive(); } catch (...) {}
    } else if constexpr (requires { endpoint.SetAbortiveClose(true); endpoint.Close(); }) {
        try { endpoint.SetAbortiveClose(true); endpoint.Close(); } catch (...) {}
    } else if constexpr (requires { endpoint.RelayControl(); }) {
        CloseAbortiveIfSupported(endpoint.RelayControl());
    } else {
        if constexpr (requires { endpoint.SetAbortiveClose(true); }) endpoint.SetAbortiveClose(true);
        CloseIfSupported(endpoint);
    }
}

template <typename Endpoint>
void CancelIfSupported(Endpoint& endpoint) noexcept {
    if constexpr (requires { endpoint.Cancel(); }) {
        try { endpoint.Cancel(); } catch (...) {}
    } else if constexpr (requires { endpoint.RelayControl(); }) {
        CancelIfSupported(endpoint.RelayControl());
    }
}

template <typename Endpoint>
bool StartPhaseDeadlineIfSupported(Endpoint& endpoint, std::chrono::seconds timeout) {
    auto& ctrl = RelayControlOf(endpoint);
    if constexpr (requires { static_cast<bool>(endpoint.StartPhaseDeadline(timeout)); }) {
        return static_cast<bool>(endpoint.StartPhaseDeadline(timeout));
    } else if constexpr (requires { static_cast<bool>(ctrl.StartPhaseDeadline(timeout)); }) {
        return static_cast<bool>(ctrl.StartPhaseDeadline(timeout));
    } else {
        return true;
    }
}

template <typename Endpoint>
void ClearPhaseDeadlineIfSupported(Endpoint& endpoint) noexcept {
    auto& ctrl = RelayControlOf(endpoint);
    if constexpr (requires { endpoint.ClearPhaseDeadline(); }) {
        try { endpoint.ClearPhaseDeadline(); } catch (...) {}
    } else if constexpr (requires { ctrl.ClearPhaseDeadline(); }) {
        try { ctrl.ClearPhaseDeadline(); } catch (...) {}
    }
}

template <typename Writer, typename Control>
net::awaitable<void> ShutdownWriteForClose(
    Writer& writer, Control& raw_control, bool preserve_phase_deadline = false) {
    auto& control = RelayControlOf(raw_control);
    if constexpr (requires { control.SetWriteTimeout(kRelayCloseGraceTimeout); }) {
        control.SetWriteTimeout(kRelayCloseGraceTimeout);
    }
    if (!preserve_phase_deadline) {
        (void)StartPhaseDeadlineIfSupported(control, kRelayCloseGraceTimeout);
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
            ClearPhaseDeadlineIfSupported(control);
        }
        throw;
    }
    if (!preserve_phase_deadline) {
        ClearPhaseDeadlineIfSupported(control);
    }
}

template <typename Reader>
transport::EofAction ReadEofAction(const Reader& reader) noexcept {
    const auto& ctrl = RelayControlOf(reader);
    if constexpr (requires { reader.ReadEofAction(); }) return reader.ReadEofAction();
    else if constexpr (requires { ctrl.ReadEofAction(); }) return ctrl.ReadEofAction();
    else return transport::EofAction::WaitForPeer;
}

template <typename Writer>
bool WriteShutdownClosesLink(const Writer& writer) noexcept {
    const auto& ctrl = RelayControlOf(writer);
    if constexpr (requires { writer.WriteShutdownClosesLink(); }) return writer.WriteShutdownClosesLink();
    else if constexpr (requires { ctrl.WriteShutdownClosesLink(); }) return ctrl.WriteShutdownClosesLink();
    else return false;
}

void FlushRelayStats(StatsShard& stats, LocalStatsAccumulator& acc);

template <typename Control>
bool ConsumeTimeoutSignals(Control& raw_control) {
    auto& control = RelayControlOf(raw_control);
    bool expired = false;
    if constexpr (requires { control.ConsumeReadTimeout(); }) {
        expired = control.ConsumeReadTimeout() || expired;
    }
    if constexpr (requires { control.ConsumeWriteTimeout(); }) {
        expired = control.ConsumeWriteTimeout() || expired;
    }
    if constexpr (requires { control.ConsumeIdleTimeout(); }) {
        expired = control.ConsumeIdleTimeout() || expired;
    }
    if constexpr (requires { control.ConsumePhaseDeadline(); }) {
        expired = control.ConsumePhaseDeadline() || expired;
    }
    return expired;
}

struct RelayTargetAdapter {
    void* target = nullptr;
    transport::CancellationSource* cancellation = nullptr;
    net::awaitable<common::MultiBuffer> (*read)(void*) = nullptr;
    net::awaitable<void> (*write)(void*, common::MultiBuffer) = nullptr;
    net::awaitable<void> (*shutdown_write)(void*, bool preserve_phase_deadline) = nullptr;
    transport::EofAction (*read_eof_action)(const void*) noexcept = nullptr;
    bool (*write_shutdown_closes_link)(const void*) noexcept = nullptr;
    bool (*start_phase_deadline)(void*, std::chrono::seconds) = nullptr;
    void (*clear_phase_deadline)(void*) noexcept = nullptr;
    bool (*consume_timeouts)(void*) = nullptr;
    void (*cancel)(void*) noexcept = nullptr;
    void (*close)(void*) noexcept = nullptr;
    void (*close_abortive)(void*) noexcept = nullptr;
};

net::awaitable<RelayResult> DoRelayLinkImpl(
    net::io_context& io_context,
    transport::MultiBufferReader& client_reader,
    transport::MultiBufferWriter& client_writer,
    transport::AsyncStream* client_control,
    RelayTargetAdapter target,
    common::Context& ctx,
    StatsShard& stats,
    const RelayConfig& config,
    common::MultiBufferBatch initial_payload);
enum class RelayPhase { Transferring, HalfClosed, Completing, Stopping, Joined };
struct RelayDirectionState {
    bool eof = false;
    bool write_shutdown = false;
};

struct RelayState {
    explicit RelayState(net::io_context& io);

    void Mark(bool client_side) noexcept;
    void Stop(common::ErrorCode error) noexcept;
    void Complete() noexcept;
    bool Ending() const noexcept {
        return phase == RelayPhase::Completing || phase == RelayPhase::Stopping;
    }

    RelayPhase phase = RelayPhase::Transferring;
    common::ErrorCode reason = common::ErrorCode::OK;
    bool close_side_known = false;
    bool client_closed_first = false;
    bool local_failure = false;
    RelayDirectionState up;
    RelayDirectionState down;
    common::SignalChannel wake;
};

// A null client control denotes split/logical input. It changes only the
// available transport controls, never EOF, error, accounting or join semantics.
// The reader cancellation source and the joined watchdog cover this case too.
template <typename TargetEndpoint>
net::awaitable<RelayResult> DoRelayLink(
    net::io_context& io_context,
    transport::MultiBufferReader& client_reader,
    transport::MultiBufferWriter& client_writer,
    transport::AsyncStream* client_control,
    TargetEndpoint& target,
    common::Context& ctx,
    StatsShard& stats,
    const RelayConfig& config = RelayConfig{},
    common::MultiBufferBatch initial_payload = {}) {
    RelayTargetAdapter adapter{
        .target = std::addressof(target),
        .cancellation = std::addressof(target.Cancellation()),
        .read = +[](void* p) -> net::awaitable<common::MultiBuffer> {
            return static_cast<TargetEndpoint*>(p)->ReadMultiBuffer();
        },
        .write = +[](void* p, common::MultiBuffer payload) -> net::awaitable<void> {
            return static_cast<TargetEndpoint*>(p)->WriteMultiBuffer(std::move(payload));
        },
        .shutdown_write = +[](void* p, bool preserve_phase_deadline) -> net::awaitable<void> {
            auto& ep = *static_cast<TargetEndpoint*>(p);
            return ShutdownWriteForClose(ep, ep, preserve_phase_deadline);
        },
        .read_eof_action = +[](const void* p) noexcept -> transport::EofAction {
            return ReadEofAction(*static_cast<const TargetEndpoint*>(p));
        },
        .write_shutdown_closes_link = +[](const void* p) noexcept -> bool {
            return WriteShutdownClosesLink(*static_cast<const TargetEndpoint*>(p));
        },
        .start_phase_deadline = +[](void* p, std::chrono::seconds timeout) -> bool {
            return StartPhaseDeadlineIfSupported(*static_cast<TargetEndpoint*>(p), timeout);
        },
        .clear_phase_deadline = +[](void* p) noexcept {
            ClearPhaseDeadlineIfSupported(*static_cast<TargetEndpoint*>(p));
        },
        .consume_timeouts = +[](void* p) -> bool {
            return ConsumeTimeoutSignals(*static_cast<TargetEndpoint*>(p));
        },
        .cancel = +[](void* p) noexcept {
            CancelIfSupported(*static_cast<TargetEndpoint*>(p));
        },
        .close = +[](void* p) noexcept {
            CloseIfSupported(*static_cast<TargetEndpoint*>(p));
        },
        .close_abortive = +[](void* p) noexcept {
            CloseAbortiveIfSupported(*static_cast<TargetEndpoint*>(p));
        },
    };
    return DoRelayLinkImpl(
        io_context, client_reader, client_writer, client_control,
        adapter, ctx, stats, config, std::move(initial_payload));
}

}  // namespace app

