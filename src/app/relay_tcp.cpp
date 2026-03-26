#include "acppnode/app/relay.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/app/token_bucket.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/multi_buffer.hpp"
#include "acppnode/transport/tcp_stream.hpp"
#include "acppnode/infra/log.hpp"

#include <boost/asio/steady_timer.hpp>
#include <optional>

namespace acpp {

namespace {

constexpr uint64_t kRelayStatsFlushBytes = 64 * 1024;

void MarkAbortiveClose(AsyncStream& stream) {
    if (auto* tcp = stream.GetBaseTcpStream()) {
        tcp->SetAbortiveClose(true);
    }
}

void FlushRelayStats(StatsShard* stats, LocalStatsAccumulator& acc) {
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

cobalt::task<std::pair<uint64_t, ErrorCode>> RelayOneDirection(
    AsyncStream& from,
    AsyncStream& to,
    std::atomic<bool>& my_eof,
    std::atomic<bool>& peer_eof,
    std::chrono::seconds half_close_timeout,
    StatsShard* stats,
    bool is_upload,
    uint64_t speed_limit,
    uint64_t* live_bytes_counter,
    const SessionContext& ctx) {

    auto executor = co_await cobalt::this_coro::executor;

    uint64_t total_bytes = 0;
    ErrorCode error = ErrorCode::OK;
    if (live_bytes_counter) {
        *live_bytes_counter = 0;
    }

    TokenBucket rate_limiter(speed_limit);
    std::optional<net::steady_timer> rate_timer;
    if (speed_limit > 0) {
        rate_timer.emplace(executor);
    }
    LocalStatsAccumulator stats_acc;

    while (true) {
        // 注意：不在这里检查 peer_eof。
        // TCP 全双工：对端关闭写端（EOF）不代表关闭读端，
        // 本方向应继续转发直到自身 EOF 或半关闭超时到期后被 Cancel。

        try {
            MultiBuffer mb = co_await from.ReadMultiBuffer();
            MultiBufferGuard guard{mb};

            if (mb.empty()) {
                if (ConsumeReadSideTimeout(from)) {
                    error = ErrorCode::RELAY_TIMEOUT;
                    LOG_CONN_DEBUG(ctx, "[relay] {} idle/read timeout, transferred={}B",
                                   is_upload ? "up" : "down", total_bytes);
                    break;
                }

                // 被对端半关闭超时后 Cancel 的情况：对端已 EOF 且超时到期，
                // 主动 Cancel 了我们的 from 流，直接退出即可
                if (peer_eof.load(std::memory_order_acquire)) {
                    LOG_CONN_DEBUG(ctx, "[relay] {} forced exit by peer half-close timeout, transferred={}B",
                                   is_upload ? "up" : "down", total_bytes);
                    break;
                }

                LOG_CONN_DEBUG(ctx, "[relay] {} EOF after {}B", is_upload ? "up" : "down", total_bytes);
                my_eof.store(true, std::memory_order_release);

                // 对齐 Xray：半关闭只切换 idle timer，不发送 TCP FIN / TLS close_notify。
                // VMess EOF marker 和 TLS close_notify 在 DoRelay 全关闭阶段统一发送。
                if (!peer_eof.load(std::memory_order_acquire)) {
                    if (half_close_timeout.count() > 0) {
                        LOG_CONN_DEBUG(ctx, "[relay] {} half-close: arming idle timeout {}s for peer direction",
                                       is_upload ? "up" : "down", half_close_timeout.count());
                        from.SetIdleTimeout(half_close_timeout);
                        to.SetIdleTimeout(half_close_timeout);
                        // 一侧已经 EOF 后，继续向另一侧写数据不应无限等待。
                        // 给两端都加上 half-close 写 deadline，尽快收敛阻塞写。
                        from.SetWriteTimeout(half_close_timeout);
                        to.SetWriteTimeout(half_close_timeout);
                    } else {
                        LOG_CONN_DEBUG(ctx, "[relay] {} half-close: timeout=0, cancel peer immediately",
                                       is_upload ? "up" : "down");
                        // 超时为 0：立即终止对端方向
                        to.Cancel();
                    }
                } else {
                    LOG_CONN_DEBUG(ctx, "[relay] {} EOF, peer already EOF, both done",
                                   is_upload ? "up" : "down");
                }
                break;
            }

            size_t n = TotalLen(mb);
            auto wait_time = rate_limiter.Consume(n);
            if (wait_time.count() > 0) {
                rate_timer->expires_after(wait_time);
                co_await rate_timer->async_wait(cobalt::use_op);
            }

            co_await to.WriteMultiBuffer(std::move(mb));

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

        } catch (const boost::system::system_error& e) {
            error = MapAsioError(e.code());
            if (error == ErrorCode::CANCELLED &&
                (ConsumeReadSideTimeout(from) || ConsumeWriteSideTimeout(to))) {
                error = ErrorCode::RELAY_TIMEOUT;
                LOG_CONN_DEBUG(ctx, "[relay] {} cancelled by timeout, transferred={}B",
                               is_upload ? "up" : "down", total_bytes);
            } else {
                LOG_CONN_DEBUG(ctx, "[relay] {} error: {} ({}), transferred={}B",
                               is_upload ? "up" : "down",
                               ErrorCodeToString(error), e.what(), total_bytes);
            }
            break;
        }
    }

    FlushRelayStats(stats, stats_acc);
    co_return std::make_pair(total_bytes, error);
}

}  // namespace

cobalt::task<RelayResult> DoRelay(
    AsyncStream& client,
    AsyncStream& target,
    SessionContext& ctx,
    StatsShard& stats,
    const RelayConfig& config) {

    RelayResult result;
    std::atomic<bool> client_eof{false};
    std::atomic<bool> target_eof{false};

    LOG_CONN_DEBUG(ctx, "Relay started, speed_limit={}, uplink_only={}s, downlink_only={}s",
                   config.speed_limit > 0 ?
                   std::format("{}MB/s", config.speed_limit / 1024 / 1024) : "unlimited",
                   config.uplink_only.count(),
                   config.downlink_only.count());

    auto [raw_up, raw_down] = co_await cobalt::gather(
        RelayOneDirection(client, target, client_eof, target_eof,
                          config.downlink_only,
                          &stats, true, config.speed_limit, &ctx.bytes_up, ctx),
        RelayOneDirection(target, client, target_eof, client_eof,
                          config.uplink_only,
                          &stats, false, config.speed_limit, &ctx.bytes_down, ctx)
    );

    auto up_result = raw_up.has_value()
        ? std::move(*raw_up)
        : std::make_pair(uint64_t(0), ErrorCode::RELAY_READ_FAILED);
    auto down_result = raw_down.has_value()
        ? std::move(*raw_down)
        : std::make_pair(uint64_t(0), ErrorCode::RELAY_READ_FAILED);

    auto [bytes_up, error_up] = up_result;
    auto [bytes_down, error_down] = down_result;

    result.bytes_up = bytes_up;
    result.bytes_down = bytes_down;

    ctx.bytes_up = bytes_up;
    ctx.bytes_down = bytes_down;

    if (error_up != ErrorCode::OK) {
        result.error = error_up;
        result.client_closed_first = true;
    } else if (error_down != ErrorCode::OK) {
        result.error = error_down;
    }

    LOG_CONN_DEBUG(ctx, "Relay CLOSING: up_err={} down_err={} up={}B down={}B closer={}",
                   ErrorCodeToString(error_up), ErrorCodeToString(error_down),
                   bytes_up, bytes_down,
                   result.client_closed_first ? "client" : "target");

    // 错误路径快速关闭：跳过 TLS close_notify / VMess EOF marker，
    // 直接 Cancel 所有挂起操作后由析构链关闭 socket。
    // 正常关闭（双方均 EOF）才执行协议级优雅关闭。
    if (error_up != ErrorCode::OK || error_down != ErrorCode::OK) {
        MarkAbortiveClose(client);
        MarkAbortiveClose(target);
        client.Cancel();
        target.Cancel();
    } else {
        // 并行发送双向 close_notify / EOF marker，减少 1 次 RTT
        auto shutdown_client = [&]() -> cobalt::task<void> {
            try { co_await client.AsyncShutdownWrite(); } catch (...) {}
        };
        auto shutdown_target = [&]() -> cobalt::task<void> {
            try { co_await target.AsyncShutdownWrite(); } catch (...) {}
        };
        co_await cobalt::gather(shutdown_client(), shutdown_target());
        client.Cancel();
        target.Cancel();
    }

    LOG_CONN_DEBUG(ctx, "Relay finished: up={} down={}", bytes_up, bytes_down);

    co_return result;
}

cobalt::task<RelayResult> DoRelayWithFirstPacket(
    AsyncStream& client,
    AsyncStream& target,
    SessionContext& ctx,
    StatsShard& stats,
    std::vector<uint8_t> first_packet,
    const RelayConfig& config) {

    const size_t first_packet_size = first_packet.size();

    if (!first_packet.empty()) {
        try {
            size_t remaining = first_packet.size();
            size_t offset = 0;

            while (remaining > 0) {
                auto written = co_await target.AsyncWrite(
                    net::buffer(first_packet.data() + offset, remaining));

                if (written == 0) {
                    if (ConsumeWriteSideTimeout(target)) {
                        MarkAbortiveClose(client);
                        MarkAbortiveClose(target);
                        RelayResult result;
                        result.error = ErrorCode::RELAY_TIMEOUT;
                        result.error_msg = "first packet write timed out";
                        co_return result;
                    }
                    MarkAbortiveClose(client);
                    MarkAbortiveClose(target);
                    RelayResult result;
                    result.error = ErrorCode::RELAY_WRITE_FAILED;
                    result.error_msg = "failed to send first packet";
                    co_return result;
                }

                offset += written;
                remaining -= written;
            }

            stats.AddBytesOut(first_packet_size);
            first_packet.clear();
            ReleaseIdleBuffer(first_packet, 0);

        } catch (const boost::system::system_error& e) {
            MarkAbortiveClose(client);
            MarkAbortiveClose(target);
            RelayResult result;
            result.error = ConsumeWriteSideTimeout(target)
                ? ErrorCode::RELAY_TIMEOUT
                : MapAsioError(e.code());
            result.error_msg = std::string("first packet error: ") + e.what();
            co_return result;
        } catch (const std::exception& e) {
            MarkAbortiveClose(client);
            MarkAbortiveClose(target);
            RelayResult result;
            result.error = ErrorCode::RELAY_WRITE_FAILED;
            result.error_msg = std::string("first packet error: ") + e.what();
            co_return result;
        }
    }

    auto result = co_await DoRelay(client, target, ctx, stats, config);
    result.bytes_up += first_packet_size;

    co_return result;
}

}  // namespace acpp
