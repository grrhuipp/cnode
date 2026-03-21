#include "acppnode/app/relay.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/app/token_bucket.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/multi_buffer.hpp"
#include "acppnode/protocol/outbound.hpp"
#include "acppnode/infra/log.hpp"

#include <mutex>
#include <queue>
#include <boost/asio/steady_timer.hpp>
#include <array>

namespace acpp {

namespace {

constexpr uint64_t kUdpRelayStatsFlushBytes = 64 * 1024;

void FlushUdpRelayStats(StatsShard& stats, LocalStatsAccumulator& acc) {
    if (acc.bytes_in == 0 && acc.bytes_out == 0) {
        return;
    }
    stats.CommitAccumulator(acc);
    acc.Reset();
}

}  // namespace

// ============================================================================
// DoUDPRelay — 协议无关 UDP relay
//
// 协议特有的 UDP 帧编解码由 framer 负责，relay 层不感知具体协议。
// ============================================================================

cobalt::task<RelayResult> DoUDPRelay(
    AsyncStream& client_stream,
    UDPDialResult& udp_dial,
    UdpFramer& framer,
    SessionContext& ctx,
    StatsShard& stats,
    const UDPRelayConfig& config) {

    auto executor = co_await cobalt::this_coro::executor;

    RelayResult result;
    ctx.bytes_up = 0;
    ctx.bytes_down = 0;

    // ========================================================================
    // UDP 回复队列 — 单线程，无需 lockfree
    //
    // 整个 UDP 流程都在同一个 Worker 线程：
    //   1. DoReceive 回调触发（Worker io_context）
    //   2. 回调里 push 到队列
    //   3. relay 协程 pop 队列
    // ========================================================================

    struct SharedState {
        std::atomic<bool> running{true};
        std::deque<UDPPacket> reply_queue;
        size_t queued_bytes = 0;
        std::atomic<uint64_t> total_replies{0};
        bool shrink_queue_on_drain = false;

        void push(UDPPacket&& pkt) {
            const size_t pkt_bytes = pkt.data.size();
            queued_bytes += pkt_bytes;
            reply_queue.push_back(std::move(pkt));
            if (reply_queue.size() >= 64 || queued_bytes >= 256 * 1024) {
                shrink_queue_on_drain = true;
            }
        }

        bool pop(UDPPacket& pkt) {
            if (reply_queue.empty()) return false;
            queued_bytes -= reply_queue.front().data.size();
            pkt = std::move(reply_queue.front());
            reply_queue.pop_front();
            if (reply_queue.empty() && shrink_queue_on_drain) {
                TryShrinkSequence(reply_queue);
                shrink_queue_on_drain = false;
            }
            return true;
        }

        bool empty() const { return reply_queue.empty(); }
    };
    auto state = std::make_shared<SharedState>();

    const uint64_t conn_id = ctx.conn_id;
    uint64_t callback_id = 0;

    // 注册回包回调
    if (udp_dial.register_callback) {
        callback_id = udp_dial.register_callback("",
            [state, conn_id](const UDPPacket& pkt) {
                if (!state->running.load()) return;
                LOG_ACCESS_DEBUG("[conn={}] UDP Full Cone received {} bytes from {}:{}",
                          conn_id, pkt.data.size(), pkt.target.host, pkt.target.port);
                UDPPacket pkt_copy = pkt;
                state->total_replies.fetch_add(1, std::memory_order_relaxed);
                state->push(std::move(pkt_copy));
            });
        LOG_CONN_DEBUG(ctx, "Registered Full Cone callback {}", callback_id);
    } else if (udp_dial.set_callback) {
        udp_dial.set_callback([state, conn_id](const UDPPacket& pkt) {
            if (!state->running.load()) return;
            UDPPacket pkt_copy = pkt;
            state->total_replies.fetch_add(1, std::memory_order_relaxed);
            state->push(std::move(pkt_copy));
        });
    } else {
        LOG_CONN_DEBUG(ctx, "UDP dial result has no callback mechanism!");
    }

    // 限速器（上行/下行各一个）
    TokenBucket upload_limiter(config.speed_limit);
    TokenBucket download_limiter(config.speed_limit);
    net::steady_timer rate_timer(executor);
    LocalStatsAccumulator stats_acc;

    // 序列化并发送回包
    auto send_reply = [&](const UDPPacket& packet) -> cobalt::task<bool> {
        try {
            std::array<uint8_t, 8 * 1024> stack_buf{};
            size_t encoded_len = UdpFramerEncodeTo(framer, packet, stack_buf.data(), stack_buf.size());

            const uint8_t* send_data;
            size_t send_len;
            std::vector<uint8_t> heap_buf;

            if (encoded_len > 0) {
                send_data = stack_buf.data();
                send_len  = encoded_len;
            } else {
                heap_buf  = UdpFramerEncode(framer, packet);
                send_data = heap_buf.data();
                send_len  = heap_buf.size();
            }

            if (send_len == 0 || send_data == nullptr) {
                LOG_CONN_DEBUG(ctx, "UDP reply serialize failed for {}:{}",
                               packet.target.host, packet.target.port);
                co_return false;
            }

            // 下行限速
            auto wait_time = download_limiter.Consume(send_len);
            if (wait_time.count() > 0) {
                rate_timer.expires_after(wait_time);
                co_await rate_timer.async_wait(cobalt::use_op);
            }

            size_t written = co_await client_stream.AsyncWrite(
                net::buffer(send_data, send_len));
            if (written > 0) {
                ctx.bytes_down += written;
                result.bytes_down += written;
                stats_acc.AddBytesIn(written);
                if (stats_acc.bytes_in + stats_acc.bytes_out >= kUdpRelayStatsFlushBytes) {
                    FlushUdpRelayStats(stats, stats_acc);
                }
            }
            co_return written > 0;

        } catch (const std::exception& e) {
            LOG_CONN_DEBUG(ctx, "UDP reply write failed: {}", e.what());
            co_return false;
        }
    };

    // 读缓冲区（协程局部，避免 thread_local 在多协程间共享的风险）
    std::array<uint8_t, 8 * 1024> read_buffer_storage{};
    uint8_t* read_buffer      = read_buffer_storage.data();
    size_t   read_buffer_size = read_buffer_storage.size();

    LOG_CONN_DEBUG(ctx, "UDP relay started, target={}", ctx.target.ToString());

    net::steady_timer read_timer(executor);

    // 读轮询状态（循环外分配一次，避免每 100ms 一次 make_shared）
    struct ReadPollState {
        std::atomic<bool> timed_out{false};
        std::atomic<bool> active{true};
        void Reset() noexcept {
            timed_out.store(false, std::memory_order_relaxed);
            active.store(true, std::memory_order_relaxed);
        }
    };
    auto read_poll = std::make_shared<ReadPollState>();
    AsyncStream* client_ptr = &client_stream;

    while (state->running.load()) {
        // ── 批量处理回包（减少协程切换）────────────────────────────────────
        {
            std::vector<UDPPacket> batch;
            batch.reserve(32);
            UDPPacket pkt;
            while (batch.size() < 32 && state->pop(pkt))
                batch.push_back(std::move(pkt));

            for (const auto& item : batch) {
                bool ok = co_await send_reply(item);
                if (!ok) { state->running.store(false); break; }
                LOG_CONN_DEBUG(ctx, "UDP reply: {} bytes from {}:{}",
                               item.data.size(), item.target.host, item.target.port);
            }
            if (!batch.empty())
                LOG_CONN_DEBUG(ctx, "Sent {} reply packets (batched)", batch.size());
        }

        if (!state->running.load()) break;

        try {
            // 轮询读取（100ms 超时，以便处理回包队列）
            // 空闲检测由 TcpStream idle_timeout 统一处理，通过 ConsumeReadSideTimeout 消费
            read_poll->Reset();
            read_timer.expires_after(std::chrono::milliseconds(100));
            read_timer.async_wait([read_poll, client_ptr](const boost::system::error_code& ec) {
                if (!ec && read_poll->active.exchange(false, std::memory_order_acq_rel)) {
                    read_poll->timed_out.store(true, std::memory_order_release);
                    client_ptr->Cancel();
                }
            });

            size_t n = 0;
            bool read_ok = false;
            try {
                n = co_await client_stream.AsyncRead(net::buffer(read_buffer, read_buffer_size));
                read_ok = true;
            } catch (const boost::system::system_error& e) {
                (void)e;
                read_poll->active.store(false, std::memory_order_release);
                read_timer.cancel();
                if (read_poll->timed_out.load(std::memory_order_acquire))
                    continue;  // 超时（非错误），继续处理回包
                throw;
            }

            read_poll->active.store(false, std::memory_order_release);
            read_timer.cancel();

            if (read_poll->timed_out.load(std::memory_order_acquire) && n == 0) {
                if (ConsumeReadSideTimeout(client_stream)) {
                    result.error = ErrorCode::TIMEOUT;
                    break;
                }
                continue;
            }

            if (!read_ok) continue;

            LOG_CONN_DEBUG(ctx, "UDP read {} bytes from client", n);

            if (n == 0) {
                if (ConsumeReadSideTimeout(client_stream)) {
                    result.error = ErrorCode::TIMEOUT;
                    LOG_CONN_DEBUG(ctx, "UDP relay: TCP idle/read timeout, up={}B down={}B",
                                   result.bytes_up, result.bytes_down);
                    break;
                }

                // TCP 侧关闭，排水剩余回包
                LOG_CONN_DEBUG(ctx, "UDP relay: TCP EOF, up={}B down={}B, draining replies...",
                               result.bytes_up, result.bytes_down);
                constexpr auto kDrainTimeout      = std::chrono::milliseconds(2000);
                constexpr auto kDrainPollInterval = std::chrono::milliseconds(50);
                auto drain_start = std::chrono::steady_clock::now();

                while (std::chrono::steady_clock::now() - drain_start < kDrainTimeout) {
                    std::vector<UDPPacket> pending;
                    { UDPPacket p; while (state->pop(p)) pending.push_back(std::move(p)); }

                    for (const auto& pkt : pending) {
                        bool ok = co_await send_reply(pkt);
                        if (!ok) goto drain_done;
                    }

                    if (!pending.empty() && result.bytes_down > 0) {
                        net::steady_timer poll_timer(executor);
                        poll_timer.expires_after(std::chrono::milliseconds(100));
                        try { co_await poll_timer.async_wait(cobalt::use_op); } catch (...) {}
                        if (state->empty()) break;
                    }

                    net::steady_timer poll_timer(executor);
                    poll_timer.expires_after(kDrainPollInterval);
                    try { co_await poll_timer.async_wait(cobalt::use_op); } catch (...) {}
                }

            drain_done:
                LOG_CONN_DEBUG(ctx, "Drain finished, bytes_down={}", result.bytes_down);
                result.client_closed_first = true;
                break;
            }

            ctx.bytes_up += n;
            result.bytes_up += n;
            stats_acc.AddBytesOut(n);
            if (stats_acc.bytes_in + stats_acc.bytes_out >= kUdpRelayStatsFlushBytes) {
                FlushUdpRelayStats(stats, stats_acc);
            }

            // 上行限速
            {
                auto wait_time = upload_limiter.Consume(n);
                if (wait_time.count() > 0) {
                    rate_timer.expires_after(wait_time);
                    co_await rate_timer.async_wait(cobalt::use_op);
                }
            }

            // ── 协议无关：将字节交给 framer 解析，取出所有完整包发送 ──────
            UdpFramerFeed(framer, read_buffer, n);
            UDPPacket pkt;
            while (UdpFramerNext(framer, pkt)) {
                LOG_CONN_DEBUG(ctx, "UDP parsed: target={}:{}, data_len={}",
                               pkt.target.host, pkt.target.port, pkt.data.size());
                if (udp_dial.send) {
                    auto send_result = co_await udp_dial.send(pkt, callback_id);
                    if (send_result != ErrorCode::OK) {
                        LOG_CONN_DEBUG(ctx, "UDP send failed: {}", ErrorCodeToString(send_result));
                    }
                }
            }

        } catch (const boost::system::system_error& e) {
            if (e.code() == net::error::operation_aborted) {
                if (ConsumeReadSideTimeout(client_stream) ||
                    ConsumeWriteSideTimeout(client_stream)) {
                    result.error = ErrorCode::TIMEOUT;
                    LOG_CONN_DEBUG(ctx, "UDP relay: cancelled by timeout, up={}B down={}B",
                                   result.bytes_up, result.bytes_down);
                    break;
                }
                continue;
            }
            result.error = MapAsioError(e.code());
            LOG_CONN_DEBUG(ctx, "UDP relay error: {} ({}), up={}B down={}B",
                           ErrorCodeToString(result.error), e.what(),
                           result.bytes_up, result.bytes_down);
            break;
        } catch (const std::exception& e) {
            LOG_CONN_DEBUG(ctx, "UDP relay unexpected error: {}", e.what());
            result.error = ErrorCode::INTERNAL;
            break;
        }
    }

    state->running.store(false);
    FlushUdpRelayStats(stats, stats_acc);

    if (callback_id != 0 && udp_dial.unregister_callback) {
        udp_dial.unregister_callback(callback_id);
        LOG_CONN_DEBUG(ctx, "Unregistered Full Cone callback {}", callback_id);
    }

#ifndef NDEBUG
    uint64_t total   = state->total_replies.load();
    if (total > 0) {
        LOG_CONN_DEBUG(ctx, "UDP relay stats: total_replies={}, queued_bytes={}",
                       total, state->queued_bytes);
    }
    LOG_CONN_DEBUG(ctx, "UDP relay finished: up={} down={}", result.bytes_up, result.bytes_down);
#endif

    co_return result;
}

}  // namespace acpp
