#include "acppnode/app/mux_relay.hpp"
#include "acppnode/protocol/mux/mux_codec.hpp"
#include "acppnode/protocol/outbound.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/transport_dialer.hpp"
#include "acppnode/infra/log.hpp"

#include <unordered_map>
#include <deque>
#include <memory>
#include <atomic>
#include <array>
#include <chrono>

#include <boost/asio/steady_timer.hpp>

namespace acpp {

// ============================================================================
// 内部类型
// ============================================================================
namespace {

// 回包元素（出站 → 客户端）
struct MuxReply {
    uint16_t session_id = 0;
    bool is_end = false;
    bool is_udp = false;     // true → EncodeKeepUDP（带源地址）
    TargetAddress udp_src;   // UDP 源地址（is_udp == true 时有效）
    std::vector<uint8_t> data;
};

using ReplyQueue = std::deque<MuxReply>;

// 可跨 Mux 连接共享的 UDP 拨号状态（GlobalID 复用）
struct SharedUdpDial {
    UDPDialResult dial;
    std::array<uint8_t, 8> global_id{};
};

// 当前 DoMuxRelay 持有的 UDP 子会话句柄
struct UdpSubInfo {
    std::shared_ptr<SharedUdpDial> shared;
    uint64_t callback_id = 0;   // 注册在本 Mux 连接上的回调 ID
    TargetAddress last_target;  // 最近发送的目标（KEEP 帧可能复用）
};

// 当前 DoMuxRelay 持有的 TCP 子会话句柄
// stream 使用 shared_ptr：TcpReceiveLoop 协程（net::detached）值捕获后保活，
// 避免 DoMuxRelay 退出后 stream 被析构导致协程访问悬空指针
struct TcpSubInfo {
    std::shared_ptr<AsyncStream> stream;
    std::shared_ptr<std::atomic<bool>> cancel_flag;
};

// ============================================================================
// thread_local GlobalID 映射（per-Worker，接受跨 Worker 无法复用的限制）
// ============================================================================
thread_local std::unordered_map<uint64_t, std::weak_ptr<SharedUdpDial>> g_global_id_map;

void CleanupGlobalIdMap() {
    // 每次新建 UDP 子会话时清理过期条目（频率不高，无需限流）
    for (auto it = g_global_id_map.begin(); it != g_global_id_map.end(); ) {
        if (it->second.expired()) {
            it = g_global_id_map.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// TCP 子会话接收协程（cobalt::spawn 启动，持续读取出站数据推入回包队列）
// ============================================================================
cobalt::task<void> TcpReceiveLoop(
    uint16_t session_id,
    std::shared_ptr<AsyncStream> stream,
    std::shared_ptr<ReplyQueue> queue,
    std::shared_ptr<std::atomic<bool>> cancel_flag)
{
    // 16KB：兼顾协程帧大小和高吞吐子会话的读效率（原 32KB 过大）
    std::array<uint8_t, 16384> buf;
    while (!cancel_flag->load(std::memory_order_relaxed)) {
        try {
            auto n = co_await stream->AsyncRead(net::buffer(buf));
            if (n == 0) {
                MuxReply reply;
                reply.session_id = session_id;
                reply.is_end     = true;
                queue->push_back(std::move(reply));
                break;
            }
            MuxReply reply;
            reply.session_id = session_id;
            reply.is_end     = false;
            reply.is_udp     = false;
            reply.data.assign(buf.data(), buf.data() + n);
            queue->push_back(std::move(reply));
        } catch (...) {
            MuxReply reply;
            reply.session_id = session_id;
            reply.is_end     = true;
            queue->push_back(std::move(reply));
            break;
        }
    }
}

}  // namespace

// ============================================================================
// DoMuxRelay
//
// 处理已解密的 Mux.Cool 帧流（client_stream 是 VMessServerAsyncStream）。
// 每帧可携带 TCP 或 UDP 子会话数据；服务端负责为每个子会话拨号出站。
// ============================================================================
cobalt::task<RelayResult> DoMuxRelay(
    AsyncStream& client_stream,
    IOutbound* outbound,
    SessionContext& parent_ctx,
    StatsShard& stats,
    const UDPRelayConfig& /*config*/)
{
    (void)stats;
    auto executor = co_await cobalt::this_coro::executor;

    // 回包队列：单线程，无锁
    // mux_running 保护回调不在 DoMuxRelay 退出后继续推送
    auto reply_queue = std::make_shared<ReplyQueue>();
    auto mux_running = std::make_shared<std::atomic<bool>>(true);

    // 子会话集合
    std::unordered_map<uint16_t, UdpSubInfo> udp_subs;
    std::unordered_map<uint16_t, TcpSubInfo> tcp_subs;

    // 帧累积缓冲区（处理粘包），使用偏移游标避免逐帧 O(n) erase
    std::vector<uint8_t> frame_buf;
    frame_buf.reserve(4096);
    size_t frame_buf_offset = 0;

    RelayResult result;
    parent_ctx.bytes_up = 0;
    parent_ctx.bytes_down = 0;
    std::array<uint8_t, 16384> read_buf;

    // 轮询定时器（100ms 打断读，回到循环排空回包队列）
    net::steady_timer timer(executor);
    const uint64_t parent_conn_id = parent_ctx.conn_id;
    AsyncStream* client_ptr = &client_stream;

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

    bool running = true;
    auto write_frame_to_client =
        [&](const std::vector<uint8_t>& frame) -> cobalt::task<bool> {
            try {
                size_t written = co_await client_stream.AsyncWrite(net::buffer(frame));
                if (written > 0) {
                    parent_ctx.bytes_down += written;
                    result.bytes_down += written;
                }
                co_return true;
            } catch (const boost::system::system_error&) {
                if (ConsumeWriteSideTimeout(client_stream)) {
                    result.error = ErrorCode::RELAY_TIMEOUT;
                }
                co_return false;
            } catch (...) {
                co_return false;
            }
        };

    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Start");

    while (running) {
        // --------------------------------------------------------------------
        // 1. 排空回包队列 → 序列化写回客户端
        // --------------------------------------------------------------------
        while (!reply_queue->empty()) {
            MuxReply reply = std::move(reply_queue->front());
            reply_queue->pop_front();

            std::vector<uint8_t> frame;
            if (reply.is_end) {
                frame = mux::EncodeEnd(reply.session_id);
                // 子会话已结束，清理本地记录
                udp_subs.erase(reply.session_id);
                tcp_subs.erase(reply.session_id);
            } else if (reply.is_udp) {
                frame = mux::EncodeKeepUDP(
                    reply.session_id, reply.udp_src,
                    reply.data.data(), reply.data.size());
            } else {
                frame = mux::EncodeKeepData(
                    reply.session_id,
                    reply.data.data(), reply.data.size());
            }

            if (!co_await write_frame_to_client(frame)) {
                running = false;
                break;
            }
        }
        if (!running) break;

        // --------------------------------------------------------------------
        // 2. 从客户端读取（100ms 轮询：超时则回到步骤 1 排空回包队列）
        // --------------------------------------------------------------------
        read_poll->Reset();
        timer.expires_after(std::chrono::milliseconds(100));
        timer.async_wait([read_poll, client_ptr](
                              const boost::system::error_code& ec) {
            if (!ec && read_poll->active.exchange(false, std::memory_order_acq_rel)) {
                read_poll->timed_out.store(true, std::memory_order_release);
                client_ptr->Cancel();
            }
        });

        size_t n = 0;
        try {
            n = co_await client_stream.AsyncRead(net::buffer(read_buf));
            read_poll->active.store(false, std::memory_order_release);
            timer.cancel();
        } catch (const boost::system::system_error&) {
            read_poll->active.store(false, std::memory_order_release);
            timer.cancel();
            if (read_poll->timed_out.load(std::memory_order_acquire)) {
                if (ConsumeReadSideTimeout(client_stream)) {
                    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                    result.error = ErrorCode::RELAY_TIMEOUT;
                    running = false;
                    break;
                }
                // 100ms 超时：继续排空回包队列
                continue;
            }
            if (ConsumeReadSideTimeout(client_stream)) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                result.error = ErrorCode::RELAY_TIMEOUT;
            }
            // 真实 I/O 错误
            running = false;
            break;
        }

        if (read_poll->timed_out.load(std::memory_order_acquire) && n == 0) {
            if (ConsumeReadSideTimeout(client_stream)) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                result.error = ErrorCode::RELAY_TIMEOUT;
                running = false;
                break;
            }
            continue;
        }

        if (n == 0) {
            if (ConsumeReadSideTimeout(client_stream)) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Read-side timeout");
                result.error = ErrorCode::RELAY_TIMEOUT;
            }
            running = false;
            break;
        }
        parent_ctx.bytes_up += n;
        result.bytes_up += n;
        frame_buf.insert(frame_buf.end(), read_buf.data(), read_buf.data() + n);

        // --------------------------------------------------------------------
        // 3. 循环解析并分发 Mux 帧
        // --------------------------------------------------------------------
        while (frame_buf_offset < frame_buf.size()) {
            size_t remaining = frame_buf.size() - frame_buf_offset;
            auto opt_hdr = mux::DecodeFrame(frame_buf.data() + frame_buf_offset, remaining);
            if (!opt_hdr) break;  // 数据不足，等待下次读取

            const mux::FrameHeader& hdr = *opt_hdr;
            if (hdr.frame_size == 0) {
                LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Invalid frame");
                result.error = ErrorCode::PROTOCOL_DECODE_FAILED;
                running = false;
                break;
            }

            // Payload 指针（仅 has_data 时有效）
            const uint8_t* payload = nullptr;
            if (hdr.has_data && hdr.data_len > 0) {
                payload = frame_buf.data() + frame_buf_offset + (hdr.frame_size - hdr.data_len);
            }

            switch (hdr.status) {

            // ----------------------------------------------------------------
            case mux::SessionStatus::KEEPALIVE: {
                auto ka = mux::EncodeKeepAlive();
                if (!co_await write_frame_to_client(ka)) {
                    running = false;
                }
                break;
            }

            // ----------------------------------------------------------------
            case mux::SessionStatus::NEW: {
                if (hdr.network == mux::NetworkType::UDP) {
                    // ---- 新建 UDP 子会话 ----
                    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] New UDP sid={}", hdr.session_id);

                    // GlobalID 复用检查
                    std::shared_ptr<SharedUdpDial> shared;
                    if (hdr.has_global_id && !mux::IsNullGlobalId(hdr.global_id)) {
                        CleanupGlobalIdMap();
                        uint64_t gid_key = mux::GlobalIdToKey(hdr.global_id);
                        auto it = g_global_id_map.find(gid_key);
                        if (it != g_global_id_map.end()) {
                            shared = it->second.lock();
                        }
                    }

                    if (!shared) {
                        // 新建 UDP 拨号
                        auto dial_result = co_await outbound->DialUDP(
                            parent_ctx, executor, nullptr);
                        if (!dial_result.Ok()) {
                            LOG_CONN_DEBUG(parent_ctx,
                                "[MuxRelay] UDP dial failed sid={}", hdr.session_id);
                            auto ef = mux::EncodeEnd(hdr.session_id, true);
                            (void)co_await write_frame_to_client(ef);
                            break;
                        }
                        shared = std::make_shared<SharedUdpDial>();
                        shared->dial = std::move(dial_result);
                        if (hdr.has_global_id && !mux::IsNullGlobalId(hdr.global_id)) {
                            shared->global_id = hdr.global_id;
                            g_global_id_map[mux::GlobalIdToKey(hdr.global_id)] = shared;
                        }
                    }

                    // 注册回包回调，推入 reply_queue
                    // 捕获 mux_running 防止 DoMuxRelay 退出后回调仍推送
                    uint16_t sid       = hdr.session_id;
                    auto     rq        = reply_queue;
                    auto     mr        = mux_running;
                    uint64_t cb_id     = 0;
                    if (shared->dial.register_callback) {
                        cb_id = shared->dial.register_callback("",
                            [rq, mr, sid, parent_conn_id](const UDPPacket& pkt) {
                                if (!mr->load(std::memory_order_acquire)) return;
                                LOG_ACCESS_DEBUG("[conn={}] [MuxRelay] UDP recv sid={} {}B",
                                          parent_conn_id, sid, pkt.data.size());
                                MuxReply reply;
                                reply.session_id = sid;
                                reply.is_end     = false;
                                reply.is_udp     = true;
                                reply.udp_src    = pkt.target;
                                reply.data       = pkt.data;
                                rq->push_back(std::move(reply));
                            });
                    }

                    UdpSubInfo sub;
                    sub.shared      = shared;
                    sub.callback_id = cb_id;
                    if (hdr.has_target) sub.last_target = hdr.target;

                    // 转发首包数据
                    if (payload && hdr.data_len > 0 && hdr.has_target) {
                        UDPPacket pkt;
                        pkt.target = hdr.target;
                        pkt.data.assign(payload, payload + hdr.data_len);
                        if (shared->dial.send) {
                            try { co_await shared->dial.send(pkt, cb_id); }
                            catch (...) {}
                        }
                    }

                    udp_subs[hdr.session_id] = std::move(sub);

                } else {
                    // ---- 新建 TCP 子会话 ----
                    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] New TCP sid={} -> {}",
                        hdr.session_id,
                        hdr.has_target ? hdr.target.ToString() : "?");

                    // 用父上下文构造子会话上下文（SessionContext 不可拷贝，手动复制需要的字段）
                    SessionContext sub_ctx;
                    sub_ctx.conn_id          = parent_ctx.conn_id;
                    sub_ctx.worker_id        = parent_ctx.worker_id;
                    sub_ctx.src_addr         = parent_ctx.src_addr;
                    sub_ctx.client_ip        = parent_ctx.client_ip;
                    sub_ctx.inbound_tag      = parent_ctx.inbound_tag;
                    sub_ctx.inbound_tags     = parent_ctx.inbound_tags;
                    sub_ctx.inbound_protocol = parent_ctx.inbound_protocol;
                    sub_ctx.panel_name       = parent_ctx.panel_name;
                    sub_ctx.node_id          = parent_ctx.node_id;
                    sub_ctx.user_id          = parent_ctx.user_id;
                    sub_ctx.user_email       = parent_ctx.user_email;
                    sub_ctx.outbound_tag     = parent_ctx.outbound_tag;
                    sub_ctx.speed_limit      = parent_ctx.speed_limit;
                    if (hdr.has_target) {
                        sub_ctx.target       = hdr.target;
                        sub_ctx.final_target = hdr.target;
                    }
                    sub_ctx.network = Network::TCP;

                    auto transport_target = co_await outbound->ResolveTransportTarget(sub_ctx);
                    if (!transport_target) {
                        LOG_CONN_DEBUG(parent_ctx,
                            "[MuxRelay] TCP resolve target failed sid={}", hdr.session_id);
                        auto ef = mux::EncodeEnd(hdr.session_id, true);
                        (void)co_await write_frame_to_client(ef);
                        break;
                    }

                    auto dial_result = co_await TransportDialer::Dial(
                        executor, sub_ctx, *transport_target);
                    if (!dial_result.Ok()) {
                        LOG_CONN_DEBUG(parent_ctx,
                            "[MuxRelay] TCP dial failed sid={}", hdr.session_id);
                        auto ef = mux::EncodeEnd(hdr.session_id, true);
                        (void)co_await write_frame_to_client(ef);
                        break;
                    }

                    auto cancel_flag = std::make_shared<std::atomic<bool>>(false);
                    uint16_t    sid  = hdr.session_id;

                    TcpSubInfo sub;
                    sub.cancel_flag = cancel_flag;
                    // unique_ptr → shared_ptr：协程值捕获后保活
                    sub.stream = std::shared_ptr<AsyncStream>(dial_result.stream.release());

                    // 启动接收协程（值捕获 shared_ptr，保证 stream 存活到协程结束）
                    cobalt::spawn(executor,
                        TcpReceiveLoop(sid, sub.stream, reply_queue, cancel_flag),
                        net::detached);

                    // 转发首包数据
                    bool first_write_failed = false;
                    if (payload && hdr.data_len > 0) {
                        try {
                            co_await sub.stream->AsyncWrite(
                                net::buffer(payload, hdr.data_len));
                        } catch (...) {
                            first_write_failed = true;
                            cancel_flag->store(true);
                            sub.stream->Cancel();
                        }
                    }
                    if (first_write_failed) {
                        auto ef = mux::EncodeEnd(hdr.session_id, true);
                        (void)co_await write_frame_to_client(ef);
                        break;
                    }

                    tcp_subs[hdr.session_id] = std::move(sub);
                }
                break;
            }

            // ----------------------------------------------------------------
            case mux::SessionStatus::KEEP: {
                if (hdr.has_target) {
                    // UDP 数据包（携带目标/源地址）
                    auto it = udp_subs.find(hdr.session_id);
                    if (it != udp_subs.end() && payload && hdr.data_len > 0) {
                        it->second.last_target = hdr.target;
                        UDPPacket pkt;
                        pkt.target = hdr.target;
                        pkt.data.assign(payload, payload + hdr.data_len);
                        if (it->second.shared->dial.send) {
                            try {
                                co_await it->second.shared->dial.send(
                                    pkt, it->second.callback_id);
                            } catch (...) {}
                        }
                    }
                } else {
                    // TCP 数据
                    auto it = tcp_subs.find(hdr.session_id);
                    bool tcp_write_failed = false;
                    if (it != tcp_subs.end() && payload && hdr.data_len > 0) {
                        try {
                            co_await it->second.stream->AsyncWrite(
                                net::buffer(payload, hdr.data_len));
                        } catch (...) {
                            // 写入失败：关闭子会话
                            tcp_write_failed = true;
                            it->second.cancel_flag->store(true);
                            it->second.stream->Cancel();
                            tcp_subs.erase(it);
                        }
                    }
                    if (tcp_write_failed) {
                        auto ef = mux::EncodeEnd(hdr.session_id);
                        if (!co_await write_frame_to_client(ef)) {
                            running = false;
                        }
                    }
                }
                break;
            }

            // ----------------------------------------------------------------
            case mux::SessionStatus::END: {
                uint16_t sid = hdr.session_id;

                // 注销 UDP 子会话
                auto udp_it = udp_subs.find(sid);
                if (udp_it != udp_subs.end()) {
                    if (udp_it->second.shared->dial.unregister_callback &&
                        udp_it->second.callback_id != 0) {
                        udp_it->second.shared->dial.unregister_callback(
                            udp_it->second.callback_id);
                    }
                    udp_subs.erase(udp_it);
                }

                // 取消 TCP 子会话
                auto tcp_it = tcp_subs.find(sid);
                if (tcp_it != tcp_subs.end()) {
                    tcp_it->second.cancel_flag->store(true);
                    tcp_it->second.stream->Cancel();
                    tcp_subs.erase(tcp_it);
                }

                // 回送 End 帧
                auto ef = mux::EncodeEnd(sid);
                if (!co_await write_frame_to_client(ef)) {
                    running = false;
                }
                break;
            }

            }  // switch (hdr.status)

            // 移动偏移游标（O(1)），代替逐帧 erase 的 O(n) memmove
            frame_buf_offset += hdr.frame_size;
        }

        // 压缩：所有帧处理完毕后一次性移除已消费的前缀
        if (frame_buf_offset > 0) {
            if (frame_buf_offset >= frame_buf.size()) {
                frame_buf.clear();
            } else {
                frame_buf.erase(frame_buf.begin(),
                    frame_buf.begin() + static_cast<std::ptrdiff_t>(frame_buf_offset));
            }
            frame_buf_offset = 0;
        }
    }

    // ------------------------------------------------------------------------
    // 清理所有存活的子会话
    // ------------------------------------------------------------------------
    // 先标记停止，阻止回调继续推送到 reply_queue
    mux_running->store(false, std::memory_order_release);

    LOG_CONN_DEBUG(parent_ctx, "[MuxRelay] Cleanup: UDP={} TCP={}",
        udp_subs.size(), tcp_subs.size());

    for (const auto& [sid, udp_sub] : udp_subs) {
        if (udp_sub.shared->dial.unregister_callback && udp_sub.callback_id != 0) {
            udp_sub.shared->dial.unregister_callback(udp_sub.callback_id);
        }
    }
    for (const auto& [sid, tcp_sub] : tcp_subs) {
        tcp_sub.cancel_flag->store(true);
        tcp_sub.stream->Cancel();
    }

    co_return result;
}

}  // namespace acpp
