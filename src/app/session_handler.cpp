#include "acppnode/app/session_handler.hpp"
#include "acppnode/app/mux_relay.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/protocol/outbound.hpp"
#include "acppnode/transport/transport_dialer.hpp"
#include "acppnode/transport/tcp_stream.hpp"

namespace acpp {

namespace {

ErrorCode ResolvePhaseError(const PhaseDeadlineHandle& deadline, ErrorCode fallback) {
    return deadline.Expired() ? ErrorCode::TIMEOUT : fallback;
}

}  // namespace

SessionHandler::SessionHandler(
    OutboundManager& outbound_manager,
    Router& router,
    IDnsService& dns,
    StatsShard& stats,
    const TimeoutsConfig& timeouts)
    : outbound_manager_(outbound_manager)
    , router_(router)
    , dns_(dns)
    , stats_(stats)
    , timeouts_(timeouts)
{}

// ============================================================================
// Handle - 完整会话处理流程（零协议知识）
//
// 状态转换由协程顺序执行保证，无需显式 FSM：
//   ACCEPTED → HANDSHAKING → SNIFFING → ROUTING → DIALING → RELAYING → CLOSING
// ============================================================================
cobalt::task<void> SessionHandler::Handle(
    std::unique_ptr<AsyncStream> raw_conn,
    SessionContext& ctx,
    const ListenerContext& listener)
{
    // ----------------------------------------------------------------
    // 0. 早期 IP ban 检查（TLS 握手前，避免被封 IP 消耗 TLS 资源）
    // ----------------------------------------------------------------
    if (listener.limiter &&
        listener.limiter->GetLimiter().IsBanned(ctx.inbound_tag, ctx.client_ip)) {
        LOG_ACCESS_FMT("{} from {}:{} rejected ip_banned [{}] (early)",
            FormatTimestamp(ctx.accept_time_us),
            ctx.client_ip, ctx.src_addr.port(), ctx.inbound_tag);
        ctx.SetError(ErrorCode::BLOCKED);
        ctx.TransitionTo(ConnState::CLOSING);
        stats_.OnError();
        co_return;
    }

    // ----------------------------------------------------------------
    // 1. 构建入站传输层堆栈（TLS 握手 + WS 升级）
    //    协议层对此一无所知
    // ----------------------------------------------------------------
    // 标记入站流，便于超时日志区分 inbound/outbound
    if (auto* tcp = raw_conn->GetBaseTcpStream()) {
        tcp->SetStreamLabel("in");
    }
    // 设置握手阶段空闲超时：TLS/WS/协议解析期间，
    // 客户端不发数据则自动 Cancel 底层 socket
    raw_conn->SetIdleTimeout(timeouts_.HandshakeTimeout());
    auto inbound_handshake_deadline =
        raw_conn->StartPhaseDeadline(timeouts_.HandshakeTimeout());

    std::string ws_real_ip;
    auto build_result = co_await TransportStack::BuildInbound(
        std::move(raw_conn), listener.stream_settings,
        listener.stream_settings.IsWs() ? &ws_real_ip : nullptr);

    if (!build_result) {
        LOG_CONN_DEBUG(ctx, "[SessionHandler] Transport handshake failed ({}/{})",
                       listener.stream_settings.security,
                       listener.stream_settings.network);
        ctx.SetError(ResolvePhaseError(inbound_handshake_deadline, build_result.error()));
        ctx.TransitionTo(ConnState::CLOSING);
        stats_.OnError();
        co_return;
    }
    auto stream = std::move(*build_result);

    // WS CDN 真实 IP：覆盖 TCP 层地址（仅当配置了 real_ip_header 且头存在时）
    if (!ws_real_ip.empty()) {
        LOG_CONN_DEBUG(ctx, "[SessionHandler] WS real IP from header: {} -> {}",
                       ctx.client_ip, ws_real_ip);
        ctx.client_ip = std::move(ws_real_ip);
    }

    LOG_CONN_DEBUG(ctx, "[SessionHandler] Transport ready ({}/{})",
                   listener.stream_settings.security,
                   listener.stream_settings.network);
    ctx.TransitionTo(ConnState::HANDSHAKING);

    // ----------------------------------------------------------------
    // 2. 协议解析（IInboundHandler vtable）
    //    不知道是 VMess / Trojan / 其他协议
    // ----------------------------------------------------------------
    auto parse_result = co_await listener.inbound_handler->ParseStream(*stream, ctx);
    const bool inbound_phase_timed_out =
        inbound_handshake_deadline.Expired() || stream->ConsumePhaseDeadline();
    stream->ClearPhaseDeadline();
    if (!parse_result) {
        ctx.SetError(inbound_phase_timed_out ? ErrorCode::TIMEOUT : parse_result.error());
        ctx.TransitionTo(ConnState::CLOSING);
        stats_.OnError();
        co_return;
    }
    auto& action = *parse_result;

    ctx.TransitionTo(ConnState::SNIFFING);  // 记录 handshake_done_us

    // 填充上下文目标地址
    ctx.target       = action.target;
    ctx.final_target = action.target;
    ctx.network      = action.network;

    LOG_CONN_DEBUG(ctx, "[SessionHandler] Protocol auth ok: [{}] -> {} user={}",
                   ctx.inbound_tag, action.target.ToString(), ctx.user_email);

    // ----------------------------------------------------------------
    // 3. 流量嗅探（可选）
    //    - 快速路径：Trojan/SS 等协议在 ParseStream 时已解密首包
    //    - 延迟路径：VMess 等需要先 WrapStream 建立解密流再读首包
    // ----------------------------------------------------------------
    std::unique_ptr<AsyncStream> early_wrapped_in;  // 延迟嗅探时提前创建的解密流
    std::vector<uint8_t> late_sniff_payload;        // 延迟嗅探读出的首包明文

    // 确定嗅探数据源
    std::span<const uint8_t> sniff_data;
    if (listener.sniff_config.enabled && !action.initial_payload.empty()) {
        // 快速路径：直接使用 initial_payload
        sniff_data = std::span<const uint8_t>(
            action.initial_payload.data(), action.initial_payload.size());
    } else if (listener.sniff_config.enabled && action.initial_payload.empty()
               && action.network == Network::TCP) {
        // 延迟路径：VMess 等加密协议在 ParseStream 时无法解密首包
        // WrapStream 建立解密流后读取首包明文，用于嗅探和 dest_override
        auto wrap_result = co_await listener.inbound_handler->WrapStream(
            std::move(stream), ctx);
        if (wrap_result) {
            early_wrapped_in = std::move(*wrap_result);
            // 读取首个解密 chunk（通常包含 TLS ClientHello 或 HTTP 请求）
            late_sniff_payload.resize(4096);
            size_t n = co_await early_wrapped_in->AsyncRead(
                net::buffer(late_sniff_payload.data(), late_sniff_payload.size()));
            late_sniff_payload.resize(n);
            if (n > 0) {
                sniff_data = std::span<const uint8_t>(
                    late_sniff_payload.data(), late_sniff_payload.size());
            }
        }
    }

    // 执行嗅探
    if (!sniff_data.empty()) {
        auto result = Sniff(sniff_data);
        ctx.sniff_result = result;

        if (result.success && !result.domain.empty()) {
            LOG_CONN_DEBUG(ctx, "[SessionHandler] Sniff: proto={} domain={}",
                           result.protocol, result.domain);

            // 协议是否在 dest_override 列表中
            bool proto_matched = false;
            for (const auto& proto : listener.sniff_config.dest_override) {
                if (proto == result.protocol) { proto_matched = true; break; }
            }

            // 排除列表检查
            bool excluded = false;
            for (const auto& ex : listener.sniff_config.domains_excluded) {
                if (result.domain == ex) { excluded = true; break; }
            }

            if (proto_matched && !excluded) {
                ctx.final_target.type = AddressType::Domain;
                ctx.final_target.host = result.domain;
                ctx.final_target.port = ctx.target.port;
            }
        }
    }

    ctx.TransitionTo(ConnState::ROUTING);  // 记录 sniff_done_us

    // ----------------------------------------------------------------
    // 4. 路由决策
    // ----------------------------------------------------------------
    if (!listener.fixed_outbound.empty()) {
        ctx.outbound_tag = listener.fixed_outbound;
        LOG_CONN_DEBUG(ctx, "[SessionHandler] Route: {} -> outbound={} (fixed, bypass router)",
                       ctx.final_target.ToString(), ctx.outbound_tag);
    } else {
        ctx.outbound_tag = router_.Route(ctx);
        LOG_CONN_DEBUG(ctx, "[SessionHandler] Route: {} -> outbound={}",
                       ctx.final_target.ToString(), ctx.outbound_tag);
    }

    auto* outbound = outbound_manager_.GetOutbound(ctx.outbound_tag);
    if (!outbound) {
        LOG_CONN_FAIL_CTX(ctx, "OUTBOUND_NOT_FOUND {} -> {} via {}",
                          ctx.client_ip, ctx.final_target.ToString(), ctx.outbound_tag);
        ctx.SetError(ErrorCode::ROUTER_OUTBOUND_NOT_FOUND);
        ctx.TransitionTo(ConnState::CLOSING);
        co_return;
    }

    ctx.TransitionTo(ConnState::DIALING);

    // ----------------------------------------------------------------
    // 5. 拨号（TCP / UDP）
    // ----------------------------------------------------------------
    if (ctx.network == Network::UDP) {
        if (!outbound->SupportsUDP()) {
            LOG_CONN_DEBUG(ctx, "[SessionHandler] UDP not supported by outbound={}", ctx.outbound_tag);
            ctx.SetError(ErrorCode::NOT_SUPPORTED);
            ctx.TransitionTo(ConnState::CLOSING);
            co_return;
        }
        LOG_CONN_DEBUG(ctx, "[SessionHandler] UDP dial start -> {} via {}",
                       ctx.final_target.ToString(), ctx.outbound_tag);
        auto executor   = co_await cobalt::this_coro::executor;
        auto udp_result = co_await outbound->DialUDP(ctx, executor, nullptr);
        if (!udp_result.Ok()) {
            ctx.SetError(udp_result.error);
            ctx.TransitionTo(ConnState::CLOSING);
            co_return;
        }

        ctx.TransitionTo(ConnState::RELAYING);  // 记录 dial_done_us
        LOG_CONN_DEBUG(ctx, "[SessionHandler] UDP dial ok via {}", ctx.outbound_tag);
        LOG_ACCESS(ctx.ToAccessLog());

        // 包装入站流（VMess 有 chunk 加密；Trojan 透传）
        auto wrapped_in_result = co_await listener.inbound_handler->WrapStream(std::move(stream), ctx);
        if (!wrapped_in_result) {
            ErrorCode code = wrapped_in_result.error();
            if (code == ErrorCode::OK) {
                code = ErrorCode::PROTOCOL_DECODE_FAILED;
            }
            LOG_CONN_FAIL_CTX(ctx, "INBOUND_WRAP_FAILED {} -> {} via {}: {}",
                              ctx.client_ip, ctx.final_target.ToString(),
                              ctx.outbound_tag, ErrorCodeToString(code));
            ctx.SetError(code);
            ctx.TransitionTo(ConnState::CLOSING);
            co_return;
        }
        auto wrapped_in = std::move(*wrapped_in_result);

        // 对齐 Xray：relay 阶段只靠 connIdle
        wrapped_in->SetIdleTimeout(timeouts_.StreamIdleTimeout());
        wrapped_in->SetReadTimeout(std::chrono::seconds(0));
        wrapped_in->SetWriteTimeout(std::chrono::seconds(0));

        UDPRelayConfig udp_cfg;
        udp_cfg.speed_limit = ctx.speed_limit;

        // 协议层提供 UDP 帧编解码器，SessionHandler 无需协议分支
        UdpFramer framer = action.make_udp_framer
            ? action.make_udp_framer()
            : UdpFramer{PayloadOnlyUdpFramer{ctx.target}};

        auto relay_result = co_await DoUDPRelay(
            *wrapped_in, udp_result, framer, ctx, stats_, udp_cfg);

        if (relay_result.error != ErrorCode::OK) {
            LOG_CONN_DEBUG(ctx, "[SessionHandler] UDP relay end: {} up={}B down={}B target={}",
                           ErrorCodeToString(relay_result.error),
                           ctx.bytes_up, ctx.bytes_down,
                           ctx.final_target.ToString());
            ctx.SetError(relay_result.error);
        } else {
            LOG_CONN_DEBUG(ctx, "[SessionHandler] UDP relay end: OK up={}B down={}B target={}",
                           ctx.bytes_up, ctx.bytes_down,
                           ctx.final_target.ToString());
        }
        ctx.TransitionTo(ConnState::CLOSING);
        co_return;
    }

    // ----------------------------------------------------------------
    // Mux.Cool 多路复用（VMess Command=Mux）
    // ----------------------------------------------------------------
    if (ctx.network == Network::MUX) {
        ctx.TransitionTo(ConnState::RELAYING);
        LOG_ACCESS(ctx.ToAccessLog());

        auto wrapped_in_result = co_await listener.inbound_handler->WrapStream(std::move(stream), ctx);
        if (!wrapped_in_result) {
            ErrorCode code = wrapped_in_result.error();
            if (code == ErrorCode::OK) {
                code = ErrorCode::PROTOCOL_DECODE_FAILED;
            }
            LOG_CONN_FAIL_CTX(ctx, "INBOUND_WRAP_FAILED {} -> {} via {}: {}",
                              ctx.client_ip, ctx.final_target.ToString(),
                              ctx.outbound_tag, ErrorCodeToString(code));
            ctx.SetError(code);
            ctx.TransitionTo(ConnState::CLOSING);
            co_return;
        }
        auto wrapped_in = std::move(*wrapped_in_result);

        // 对齐 Xray：relay 阶段只靠 connIdle
        wrapped_in->SetIdleTimeout(timeouts_.StreamIdleTimeout());
        wrapped_in->SetReadTimeout(std::chrono::seconds(0));
        wrapped_in->SetWriteTimeout(std::chrono::seconds(0));

        UDPRelayConfig mux_cfg;
        mux_cfg.speed_limit = ctx.speed_limit;

        auto relay_result = co_await DoMuxRelay(
            *wrapped_in, outbound, ctx, stats_, mux_cfg);

        if (relay_result.error != ErrorCode::OK) ctx.SetError(relay_result.error);
        ctx.TransitionTo(ConnState::CLOSING);
        co_return;
    }

    // TCP 拨号（统一传输编排：TCP + [TLS/WS]，协议握手在后续步骤）
    LOG_CONN_DEBUG(ctx, "[SessionHandler] TCP dial start -> {} via {}",
                   ctx.final_target.ToString(), ctx.outbound_tag);
    auto transport_target = co_await outbound->ResolveTransportTarget(ctx);
    if (!transport_target) {
        LOG_CONN_FAIL_CTX(ctx, "RESOLVE_OUTBOUND_TARGET_FAILED {} -> {} via {}",
                          ctx.client_ip, ctx.final_target.ToString(), ctx.outbound_tag);
        ctx.SetError(transport_target.error());
        ctx.TransitionTo(ConnState::CLOSING);
        co_return;
    }
    auto dial_exec = co_await cobalt::this_coro::executor;
    auto dial_result = co_await TransportDialer::Dial(dial_exec, ctx, *transport_target);
    if (!dial_result.Ok()) {
        LOG_CONN_FAIL_CTX(ctx, "DIAL_FAILED {} -> {} via {}: {}",
                          ctx.client_ip, ctx.final_target.ToString(),
                          ctx.outbound_tag, dial_result.error_msg);
        ctx.SetError(dial_result.error_code);
        ctx.TransitionTo(ConnState::CLOSING);
        co_return;
    }
    // 标记出站流
    if (auto* tcp = dial_result.stream->GetBaseTcpStream()) {
        tcp->SetStreamLabel("out");
    }
    LOG_CONN_DEBUG(ctx, "[SessionHandler] TCP dial ok -> {} via {}",
                   ctx.final_target.ToString(), ctx.outbound_tag);
    LOG_ACCESS(ctx.ToAccessLog());

    // ----------------------------------------------------------------
    // 6. 出站协议握手（可选，协议层由 IOutboundHandler 负责）
    //    VMess: noop（握手在 WrapStream 中完成）
    //    Trojan: 发送 SHA224+目标地址请求头
    //    Freedom: noop
    // ----------------------------------------------------------------
    auto* outbound_handler = outbound->GetOutboundHandler();
    PhaseDeadlineHandle outbound_protocol_deadline;
    if (outbound_handler) {
        dial_result.stream->SetIdleTimeout(timeouts_.HandshakeTimeout());
        outbound_protocol_deadline =
            dial_result.stream->StartPhaseDeadline(timeouts_.HandshakeTimeout());
        auto handshake_result = co_await outbound_handler->Handshake(
                *dial_result.stream, ctx,
                std::span<const uint8_t>(action.initial_payload.data(),
                                         action.initial_payload.size()));
        if (!handshake_result) {
            const bool outbound_phase_timed_out =
                outbound_protocol_deadline.Expired() ||
                dial_result.stream->ConsumePhaseDeadline();
            dial_result.stream->ClearPhaseDeadline();
            ErrorCode handshake_error = handshake_result.error();
            if (handshake_error == ErrorCode::OK) {
                handshake_error = ErrorCode::PROTOCOL_AUTH_FAILED;
            }
            const ErrorCode resolved_error = outbound_phase_timed_out
                ? ErrorCode::TIMEOUT
                : handshake_error;
            LOG_CONN_FAIL_CTX(ctx, "OUTBOUND_HANDSHAKE_FAILED {} -> {} via {}: {}",
                              ctx.client_ip, ctx.final_target.ToString(),
                              ctx.outbound_tag, ErrorCodeToString(resolved_error));
            ctx.SetError(resolved_error);
            ctx.TransitionTo(ConnState::CLOSING);
            co_return;
        }
        LOG_CONN_DEBUG(ctx, "[SessionHandler] Outbound handshake ok via {}", ctx.outbound_tag);
    }

    // ----------------------------------------------------------------
    // 7. 包装出站流（协议加密 / 帧格式）
    //    VMess: 创建 VMessClientAsyncStream + SendHandshake
    //    Trojan/Freedom: 透传（协议头已在步骤 6 发出）
    // ----------------------------------------------------------------
    std::unique_ptr<AsyncStream> wrapped_out;
    if (outbound_handler) {
        auto wrap_result = co_await outbound_handler->WrapStream(
            std::move(dial_result.stream), ctx);
        if (!wrap_result) {
            LOG_CONN_FAIL_CTX(ctx, "OUTBOUND_WRAP_FAILED {} -> {} via {}",
                              ctx.client_ip, ctx.final_target.ToString(), ctx.outbound_tag);
            ErrorCode wrap_error = wrap_result.error();
            if (wrap_error == ErrorCode::OK) {
                wrap_error = ErrorCode::PROTOCOL_AUTH_FAILED;
            }
            ctx.SetError(ResolvePhaseError(outbound_protocol_deadline, wrap_error));
            ctx.TransitionTo(ConnState::CLOSING);
            co_return;
        }
        wrapped_out = std::move(*wrap_result);
        wrapped_out->ClearPhaseDeadline();
    } else {
        wrapped_out = std::move(dial_result.stream);
    }

    ctx.TransitionTo(ConnState::RELAYING);  // 记录 dial_done_us

    // ----------------------------------------------------------------
    // 8. 包装入站流（协议解密 / 帧解析）
    //    VMess: VMessServerAsyncStream（chunk 解密）
    //    Trojan: 透传
    //    延迟嗅探路径已在步骤 3 提前完成 WrapStream
    // ----------------------------------------------------------------
    std::unique_ptr<AsyncStream> wrapped_in;
    if (early_wrapped_in) {
        wrapped_in = std::move(early_wrapped_in);
    } else {
        auto wrapped_in_raw_result = co_await listener.inbound_handler->WrapStream(std::move(stream), ctx);
        if (!wrapped_in_raw_result) {
            ErrorCode code = wrapped_in_raw_result.error();
            if (code == ErrorCode::OK) {
                code = ErrorCode::PROTOCOL_DECODE_FAILED;
            }
            LOG_CONN_FAIL_CTX(ctx, "INBOUND_WRAP_FAILED {} -> {} via {}: {}",
                              ctx.client_ip, ctx.final_target.ToString(),
                              ctx.outbound_tag, ErrorCodeToString(code));
            ctx.SetError(code);
            ctx.TransitionTo(ConnState::CLOSING);
            co_return;
        }
        wrapped_in = std::move(*wrapped_in_raw_result);
    }

    // ----------------------------------------------------------------
    // 9. 双向数据转发
    //    initial_payload: 入站首包数据，先写入出站再开始双向 relay
    // ----------------------------------------------------------------
    // 对齐 Xray：relay 阶段只靠 connIdle，禁用单次读写超时
    wrapped_in->SetIdleTimeout(timeouts_.StreamIdleTimeout());
    wrapped_in->SetReadTimeout(std::chrono::seconds(0));
    wrapped_in->SetWriteTimeout(std::chrono::seconds(0));
    wrapped_out->SetIdleTimeout(timeouts_.StreamIdleTimeout());
    wrapped_out->SetReadTimeout(std::chrono::seconds(0));
    wrapped_out->SetWriteTimeout(std::chrono::seconds(0));

    RelayConfig relay_cfg;
    relay_cfg.uplink_only   = timeouts_.UplinkOnlyTimeout();
    relay_cfg.downlink_only = timeouts_.DownlinkOnlyTimeout();
    relay_cfg.speed_limit   = ctx.speed_limit;

    // 延迟嗅探路径：首包已从解密流预读，作为 relay 首包数据
    auto& relay_payload = late_sniff_payload.empty()
        ? action.initial_payload : late_sniff_payload;

    LOG_CONN_DEBUG(ctx, "[SessionHandler] Relay start: {} -> {} via {} payload={}B",
                   ctx.client_ip, ctx.final_target.ToString(), ctx.outbound_tag,
                   relay_payload.size());

    auto relay_result = co_await DoRelayWithFirstPacket(
        *wrapped_in, *wrapped_out, ctx, stats_,
        relay_payload, relay_cfg);

    if (relay_result.error != ErrorCode::OK) {
        LOG_CONN_DEBUG(ctx, "[SessionHandler] Relay end: {} up={}B down={}B closer={} target={}",
                       ErrorCodeToString(relay_result.error),
                       ctx.bytes_up, ctx.bytes_down,
                       relay_result.client_closed_first ? "client" : "target",
                       ctx.final_target.ToString());
        ctx.SetError(relay_result.error);
    } else {
        LOG_CONN_DEBUG(ctx, "[SessionHandler] Relay end: OK up={}B down={}B target={}",
                       ctx.bytes_up, ctx.bytes_down,
                       ctx.final_target.ToString());
    }
    ctx.TransitionTo(ConnState::CLOSING);
}

}  // namespace acpp
