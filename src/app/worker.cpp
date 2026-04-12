#include "acppnode/app/worker.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/connection_guard.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/transport/tcp_stream.hpp"
#include "acppnode/transport/proxy_protocol.hpp"
#include "acppnode/protocol/outbound.hpp"
#include "acppnode/protocol/protocol_registry.hpp"
#include "acppnode/router/router.hpp"
#include "acppnode/common/error.hpp"

#ifndef _WIN32
#include <sys/socket.h>
#endif
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <format>

namespace acpp {

namespace {

constexpr auto kAcceptErrorBackoff = std::chrono::milliseconds(5);
constexpr auto kAcceptResourceBackoff = std::chrono::milliseconds(100);

std::vector<std::string> BuildListenCandidates(std::string_view listen) {
    return {std::string(listen)};
}

uint32_t ComputePressureThreshold(const Config& config) {
    uint32_t threshold = defaults::kMaxConnectionsPerWorker
        * defaults::kPressurePercent / 100;

    const uint32_t configured_max = config.GetLimits().max_connections;
    const uint32_t workers = std::max<uint32_t>(1, config.GetWorkers());
    if (configured_max > 0) {
        const uint32_t per_worker_budget = std::max<uint32_t>(
            1, (configured_max + workers - 1) / workers);
        const uint32_t configured_threshold = std::max<uint32_t>(
            1, per_worker_budget * defaults::kPressurePercent / 100);
        threshold = std::min(threshold, configured_threshold);
    }

    return std::max<uint32_t>(threshold, 1);
}

}

InboundProtocolDeps Worker::GetInboundProtocolDeps() {
    auto& stats = Stats();
    return InboundProtocolDeps{
        &user_manager_,
        &trojan_user_manager_,
        &ss_user_manager_,
        &stats,
    };
}

// ============================================================================
// Worker 构造 / 析构
// ============================================================================

Worker::Worker(uint32_t id, net::io_context& io_context,
               const Config& config, ShardedStats& global_stats,
               geo::GeoManager* geo_manager)
    : id_(id)
    , io_context_(io_context)
    , config_(config)
    , global_stats_(global_stats)
    , geo_manager_(geo_manager)
    , user_manager_(true)
    , trojan_user_manager_(true) {

    InitDnsService();
    InitUDPSessionManager();
    InitOutbounds();
    InitRouter();

    session_handler_ = std::make_unique<SessionHandler>(
        *outbound_manager_,
        *router_,
        *dns_service_,
        global_stats_.GetShard(id_),
        config_.GetTimeouts());
}

Worker::~Worker() {
    while (!udp_sockets_.empty()) {
        StopUdpListening(udp_sockets_.begin()->first);
    }
    while (!udp_client_sessions_.empty()) {
        CleanupUdpClientSessions(udp_client_sessions_.begin()->first);
    }
    if (udp_session_manager_) {
        udp_session_manager_->StopAll();
    }
}

// ============================================================================
// 初始化
// ============================================================================

void Worker::InitDnsService() {
    DnsService::Config dns_config;
    dns_config.servers    = config_.GetDns().servers;
    dns_config.timeout_sec = config_.GetDns().timeout;
    dns_config.cache_size = config_.GetDns().cache_size;
    dns_config.min_ttl    = config_.GetDns().min_ttl;
    dns_config.max_ttl    = config_.GetDns().max_ttl;
    dns_service_ = CreateDnsService(io_context_.get_executor(), dns_config);
}

void Worker::InitUDPSessionManager() {
    auto timeout = config_.GetTimeouts().SessionIdleTimeout();
    udp_session_manager_ = std::make_unique<UDPSessionManager>(
        io_context_.get_executor(), dns_service_.get(), timeout);
    udp_session_manager_->StartCleanup();
    LOG_DEBUG("Worker[{}]: UDP session manager initialized (timeout={}s)",
              id_, timeout.count());
}

void Worker::InitOutbounds() {
    outbound_manager_ = std::make_unique<OutboundManager>();
    const auto dial_timeout = config_.GetTimeouts().DialTimeout();
    const auto executor     = io_context_.get_executor();

    for (const auto& ob_config : config_.GetOutbounds()) {
        auto outbound = OutboundFactory::Instance().Create(
            ob_config, executor,
            dns_service_.get(), udp_session_manager_.get(),
            dial_timeout);

        if (outbound) {
            LOG_DEBUG("Worker[{}]: registered {} outbound '{}'",
                      id_, ob_config.protocol, ob_config.tag);
            outbound_manager_->RegisterOutbound(std::move(outbound));
        } else {
            LOG_WARN("Worker[{}]: failed to create {} outbound '{}'"
                     " (unregistered protocol or invalid config)",
                     id_, ob_config.protocol, ob_config.tag);
        }
    }
}

void Worker::InitRouter() {
    const auto& routing = config_.GetRouting();
    router_ = std::make_unique<Router>();
    // 默认出站 = 第一个 outbound（LoadFromFile 保证 direct 在最前面）
    const auto& outbounds = config_.GetOutbounds();
    if (!outbounds.empty()) {
        router_->SetDefaultOutbound(outbounds.front().tag);
    }

    if (geo_manager_) {
        router_->SetGeoManager(geo_manager_);
    }

    for (const auto& rc : routing.rules) {
        CompoundRoutingRule compound;
        compound.outbound_tag = rc.outbound_tag;

        if (!rc.network.empty()) {
            compound.conditions.push_back(NetworkCondition{rc.network});
        }

        if (!rc.inbound_tag.empty()) {
            compound.conditions.push_back(InboundTagCondition{rc.inbound_tag});
        } else {
            // 隐式 inboundTag=node：没有显式 inboundTag 条件的规则只匹配面板入站
            compound.conditions.push_back(
                InboundTagCondition{std::vector<std::string>{std::string(constants::protocol::kNode)}});
        }

        if (!rc.user.empty()) {
            compound.conditions.push_back(UserCondition{rc.user});
        }

        if (!rc.source_port.empty()) {
            compound.conditions.push_back(SourcePortCondition{rc.source_port});
        }

        if (!rc.port.empty()) {
            compound.conditions.push_back(PortCondition{rc.port});
        }

        if (!rc.protocol.empty()) {
            compound.conditions.push_back(ProtocolCondition{rc.protocol});
        }

        {
            IPMatcher sim;
            for (const auto& v : rc.source) { sim.AddCIDR(v); }
            if (!sim.Empty()) {
                sim.BuildIndex();
                compound.conditions.push_back(SourceIPCondition{std::move(sim)});
            }
        }

        IPMatcher im;
        for (const auto& v : rc.ip) { im.AddCIDR(v); }
        if (!im.Empty()) {
            im.BuildIndex();
            compound.conditions.push_back(IPCondition{std::move(im)});
        }

        DomainMatcher dm;
        for (const auto& v : rc.domain)         { dm.AddSuffix(v); }
        for (const auto& v : rc.domain_suffix)  { dm.AddSuffix(v); }
        for (const auto& v : rc.domain_keyword) { dm.AddKeyword(v); }
        for (const auto& v : rc.domain_full)    { dm.AddDomain(v); }
        if (!dm.Empty()) {
            compound.conditions.push_back(DomainCondition{std::move(dm)});
        }

        if (!rc.geosite.empty()) {
            compound.conditions.push_back(GeoSiteCondition{rc.geosite});
        }

        if (!rc.geoip.empty()) {
            compound.conditions.push_back(GeoIPCondition{rc.geoip});
        }

        if (!compound.conditions.empty()) {
            router_->AddCompoundRule(std::move(compound));
        }
    }

    LOG_DEBUG("Worker[{}]: router initialized, {} rules, default='{}'",
              id_, routing.rules.size(), router_->DefaultOutbound());
}

// ============================================================================
// SO_REUSEPORT 监听管理（仅在 Worker io_context 上调用）
// ============================================================================

void Worker::StartListening(PortBinding binding) {
    if (acceptors_.contains(binding.tag)) {
        LOG_WARN("Worker[{}]: replacing existing TCP listener tag={}", id_, binding.tag);
        StopListening(binding.tag);
    }

    tcp::acceptor acceptor(io_context_);
    std::string actual_listen;
    const auto listen_candidates = BuildListenCandidates(binding.listen);

    for (size_t i = 0; i < listen_candidates.size(); ++i) {
        const auto& listen_addr = listen_candidates[i];
        boost::system::error_code ec;
        auto addr = net::ip::make_address(listen_addr, ec);
        if (ec) {
            LOG_ERROR("Worker[{}]: invalid listen address '{}': {}",
                      id_, listen_addr, ec.message());
            return;
        }
        if (!addr.is_v4()) {
            LOG_ERROR("Worker[{}]: non-IPv4 listen address '{}' is not supported",
                      id_, listen_addr);
            return;
        }

        tcp::endpoint ep(addr, binding.port);
        tcp::acceptor candidate_acceptor(io_context_);

        auto retry_or_fail = [&](std::string_view op, std::string_view msg) -> bool {
            if (i + 1 < listen_candidates.size()) {
                LOG_WARN("Worker[{}]: TCP {} {}:{} failed: {}, retrying {}",
                         id_, op, listen_addr, binding.port, msg, listen_candidates[i + 1]);
                return true;
            }
            LOG_ERROR("Worker[{}]: TCP {} {}:{} failed: {}",
                      id_, op, listen_addr, binding.port, msg);
            return false;
        };

        candidate_acceptor.open(ep.protocol(), ec);
        if (ec) {
            if (retry_or_fail("open", ec.message())) continue;
            return;
        }

        candidate_acceptor.set_option(net::socket_base::reuse_address(true), ec);

#ifndef _WIN32
        // SO_REUSEPORT：每 Worker 独立 accept，内核负责负载均衡
        // Windows 上 SO_REUSEADDR 已等效 Linux SO_REUSEPORT
        int optval = 1;
        if (::setsockopt(candidate_acceptor.native_handle(), SOL_SOCKET, SO_REUSEPORT,
                         &optval, sizeof(optval)) < 0) {
            if (retry_or_fail("SO_REUSEPORT", strerror(errno))) continue;
            return;
        }
#endif

        candidate_acceptor.bind(ep, ec);
        if (ec) {
            if (retry_or_fail("bind", ec.message())) continue;
            return;
        }

        candidate_acceptor.listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            if (retry_or_fail("listen", ec.message())) continue;
            return;
        }

        acceptor = std::move(candidate_acceptor);
        actual_listen = listen_addr;
        break;
    }

    if (actual_listen.empty()) {
        return;
    }
    binding.listen = actual_listen;

    acceptors_.emplace(binding.tag, std::move(acceptor));

    cobalt::spawn(io_context_.get_executor(),
                  AcceptLoop(binding.tag),
                  [](std::exception_ptr) {});

    LOG_INFO("Worker[{}]: listening {} tag={} protocol={} (SO_REUSEPORT)",
             id_,
             iputil::FormatEndpointForLog(binding.listen, binding.port),
             binding.tag, binding.protocol);
}

void Worker::StopListening(const std::string& tag) {
    auto it = acceptors_.find(tag);
    if (it == acceptors_.end()) return;
    boost::system::error_code ec;
    it->second.close(ec);  // 使 AcceptLoop 收到 operation_aborted 退出
    acceptors_.erase(it);
    LOG_INFO("Worker[{}]: stopped listening tag={}", id_, tag);
}

void Worker::CleanupUdpClientSessions(const std::string& tag) {
    auto sessions_it = udp_client_sessions_.find(tag);
    if (sessions_it == udp_client_sessions_.end()) {
        return;
    }

    for (auto& [client_key, session] : sessions_it->second) {
        (void)client_key;
        if (session.udp_dial.unregister_callback && session.callback_id != 0) {
            session.udp_dial.unregister_callback(session.callback_id);
        } else if (session.udp_dial.set_callback) {
            session.udp_dial.set_callback(std::function<void(const UDPPacket&)>{});
        }
    }

    udp_client_sessions_.erase(sessions_it);
    MaybeShrinkHashContainer(udp_client_sessions_, 8);
}

void Worker::StopUdpListening(const std::string& tag) {
    CleanupUdpClientSessions(tag);
    udp_reply_queues_.erase(tag);
    MaybeShrinkHashContainer(udp_reply_queues_, 8);

    auto sock_it = udp_sockets_.find(tag);
    if (sock_it != udp_sockets_.end()) {
        boost::system::error_code ec;
        sock_it->second->cancel(ec);
        sock_it->second->close(ec);
        udp_sockets_.erase(sock_it);
    }

    udp_inbound_handlers_.erase(tag);
}

void Worker::EnqueueUdpReply(const std::string& tag,
                             std::shared_ptr<udp::socket> sock,
                             udp::endpoint endpoint,
                             memory::ByteVector payload) {
    if (!sock || !sock->is_open() || payload.empty()) {
        return;
    }

    auto& queue = udp_reply_queues_[tag];
    queue.queued_bytes += payload.size();
    queue.pending.push_back(PendingUdpReply{std::move(endpoint), std::move(payload)});
    if (queue.pending.size() >= 64 || queue.queued_bytes >= 256 * 1024) {
        queue.shrink_pending_on_drain = true;
    }

    if (!queue.write_in_progress) {
        StartUdpReplySend(tag, sock);
    }
}

void Worker::StartUdpReplySend(const std::string& tag,
                               const std::shared_ptr<udp::socket>& sock) {
    auto queue_it = udp_reply_queues_.find(tag);
    if (queue_it == udp_reply_queues_.end() || !sock || !sock->is_open()) {
        return;
    }

    auto& queue = queue_it->second;
    if (queue.write_in_progress || queue.pending.empty()) {
        return;
    }

    auto packet = std::allocate_shared<PendingUdpReply>(
        memory::ThreadLocalAllocator<PendingUdpReply>{},
        std::move(queue.pending.front()));
    queue.queued_bytes -= packet->payload.size();
    queue.pending.pop_front();
    queue.write_in_progress = true;

    sock->async_send_to(
        net::buffer(packet->payload),
        packet->endpoint,
        [this, tag, sock, packet](boost::system::error_code ec, size_t /*bytes_sent*/) {
            auto it = udp_reply_queues_.find(tag);
            if (it == udp_reply_queues_.end()) {
                return;
            }

            auto& state = it->second;
            state.write_in_progress = false;

            if (ec && ec != net::error::operation_aborted) {
                LOG_ACCESS_DEBUG("Worker[{}]: UDP reply send failed tag={}: {}",
                                 id_, tag, ec.message());
            }

            if (!state.pending.empty() && sock && sock->is_open()) {
                StartUdpReplySend(tag, sock);
            } else if (state.pending.empty() && state.shrink_pending_on_drain) {
                TryShrinkSequence(state.pending);
                state.shrink_pending_on_drain = false;
            }
        });
}

// ============================================================================
// AcceptLoop — 每 tag 一个协程，运行在 Worker io_context 上
// ============================================================================

cobalt::task<void> Worker::AcceptLoop(std::string tag) {
    while (true) {
        auto acc_it = acceptors_.find(tag);
        if (acc_it == acceptors_.end()) co_return;

        auto [ec, socket] = co_await acc_it->second.async_accept(
            net::as_tuple(cobalt::use_op));

        if (ec == net::error::operation_aborted) co_return;
        if (ec) {
            LOG_WARN("Worker[{}]: accept error tag={}: {}", id_, tag, ec.message());
            const auto backoff = MapAsioError(ec) == ErrorCode::RESOURCE_EXHAUSTED
                ? kAcceptResourceBackoff
                : kAcceptErrorBackoff;
            net::steady_timer timer(io_context_);
            timer.expires_after(backoff);
            (void)co_await timer.async_wait(net::as_tuple(cobalt::use_op));
            continue;
        }

        // 获取远端地址（可能失败，不影响接受）
        tcp::endpoint remote_ep;
        boost::system::error_code ep_ec;
        remote_ep = socket.remote_endpoint(ep_ec);

        SetupConnectedSocket(socket);
        active_connections_.fetch_add(1, std::memory_order_relaxed);

        cobalt::spawn(io_context_.get_executor(),
                      ProcessReceivedConnection(std::move(socket), remote_ep, tag),
                      [this](std::exception_ptr) {
                          active_connections_.fetch_sub(1, std::memory_order_relaxed);
                      });
    }
}

// ============================================================================
// ProcessReceivedConnection — per-connection 协程
// ============================================================================

cobalt::task<void> Worker::ProcessReceivedConnection(
    tcp::socket socket, tcp::endpoint remote_ep, std::string tag) {

    auto lc_it = listener_contexts_.find(tag);
    if (lc_it == listener_contexts_.end()) {
        LOG_ERROR("Worker[{}]: no listener context for tag={}", id_, tag);
        socket.close();
        co_return;
    }

    // ListenerContext 存在 unordered_map 中。连接建立后如果继续新增/重建监听，
    // map rehash 会使对 value 的引用失效；把它复制到协程帧里可避免悬空引用。
    ListenerContext listener = lc_it->second;

    auto tcp_stream = std::make_unique<TcpStream>(std::move(socket));

    SessionContext ctx;
    ctx.worker_id        = id_;
    ctx.inbound_tag      = tag;
    ctx.inbound_tags     = listener.inbound_tags;
    ctx.inbound_protocol = listener.protocol;
    try {
        const auto normalized_remote = iputil::NormalizeAddress(remote_ep.address());
        ctx.client_ip = normalized_remote.to_string();
        ctx.src_addr  = tcp::endpoint(normalized_remote, remote_ep.port());

        const auto local_ep = tcp_stream->LocalEndpoint();
        ctx.inbound_local_addr = tcp::endpoint(
            iputil::NormalizeAddress(local_ep.address()),
            local_ep.port());
    } catch (...) {
        ctx.client_ip = "unknown";
    }
    ctx.worker_active_connections = active_connections_.load(std::memory_order_relaxed);

    const uint32_t pressure_threshold = ComputePressureThreshold(config_);
    if (ctx.worker_active_connections >= pressure_threshold) {
        const uint32_t pressure_idle = defaults::kPressureIdleTimeout;
        if (config_.GetTimeouts().idle > pressure_idle) {
            ctx.pressure_idle_timeout = pressure_idle;
        }
    }

    std::optional<ConnectionLimitGuard> connection_limit;
    if (listener.limiter) {
        auto reject = listener.limiter->TryAcceptGlobal();
        if (reject != ConnectionLimiter::RejectReason::NONE) {
            LOG_ACCESS_FMT("{} from {}:{} rejected conn_limit [{}] reason={} (pre-proxy)",
                FormatTimestamp(ctx.accept_time_us),
                ctx.client_ip, ctx.src_addr.port(), ctx.inbound_tag,
                ConnectionLimiter::RejectReasonToString(reject));
            global_stats_.GetShard(id_).OnError();
            tcp_stream->Close();
            co_return;
        }
        connection_limit.emplace(listener.limiter, ctx.client_ip);
    }

    // ----------------------------------------------------------------
    // PROXY Protocol 检测（负载均衡器透传真实客户端 IP）
    //
    // 支持 v1（文本）和 v2（二进制，IPv4 头恰好 28 字节）自动检测。
    // 若数据不是 PROXY 头，全部放回 pending_data，对后续协议透明。
    // ----------------------------------------------------------------
    if (listener.proxy_protocol) {
        const auto handshake_timeout = config_.GetTimeouts().HandshakeTimeout();
        tcp_stream->SetIdleTimeout(handshake_timeout);
        auto proxy_deadline = tcp_stream->StartPhaseDeadline(handshake_timeout);

        constexpr size_t kMaxProxyHeaderBytes = 2048;
        memory::ByteVector buf;
        buf.reserve(256);

        while (buf.size() < kMaxProxyHeaderBytes) {
            std::array<uint8_t, 256> chunk{};
            size_t n = co_await tcp_stream->AsyncRead(net::buffer(chunk));
            if (n == 0) {
                const bool timed_out = proxy_deadline.Expired()
                    || tcp_stream->ConsumePhaseDeadline()
                    || tcp_stream->ConsumeIdleTimeout();
                if (timed_out) {
                    LOG_WARN("Worker[{}]: PROXY protocol pre-read timed out tag={} client={}",
                             id_, tag, ctx.client_ip);
                    tcp_stream->Close();
                    co_return;
                }
                auto result = ProxyProtocolParser::Parse(buf.data(), buf.size());
                if (result.incomplete()) {
                    LOG_WARN("Worker[{}]: truncated PROXY protocol header tag={}", id_, tag);
                    tcp_stream->Close();
                    co_return;
                }
                if (!buf.empty()) {
                    tcp_stream->SetPendingData(std::span<const uint8_t>(buf));
                }
                break;
            }

            buf.insert(buf.end(), chunk.begin(), chunk.begin() + static_cast<ptrdiff_t>(n));

            auto result = ProxyProtocolParser::Parse(buf.data(), buf.size());
            if (result.incomplete()) {
                continue;
            }

            if (result.status == ProxyProtocolParseStatus::Invalid) {
                LOG_WARN("Worker[{}]: invalid PROXY protocol header tag={}", id_, tag);
                tcp_stream->Close();
                co_return;
            }

            size_t skip = 0;
            if (result.success()) {
                skip = result.consumed;
                if (!result.src_ip.empty()) {
                    boost::system::error_code src_ec;
                    auto src_addr = net::ip::make_address(result.src_ip, src_ec);
                    ctx.client_ip = src_ec
                        ? result.src_ip
                        : iputil::NormalizeAddressString(src_addr);
                    LOG_CONN_DEBUG(ctx, "[{}] PROXY protocol: proxy={} real_ip={}:{}",
                                  tag, iputil::NormalizeAddressString(remote_ep.address()),
                                  ctx.client_ip, result.src_port);
                }
            }

            if (skip < buf.size()) {
                tcp_stream->SetPendingData(std::span<const uint8_t>(buf).subspan(skip));
            }
            break;
        }

        if (buf.size() >= kMaxProxyHeaderBytes) {
            LOG_WARN("Worker[{}]: PROXY protocol header exceeded {} bytes tag={}",
                     id_, kMaxProxyHeaderBytes, tag);
            tcp_stream->Close();
            co_return;
        }

        tcp_stream->ClearPhaseDeadline();
    }

    // 活跃会话追踪只覆盖真正进入 relay 的连接，避免大量握手失败/瞬断连接
    // 把 active_sessions_ 在洪峰时冲大。
    struct ActiveSessionGuard {
        memory::ThreadLocalUnorderedMap<uint64_t, ActiveSession>& map;
        uint64_t conn_id;
        const SessionContext* ctx = nullptr;
        uint64_t last_up = 0;
        uint64_t last_down = 0;
        bool active = false;

        void Start(const SessionContext& session_ctx) {
            if (active || session_ctx.user_id <= 0) {
                return;
            }
            ctx = &session_ctx;
            map[conn_id] = ActiveSession{ctx, 0, 0};
            active = true;
        }

        void Stop() {
            if (!active) {
                return;
            }
            if (auto it = map.find(conn_id); it != map.end()) {
                last_up = it->second.last_reported_up;
                last_down = it->second.last_reported_down;
                map.erase(it);
                MaybeShrinkHashContainer(map, 256);
            }
            ctx = nullptr;
            active = false;
        }

        ~ActiveSessionGuard() {
            Stop();
        }
    } session_guard{active_sessions_, ctx.conn_id};

    ctx.on_relay_start = [&session_guard, &ctx] {
        session_guard.Start(ctx);
    };
    ctx.on_relay_end = [&session_guard] {
        session_guard.Stop();
    };

    co_await session_handler_->Handle(
        std::move(tcp_stream), ctx, listener, std::move(connection_limit));

    // 写入剩余增量流量（总流量 - guard 记录的已上报部分），避免重复计数
    // relay 结束时 guard 会记录最后一次已上报快照。
    const uint64_t already_up = session_guard.last_up;
    const uint64_t already_down = session_guard.last_down;
    uint64_t remaining_up = ctx.bytes_up > already_up ? ctx.bytes_up - already_up : 0;
    uint64_t remaining_down = ctx.bytes_down > already_down ? ctx.bytes_down - already_down : 0;
    if (remaining_up > 0 || remaining_down > 0) {
        AddUserTraffic(ctx.inbound_tag, ctx.user_id, remaining_up, remaining_down);
    }
}

// ============================================================================
// 线程安全 Async 接口（主线程调用，post 到 Worker 线程）
// ============================================================================

void Worker::AddListenerAsync(PortBinding binding) {
    net::post(io_context_,
        [this, b = std::move(binding)]() mutable {
            StartListening(std::move(b));
        });
}

void Worker::RemoveListenerAsync(std::string tag) {
    net::post(io_context_,
        [this, t = std::move(tag)] {
            StopListening(t);
            StopUdpListening(t);
        });
}

void Worker::RegisterListenerAsync(ListenerContext ctx,
                                   std::shared_ptr<IInboundHandler> handler) {
    net::post(io_context_,
        [this, ctx = std::move(ctx), h = std::move(handler)]() mutable {
            ctx.inbound_handler = h;  // shared_ptr 赋值，两处共享所有权
            inbound_handlers_[ctx.inbound_tag] = std::move(h);
            listener_contexts_[ctx.inbound_tag] = std::move(ctx);
        });
}

void Worker::UnregisterListenerAsync(std::string tag) {
    net::post(io_context_,
        [this, t = std::move(tag)] {
            StopListening(t);
            StopUdpListening(t);
            listener_contexts_.erase(t);
            inbound_handlers_.erase(t);
        });
}

// ============================================================================
// 数据收集协程（在 Worker 线程执行，供 cobalt::spawn 从主线程调用）
// ============================================================================

cobalt::task<std::unordered_map<int64_t, Worker::UserTraffic>>
Worker::CollectTrafficTask(std::string tag) {
    // 1. 收集已关闭连接的流量
    std::unordered_map<int64_t, UserTraffic> result;
    if (auto it = local_traffic_.find(tag); it != local_traffic_.end()) {
        result.reserve(it->second.size());
        for (auto& [user_id, traffic] : it->second) {
            result.emplace(user_id, std::move(traffic));
        }
        it->second.clear();
        MaybeShrinkHashContainer(it->second, 64);
    }

    // 2. 收集活跃会话的增量流量（实时统计，无需等连接关闭）
    for (auto& [conn_id, session] : active_sessions_) {
        if (session.ctx->inbound_tag != tag) continue;
        if (session.ctx->user_id <= 0) continue;

        uint64_t cur_up = session.ctx->bytes_up;
        uint64_t cur_down = session.ctx->bytes_down;
        uint64_t delta_up = cur_up - session.last_reported_up;
        uint64_t delta_down = cur_down - session.last_reported_down;
        session.last_reported_up = cur_up;
        session.last_reported_down = cur_down;

        if (delta_up > 0 || delta_down > 0) {
            auto& t = result[session.ctx->user_id];
            t.upload   += delta_up;
            t.download += delta_down;
        }
    }

    co_return result;
}

cobalt::task<std::vector<int64_t>>
Worker::CollectOnlineUsersTask(std::string tag) {
    auto lc_it = listener_contexts_.find(tag);
    if (lc_it == listener_contexts_.end()) co_return {};
    co_return GetOnlineUserIds(tag, lc_it->second.protocol);
}

// ============================================================================
// 内存统计（近似，主线程 stats_coro 读取）
// ============================================================================

Worker::MemoryStats Worker::GetMemoryStats() const {
    MemoryStats stats;

    if (dns_service_) {
        auto dns_stats       = dns_service_->GetCacheStats();
        stats.dns_entries    = dns_stats.entries;
        stats.dns_estimated_bytes = dns_stats.entries * 256;
    }

    if (udp_session_manager_) {
        stats.udp_sessions        = udp_session_manager_->ActiveSessionCount();
        stats.udp_estimated_bytes = stats.udp_sessions * 1024;
    }

    stats.vmess_users   = user_manager_.Size();
    stats.trojan_users  = trojan_user_manager_.Size();
    stats.users_estimated_bytes = (stats.vmess_users + stats.trojan_users + ss_user_manager_.Size()) * 512;

    stats.total_estimated_bytes = stats.dns_estimated_bytes
                                + stats.udp_estimated_bytes
                                + stats.users_estimated_bytes;
    return stats;
}

// ============================================================================
// UDP 监听（SO_REUSEPORT，与 TCP acceptor 同端口）
//
// 具体的解码/认证/ban 逻辑委托给 SsUdpInboundHandler（直接调用，无虚分派）。
// ============================================================================

void Worker::AddUdpListenerAsync(PortBinding binding,
                                 std::unique_ptr<ss::SsUdpInboundHandler> handler) {
    net::post(io_context_,
        [this, b = std::move(binding), h = std::move(handler)]() mutable {
            StartUdpListening(std::move(b), std::move(h));
        });
}

void Worker::StartUdpListening(PortBinding binding,
                               std::unique_ptr<ss::SsUdpInboundHandler> handler) {
    auto sock_it = udp_sockets_.find(binding.tag);
    if (sock_it != udp_sockets_.end() && sock_it->second && sock_it->second->is_open()) {
        boost::system::error_code ec;
        auto addr = net::ip::make_address(binding.listen, ec);
        if (ec) {
            LOG_ERROR("Worker[{}]: SS UDP invalid listen address '{}': {}",
                      id_, binding.listen, ec.message());
            return;
        }
        udp::endpoint ep(addr, binding.port);
        boost::system::error_code local_ec;
        auto local_ep = sock_it->second->local_endpoint(local_ec);
        if (!local_ec && local_ep == ep) {
            CleanupUdpClientSessions(binding.tag);
            udp_inbound_handlers_[binding.tag] = std::move(handler);
            LOG_INFO("Worker[{}]: reused UDP socket {} tag={} protocol={}",
                     id_,
                     iputil::FormatEndpointForLog(binding.listen, binding.port),
                     binding.tag,
                     udp_inbound_handlers_.at(binding.tag)->Protocol());
            return;
        }

        LOG_WARN("Worker[{}]: replacing existing UDP listener tag={}", id_, binding.tag);
        StopUdpListening(binding.tag);
    }

    auto sock = std::allocate_shared<udp::socket>(
        memory::ThreadLocalAllocator<udp::socket>{}, io_context_);
    std::string actual_listen;
    const auto listen_candidates = BuildListenCandidates(binding.listen);

    for (size_t i = 0; i < listen_candidates.size(); ++i) {
        const auto& listen_addr = listen_candidates[i];
        boost::system::error_code ec;
        auto addr = net::ip::make_address(listen_addr, ec);
        if (ec) {
            LOG_ERROR("Worker[{}]: SS UDP invalid listen address '{}': {}",
                      id_, listen_addr, ec.message());
            return;
        }
        if (!addr.is_v4()) {
            LOG_ERROR("Worker[{}]: non-IPv4 UDP listen address '{}' is not supported",
                      id_, listen_addr);
            return;
        }

        udp::endpoint ep(addr, binding.port);
        auto candidate_sock = std::allocate_shared<udp::socket>(
            memory::ThreadLocalAllocator<udp::socket>{}, io_context_);

        auto retry_or_fail = [&](std::string_view op, std::string_view msg) -> bool {
            if (i + 1 < listen_candidates.size()) {
                LOG_WARN("Worker[{}]: UDP {} {}:{} failed: {}, retrying {}",
                         id_, op, listen_addr, binding.port, msg, listen_candidates[i + 1]);
                return true;
            }
            LOG_ERROR("Worker[{}]: UDP {} {}:{} failed: {}",
                      id_, op, listen_addr, binding.port, msg);
            return false;
        };

        candidate_sock->open(ep.protocol(), ec);
        if (ec) {
            if (retry_or_fail("open", ec.message())) continue;
            return;
        }

        candidate_sock->set_option(net::socket_base::reuse_address(true), ec);

#ifndef _WIN32
        // SO_REUSEPORT：每 Worker 独立绑定，内核负载均衡
        // Windows 上 SO_REUSEADDR 已等效 Linux SO_REUSEPORT
        int optval = 1;
        if (::setsockopt(candidate_sock->native_handle(), SOL_SOCKET, SO_REUSEPORT,
                         &optval, sizeof(optval)) < 0) {
            if (retry_or_fail("SO_REUSEPORT", strerror(errno))) continue;
            return;
        }
#endif

        candidate_sock->bind(ep, ec);
        if (ec) {
            if (retry_or_fail("bind", ec.message())) continue;
            return;
        }

        sock = std::move(candidate_sock);
        actual_listen = listen_addr;
        break;
    }

    if (actual_listen.empty()) {
        return;
    }
    binding.listen = actual_listen;

    udp_sockets_[binding.tag] = sock;
    udp_inbound_handlers_[binding.tag] = std::move(handler);

    cobalt::spawn(io_context_.get_executor(),
                  UdpReceiveLoop(binding.tag),
                  [](std::exception_ptr) {});

    LOG_INFO("Worker[{}]: UDP listening {} tag={} protocol={} (SO_REUSEPORT)",
             id_,
             iputil::FormatEndpointForLog(binding.listen, binding.port),
             binding.tag,
             udp_inbound_handlers_.at(binding.tag)->Protocol());
}

// ============================================================================
// UdpReceiveLoop — 通用 UDP 数据报收发主循环（协议无关）
//
// 设计参考 Xray Cone 模式：
//   - 每个客户端 (IP:port) 维护一个出站 UDPSession（首包建立，后续复用）
//   - 协议解码/ban 检查/认证失败记录 完全委托给 SsUdpInboundHandler（直接调用）
//   - 回包编码函数由 Decode 绑定，Worker 无需感知协议细节
//   - 会话空闲超过配置的 session idle 后下次收包时懒清理
// ============================================================================

cobalt::task<void> Worker::UdpReceiveLoop(std::string tag) {
    constexpr size_t kRecvBufSize  = 65536;
    constexpr size_t kUdpReplyStackBufSize = 8 * 1024;
    const auto session_idle_timeout = config_.GetTimeouts().SessionIdleTimeout();

    auto sock_it = udp_sockets_.find(tag);
    if (sock_it == udp_sockets_.end()) co_return;
    auto sock = sock_it->second;  // shared_ptr，回调安全捕获

    memory::ByteVector recv_buf(kRecvBufSize);
    auto& client_sessions = udp_client_sessions_[tag];

    while (true) {
        udp::endpoint client_ep;
        auto [ec, n] = co_await sock->async_receive_from(
            net::buffer(recv_buf), client_ep,
            net::as_tuple(cobalt::use_op));

        if (ec == net::error::operation_aborted) co_return;
        if (ec || n == 0) continue;

        // ── 懒清理空闲会话 ────────────────────────────────────────────────
        const auto now = std::chrono::steady_clock::now();
        if (session_idle_timeout.count() > 0) {
            bool removed_idle_session = false;
            for (auto it = client_sessions.begin(); it != client_sessions.end(); ) {
                if (now - it->second.last_active > session_idle_timeout) {
                    if (it->second.udp_dial.unregister_callback && it->second.callback_id) {
                        it->second.udp_dial.unregister_callback(it->second.callback_id);
                    }
                    it = client_sessions.erase(it);
                    removed_idle_session = true;
                } else {
                    ++it;
                }
            }
            if (removed_idle_session) {
                MaybeShrinkHashContainer(client_sessions, 64);
            }
        }

        // ── 协议解码（ban 检查 + 用户匹配 + 认证失败记录 均在协议层处理）──
        auto hdl_it = udp_inbound_handlers_.find(tag);
        if (hdl_it == udp_inbound_handlers_.end() || !hdl_it->second) {
            continue;
        }
        auto* handler = hdl_it->second.get();

        auto lc_it = listener_contexts_.find(tag);
        const std::string fixed_outbound =
            (lc_it != listener_contexts_.end()) ? lc_it->second.fixed_outbound : "";

        const std::string client_ip =
            iputil::NormalizeAddressString(client_ep.address());
        const auto normalized_client_addr =
            iputil::NormalizeAddress(client_ep.address());
        auto decoded = handler->Decode(tag, client_ip, recv_buf.data(), n);
        if (!decoded) continue;

        // ── 找到或创建客户端会话 ──────────────────────────────────────────
        const std::string client_key =
            iputil::FormatEndpointForLog(client_ip, client_ep.port());

        auto session_it = client_sessions.find(client_key);
        bool need_new_session = (session_it == client_sessions.end()) ||
                                !session_it->second.udp_dial.Ok();

        if (need_new_session) {
            // 路由决策
            SessionContext ctx;
            ctx.worker_id        = id_;
            ctx.inbound_tag      = tag;
            if (auto lc = listener_contexts_.find(tag); lc != listener_contexts_.end()) {
                ctx.inbound_tags = lc->second.inbound_tags;
            }
            ctx.inbound_protocol = std::string(handler->Protocol());
            ctx.client_ip        = client_ip;
            ctx.src_addr         = tcp::endpoint(normalized_client_addr, client_ep.port());
            ctx.network          = Network::UDP;
            ctx.target           = decoded->target;
            ctx.final_target     = decoded->target;
            ctx.user_id          = decoded->user_id;
            ctx.user_email       = decoded->user_email;
            ctx.speed_limit      = decoded->speed_limit;

            std::string outbound_tag = fixed_outbound.empty()
                ? router_->Route(ctx) : fixed_outbound;
            ctx.outbound_tag = outbound_tag;

            auto* outbound = outbound_manager_->GetOutbound(outbound_tag);
            if (!outbound || !outbound->SupportsUDP()) {
                LOG_ACCESS_DEBUG("Worker[{}]: UDP no UDP outbound for tag={} client={}",
                          id_, tag, client_key);
                continue;
            }

            auto executor   = io_context_.get_executor();
            auto udp_result = co_await outbound->DialUDP(ctx, executor, nullptr);
            if (!udp_result.Ok()) {
                LOG_ACCESS_DEBUG("Worker[{}]: UDP DialUDP failed for client={}", id_, client_key);
                continue;
            }

            // ── 注册回包回调：协议编码后 send_to 客户端 ──────────────────
            // encode_reply 由协议层绑定，已值捕获用户密钥等上下文
            auto encode_fn         = std::move(decoded->encode_reply);
            udp::endpoint ep_copy  = client_ep;

            uint64_t cb_id = 0;
            auto reply_cb = [this, tag, sock, ep_copy, encode_fn = std::move(encode_fn)](const UDPPacket& pkt) {
                std::array<uint8_t, kUdpReplyStackBufSize> stack_buf;
                size_t encoded_len = encode_fn(
                    pkt.target, pkt.data.data(), pkt.data.size(),
                    stack_buf.data(), stack_buf.size());
                if (encoded_len == 0) return;

                memory::ByteVector payload(encoded_len);

                if (encoded_len <= stack_buf.size()) {
                    std::memcpy(payload.data(), stack_buf.data(), encoded_len);
                } else {
                    const size_t written = encode_fn(
                        pkt.target, pkt.data.data(), pkt.data.size(),
                        payload.data(), payload.size());
                    if (written != encoded_len) return;
                }

                EnqueueUdpReply(tag, sock, ep_copy, std::move(payload));
            };

            if (udp_result.register_callback) {
                cb_id = udp_result.register_callback("", std::move(reply_cb));
            } else if (udp_result.set_callback) {
                udp_result.set_callback(std::move(reply_cb));
            }

            LOG_ACCESS(ctx.ToAccessLog());

            UdpClientSession sess;
            sess.udp_dial       = std::move(udp_result);
            sess.callback_id    = cb_id;
            sess.user_id        = decoded->user_id;
            sess.fixed_outbound = fixed_outbound;
            sess.last_active    = now;

            client_sessions[client_key] = std::move(sess);
            session_it = client_sessions.find(client_key);
        }

        // ── 发往出站 ──────────────────────────────────────────────────────
        auto& sess = session_it->second;
        sess.last_active = now;

        UDPPacket out_pkt;
        out_pkt.target = decoded->target;
        out_pkt.data   = std::move(decoded->payload);

        auto send_ec = co_await sess.udp_dial.send(out_pkt, sess.callback_id);
        if (send_ec != ErrorCode::OK && send_ec != ErrorCode::SUCCESS) {
            LOG_ACCESS_DEBUG("Worker[{}]: UDP send failed for client={}", id_, client_key);
            // 下次收包时懒清理
            if (session_idle_timeout.count() > 0) {
                sess.last_active -= session_idle_timeout;
            }
        } else {
            // 流量统计（上行：客户端发送的原始载荷）
            AddUserTraffic(tag, sess.user_id,
                           static_cast<uint64_t>(out_pkt.data.size()), 0);
        }
    }
}

}  // namespace acpp
