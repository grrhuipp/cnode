#include "acppnode/app/worker.hpp"
#include "worker/udp_receive_loop.hpp"
#include "worker/udp_association_reclaimer.hpp"
#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/traffic_types.hpp"
#include "acppnode/app/worker_runtime_config.hpp"
#include "worker_memory_reclaimer.hpp"
#include "acppnode/app/worker_stats.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/rule.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/runtime_failure.hpp"
#include "acppnode/app/dispatcher/default_dispatcher.hpp"
#include "acppnode/app/request_load_state.hpp"
#include "acppnode/app/proxyman/inbound/manager.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "worker/tcp_listener.hpp"
#include "worker/udp_ingress.hpp"
#include "acppnode/app/proxyman/outbound/manager.hpp"
#include "acppnode/app/session_tracking.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/dns/dns_worker.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "acppnode/transport/internet/datagram_socket.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/tls_stream.hpp"
#include "acppnode/transport/internet/async_delay.hpp"
#include "acppnode/app/router/router.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/proxyman/inbound/handler.hpp"
#include "acppnode/proxy/inbound.hpp"

#ifndef _WIN32
#include <sys/socket.h>
#endif
#include <algorithm>
#include <chrono>
#include <cstring>
#include <format>
#include <atomic>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <system_error>

namespace acpp {

struct Worker::ListenerSlot {
    // Worker 线程内稳定的 per-tag slot。AcceptLoop 持有 slot 指针；
    // 配置热更新只替换当前 inbound handler；每个已接受连接复制 shared_ptr，
    // 让 HTTP/2/gRPC/XHTTP detached 逻辑子流覆盖 handler 的完整生命周期。
    std::shared_ptr<proxyman::inbound::Handler> handler;
    std::unique_ptr<worker_detail::TcpListenerOwner> tcp_worker;
    std::optional<PortBinding> tcp_binding;
    std::optional<PortBinding> udp_binding;
    // Keeps a stopped ingress alive until every native dispatch job completes.
    std::unique_ptr<worker_detail::UdpIngress> retiring_udp;
};

struct Worker::ListenerState : worker_detail::UdpReplySink {
    using ListenerSlotMap =
        memory::ThreadLocalUnorderedMap<std::string, ListenerSlot>;
    using ListenerKeys = memory::ThreadLocalVector<std::string>;

    memory::ThreadLocalUnorderedMap<std::string, std::string> tcp_listener_tags;
    ListenerSlotMap listener_slots;
    memory::ThreadLocalUnorderedMap<std::string, std::string> udp_socket_tags;
    memory::ThreadLocalUnorderedMap<std::string, std::unique_ptr<worker_detail::UdpIngress>>
        udp_workers;
    uint64_t udp_resource_drops = 0;
    size_t udp_receive_loops = 0;

    [[nodiscard]] bool StartListening(Worker& worker, const PortBinding& binding);
    [[nodiscard]] ListenerKeys CollectTcpListenerKeys(const std::string& tag) const;
    void StopListening(const std::string& tag,
                       ListenerKeys listener_keys) noexcept;
    net::awaitable<bool> StartUdpListening(
        Worker& worker,
        const PortBinding& binding,
        std::unique_ptr<Inbound> handler);
    [[nodiscard]] ListenerKeys CollectUdpSocketKeys(const std::string& tag) const;
    net::awaitable<void> RetireUdpListening(
        const std::string& tag, ListenerKeys socket_keys);

    net::awaitable<void> AcceptLoop(
        Worker& worker,
        std::string listener_key,
        std::string tag,
        worker_detail::TcpListenerOwner::AcceptorPtr acceptor,
        ListenerSlot* slot);

    net::awaitable<void> ProcessReceivedConnection(
        Worker& worker,
        tcp::socket socket,
        tcp::endpoint remote_ep,
        std::shared_ptr<proxyman::inbound::Handler> inbound_handler);

    net::awaitable<void> UdpReceiveLoop(
        Worker& worker,
        std::string socket_key,
        worker_detail::UdpIngress::SocketPtr sock,
        ListenerSlot* listener_slot);

    [[nodiscard]] worker_detail::UdpIngress*
    FindUdpWorkerBySocketKey(const std::string& socket_key) noexcept;
    [[nodiscard]] const worker_detail::UdpIngress*
    FindUdpWorkerBySocketKey(const std::string& socket_key) const noexcept;

    [[nodiscard]] bool EnqueueUdpReply(
        const std::string& tag,
        udp::socket* sock,
        udp::endpoint endpoint,
        buf::MultiBuffer payload,
        uint32_t worker_id) override;
    void StartUdpReplySend(const std::string& tag,
                           worker_detail::UdpIngress::SocketPtr sock,
                           uint32_t worker_id);
};

// Worker-local capability owner. Constructs, starts and holds every live
// inbound/outbound/dns/udp/router/dispatcher instance for this Worker.
struct Worker::RuntimeState {
    RuntimeState(net::io_context& io_context,
                 const WorkerRuntimeConfig& runtime_config,
                 StatsShard& stats_ref,
                 app::dns::DNSWorker& dns_worker,
                 geo::GeoManager* geo_manager_ref)
        : io_context(io_context)
        , runtime_snapshot(std::make_shared<WorkerRuntimeConfig>(runtime_config))
        , stats(stats_ref)
        , geo_manager(geo_manager_ref)
        , request_load(runtime_config.pressure_threshold,
                       runtime_config.pressure_idle_timeout)
        , listener_state(std::make_unique<ListenerState>())
        , inbound_manager(std::make_unique<proxyman::inbound::Manager>(stats))
        , session_tracking(std::make_unique<app::SessionTrackingState>())
        , dns_service(std::make_unique<app::dns::DNS>(dns_worker))
        , outbound_manager(std::make_unique<proxyman::outbound::Manager>())
        , rule_manager(std::make_unique<rule::Manager>()) {}

    ~RuntimeState() {
        if (udp_association_reclaimer) udp_association_reclaimer->Stop();
    }

    [[nodiscard]] std::shared_ptr<const WorkerRuntimeConfig> Snapshot() const {
        return runtime_snapshot.load(std::memory_order_acquire);
    }

    void StoreSnapshot(std::shared_ptr<WorkerRuntimeConfig> snapshot) noexcept {
        const auto current = runtime_snapshot.load(std::memory_order_acquire);
        if (current) {
            snapshot->runtime_generation = current->runtime_generation + 1;
            snapshot->config_generation = current->config_generation + 1;
        }
        request_load.Configure(
            snapshot->pressure_threshold,
            snapshot->pressure_idle_timeout);
        runtime_snapshot.store(std::move(snapshot), std::memory_order_release);
    }

    void Start(Worker& worker);
    void InitOutbounds(Worker& worker,
                       const std::vector<proxyman::outbound::PreparedOutboundConfig>& outbounds);
    void InitRouter(Worker& worker,
                    const RoutingConfig& routing,
                    geo::GeoManager* geo_manager_ref);

    net::io_context& io_context;
    std::atomic<std::shared_ptr<const WorkerRuntimeConfig>> runtime_snapshot;
    StatsShard& stats;
    geo::GeoManager* geo_manager = nullptr;
    app::RequestLoadState request_load;

    // Declared before the row owners: Stop precedes their teardown, but the
    // reclaimer remains alive while all map-owned hooks are unlinked.
    std::unique_ptr<worker_detail::UdpAssociationReclaimer> udp_association_reclaimer;
    std::unique_ptr<ListenerState> listener_state;
    std::unique_ptr<proxyman::inbound::Manager> inbound_manager;
    std::unique_ptr<app::SessionTrackingState> session_tracking;
    std::unique_ptr<app::dns::DNS> dns_service;
    std::unique_ptr<proxyman::outbound::Manager> outbound_manager;
    std::unique_ptr<app::router::Router> router;
    std::unique_ptr<rule::Manager> rule_manager;
    std::unique_ptr<app::dispatcher::DefaultDispatcher> dispatcher;
    bool started = false;
    bool cold_mutation_active = false;
    WorkerMemoryReclaimer memory_reclaimer;
};

namespace {

constexpr auto kAcceptErrorBackoff = std::chrono::milliseconds(5);
constexpr auto kAcceptResourceBackoff = std::chrono::milliseconds(100);

class ColdMutationGuard {
public:
    explicit ColdMutationGuard(bool& active) : active_(active) {
        if (active_) {
            throw std::system_error(
                std::make_error_code(std::errc::device_or_resource_busy),
                "Worker cold mutation busy");
        }
        active_ = true;
    }
    ~ColdMutationGuard() { active_ = false; }
    ColdMutationGuard(const ColdMutationGuard&) = delete;
    ColdMutationGuard& operator=(const ColdMutationGuard&) = delete;

private:
    bool& active_;
};

std::string BuildListenerKey(std::string_view tag, std::string_view listen, uint16_t port) {
    std::string key;
    key.reserve(tag.size() + listen.size() + 12);
    key.append(tag);
    key.push_back('|');
    key.append(listen);
    key.push_back('|');
    key.append(std::to_string(port));
    return key;
}

void RemoveInboundRuntimeFromSnapshot(WorkerRuntimeConfig& snapshot, std::string_view tag) {
    std::erase_if(snapshot.static_inbounds, [&](const StaticInboundRuntimeEntry& entry) {
        return entry.tag == tag;
    });
}

}  // namespace

// ============================================================================
// Worker 构造 / 析构
// ============================================================================

Worker::Worker(uint32_t id, net::io_context& io_context,
               const WorkerRuntimeConfig& runtime_config, StatsShard& stats,
               app::dns::DNSWorker& dns_worker,
               geo::GeoManager* geo_manager)
    : id_(id)
    , runtime_(std::make_unique<RuntimeState>(
          io_context, runtime_config, stats, dns_worker, geo_manager))
    , mailbox_(std::make_unique<WorkerMailbox>(
          runtime_->io_context,
          runtime_config.mailbox_capacity == 0
              ? defaults::kWorkerMailboxCapacity
              : runtime_config.mailbox_capacity)) {}

Worker::~Worker() = default;

net::awaitable<void> Worker::StartRuntimeTask() {
    runtime_->Start(*this);
    co_return;
}

// ============================================================================
// 初始化
// ============================================================================

void Worker::RuntimeState::Start(Worker& worker) {
    if (started) {
        return;
    }

    auto& scheduler = TimeoutScheduler::ForIoContext(io_context);
    memory_reclaimer.Start(scheduler);
    udp_association_reclaimer =
        std::make_unique<worker_detail::UdpAssociationReclaimer>(scheduler);
    const auto config = Snapshot();
    InitOutbounds(worker, config->outbounds);
    InitRouter(worker, config->routing, geo_manager);
    dispatcher = std::make_unique<app::dispatcher::DefaultDispatcher>(
        *router, *outbound_manager, *rule_manager, *session_tracking,
        *dns_service, request_load);
    started = true;
}

void Worker::RuntimeState::InitOutbounds(
    Worker& worker,
    const std::vector<proxyman::outbound::PreparedOutboundConfig>& outbounds) {
    outbound_manager->Clear();
    const auto snapshot = Snapshot();
    const auto dial_timeout = snapshot->timeouts.DialTimeout();

    for (const auto& prepared_outbound : outbounds) {
        auto handler = proxyman::outbound::NewHandler(
            prepared_outbound, worker.runtime_->io_context,
            *dns_service, dial_timeout);

        if (!outbound_manager->AddHandler(std::move(handler))) {
            throw std::logic_error(
                "failed to install prepared outbound '" +
                prepared_outbound.tag + "'");
        }
        LOG_DEBUG("Worker[{}]: registered {} outbound '{}'",
                  worker.id_, prepared_outbound.protocol, prepared_outbound.tag);
    }
}

void Worker::RuntimeState::InitRouter(
    Worker& worker,
    const RoutingConfig& routing,
    geo::GeoManager* geo_manager_ref) {
    router = std::make_unique<app::router::Router>(routing, geo_manager_ref);

    LOG_DEBUG("Worker[{}]: router initialized, {} rules",
              worker.id_, routing.rules.size());
}

// ============================================================================
// SO_REUSEPORT 监听管理（仅在 Worker io_context 上调用）
// ============================================================================

bool Worker::ListenerState::StartListening(Worker& worker, const PortBinding& binding) {
    // Windows uses SO_REUSEADDR as an explicitly accepted degradation of
    // SO_REUSEPORT: every Worker still owns its own listener and connections.
    auto inbound_handler = worker.runtime_->inbound_manager->GetHandler(binding.tag);
    if (!inbound_handler) {
        LOG_ERROR("Worker[{}]: TCP listener tag={} has no inbound handler",
                  worker.id_, binding.tag);
        return false;
    }

    for (const auto& [tag, slot] : listener_slots) {
        if (tag != binding.tag && slot.tcp_binding &&
            slot.tcp_binding->port == binding.port &&
            slot.tcp_binding->listen.Overlaps(binding.listen)) {
            LOG_ERROR("Worker[{}]: TCP listener conflict tag={} owner={} port={}",
                      worker.id_, binding.tag, tag, binding.port);
            return false;
        }
    }

    const bool replacing = std::ranges::any_of(
        tcp_listener_tags,
        [&](const auto& item) { return item.second == binding.tag; });
    auto existing_slot = listener_slots.find(binding.tag);
    if (replacing && existing_slot != listener_slots.end() &&
        existing_slot->second.tcp_worker &&
        existing_slot->second.tcp_binding &&
        existing_slot->second.tcp_binding->UsesSameSocket(binding)) {
        return true;
    }

    PortBinding committed_binding = binding;
    auto replacement_worker =
        std::make_unique<worker_detail::TcpListenerOwner>(binding.tag);
    ListenerKeys prepared_listener_keys;
    decltype(tcp_listener_tags) prepared_listener_tags;

    const auto listen_candidates = binding.listen.Candidates();
    prepared_listener_keys.reserve(listen_candidates.size());
    prepared_listener_tags.reserve(listen_candidates.size());
    size_t bound_count = 0;

    for (const auto& addr : listen_candidates) {
        const std::string listen_addr = addr.to_string();
        IoErrorCode ec;

        tcp::endpoint ep(addr, binding.port);
        const std::string listener_key = BuildListenerKey(binding.tag, listen_addr, binding.port);
        auto candidate_acceptor =
            replacement_worker->CreateAcceptor(listener_key, worker.runtime_->io_context);
        if (!candidate_acceptor) {
            LOG_ERROR("Worker[{}]: failed to create TCP acceptor tag={} key={}",
                      worker.id_, binding.tag, listener_key);
            continue;
        }

        auto fail_candidate = [&](std::string_view op, std::string_view msg) -> bool {
            replacement_worker->CloseAcceptor(listener_key);
            if (listen_candidates.size() > 1) {
                LOG_WARN("Worker[{}]: TCP {} {} failed: {}, continuing dual-stack bind",
                         worker.id_,
                         op,
                         iputil::FormatEndpointForLog(listen_addr, binding.port),
                         msg);
                return true;
            }
            LOG_ERROR("Worker[{}]: TCP {} {} failed: {}",
                      worker.id_, op,
                      iputil::FormatEndpointForLog(listen_addr, binding.port),
                      msg);
            return false;
        };

        candidate_acceptor->open(ep.protocol(), ec);
        if (ec) {
            if (fail_candidate("open", ec.message())) continue;
            break;
        }

        if (addr.is_v6()) {
            candidate_acceptor->set_option(net::ip::v6_only(true), ec);
            if (ec) {
                if (fail_candidate("set IPV6_V6ONLY", ec.message())) continue;
                break;
            }
        }

        candidate_acceptor->set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            if (fail_candidate("set SO_REUSEADDR", ec.message())) continue;
            break;
        }

#ifndef _WIN32
        // SO_REUSEPORT：每 Worker 独立 accept，内核负责负载均衡。
        int optval = 1;
        if (::setsockopt(candidate_acceptor->native_handle(), SOL_SOCKET, SO_REUSEPORT,
                         &optval, sizeof(optval)) < 0) {
            if (fail_candidate("SO_REUSEPORT", strerror(errno))) continue;
            break;
        }
#endif

        candidate_acceptor->bind(ep, ec);
        if (ec) {
            if (fail_candidate("bind", ec.message())) continue;
            break;
        }

        candidate_acceptor->listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            if (fail_candidate("listen", ec.message())) continue;
            break;
        }

        prepared_listener_keys.push_back(listener_key);
        prepared_listener_tags.emplace(listener_key, binding.tag);

        ++bound_count;
    }

    if (bound_count == 0) {
        LOG_ERROR("Worker[{}]: no TCP listener bound tag={} protocol={}",
                  worker.id_, binding.tag, binding.protocol);
        return false;
    }

    auto slot_it = listener_slots.try_emplace(binding.tag).first;
    tcp_listener_tags.reserve(
        tcp_listener_tags.size() + prepared_listener_tags.size());
    auto& listener_slot = slot_it->second;

    if (replacing) {
        LOG_WARN("Worker[{}]: replacing existing TCP listeners tag={}", worker.id_, binding.tag);
        StopListening(binding.tag, CollectTcpListenerKeys(binding.tag));
    } else if (listener_slot.tcp_worker) {
        listener_slot.tcp_worker->Close();
    }

    listener_slot.tcp_worker = std::move(replacement_worker);
    tcp_listener_tags.merge(prepared_listener_tags);
    listener_slot.tcp_binding = std::move(committed_binding);

    for (const auto& listener_key : prepared_listener_keys) {
        auto acceptor = listener_slot.tcp_worker->FindAcceptor(listener_key);
        if (!acceptor) {
            continue;
        }
        net::co_spawn(worker.runtime_->io_context.get_executor(),
                      AcceptLoop(worker, listener_key, binding.tag, acceptor, &listener_slot),
                      [](std::exception_ptr) {});

#ifdef _WIN32
        LOG_DEBUG("worker.listener ready worker={} key={} tag={} protocol={} accept=SO_REUSEADDR",
                  worker.id_, listener_key, binding.tag, binding.protocol);
#else
        LOG_DEBUG("worker.listener ready worker={} key={} tag={} protocol={} accept=SO_REUSEPORT",
                  worker.id_, listener_key, binding.tag, binding.protocol);
#endif
    }
    return true;
}

Worker::ListenerState::ListenerKeys
Worker::ListenerState::CollectTcpListenerKeys(const std::string& tag) const {
    ListenerKeys listener_keys;
    for (const auto& [listener_key, listener_tag] : tcp_listener_tags) {
        if (listener_tag == tag) {
            listener_keys.push_back(listener_key);
        }
    }
    return listener_keys;
}

void Worker::ListenerState::StopListening(
    const std::string& tag,
    ListenerKeys listener_keys) noexcept {
    if (listener_keys.empty()) return;

    auto slot_it = listener_slots.find(tag);
    for (const auto& listener_key : listener_keys) {
        if (slot_it != listener_slots.end() && slot_it->second.tcp_worker) {
            slot_it->second.tcp_worker->CloseAcceptor(listener_key);  // 使 AcceptLoop 收到 operation_aborted 退出
        }
        tcp_listener_tags.erase(listener_key);
    }
    MaybeShrinkHashContainer(tcp_listener_tags, 8);
    if (slot_it != listener_slots.end()) {
        slot_it->second.tcp_binding.reset();
    }
}

worker_detail::UdpIngress*
Worker::ListenerState::FindUdpWorkerBySocketKey(const std::string& socket_key) noexcept {
    auto tag_it = udp_socket_tags.find(socket_key);
    if (tag_it == udp_socket_tags.end()) {
        return nullptr;
    }
    auto worker_it = udp_workers.find(tag_it->second);
    if (worker_it == udp_workers.end() || !worker_it->second) {
        return nullptr;
    }
    return worker_it->second.get();
}

const worker_detail::UdpIngress*
Worker::ListenerState::FindUdpWorkerBySocketKey(const std::string& socket_key) const noexcept {
    auto tag_it = udp_socket_tags.find(socket_key);
    if (tag_it == udp_socket_tags.end()) {
        return nullptr;
    }
    auto worker_it = udp_workers.find(tag_it->second);
    if (worker_it == udp_workers.end() || !worker_it->second) {
        return nullptr;
    }
    return worker_it->second.get();
}

Worker::ListenerState::ListenerKeys
Worker::ListenerState::CollectUdpSocketKeys(const std::string& tag) const {
    ListenerKeys socket_keys;
    for (const auto& [socket_key, socket_tag] : udp_socket_tags) {
        if (socket_tag == tag) {
            socket_keys.push_back(socket_key);
        }
    }
    return socket_keys;
}

net::awaitable<void> Worker::ListenerState::RetireUdpListening(
    const std::string& tag, ListenerKeys socket_keys) {
    auto slot_it = listener_slots.find(tag);
    auto worker_it = udp_workers.find(tag);
    if (worker_it != udp_workers.end() && worker_it->second) {
        if (slot_it == listener_slots.end() || slot_it->second.retiring_udp) {
            FailRuntime("udp-retirement", "missing or occupied retiring UDP slot");
        }
        slot_it->second.retiring_udp = std::move(worker_it->second);
    }
    if (worker_it != udp_workers.end()) worker_it->second.reset();

    // Retire authoritative listener lookup before cancellation. RequestStop
    // marks the whole ingress stopping before it closes any owned socket.
    for (const auto& socket_key : socket_keys) {
        udp_socket_tags.erase(socket_key);
    }
    // Preserve preparation's reserved capacity through replacement commit.
    if (slot_it != listener_slots.end()) slot_it->second.udp_binding.reset();

    if (slot_it != listener_slots.end() && slot_it->second.retiring_udp) {
        auto& retiring = *slot_it->second.retiring_udp;
        retiring.RequestStop();
        try {
            co_await retiring.AsyncJoin();
        } catch (const std::exception& error) {
            FailRuntime("udp-join", error.what());
        } catch (...) {
            FailRuntime("udp-join", "unknown UDP native-job join failure");
        }
        slot_it->second.retiring_udp.reset();
    }
    co_return;
}

bool Worker::ListenerState::EnqueueUdpReply(
    const std::string& tag,
    udp::socket* sock,
    udp::endpoint endpoint,
    buf::MultiBuffer payload,
    uint32_t worker_id) {
    auto* udp_worker = FindUdpWorkerBySocketKey(tag);
    if (!udp_worker || !udp_worker->OwnsSocket(tag, sock) ||
        !sock->is_open() || payload.empty()) {
        return false;
    }

    const auto admitted = udp_worker->EnqueueReply(
        tag, std::move(endpoint), std::move(payload));
    if (admitted == worker_detail::UdpIngress::ReplyEnqueueResult::Rejected) {
        return false;
    }
    if (admitted == worker_detail::UdpIngress::ReplyEnqueueResult::StartSend) {
        StartUdpReplySend(tag, udp_worker->FindSocket(tag), worker_id);
    }
    return true;
}

void Worker::ListenerState::StartUdpReplySend(const std::string& tag,
                                              worker_detail::UdpIngress::SocketPtr sock,
                                              uint32_t worker_id) {
    auto* udp_worker = FindUdpWorkerBySocketKey(tag);
    if (!udp_worker || !sock ||
        !udp_worker->OwnsSocket(tag, sock.get()) || !sock->is_open()) {
        return;
    }

    auto packet = udp_worker->BeginReplySend(tag);
    if (!packet) {
        return;
    }

    const auto send_buffers =
        worker_detail::UdpIngress::ReplySendBuffers(*packet);
    const auto endpoint =
        worker_detail::UdpIngress::ReplyEndpoint(*packet);

    sock->async_send_to(
        send_buffers,
        endpoint,
        [this, tag, sock, packet = std::move(packet), worker_id](IoErrorCode ec, size_t /*bytes_sent*/) {
            auto* udp_worker = FindUdpWorkerBySocketKey(tag);
            if (!udp_worker) {
                return;
            }

            if (ec && ec != io_error::operation_aborted) {
                LOG_NET_DEBUG("Worker[{}]: UDP reply send failed tag={}: {}",
                                 worker_id, tag, ec.message());
            }

            const bool current_sock =
                udp_worker->OwnsSocket(tag, sock.get());

            const bool has_pending =
                udp_worker->CompleteReplySend(tag, *packet);
            if (has_pending && current_sock && sock && sock->is_open()) {
                StartUdpReplySend(tag, sock, worker_id);
            }
        });
}

// ============================================================================
// AcceptLoop — 每个 TCP socket 一个协程，运行在 Worker io_context 上
// ============================================================================

net::awaitable<void> Worker::ListenerState::AcceptLoop(
    Worker& worker,
    std::string listener_key,
    std::string tag,
    worker_detail::TcpListenerOwner::AcceptorPtr acceptor,
    ListenerSlot* slot) {
    const auto owns_acceptor = [&]() {
        return acceptor && slot && slot->tcp_worker &&
            slot->tcp_worker->OwnsAcceptor(listener_key, acceptor.get());
    };
    while (owns_acceptor()) {

        auto [ec, socket] = co_await acceptor->async_accept(
            net::as_tuple(net::use_awaitable));

        if (!owns_acceptor()) co_return;

        if (ec == io_error::operation_aborted) co_return;
        if (ec) {
            LOG_WARN("Worker[{}]: accept error tag={}: {}", worker.id_, tag, ec.message());
            const auto backoff = MapAsioError(ec) == ErrorCode::RESOURCE_EXHAUSTED
                ? kAcceptResourceBackoff
                : kAcceptErrorBackoff;
            AsyncDelay sleep(worker.runtime_->io_context);
            co_await sleep.WaitFor(
                std::chrono::duration_cast<std::chrono::milliseconds>(backoff));
            continue;
        }

        // 获取远端地址（可能失败，不影响接受）
        tcp::endpoint remote_ep;
        IoErrorCode ep_ec;
        remote_ep = socket.remote_endpoint(ep_ec);

        auto inbound_handler = slot ? slot->handler : nullptr;
        if (!inbound_handler) {
            LOG_ERROR("Worker[{}]: no inbound handler for tag={}", worker.id_, tag);
            socket.close();
            continue;
        }

        net::co_spawn(worker.runtime_->io_context.get_executor(),
                      ProcessReceivedConnection(
                          worker, std::move(socket), remote_ep,
                          std::move(inbound_handler)),
                      [&worker](std::exception_ptr ep) {
                          if (ep) {
                              try {
                                  std::rethrow_exception(ep);
                              } catch (const std::exception& e) {
                                  LOG_ERROR("Worker[{}]: TCP connection coroutine failed: {}",
                                            worker.id_, e.what());
                              } catch (...) {
                                  LOG_ERROR("Worker[{}]: TCP connection coroutine failed: unknown",
                                            worker.id_);
                              }
                          }
                      });
    }
}

// ============================================================================
// ProcessReceivedConnection — per-connection 协程
// ============================================================================

net::awaitable<void> Worker::ListenerState::ProcessReceivedConnection(
    Worker& worker,
    tcp::socket socket,
    tcp::endpoint remote_ep,
    std::shared_ptr<proxyman::inbound::Handler> inbound_handler) {
    app::RequestLoadState::PhysicalConnectionScope physical_scope(
        worker.runtime_->request_load);
    if (!inbound_handler) {
        LOG_ERROR("Worker[{}]: no inbound handler for accepted connection", worker.id_);
        socket.close();
        co_return;
    }
    const proxyman::inbound::ReceiverSettings& listener =
        inbound_handler->ReceiverSettings();

    auto tcp_stream = std::make_unique<TcpStream>(std::move(socket));
    const auto runtime_snapshot = worker.runtime_->Snapshot();

    session::Context ctx;
    ctx.conn_id = session::NewID(worker.id_);
    ctx.worker_id = worker.id_;
    ctx.runtime_generation = runtime_snapshot->runtime_generation;
    ctx.config_generation = runtime_snapshot->config_generation;
    ctx.inbound.tag = listener.inbound_tag;
    if (const auto* route_tags = listener.RouteInboundTags()) {
        ctx.inbound.tags.reserve(route_tags->size());
        for (const auto& tag : *route_tags) {
            ctx.inbound.tags.emplace_back(tag);
        }
    }
    const auto local_ep = tcp_stream->LocalEndpoint();
    if (!local_ep.address().is_unspecified()) {
        const auto local_addr = iputil::NormalizeAddress(local_ep.address());
        ctx.inbound.local_endpoint = tcp::endpoint(local_addr, local_ep.port());
    }
    try {
        const auto normalized_remote = iputil::NormalizeAddress(remote_ep.address());
        ctx.inbound.source_addr = normalized_remote;
        ctx.inbound.source_ip = normalized_remote.to_string();
        ctx.inbound.source_port = remote_ep.port();
        ctx.inbound.peer_ip = ctx.inbound.source_ip;
        ctx.inbound.peer_port = ctx.inbound.source_port;
    } catch (...) {
        ctx.inbound.source_ip = "unknown";
    }
    LOG_CONN_DEBUG(ctx, "Worker[{}]: accepted TCP tag={} from {}:{}",
                   worker.id_,
                   ctx.inbound.tag,
                   ctx.inbound.source_ip,
                   ctx.inbound.source_port);

    co_await inbound_handler->ProcessAcceptedTCP(
        worker.runtime_->io_context, *worker.runtime_->dispatcher,
        worker.runtime_->stats, worker.runtime_->request_load,
        runtime_snapshot->timeouts,
        std::move(tcp_stream), ctx);
}

// ============================================================================
// 线程安全 Async 接口（主线程调用，post 到 Worker 线程）
// ============================================================================

net::awaitable<bool> Worker::AddListenerTask(PortBinding binding) {
    ColdMutationGuard mutation(runtime_->cold_mutation_active);
    co_return runtime_->listener_state->StartListening(*this, binding);
}

bool Worker::RegisterInboundOnWorkerThread(
    ConnectionLimiterPtr limiter,
    const proxyman::inbound::BuildRequest& req,
    proxyman::inbound::ReceiverSettings receiver) {
    auto handler = runtime_->inbound_manager->NewHandler(limiter, req);
    if (!handler) {
        LOG_WARN("Worker[{}]: failed to create inbound handler tag={} protocol={}",
                 id_, receiver.inbound_tag, req.protocol);
        return false;
    }
    auto inbound_handler =
        std::make_unique<proxyman::inbound::Handler>(std::move(receiver), std::move(handler));
    const auto& settings = inbound_handler->ReceiverSettings();
    const std::string key(settings.inbound_tag);
    auto [slot_it, slot_inserted] =
        runtime_->listener_state->listener_slots.try_emplace(key);
    std::shared_ptr<proxyman::inbound::Handler> registered;
    try {
        registered = runtime_->inbound_manager->ReplaceHandler(
            std::move(inbound_handler));
    } catch (...) {
        if (slot_inserted) {
            runtime_->listener_state->listener_slots.erase(slot_it);
        }
        throw;
    }
    if (!registered) {
        if (slot_inserted) {
            runtime_->listener_state->listener_slots.erase(slot_it);
        }
        LOG_WARN("Worker[{}]: failed to install inbound handler tag={}", id_, key);
        return false;
    }
    slot_it->second.handler = registered;
    return true;
}

net::awaitable<bool> Worker::RegisterInboundTask(
    ConnectionLimiterPtr limiter,
    proxyman::inbound::BuildRequest req,
    proxyman::inbound::ReceiverSettings receiver) {
    ColdMutationGuard mutation(runtime_->cold_mutation_active);
    co_return RegisterInboundOnWorkerThread(
        limiter, req, std::move(receiver));
}

void Worker::AddOutboundOnWorkerThread(
    proxyman::outbound::PreparedOutboundConfig config) {
    auto current_snapshot = runtime_->Snapshot();
    auto handler = proxyman::outbound::NewHandler(
        config, runtime_->io_context,
        *runtime_->dns_service,
        current_snapshot->timeouts.DialTimeout());

    auto next_snapshot = memory::AllocateShared<WorkerRuntimeConfig>(*current_snapshot);
    std::erase_if(next_snapshot->outbounds,
                  [&](const auto& outbound) { return outbound.tag == config.tag; });
    next_snapshot->outbounds.push_back(std::move(config));
    const std::string_view installed_protocol = next_snapshot->outbounds.back().protocol;
    const std::string_view installed_tag = next_snapshot->outbounds.back().tag;

    if (!runtime_->outbound_manager->ReplaceHandler(std::move(handler))) {
        throw std::logic_error(
            "failed to install dynamic outbound '" + std::string(installed_tag) + "'");
    }
    runtime_->StoreSnapshot(std::move(next_snapshot));

    LOG_DEBUG("Worker[{}]: registered dynamic {} outbound '{}'",
              id_, installed_protocol, installed_tag);
}

net::awaitable<void> Worker::AddOutboundTask(
    proxyman::outbound::PreparedOutboundConfig config) {
    ColdMutationGuard mutation(runtime_->cold_mutation_active);
    AddOutboundOnWorkerThread(std::move(config));
    co_return;
}

void Worker::RemoveOutboundOnWorkerThread(std::string_view tag) {
    auto current_snapshot = runtime_->Snapshot();
    auto next_snapshot = memory::AllocateShared<WorkerRuntimeConfig>(*current_snapshot);
    std::erase_if(next_snapshot->outbounds,
                  [&](const auto& outbound) { return outbound.tag == tag; });

    runtime_->outbound_manager->RemoveHandler(tag);
    runtime_->StoreSnapshot(std::move(next_snapshot));
}

net::awaitable<void> Worker::RemoveOutboundTask(std::string tag) {
    ColdMutationGuard mutation(runtime_->cold_mutation_active);
    RemoveOutboundOnWorkerThread(tag);
    co_return;
}

net::awaitable<void> Worker::UnregisterListenerTask(std::string tag) {
    ColdMutationGuard mutation(runtime_->cold_mutation_active);
    auto current_snapshot = runtime_->Snapshot();
    auto next_snapshot = memory::AllocateShared<WorkerRuntimeConfig>(*current_snapshot);
    RemoveInboundRuntimeFromSnapshot(*next_snapshot, tag);
    auto tcp_listener_keys =
        runtime_->listener_state->CollectTcpListenerKeys(tag);
    auto udp_socket_keys =
        runtime_->listener_state->CollectUdpSocketKeys(tag);

    const auto cancel_throwing = co_await net::this_coro::throw_if_cancelled();
    auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(net::error::operation_aborted);
    }
    co_await net::this_coro::throw_if_cancelled(false);
    try {
        runtime_->listener_state->StopListening(tag, std::move(tcp_listener_keys));
        co_await runtime_->listener_state->RetireUdpListening(
            tag, std::move(udp_socket_keys));
    } catch (const std::exception& error) {
        FailRuntime("udp-retirement", error.what());
    } catch (...) {
        FailRuntime("udp-retirement", "unknown UDP retirement failure");
    }

    runtime_->listener_state->udp_workers.erase(tag);
    auto retiring = runtime_->inbound_manager->GetHandler(tag);
    runtime_->inbound_manager->RemoveHandler(tag);
    if (auto slot_it = runtime_->listener_state->listener_slots.find(tag);
            slot_it != runtime_->listener_state->listener_slots.end() &&
            slot_it->second.handler == retiring) {
        slot_it->second.handler.reset();
    }
    runtime_->StoreSnapshot(std::move(next_snapshot));
    co_await net::this_coro::throw_if_cancelled(cancel_throwing);
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(net::error::operation_aborted);
    }
    co_return;
}

net::awaitable<void> Worker::UpdateRuleTask(
    std::string tag,
    std::vector<rule::DetectRule> rules) {
    runtime_->rule_manager->UpdateRule(tag, rules);
    co_return;
}

// ============================================================================
// 数据收集协程（在 Worker 线程执行，供 Spawn 从主线程调用）
// ============================================================================

net::awaitable<Worker::UserTrafficSnapshot>
Worker::GetTrafficTask(std::string tag) {
    co_return runtime_->session_tracking->CollectAndResetTraffic(tag);
}

void Worker::AddUserTraffic(std::string_view tag,
                            int64_t user_id,
                            uint64_t upload,
                            uint64_t download) {
    runtime_->session_tracking->AddUserTraffic(
        tag,
        user_id,
        upload,
        download);
}

net::awaitable<std::vector<OnlineDevice>>
Worker::GetOnlineDeviceTask(std::string tag) {
    auto handler = runtime_->inbound_manager->GetHandler(tag);
    if (!handler) {
        co_return std::vector<OnlineDevice>{};
    }
    co_return runtime_->inbound_manager->GetOnlineDevices(handler->ReceiverSettings().protocol, tag);
}

net::awaitable<std::vector<rule::DetectResult>>
Worker::GetDetectResultTask(std::string tag) {
    co_return runtime_->rule_manager->GetDetectResult(tag);
}

// ============================================================================
// 运行时资源计数，仅通过 Worker executor 上的收集任务读取。
// ============================================================================

Worker::MemoryStats Worker::GetMemoryStats() const {
    MemoryStats stats;

    // Sample this Worker-owned transport state on its own event loop.
    stats.udp_sockets        = transport::internet::DatagramSocket::ActiveCount();
    const auto pool = memory::ThreadPool().GetFootprint();
    stats.pool_mapped_bytes = pool.mapped_bytes;
    stats.pool_direct_bytes = pool.direct_bytes;
    stats.pool_idle_bytes = pool.idle_bytes;
    stats.pool_chunks = pool.chunks;
    return stats;
}

net::awaitable<Worker::RuntimeStatsSnapshot>
Worker::CollectRuntimeStatsTask(bool include_resources) const {
    RuntimeStatsSnapshot snapshot;
    snapshot.memory = GetMemoryStats();
    snapshot.stats = runtime_->stats.Snapshot();
    snapshot.worker_id = id_;
    snapshot.active_connections = runtime_->request_load.ActiveConnections();
    if (!include_resources) co_return snapshot;
    auto& resources = snapshot.resources.emplace();
    resources.udp_resource_drops = runtime_->listener_state->udp_resource_drops;
    resources.udp_receive_loops = runtime_->listener_state->udp_receive_loops;
    resources.udp_listeners = runtime_->listener_state->udp_socket_tags.size();
    auto collect_udp = [&](const worker_detail::UdpIngress* ingress) {
        if (!ingress) return;
        const auto udp = ingress->GetResourceStats();
        resources.udp_associations += udp.associations;
        resources.udp_closed_associations += udp.closed_associations;
        resources.udp_input_datagrams += udp.input_datagrams;
        resources.udp_input_bytes += udp.input_bytes;
        resources.udp_reply_datagrams += udp.reply_datagrams;
        resources.udp_reply_bytes += udp.reply_bytes;
        resources.udp_reply_senders += udp.active_reply_senders;
        resources.udp_native_dispatches += udp.native_dispatches;
    };
    for (const auto& [tag, ingress] : runtime_->listener_state->udp_workers) {
        (void)tag;
        collect_udp(ingress.get());
    }
    for (const auto& [tag, slot] : runtime_->listener_state->listener_slots) {
        (void)tag;
        collect_udp(slot.retiring_udp.get());
    }
    const auto timeouts = TimeoutScheduler::ForIoContext(
        runtime_->io_context).GetResourceStats();
    resources.timeout_events = timeouts.active_events;
    resources.timeout_heap_entries = timeouts.heap_entries;
    resources.timeout_heap_capacity = timeouts.heap_capacity;
    resources.timeout_event_buckets = timeouts.event_buckets;
    resources.timeout_ready_events = timeouts.ready_events;
    resources.timeout_waiters = timeouts.wait_pending ? 1 : 0;
    co_return snapshot;
}

net::awaitable<void> Worker::CollectHeapTask(bool force) {
    TlsStream::CollectIdleBuffersForCurrentThread();
    if (force) {
        memory::CollectBurst();
    } else {
        memory::CollectSteady();
    }
    co_return;
}

// ============================================================================
// UDP 监听（SO_REUSEPORT，与 TCP acceptor 同端口）
//
// 具体的解码、认证和 ban 逻辑委托给统一 Inbound；Worker 只维护监听
// socket 与当前 Worker-local UDP ingress 生命周期。
// ============================================================================

net::awaitable<bool> Worker::AddUdpListenerTask(
    PortBinding binding,
    ConnectionLimiterPtr limiter,
    proxyman::inbound::BuildRequest req) {
    ColdMutationGuard mutation(runtime_->cold_mutation_active);
    auto result =
        runtime_->inbound_manager->NewDatagramHandler(limiter, req);
    switch (result.status) {
        case proxyman::inbound::DatagramHandlerBuildStatus::Unsupported:
            co_return true;
        case proxyman::inbound::DatagramHandlerBuildStatus::Failed:
            co_return false;
        case proxyman::inbound::DatagramHandlerBuildStatus::Ready:
            if (!result.handler) {
                co_return false;
            }
            break;
    }
    co_return co_await runtime_->listener_state->StartUdpListening(
        *this, binding, std::move(result.handler));
}

net::awaitable<bool> Worker::ListenerState::StartUdpListening(
    Worker& worker,
    const PortBinding& binding,
    std::unique_ptr<Inbound> handler) {
    // TCP and UDP listeners both remain local to the Worker that bound them.
    for (const auto& [tag, slot] : listener_slots) {
        if (tag != binding.tag && slot.udp_binding &&
            slot.udp_binding->port == binding.port &&
            slot.udp_binding->listen.Overlaps(binding.listen)) {
            LOG_ERROR("Worker[{}]: UDP listener conflict tag={} owner={} port={}",
                      worker.id_, binding.tag, tag, binding.port);
            co_return false;
        }
    }

    const bool replacing = std::ranges::any_of(
        udp_socket_tags,
        [&](const auto& item) { return item.second == binding.tag; });
    auto existing_slot = listener_slots.find(binding.tag);
    auto existing_worker = udp_workers.find(binding.tag);
    if (replacing && existing_slot != listener_slots.end() &&
        existing_slot->second.udp_binding &&
        existing_slot->second.udp_binding->UsesSameSocket(binding) &&
        existing_worker != udp_workers.end() && existing_worker->second) {
        auto cancellation = co_await net::this_coro::cancellation_state;
        if (cancellation.cancelled() != net::cancellation_type::none)
            throw IoSystemError(net::error::operation_aborted);
        const bool replaced = existing_worker->second->ReplaceHandler(std::move(handler));
        if (cancellation.cancelled() != net::cancellation_type::none)
            throw IoSystemError(net::error::operation_aborted);
        co_return replaced;
    }

#ifdef CNODE_TEST_UDP_LISTENER_RUNTIME_FAULT
    worker_udp_listener_runtime_test::OnStage("prepare-listener", 0);
#endif
    if (!worker.runtime_->udp_association_reclaimer) {
        throw std::logic_error("UDP listener runtime is not started");
    }
    PortBinding committed_binding = binding;
    auto replacement_worker =
        std::make_unique<worker_detail::UdpIngress>(
            binding.tag, std::move(handler), *worker.runtime_->udp_association_reclaimer,
            worker.runtime_->io_context);
    ListenerKeys prepared_socket_keys;
    decltype(udp_socket_tags) prepared_socket_tags;

    const auto listen_candidates = binding.listen.Candidates();
    prepared_socket_keys.reserve(listen_candidates.size());
    prepared_socket_tags.reserve(listen_candidates.size());
    size_t bound_count = 0;

    for (const auto& addr : listen_candidates) {
        const std::string listen_addr = addr.to_string();
        IoErrorCode ec;
        udp::endpoint ep(addr, binding.port);
        auto candidate_sock =
            replacement_worker->MakeSocket(worker.runtime_->io_context);

        auto fail_candidate = [&](std::string_view op, std::string_view msg) -> bool {
            if (listen_candidates.size() > 1) {
                LOG_WARN("Worker[{}]: UDP {} {} failed: {}, continuing dual-stack bind",
                         worker.id_,
                         op,
                         iputil::FormatEndpointForLog(listen_addr, binding.port),
                         msg);
                return true;
            }
            LOG_ERROR("Worker[{}]: UDP {} {} failed: {}",
                      worker.id_, op, iputil::FormatEndpointForLog(listen_addr, binding.port), msg);
            return false;
        };

        candidate_sock->open(ep.protocol(), ec);
        if (ec) {
            if (fail_candidate("open", ec.message())) continue;
            break;
        }

        if (addr.is_v6()) {
            candidate_sock->set_option(net::ip::v6_only(true), ec);
            if (ec) {
                if (fail_candidate("set IPV6_V6ONLY", ec.message())) continue;
                break;
            }
        }

        candidate_sock->set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            if (fail_candidate("set SO_REUSEADDR", ec.message())) continue;
            break;
        }

#ifndef _WIN32
        // SO_REUSEPORT：每 Worker 独立绑定，内核负载均衡。
        int optval = 1;
        if (::setsockopt(candidate_sock->native_handle(), SOL_SOCKET, SO_REUSEPORT,
                         &optval, sizeof(optval)) < 0) {
            if (fail_candidate("SO_REUSEPORT", strerror(errno))) continue;
            break;
        }
#endif

        // The OOM path must consume a datagram without allocating another
        // async operation. Asio's synchronous receive requires user-level
        // nonblocking mode, not merely native_non_blocking.
        candidate_sock->non_blocking(true, ec);
        if (ec) {
            if (fail_candidate("set nonblocking", ec.message())) continue;
            break;
        }
        candidate_sock->bind(ep, ec);
        if (ec) {
            if (fail_candidate("bind", ec.message())) continue;
            break;
        }

        const std::string socket_key = BuildListenerKey(binding.tag, listen_addr, binding.port);
        auto bound_sock =
            replacement_worker->AttachSocket(socket_key, std::move(candidate_sock));
        if (!bound_sock) {
            LOG_ERROR("Worker[{}]: failed to attach UDP socket tag={} key={}",
                      worker.id_, binding.tag, socket_key);
            continue;
        }
        prepared_socket_keys.push_back(socket_key);
        prepared_socket_tags.emplace(socket_key, binding.tag);

        ++bound_count;
    }

    if (bound_count == 0) {
        LOG_ERROR("Worker[{}]: no UDP listener bound tag={} protocol={}",
                  worker.id_, binding.tag, binding.protocol);
        co_return false;
    }

    struct PreparedReceive {
        std::string socket_key;
        worker_detail::UdpIngress::SocketPtr socket;
        net::awaitable<void> receive;
    };
    memory::ThreadLocalVector<PreparedReceive> prepared_receives;
    auto retired_socket_keys =
        (replacing || (existing_worker != udp_workers.end() && existing_worker->second))
            ? CollectUdpSocketKeys(binding.tag) : ListenerKeys{};
    ListenerSlotMap::iterator slot_it;
    decltype(udp_workers)::iterator worker_it;
    bool inserted_slot = false;
    bool inserted_worker = false;
    try {
        auto slot_entry = listener_slots.try_emplace(binding.tag);
        slot_it = slot_entry.first;
        inserted_slot = slot_entry.second;
        auto worker_entry = udp_workers.try_emplace(binding.tag);
        worker_it = worker_entry.first;
        inserted_worker = worker_entry.second;
        udp_socket_tags.reserve(udp_socket_tags.size() + prepared_socket_tags.size());
        prepared_receives.reserve(prepared_socket_keys.size());
        for (const auto& socket_key : prepared_socket_keys) {
            auto socket = replacement_worker->FindSocket(socket_key);
            if (!socket) throw std::logic_error("prepared UDP socket is missing");
            // Prepare frame and owned captures before retiring the old listener.
            auto receive = UdpReceiveLoop(worker, socket_key, socket, &slot_it->second);
            prepared_receives.push_back({socket_key, std::move(socket), std::move(receive)});
        }
        if (replacing) {
            LOG_WARN("Worker[{}]: replacing existing UDP listeners tag={}", worker.id_, binding.tag);
        }
    } catch (...) {
        if (inserted_worker) udp_workers.erase(worker_it);
        if (inserted_slot) listener_slots.erase(slot_it);
        throw;
    }
#ifdef CNODE_TEST_UDP_LISTENER_RUNTIME_FAULT
    worker_udp_listener_runtime_test::FinishPreparation();
#endif

    const bool has_retiring_worker = worker_it->second != nullptr;
    const bool cancel_throwing = co_await net::this_coro::throw_if_cancelled();
    auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        if (inserted_worker) udp_workers.erase(worker_it);
        if (inserted_slot) listener_slots.erase(slot_it);
        throw IoSystemError(net::error::operation_aborted);
    }
    if (replacing || has_retiring_worker) {
        co_await net::this_coro::throw_if_cancelled(false);
        try {
            co_await RetireUdpListening(binding.tag, std::move(retired_socket_keys));
        } catch (const std::exception& error) {
            FailRuntime("udp-retirement", error.what());
        } catch (...) {
            FailRuntime("udp-retirement", "unknown UDP retirement failure");
        }
    }
    try {
        worker_it->second = std::move(replacement_worker);
        udp_socket_tags.merge(prepared_socket_tags);
        auto& listener_slot = slot_it->second;
        listener_slot.udp_binding = std::move(committed_binding);

        for (size_t index = 0; index < prepared_receives.size(); ++index) {
            auto& prepared = prepared_receives[index];
            const auto& socket_key = prepared_socket_keys[index];
            auto completion = [this, socket_key = std::move(prepared.socket_key),
                               socket = std::move(prepared.socket)](std::exception_ptr error) {
                --udp_receive_loops;
                auto* current = FindUdpWorkerBySocketKey(socket_key);
                if (!current || !current->OwnsSocket(socket_key, socket.get())) {
                    return; // Formal retirement; never affect a replacement socket.
                }
                if (error) {
                    try {
                        std::rethrow_exception(error);
                    } catch (const std::exception& failure) {
                        FailRuntime("udp-receive", failure.what());
                    } catch (...) {
                        FailRuntime("udp-receive", "unknown receive loop failure");
                    }
                }
                FailRuntime("udp-receive", "registered socket receive loop stopped");
            };
            ++udp_receive_loops;
#ifdef CNODE_TEST_UDP_LISTENER_RUNTIME_FAULT
            worker_udp_listener_runtime_test::OnStage("spawn", index);
#endif
            net::co_spawn(worker.runtime_->io_context.get_executor(),
                          std::move(prepared.receive), std::move(completion));
#ifdef CNODE_TEST_UDP_LISTENER_RUNTIME_FAULT
            worker_udp_listener_runtime_test::ReportSuccessfulSpawn(index);
            worker_udp_listener_runtime_test::OnStage("ready", index);
#endif

#ifdef _WIN32
            LOG_DEBUG("worker.udp_listener ready worker={} key={} tag={} protocol={} accept=SO_REUSEADDR",
                  worker.id_, socket_key, binding.tag, binding.protocol);
#else
            LOG_DEBUG("worker.udp_listener ready worker={} key={} tag={} protocol={} accept=SO_REUSEPORT",
                  worker.id_, socket_key, binding.tag, binding.protocol);
#endif
        }
    } catch (const std::exception& failure) {
        // Includes commit, every spawn and readiness formatting. Retirement
        // cannot be rolled back after any of these operations has begun.
        FailRuntime("udp-listener-start", failure.what());
    } catch (...) {
        FailRuntime("udp-listener-start", "unknown listener commit/startup failure");
    }
    co_await net::this_coro::throw_if_cancelled(cancel_throwing);
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(net::error::operation_aborted);
    }
    co_return true;
}

// ============================================================================
// UdpReceiveLoop — 通用 UDP 数据报收发主循环（协议无关）
//
// Worker binds current-owner checks and the existing Ingress -> Dispatcher
// entry once. The private loop helper handles bytes only, not request policy.
// This is a normal factory, not a second listener-lifetime coroutine frame.
// ============================================================================

net::awaitable<void> Worker::ListenerState::UdpReceiveLoop(
    Worker& worker,
    std::string socket_key,
    worker_detail::UdpIngress::SocketPtr sock,
    ListenerSlot* listener_slot) {
    const auto runtime_snapshot = worker.runtime_->Snapshot();
    auto is_owned = [this, socket_key](const worker_detail::UdpIngress::SocketPtr& socket) noexcept {
        const auto* current = FindUdpWorkerBySocketKey(socket_key);
        return current && current->OwnsSocket(socket_key, socket.get());
    };
    auto process_datagram = [this, &worker, socket_key = std::move(socket_key),
                            socket = sock.get(), listener_slot,
                            runtime_snapshot](
        const udp::endpoint& client_ep, std::span<const uint8_t> received) {
        auto* ingress = FindUdpWorkerBySocketKey(socket_key);
        if (!ingress || !ingress->OwnsSocket(socket_key, socket)) return;
        const auto* receiver = listener_slot && listener_slot->handler
            ? &listener_slot->handler->ReceiverSettings() : nullptr;
        ingress->ProcessDatagram(worker_detail::UdpDatagramContext{
            .socket_key = socket_key,
            .sock = socket,
            .client_endpoint = client_ep,
            .payload = received,
            .receiver = receiver,
            .io_context = worker.runtime_->io_context,
            .dispatcher = *worker.runtime_->dispatcher,
            .stats = worker.runtime_->stats,
            .timeouts = runtime_snapshot->timeouts,
            .worker_id = worker.id_,
            .runtime_generation = runtime_snapshot->runtime_generation,
            .config_generation = runtime_snapshot->config_generation,
            .reply_sink = *this,
        });
    };
    return worker_detail::RunUdpReceiveLoop(
        std::move(sock), std::move(is_owned), std::move(process_datagram), udp_resource_drops);
}

}  // namespace acpp
