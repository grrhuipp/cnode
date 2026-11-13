#include "app/worker.hpp"
#include "app/group_coordinator.hpp"
#include "app/prepared_inbound.hpp"
#include "app/rate_limiter.hpp"
#include "app/request_load.hpp"
#include "transport/quic_listener.hpp"
#include "common/awaitable_task_group.hpp"
#include "app/stats.hpp"
#include "common/allocator.hpp"
#include "common/session.hpp"
#include "common/rule.hpp"
#include "common/ip_address.hpp"
#include "common/hash.hpp"
#include "infra/log.hpp"
#include "app/user_store.hpp"
#include "app/udp_ingress.hpp"
#include "app/dns.hpp"
#include "transport/datagram_socket.hpp"
#include "transport/tcp_stream.hpp"
#include "transport/async_delay.hpp"
#include "transport/xhttp_session.hpp"
#include "app/router.hpp"
#include "common/defaults.hpp"
#include "common/error.hpp"
#include "app/inbound_handler.hpp"
#include "proxy/inbound.hpp"
#include "app/default_dispatcher.hpp"
#include "app/outbound_handler.hpp"
#include <asio/bind_executor.hpp>
#include <asio/ip/v6_only.hpp>
#include <unordered_map>
#include <sys/socket.h>
#include <array>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <system_error>
#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/steady_timer.hpp>
#include <asio/post.hpp>
#include <asio/redirect_error.hpp>
#include <asio/co_spawn.hpp>
#include <string>
#include <vector>


namespace app {

namespace {

// 同一监听 tag 的数据报入口成对持有“活跃 + 退役”两个位置（原生 UDP 与 QUIC 两个调用方）。
// 退役入口在其全部原生任务实际结束前保持存活，之后才释放。
template <class Ingress>
struct RetirableIngress {
    std::unique_ptr<Ingress> active;
    std::unique_ptr<Ingress> retiring;

    [[nodiscard]] bool Empty() const noexcept { return !active && !retiring; }

    void RequestStop() noexcept {
        if (active) active->RequestStop();
        if (retiring) retiring->RequestStop();
    }

    net::awaitable<void> AsyncJoin() {
        if (active) co_await active->AsyncJoin();
        if (retiring) co_await retiring->AsyncJoin();
    }

    // 活跃入口移入退役位并立即停止接入；退役位已被占用说明上一次退役未收束。
    void BeginRetire(const char* phase) noexcept {
        if (!active) return;
        if (retiring) common::FailRuntime(phase, "occupied retiring ingress slot");
        retiring = std::move(active);
        retiring->RequestStop();
    }

    // 等待退役入口的全部任务实际结束后释放；join 失败无法安全回收，直接终止进程。
    net::awaitable<void> JoinRetired(const char* phase) {
        if (!retiring) co_return;
        retiring->RequestStop();
        try {
            co_await retiring->AsyncJoin();
        } catch (const std::exception& error) {
            common::FailRuntime(phase, error.what());
        } catch (...) {
            common::FailRuntime(phase, "unknown ingress join failure");
        }
        retiring.reset();
    }
};

}  // namespace

}  // namespace app

struct app::Worker::ListenerSlot {
    struct SocketBinding {
        uint16_t port;
        transport::InboundListen listen;
        // Protocol/credentials are handler state and do not change the bound
        // socket; the slot key already fixes the tag.
        [[nodiscard]] bool UsesSameSocket(const app::PortBinding& candidate) const noexcept {
            return port == candidate.port && listen == candidate.listen;
        }
    };
    // Registry owns active slots; listener frames lease retired slots until
    // their native close completions finish. No per-request slot leases.
    std::shared_ptr<app::InboundHandler> handler;
    app::DatagramSessionEnvironment datagram_environment;
    std::vector<std::shared_ptr<tcp::acceptor>> tcp_acceptors;
    RetirableIngress<app::UdpIngress> udp;
    RetirableIngress<transport::QuicListener> quic;
    std::optional<SocketBinding> tcp_binding;
    std::optional<SocketBinding> udp_binding;

    void CloseTcpAcceptors() noexcept {
        auto acceptors = std::move(tcp_acceptors);
        tcp_acceptors.clear();
        for (auto& acceptor : acceptors) {
            if (!acceptor) continue;
            IoErrorCode ec;
            acceptor->close(ec);
        }
    }
};

struct app::Worker::ListenerState {
    using SlotPtr = std::shared_ptr<ListenerSlot>;
    using ListenerSlotMap = std::unordered_map<
        std::string, SlotPtr, common::TransparentStringHash, common::TransparentStringEq>;

    ListenerSlotMap listener_slots;
    [[nodiscard]] auto FindOrCreateSlot(std::string_view tag) {
        const auto existing = listener_slots.find(tag);
        if (existing != listener_slots.end()) return std::pair{existing, false};
        auto slot = std::make_shared<ListenerSlot>();
        return listener_slots.try_emplace(
            std::string(tag), std::move(slot));
    }
    uint64_t udp_resource_drops = 0;
    size_t udp_receive_loops = 0;
    size_t tcp_tasks = 0;
    bool stopping = false;
    struct TaskCancellation final : transport::CancellationSubscription {
        explicit TaskCancellation(ListenerState& state) : owner(state), next(state.tasks) {
            if (next) next->previous = this;
            state.tasks = this;
        }
        ~TaskCancellation() {
            Unsubscribe();
            if (previous) previous->next = next;
            else owner.tasks = next;
            if (next) next->previous = previous;
        }
        ListenerState& owner;
        TaskCancellation* previous = nullptr;
        TaskCancellation* next = nullptr;
        net::cancellation_signal signal;
        transport::TcpStream* stream = nullptr;
    private:
        void OnCancellation(transport::Cancellation cancellation) noexcept override {
            if (cancellation.terminal) stream = nullptr;
            else if (stream) Resubscribe(stream->Cancellation());
        }
    };
    TaskCancellation* tasks = nullptr;
    net::steady_timer changed;
    explicit ListenerState(net::io_context& io)
        : changed(io, std::chrono::steady_clock::time_point::max()) {}
    void NotifyCompletion() { changed.cancel(); }
    void Spawn(app::Worker& worker, net::awaitable<void> task, bool listener,
               std::unique_ptr<TaskCancellation> registration) {
        auto cancel_slot = registration->signal.slot();
        ++tcp_tasks;
        try {
            net::co_spawn(worker.io_context_,
                std::move(task),
                net::bind_cancellation_slot(cancel_slot,
                    [this, &worker, listener, registration = std::move(registration)](
                        std::exception_ptr error) mutable {
                        registration.reset();
                        --tcp_tasks;
                        NotifyCompletion();
                        if (!error) return;
                        try { std::rethrow_exception(error); }
                        catch (const IoSystemError& failure) {
                            if (failure.code() == net::error::operation_aborted ||
                                (!listener && failure.code() == net::error::eof)) return;
                        } catch (...) {}
                        if (listener) worker.ReportFailure(error);
                        else {
                            try {
                                try { std::rethrow_exception(error); }
                                catch (const std::exception& failure) {
                                    LOG_ERROR("TCP task failed worker={} > {}", worker.id_, failure.what());
                                } catch (...) {
                                    LOG_ERROR("TCP task failed worker={} > unknown error", worker.id_);
                                }
                            } catch (...) {} // Reporting must not fail completion under memory pressure.
                        }
                    }));
        } catch (...) {
            --tcp_tasks;
            throw;
        }
    }

    [[nodiscard]] bool StartListening(app::Worker& worker, const app::PortBinding& binding);
    void StopListening(std::string_view tag) noexcept;
    net::awaitable<bool> StartUdpListening(
        app::Worker& worker,
        const app::PortBinding& binding,
        std::unique_ptr<proxy::Inbound> handler);
    net::awaitable<bool> StartQuicListening(
        app::Worker& worker,
        const app::PortBinding& binding);
    net::awaitable<void> RetireUdpListening(std::string_view tag);

    net::awaitable<void> AcceptLoop(
        app::Worker& worker,
        std::string tag,
        std::shared_ptr<tcp::acceptor> acceptor,
        SlotPtr slot);

    static net::awaitable<void> ProcessReceivedConnection(
        app::Worker& worker,
        std::shared_ptr<app::InboundHandler> inbound_handler,
        TaskCancellation& registration,
        tcp::socket socket, tcp::endpoint remote_ep);

    net::awaitable<void> UdpReceiveLoop(
        app::Worker& worker,
        app::UdpIngress::SocketPtr sock,
        app::UdpIngress::SocketStatePtr socket_state,
        SlotPtr listener_slot,
        app::UdpIngress* expected_ingress);

private:
    [[nodiscard]] bool HasBindingConflict(
        const app::Worker& worker,
        const app::PortBinding& binding,
        bool tcp) const;
    [[nodiscard]] static bool OpenAndBindUdpSocket(
        const app::Worker& worker,
        std::string_view listener_kind,
        udp::socket& socket,
        const net::ip::address& address,
        std::string_view listen_addr,
        uint16_t port,
        bool dual_stack);
};

// 冷路径变更槽位守卫：同一时刻只允许一个冷变更，结束时唤醒等待排空的观察者。
class app::Worker::ColdMutation {
public:
    ColdMutation(bool& active, ListenerState& listeners)
        : active_(active), listeners_(listeners) {
        if (active_) {
            throw std::system_error(
                std::make_error_code(std::errc::device_or_resource_busy),
                "Worker cold mutation busy");
        }
        active_ = true;
    }
    ~ColdMutation() {
        active_ = false;
        listeners_.NotifyCompletion();
    }
    ColdMutation(const ColdMutation&) = delete;
    ColdMutation& operator=(const ColdMutation&) = delete;

private:
    bool& active_;
    ListenerState& listeners_;
};

// Worker-owned listeners, configuration publication and admission ledgers.
// Every TCP, QUIC and native UDP request dispatches within its session domain.
struct app::Worker::RuntimeState {
    RuntimeState(net::io_context& io_context,
                 const app::WorkerRuntimeConfig& runtime_config,
                 app::StatsShard& stats_ref,
                 app::DNSWorker& dns_worker)
        : io_context(io_context)
        , startup_config(std::make_unique<app::WorkerRuntimeConfig>(runtime_config))
        , timeouts(runtime_config.timeouts)
        , initial_user_view(app::UserStore::PrepareWorkerView(
              app::UserStore::CaptureSnapshot()))
        , stats(stats_ref)
        , request_load(runtime_config.pressure_threshold,
                       runtime_config.pressure_idle_timeout)
        , dns_worker(dns_worker)
        , dns(dns_worker)
        , listener_state(std::make_unique<ListenerState>(io_context))
        {}

    ~RuntimeState() {
        if (udp_association_reclaimer) udp_association_reclaimer->Stop();
    }

    void Start(app::Worker& worker);

    net::io_context& io_context;
    // Prepared control-plane data is consumed once, never retained by requests
    // or copied to mirror the manager's live handler set.
    std::unique_ptr<const app::WorkerRuntimeConfig> startup_config;
    const infra::TimeoutsConfig timeouts;
    app::UserStore::WorkerView initial_user_view;
    app::StatsShard& stats;
    app::RequestLoadState request_load;
    app::DNSWorker& dns_worker;
    app::DNS dns;
    std::unique_ptr<common::ResidentTaskGroup> outbound_tasks;
    std::unique_ptr<app::OutboundHandlerRegistry> outbound_handlers;
    std::unique_ptr<app::DefaultDispatcher> dispatcher;

    // Constructed on this Worker's executor; outlives managers, retired
    // listeners and their request guards. Runtime teardown stays on that thread.
    std::shared_ptr<app::ConnectionLimiter> connection_limiter;
    std::optional<common::UserOnlineTracker> online_users;
    std::optional<app::AdmissionEnvironment> admission;

    // Declared before the row owners: Stop precedes their teardown, but the
    // reclaimer remains alive while all map-owned hooks are unlinked.
    std::unique_ptr<app::UdpAssociationReclaimer> udp_association_reclaimer;
    app::UdpResourceBudget udp_resource_budget;
    std::unique_ptr<ListenerState> listener_state;
    std::unique_ptr<app::InboundHandlerRegistry> inbound_handlers;
    std::unique_ptr<app::SessionTrackingState> session_tracking;
    std::shared_ptr<const app::Router> router;
    std::unique_ptr<common::DetectRulePolicy> detect_rule_policy;
    bool started = false;
    bool cold_mutation_active = false;
};

namespace app {

namespace {

constexpr auto kAcceptErrorBackoff = std::chrono::milliseconds(5);
constexpr auto kAcceptResourceBackoff = std::chrono::milliseconds(100);

std::string BuildListenerKey(std::string_view tag, std::string_view listen, uint16_t port) {
    std::string key;
    key.reserve(tag.size() + listen.size() + 12);
    key.append(tag);
    key.push_back('|');
    key.append(listen);
    key.push_back('|');
    char port_text[5];
    const auto [end, error] = std::to_chars(port_text, port_text + sizeof(port_text), port);
    (void)error;
    key.append(port_text, end);
    return key;
}
}  // namespace

// ============================================================================
// Worker 构造 / 析构
// ============================================================================

Worker::Worker(uint32_t id, net::io_context& io_context,
               const WorkerRuntimeConfig& runtime_config, StatsShard& stats,
               app::DNSWorker& dns_worker,
               std::shared_ptr<GroupCoordinator> coordinator)
    : id_(id)
    , io_context_(io_context)
    , runtime_(std::make_unique<RuntimeState>(
          io_context, runtime_config, stats, dns_worker))
    , mailbox_(std::make_unique<WorkerMailbox>(
          runtime_->io_context,
          common::kWorkerMailboxCapacity))
    , group_coordinator_(std::move(coordinator)) {
    if (!group_coordinator_)
        throw std::invalid_argument("Worker requires a group coordinator");
    group_coordinator_->RegisterWorker();
}

Worker::~Worker() = default;

void Worker::StartRuntime() {
    if (stop_requested_.load(std::memory_order_acquire))
        throw IoSystemError(net::error::operation_aborted);
    runtime_->Start(*this);
    if (runtime_->initial_user_view) {
        UserStore::InstallWorkerView(
            std::move(runtime_->initial_user_view));
    }
}

void Worker::SetFailureHandler(void* context, FailureHandler handler) noexcept {
    failure_context_ = context;
    failure_handler_ = handler;
}

void Worker::ThrowIfStopping() const {
    if (stop_requested_.load(std::memory_order_acquire) ||
        drain_requested_.load(std::memory_order_relaxed) ||
        !runtime_ || runtime_->listener_state->stopping)
        throw IoSystemError(net::error::operation_aborted);
}

Worker::ColdMutation Worker::BeginColdMutation() {
    ThrowIfStopping();
    return ColdMutation(runtime_->cold_mutation_active, *runtime_->listener_state);
}

void Worker::RunEventLoop() noexcept {
    for (;;) {
        try {
            io_context_.run();
            if (!runtime_) return;
            ReportFailure(std::make_exception_ptr(
                std::runtime_error("worker event loop returned with live runtime")));
            io_context_.restart();
        } catch (...) {
            ReportFailure(std::current_exception());
        }
    }
}

void Worker::ReportFailure(std::exception_ptr error) noexcept {
    RequestDrain();
    if (failure_handler_) failure_handler_(failure_context_, std::move(error));
    else common::FailRuntime("worker-failure", "no runtime failure owner");
}

void Worker::RequestDrain() noexcept {
    if (drain_requested_.exchange(true, std::memory_order_acq_rel)) return;
    try {
        net::post(io_context_, [this] {
            BeginStopOnWorker();
            if (runtime_) runtime_->listener_state->NotifyCompletion();
        });
    } catch (...) {
        common::FailRuntime("worker-drain", "cannot post reserved lifecycle notification");
    }
}

net::awaitable<void> Worker::DrainRuntimeTask() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (!runtime_) co_return;
    BeginStopOnWorker();
    auto& listeners = *runtime_->listener_state;
    while (runtime_->cold_mutation_active) {
        IoErrorCode ec;
        co_await listeners.changed.async_wait(net::redirect_error(net::use_awaitable, ec));
    }
    std::vector<ListenerState::SlotPtr> slots;
    slots.reserve(listeners.listener_slots.size());
    for (auto& [tag, slot] : listeners.listener_slots) {
        (void)tag;
        if (slot) slots.push_back(slot);
    }
    for (const auto& slot : slots) {
        co_await slot->udp.AsyncJoin();
        co_await slot->quic.AsyncJoin();
    }
    while (listeners.tcp_tasks || listeners.udp_receive_loops) {
        IoErrorCode ec;
        co_await listeners.changed.async_wait(net::redirect_error(net::use_awaitable, ec));
    }
}

net::awaitable<void> Worker::AsyncDrain() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    co_await net::co_spawn(io_context_, DrainRuntimeTask(), net::use_awaitable);
}

void Worker::RequestStop() noexcept {
    if (stop_requested_.exchange(true, std::memory_order_acq_rel)) return;
    mailbox_->CloseAdmission();
    try {
        net::post(io_context_, [this] {
            stop_notification_delivered_ = true;
            BeginStopOnWorker();
            if (runtime_) runtime_->listener_state->NotifyCompletion();
        });
    } catch (...) {
        common::FailRuntime("worker-stop", "cannot post reserved lifecycle notification");
    }
}

void Worker::BeginStopOnWorker() noexcept {
    if (!runtime_) return;
    auto& listeners = *runtime_->listener_state;
    if (listeners.stopping) return;
    listeners.stopping = true;
    for (auto& [tag, slot] : listeners.listener_slots) {
        slot->CloseTcpAcceptors();
        slot->udp.RequestStop();
        slot->quic.RequestStop();
    }
    for (auto* task = listeners.tasks; task; task = task->next) {
        if (task->stream) task->stream->Cancel();
        task->signal.emit(net::cancellation_type::all);
    }
}

net::awaitable<void> Worker::StopRuntimeTask() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (!runtime_) co_return;
    BeginStopOnWorker();
    while (!stop_notification_delivered_) {
        IoErrorCode ec;
        co_await runtime_->listener_state->changed.async_wait(
            net::redirect_error(net::use_awaitable, ec));
    }
    // Cold mutation frames may hold slot references across UDP retirement.
    // They must finish before traversing or destroying those stable slots.
    co_await mailbox_->AsyncJoinAccepted();
    co_await DrainRuntimeTask();
    runtime_->outbound_handlers.reset();
    if (runtime_->outbound_tasks) {
        runtime_->outbound_tasks->Tasks().Cancel();
        co_await runtime_->outbound_tasks->AsyncJoin();
    }
    co_await transport::JoinXHttpClientTasks(io_context_);
    co_await transport::TimeoutScheduler::AsyncReleaseForIoContext(io_context_);
    runtime_.reset();
    UserStore::ClearWorkerView();
    group_coordinator_.reset();
}

net::awaitable<void> Worker::AsyncJoin() {
    if (joined_.load(std::memory_order_acquire)) co_return;
    RequestStop();
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    co_await net::co_spawn(io_context_, StopRuntimeTask(), net::use_awaitable);
    joined_.store(true, std::memory_order_release);
}

// ============================================================================
// 初始化
// ============================================================================

void Worker::RuntimeState::Start(Worker& worker) {
    if (started) {
        return;
    }

    auto& scheduler = transport::TimeoutScheduler::ForIoContext(io_context);
    udp_association_reclaimer =
        std::make_unique<app::UdpAssociationReclaimer>(
            scheduler, &worker,
            +[](void* ctx, std::exception_ptr error) {
                static_cast<Worker*>(ctx)->ReportFailure(std::move(error));
            });
    session_tracking = std::make_unique<app::SessionTrackingState>();
    detect_rule_policy = std::make_unique<common::DetectRulePolicy>();
    const auto* config = startup_config.get();
    if (!connection_limiter) {
        connection_limiter = ConnectionLimiter::Acquire(RateLimitConfig{
            .max_connections = config->limits.max_connections,
            .max_conn_per_ip = config->limits.max_connections_per_ip,
            .ip_ban = config->limits.ip_ban,
        }, worker.group_coordinator_);
    }
    online_users.emplace(*worker.group_coordinator_);
    admission.emplace(*worker.group_coordinator_, *connection_limiter, *online_users, stats);
    inbound_handlers = std::make_unique<InboundHandlerRegistry>(*admission);
    router = config->router
        ? config->router
        : std::make_shared<const app::Router>(infra::RoutingConfig{}, nullptr);
    LOG_DEBUG("router initialized worker={} rules={}",
              worker.id_, router->RuleCount());
    outbound_tasks = std::make_unique<common::ResidentTaskGroup>(io_context.get_executor());
    outbound_handlers = std::make_unique<OutboundHandlerRegistry>(
        config->outbounds, io_context, dns, timeouts.DialTimeout(), outbound_tasks->Tasks());
    dispatcher = std::make_unique<app::DefaultDispatcher>(
        *router, *outbound_handlers, *detect_rule_policy,
        *session_tracking, dns, request_load);
    started = true;
    startup_config.reset();
}

// ============================================================================
// SO_REUSEPORT 监听管理（仅在 Worker io_context 上调用）
// ============================================================================

bool Worker::ListenerState::HasBindingConflict(
    const Worker& worker,
    const PortBinding& binding,
    bool tcp) const {
    for (const auto& [tag, slot] : listener_slots) {
        const auto& existing = tcp ? slot->tcp_binding : slot->udp_binding;
        if (tag != std::string_view(binding.tag) && existing &&
            existing->port == binding.port &&
            existing->listen.Overlaps(binding.listen)) {
            LOG_ERROR("{} listener conflict worker={} tag={} owner={} port={}",
                      tcp ? "TCP" : "UDP", worker.id_, binding.tag, tag, binding.port);
            return true;
        }
    }
    return false;
}

bool Worker::ListenerState::OpenAndBindUdpSocket(
    const Worker& worker,
    std::string_view listener_kind,
    udp::socket& socket,
    const net::ip::address& address,
    std::string_view listen_addr,
    uint16_t port,
    bool dual_stack) {
    const udp::endpoint endpoint(address, port);
    IoErrorCode error;
    std::string_view operation = "open";
    socket.open(endpoint.protocol(), error);
    if (!error && address.is_v6()) {
        operation = "set IPV6_V6ONLY";
        socket.set_option(net::ip::v6_only(true), error);
    }
    if (!error) {
        operation = "set SO_REUSEADDR";
        socket.set_option(net::socket_base::reuse_address(true), error);
    }
    if (!error) {
        operation = "SO_REUSEPORT";
        int optval = 1;
        if (::setsockopt(socket.native_handle(), SOL_SOCKET, SO_REUSEPORT,
                         &optval, sizeof(optval)) < 0) {
            error = IoErrorCode(errno, std::system_category());
        }
    }
    if (!error) {
        // The OOM path must consume a datagram without allocating another
        // async operation. Asio's synchronous receive requires user-level
        // nonblocking mode, not merely native_non_blocking.
        operation = "set nonblocking";
        socket.non_blocking(true, error);
    }
    if (!error) {
        operation = "bind";
        socket.bind(endpoint, error);
    }
    if (!error) {
        return true;
    }
    if (dual_stack) {
        LOG_WARN("{} listener operation failed worker={} operation={} endpoint={} > {}; continuing dual-stack bind",
                 listener_kind, worker.id_, operation,
                 common::FormatEndpointForLog(listen_addr, port),
                 error.message());
    } else {
        LOG_ERROR("{} listener operation failed worker={} operation={} endpoint={} > {}",
                  listener_kind, worker.id_, operation,
                  common::FormatEndpointForLog(listen_addr, port),
                  error.message());
    }
    return false;
}

bool Worker::ListenerState::StartListening(Worker& worker, const PortBinding& binding) {
    auto inbound_handler = worker.runtime_->inbound_handlers->GetHandler(binding.tag);
    if (!inbound_handler) {
        LOG_ERROR("TCP listener unavailable worker={} tag={} > no inbound handler",
                  worker.id_, binding.tag);
        return false;
    }

    if (HasBindingConflict(worker, binding, true)) {
        return false;
    }

    auto existing_slot = listener_slots.find(binding.tag);
    const bool replacing = existing_slot != listener_slots.end() &&
        !existing_slot->second->tcp_acceptors.empty() &&
        existing_slot->second->tcp_binding.has_value();
    if (replacing &&
        existing_slot->second->tcp_binding->UsesSameSocket(binding)) {
        return true;
    }

    ListenerSlot::SocketBinding committed_binding{binding.port, binding.listen};
    struct PreparedListener {
        std::string key;
        std::shared_ptr<tcp::acceptor> acceptor;
    };
    std::vector<PreparedListener> prepared_listeners;

    const auto listen_candidates = binding.listen.Candidates();
    prepared_listeners.reserve(listen_candidates.size());
    size_t bound_count = 0;

    for (const auto& addr : listen_candidates) {
        const common::AddressText listen_text(addr);
        const auto listen_addr = listen_text.View();
        IoErrorCode ec;

        tcp::endpoint ep(addr, binding.port);
        auto listener_key = BuildListenerKey(binding.tag, listen_addr, binding.port);
        auto candidate_acceptor = std::make_shared<tcp::acceptor>(worker.runtime_->io_context);

        auto fail_candidate = [&](std::string_view op, std::string_view msg) -> bool {
            IoErrorCode close_ec;
            candidate_acceptor->close(close_ec);
            if (listen_candidates.size() > 1) {
                LOG_WARN("TCP listener operation failed worker={} operation={} endpoint={} > {}; continuing dual-stack bind",
                         worker.id_,
                         op,
                         common::FormatEndpointForLog(listen_addr, binding.port),
                         msg);
                return true;
            }
            LOG_ERROR("TCP listener operation failed worker={} operation={} endpoint={} > {}",
                      worker.id_, op,
                      common::FormatEndpointForLog(listen_addr, binding.port),
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

        // SO_REUSEPORT：每 Worker 独立 accept，内核负责负载均衡。
        int optval = 1;
        if (::setsockopt(candidate_acceptor->native_handle(), SOL_SOCKET, SO_REUSEPORT,
                         &optval, sizeof(optval)) < 0) {
            if (fail_candidate("SO_REUSEPORT", strerror(errno))) continue;
            break;
        }

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


        prepared_listeners.push_back({std::move(listener_key), std::move(candidate_acceptor)});
        ++bound_count;
    }

    if (bound_count == 0) {
        LOG_ERROR("no TCP listener bound worker={} tag={} protocol={}",
                  worker.id_, binding.tag, binding.protocol);
        return false;
    }

    auto slot_it = FindOrCreateSlot(binding.tag).first;
    auto& listener_slot = *slot_it->second;

    if (replacing) {
        LOG_WARN("replacing existing TCP listeners worker={} tag={}", worker.id_, binding.tag);
    }
    listener_slot.CloseTcpAcceptors();
    listener_slot.tcp_acceptors.reserve(prepared_listeners.size());
    for (const auto& prepared : prepared_listeners) {
        listener_slot.tcp_acceptors.push_back(prepared.acceptor);
    }
    listener_slot.tcp_binding = std::move(committed_binding);

    for (auto& prepared : prepared_listeners) {
        const auto& listener_key = prepared.key;
        auto registration = std::make_unique<TaskCancellation>(*this);
        Spawn(worker, AcceptLoop(worker,
                                 std::string(binding.tag),
                                 std::move(prepared.acceptor), slot_it->second),
              true, std::move(registration));

        LOG_DEBUG("TCP listener ready worker={} key={} tag={} protocol={} accept=SO_REUSEPORT",
                  worker.id_, listener_key, binding.tag, binding.protocol);
    }
    return true;
}

void Worker::ListenerState::StopListening(std::string_view tag) noexcept {
    auto slot_it = listener_slots.find(tag);
    if (slot_it == listener_slots.end()) return;
    slot_it->second->CloseTcpAcceptors();
    slot_it->second->tcp_binding.reset();
}

net::awaitable<void> Worker::ListenerState::RetireUdpListening(std::string_view tag) {
    const auto slot_it = listener_slots.find(tag);
    if (slot_it == listener_slots.end()) co_return;
    // 退役期间持有槽位本身，不依赖可能失效的表迭代器。
    const SlotPtr slot = slot_it->second;
    slot->udp.BeginRetire("udp-retirement");
    slot->quic.BeginRetire("quic-retirement");
    slot->udp_binding.reset();
    co_await slot->udp.JoinRetired("udp-join");
    co_await slot->quic.JoinRetired("quic-join");
}

// ============================================================================
// AcceptLoop — 每个 TCP socket 一个协程，运行在 Worker io_context 上
// ============================================================================

net::awaitable<void> Worker::ListenerState::AcceptLoop(
    Worker& worker,
    std::string tag,
    std::shared_ptr<tcp::acceptor> acceptor,
    SlotPtr slot) {
    const auto owns_acceptor = [&]() noexcept {
        return !stopping && acceptor && acceptor->is_open() && slot &&
            std::find(slot->tcp_acceptors.begin(), slot->tcp_acceptors.end(), acceptor) !=
                slot->tcp_acceptors.end();
    };
    while (owns_acceptor()) {

        auto [ec, socket] = co_await acceptor->async_accept(
            net::as_tuple(net::use_awaitable));

        if (!owns_acceptor()) co_return;

        if (ec == io_error::operation_aborted) co_return;
        if (ec) {
            LOG_WARN("TCP accept failed worker={} tag={} > {}", worker.id_, tag, ec.message());
            const auto backoff = common::MapAsioError(ec) == common::ErrorCode::RESOURCE_EXHAUSTED
                ? kAcceptResourceBackoff
                : kAcceptErrorBackoff;
            transport::AsyncDelay sleep(worker.runtime_->io_context);
            co_await sleep.WaitFor(backoff);
            continue;
        }

        // A peer that reset before getpeername has no attributable source;
        // per-IP limits and logs must never key it as 0.0.0.0.
        IoErrorCode ep_ec;
        const auto remote_ep = socket.remote_endpoint(ep_ec);
        if (ep_ec) {
            socket.close(ep_ec);
            continue;
        }

        auto inbound_handler = slot ? slot->handler : nullptr;
        if (!inbound_handler) {
            LOG_ERROR("TCP connection rejected worker={} tag={} > no inbound handler", worker.id_, tag);
            socket.close();
            continue;
        }

        auto registration = std::make_unique<TaskCancellation>(*this);
        auto* registration_ptr = registration.get();
        Spawn(worker,
            ProcessReceivedConnection(
                worker, std::move(inbound_handler), *registration_ptr,
                std::move(socket), remote_ep),
            false, std::move(registration));
    }
}

// ============================================================================
// ProcessReceivedConnection — per-connection 协程
// ============================================================================

net::awaitable<void> Worker::ListenerState::ProcessReceivedConnection(
    Worker& worker,
    std::shared_ptr<InboundHandler> inbound_handler,
    TaskCancellation& registration,
    tcp::socket socket,
    tcp::endpoint remote_ep) {
    app::RequestLoadState::PhysicalConnectionScope physical(worker.runtime_->request_load);
    const auto& listener = inbound_handler->ReceiverSettings();
    auto tcp_stream = std::make_unique<transport::TcpStream>(std::move(socket));
    registration.stream = tcp_stream.get();
    registration.Resubscribe(tcp_stream->Cancellation());
    common::Context ctx;
    ctx.conn_id = common::NewID(worker.id_);
    ctx.worker_id = worker.id_;
    ctx.inbound.tag = listener.inbound_tag;
    if (const auto* route_tags = listener.RouteInboundTags()) {
        ctx.inbound.tags.reserve(route_tags->size());
        for (const auto& tag : *route_tags) ctx.inbound.tags.emplace_back(tag);
    }
    const auto local_ep = tcp_stream->LocalEndpoint();
    if (!local_ep.address().is_unspecified()) {
        const auto local_addr = common::NormalizeAddress(local_ep.address());
        ctx.inbound.local_endpoint = tcp::endpoint(local_addr, local_ep.port());
    }
    const auto normalized_remote = common::NormalizeAddress(remote_ep.address());
    ctx.inbound.source_addr = normalized_remote;
    ctx.inbound.source_ip = common::AddressText(normalized_remote).View();
    ctx.inbound.source_port = remote_ep.port();
    LOG_CONN_DEBUG(ctx, "accepted TCP worker={} source={}:{}",
                   worker.id_, ctx.inbound.source_ip, ctx.inbound.source_port);
    co_await inbound_handler->ProcessAcceptedTCP(
        worker.io_context_, *worker.runtime_->dispatcher,
        worker.runtime_->stats, worker.runtime_->request_load,
        worker.runtime_->timeouts, std::move(tcp_stream), ctx,
        &worker.runtime_->dns);
}

// ============================================================================
// 冷路径控制面（主线程经 mailbox 投递到 Worker 线程执行）
// ============================================================================

bool Worker::AddListener(PortBinding binding) {
    auto mutation = BeginColdMutation();
    return runtime_->listener_state->StartListening(*this, binding);
}

bool Worker::RegisterInbound(
    BuildRequest req,
    ReceiverSettings receiver) {
    auto mutation = BeginColdMutation();
    auto prepared = std::make_shared<const BuildRequest>(req);
    auto handler = runtime_->inbound_handlers->NewHandler(req);
    if (!handler) {
        LOG_WARN("failed to create inbound handler worker={} tag={} protocol={}",
                 id_, receiver.inbound_tag, req.protocol);
        return false;
    }
    auto inbound_handler =
        std::make_unique<InboundHandler>(
            std::move(receiver), std::move(handler), *runtime_->admission);
    const auto& settings = inbound_handler->ReceiverSettings();
    const std::string key(settings.inbound_tag);
    auto [slot_it, slot_inserted] =
        runtime_->listener_state->FindOrCreateSlot(key);
    std::shared_ptr<InboundHandler> registered;
    try {
        registered = runtime_->inbound_handlers->ReplaceHandler(
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
        LOG_WARN("failed to install inbound handler worker={} tag={}", id_, key);
        return false;
    }
    slot_it->second->handler = registered;
    slot_it->second->datagram_environment = app::DatagramSessionEnvironment{
        .timeouts = runtime_->timeouts,
        .dispatcher = runtime_->dispatcher.get(),
        .admission = &*runtime_->admission,
        .request_load = &runtime_->request_load,
        .handler = registered,
        .prepared = std::move(prepared),
    };
    return true;
}

void Worker::AddOutbound(PreparedOutboundConfig config) {
    auto mutation = BeginColdMutation();
    runtime_->outbound_handlers->Replace(config);

    LOG_DEBUG("registered dynamic outbound worker={} protocol={} tag={}",
              id_, config.protocol, config.tag);
}

void Worker::RemoveOutbound(std::string_view tag) {
    auto mutation = BeginColdMutation();
    runtime_->outbound_handlers->Remove(tag);
}

void Worker::InstallUserView(UserStore::WorkerView view) {
    auto mutation = BeginColdMutation();
    UserStore::InstallWorkerView(std::move(view));
}

net::awaitable<void> Worker::UnregisterListenerTask(std::string tag) {
    auto mutation = BeginColdMutation();
    const auto cancel_throwing = co_await net::this_coro::throw_if_cancelled();
    auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(net::error::operation_aborted);
    }
    co_await net::this_coro::throw_if_cancelled(false);
    try {
        runtime_->listener_state->StopListening(tag);
        co_await runtime_->listener_state->RetireUdpListening(tag);
    } catch (const std::exception& error) {
        common::FailRuntime("udp-retirement", error.what());
    } catch (...) {
        common::FailRuntime("udp-retirement", "unknown UDP retirement failure");
    }

    runtime_->inbound_handlers->RemoveHandler(tag);
    if (auto slot_it = runtime_->listener_state->listener_slots.find(tag);
            slot_it != runtime_->listener_state->listener_slots.end()) {
        slot_it->second->handler.reset();
        slot_it->second->datagram_environment = {};
        if (!slot_it->second->tcp_binding && !slot_it->second->udp_binding &&
            slot_it->second->udp.Empty() && slot_it->second->quic.Empty()) {
            runtime_->listener_state->listener_slots.erase(slot_it);
        }
    }
    common::MaybeShrinkHashContainer(runtime_->listener_state->listener_slots, 8);
    co_await net::this_coro::throw_if_cancelled(cancel_throwing);
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(net::error::operation_aborted);
    }
    co_return;
}

void Worker::UpdateRule(
    std::string_view tag,
    std::shared_ptr<const std::vector<common::DetectRule>> rules) {
    auto mutation = BeginColdMutation();
    runtime_->detect_rule_policy->UpdateRule(tag, std::move(rules));
}

// ============================================================================
// 数据收集（在 Worker 线程执行）
// ============================================================================

app::UserTrafficCounters Worker::SnapshotTraffic(std::string_view tag) {
    if (!runtime_ || !runtime_->session_tracking) return app::UserTrafficCounters{};
    return runtime_->session_tracking->SnapshotTraffic(tag);
}

void Worker::CommitTraffic(
    std::string_view tag, const app::UserTrafficCounters& snapshot) {
    if (!runtime_ || !runtime_->session_tracking) return;
    runtime_->session_tracking->CommitTraffic(tag, snapshot);
}

void Worker::RollbackTraffic(
    std::string_view tag, const app::UserTrafficCounters& snapshot) {
    if (!runtime_ || !runtime_->session_tracking) return;
    runtime_->session_tracking->RollbackTraffic(tag, snapshot);
}

std::vector<common::OnlineDevice> Worker::GetOnlineDevices(std::string_view tag) const {
    if (!runtime_ || !runtime_->inbound_handlers || !runtime_->online_users) return {};
    if (!runtime_->inbound_handlers->GetHandler(tag)) return {};
    return runtime_->online_users->GetOnlineDevices(tag);
}

// ============================================================================
// 运行时资源计数，仅在 Worker executor 上读取。
// ============================================================================

WorkerRuntimeStatsSnapshot Worker::CollectRuntimeStats(bool include_resources) const {
    WorkerRuntimeStatsSnapshot snapshot;
    // Sample Worker-owned transports on their event loop.
    snapshot.udp_sockets = transport::DatagramSocket::ActiveCount();
    snapshot.stats = runtime_->stats.Snapshot();
    snapshot.worker_id = id_;
    snapshot.active_connections = runtime_->request_load.ActiveConnections();
    if (!include_resources) return snapshot;
    auto& resources = snapshot.resources.emplace();
    resources.udp_resource_drops = runtime_->listener_state->udp_resource_drops;
    resources.udp_receive_loops = runtime_->listener_state->udp_receive_loops;
    auto collect_udp = [&](const app::UdpIngress* ingress) {
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
    for (const auto& [tag, slot] : runtime_->listener_state->listener_slots) {
        (void)tag;
        if (slot->udp.active) {
            resources.udp_listeners += slot->udp.active->SocketCount();
            collect_udp(slot->udp.active.get());
        }
        collect_udp(slot->udp.retiring.get());
    }
    const auto timeouts = transport::TimeoutScheduler::ForIoContext(
        runtime_->io_context).GetResourceStats();
    resources.timeout_events = timeouts.active_events;
    resources.timeout_heap_capacity = timeouts.heap_capacity;
    resources.timeout_waiters = timeouts.wait_pending ? 1 : 0;
    return snapshot;
}

// ============================================================================
// UDP 监听（SO_REUSEPORT，与 TCP acceptor 同端口）
//
// 具体的解码、认证和 ban 逻辑委托给统一 Inbound；Worker 只维护监听
// socket 与当前 Worker-local UDP ingress 生命周期。
// ============================================================================

net::awaitable<bool> Worker::AddUdpListenerTask(
    PortBinding binding,
    BuildRequest req) {
    auto mutation = BeginColdMutation();
    if (RegisteredDatagramTransport(req.protocol) ==
        DatagramTransport::Quic) {
        co_return co_await runtime_->listener_state->StartQuicListening(
            *this, binding);
    }
    auto result =
        runtime_->inbound_handlers->NewDatagramHandler(req);
    switch (result.status) {
        case DatagramHandlerBuildStatus::Unsupported:
            co_return true;
        case DatagramHandlerBuildStatus::Failed:
            co_return false;
        case DatagramHandlerBuildStatus::Ready:
            if (!result.handler) {
                co_return false;
            }
            break;
    }
    co_return co_await runtime_->listener_state->StartUdpListening(
        *this, binding, std::move(result.handler));
}


net::awaitable<bool> Worker::ListenerState::StartQuicListening(
    Worker& worker,
    const PortBinding& binding) {
    // Every Worker binds its own SO_REUSEPORT socket; the kernel spreads new
    // QUIC connections by 4-tuple and each Worker serves only the connections
    // it accepted (no packet forwarding between Workers).
    if (HasBindingConflict(worker, binding, false)) {
        co_return false;
    }
    const auto slot_it = listener_slots.find(binding.tag);
    if (slot_it == listener_slots.end() || !slot_it->second->handler ||
        !slot_it->second->datagram_environment.prepared) {
        LOG_ERROR("QUIC listener unavailable worker={} tag={} > missing prepared inbound",
                  worker.id_, binding.tag);
        co_return false;
    }
    auto replacement = NewQuicListener(
        binding.protocol, worker.id_, worker.group_coordinator_->WorkerCount(),
        worker.runtime_->io_context, slot_it->second->datagram_environment);
    if (!replacement) co_return false;

    size_t bound = 0;
    const auto candidates = binding.listen.Candidates();
    for (const auto& address : candidates) {
        const common::AddressText text(address);
        const auto listen_text = text.View();
        auto socket = replacement->MakeSocket();
        if (!OpenAndBindUdpSocket(
                worker, "QUIC", *socket, address, listen_text, binding.port,
                candidates.size() > 1)) {
            if (candidates.size() > 1) continue;
            co_return false;
        }
        const auto key = BuildListenerKey(
            binding.tag, listen_text, binding.port);
        if (!replacement->AttachSocket(key, std::move(socket))) {
            LOG_ERROR("failed to attach QUIC socket worker={} key={}",
                      worker.id_, key);
            co_return false;
        }
        ++bound;
        LOG_DEBUG("QUIC listener ready worker={} key={} tag={} protocol={}",
                  worker.id_, key, binding.tag, binding.protocol);
    }
    if (bound == 0) co_return false;

    // 槽位本身在退役等待期间保持存活；冷变更守卫保证同 tag 无并发变更。
    const SlotPtr slot = slot_it->second;
    slot->quic.BeginRetire("quic-retirement");
    co_await slot->quic.JoinRetired("quic-join");
    replacement->Start();
    slot->quic.active = std::move(replacement);
    slot->udp_binding = ListenerSlot::SocketBinding{binding.port, binding.listen};
    co_return true;
}

net::awaitable<bool> Worker::ListenerState::StartUdpListening(
    Worker& worker,
    const PortBinding& binding,
    std::unique_ptr<proxy::Inbound> handler) {
    // TCP and UDP listeners both remain local to the Worker that bound them.
    if (HasBindingConflict(worker, binding, false)) {
        co_return false;
    }

    auto existing_slot = listener_slots.find(binding.tag);
    const bool replacing = existing_slot != listener_slots.end() &&
        existing_slot->second->udp.active != nullptr &&
        existing_slot->second->udp_binding.has_value();
    if (replacing &&
        existing_slot->second->udp_binding->UsesSameSocket(binding)) {
        auto cancellation = co_await net::this_coro::cancellation_state;
        if (stopping ||
            worker.stop_requested_.load(std::memory_order_acquire) ||
            worker.drain_requested_.load(std::memory_order_relaxed) ||
            cancellation.cancelled() != net::cancellation_type::none)
            throw IoSystemError(net::error::operation_aborted);
        const bool replaced = existing_slot->second->udp.active->ReplaceHandler(std::move(handler));
        if (stopping ||
            worker.stop_requested_.load(std::memory_order_acquire) ||
            worker.drain_requested_.load(std::memory_order_relaxed) ||
            cancellation.cancelled() != net::cancellation_type::none)
            throw IoSystemError(net::error::operation_aborted);
        co_return replaced;
    }

    if (!worker.runtime_->udp_association_reclaimer) {
        throw std::logic_error("UDP listener runtime is not started");
    }
    ListenerSlot::SocketBinding committed_binding{binding.port, binding.listen};
    auto replacement_ingress =
        std::make_unique<app::UdpIngress>(
            binding.tag, std::move(handler), *worker.runtime_->udp_association_reclaimer,
            worker.runtime_->udp_resource_budget, worker.runtime_->io_context);
    struct PreparedSocket {
        std::string key;
        app::UdpIngress::SocketStatePtr state;
    };
    std::vector<PreparedSocket> prepared_sockets;

    const auto listen_candidates = binding.listen.Candidates();
    prepared_sockets.reserve(listen_candidates.size());

    for (const auto& addr : listen_candidates) {
        const common::AddressText listen_text(addr);
        const auto listen_addr = listen_text.View();
        auto candidate_sock =
            replacement_ingress->MakeSocket(worker.runtime_->io_context);
        if (!OpenAndBindUdpSocket(
                worker, "UDP", *candidate_sock, addr, listen_addr, binding.port,
                listen_candidates.size() > 1)) {
            if (listen_candidates.size() > 1) continue;
            break;
        }

        auto socket_key = BuildListenerKey(binding.tag, listen_addr, binding.port);
        auto state = replacement_ingress->AttachSocket(std::move(candidate_sock));
        if (!state) {
            LOG_ERROR("failed to attach UDP socket worker={} tag={} key={}",
                      worker.id_, binding.tag, socket_key);
            continue;
        }
        prepared_sockets.push_back({std::move(socket_key), std::move(state)});
    }

    if (prepared_sockets.empty()) {
        LOG_ERROR("no UDP listener bound worker={} tag={} protocol={}",
                  worker.id_, binding.tag, binding.protocol);
        co_return false;
    }

    struct PreparedReceive {
        app::UdpIngress::SocketStatePtr state;
        net::awaitable<void> receive;
    };
    std::vector<PreparedReceive> prepared_receives;
    ListenerSlotMap::iterator slot_it;
    bool inserted_slot = false;
    try {
        auto slot_entry = FindOrCreateSlot(binding.tag);
        slot_it = slot_entry.first;
        inserted_slot = slot_entry.second;
        prepared_receives.reserve(prepared_sockets.size());
        for (const auto& prepared : prepared_sockets) {
            // Prepare frame and owned captures before retiring the old listener.
            auto receive = UdpReceiveLoop(
                worker, prepared.state->socket, prepared.state, slot_it->second,
                replacement_ingress.get());
            prepared_receives.push_back({prepared.state, std::move(receive)});
        }
        if (replacing) {
            LOG_WARN("replacing existing UDP listeners worker={} tag={}", worker.id_, binding.tag);
        }
    } catch (...) {
        if (inserted_slot) listener_slots.erase(slot_it);
        throw;
    }

    const bool has_retiring_worker = slot_it->second->udp.active != nullptr;
    const bool cancel_throwing = co_await net::this_coro::throw_if_cancelled();
    auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        if (inserted_slot) listener_slots.erase(slot_it);
        throw IoSystemError(net::error::operation_aborted);
    }
    if (replacing || has_retiring_worker) {
        co_await net::this_coro::throw_if_cancelled(false);
        try {
            co_await RetireUdpListening(binding.tag);
        } catch (const std::exception& error) {
            common::FailRuntime("udp-retirement", error.what());
        } catch (...) {
            common::FailRuntime("udp-retirement", "unknown UDP retirement failure");
        }
    }
    if (stopping ||
        worker.stop_requested_.load(std::memory_order_acquire) ||
        worker.drain_requested_.load(std::memory_order_relaxed))
        throw IoSystemError(net::error::operation_aborted);
    try {
        auto& listener_slot = *slot_it->second;
        auto* committed_ingress = replacement_ingress.get();
        listener_slot.udp.active = std::move(replacement_ingress);
        listener_slot.udp_binding = std::move(committed_binding);
        for (size_t index = 0; index < prepared_receives.size(); ++index) {
            auto& prepared = prepared_receives[index];
            const auto& socket_key = prepared_sockets[index].key;
            auto completion = [this, &worker, slot = slot_it->second, committed_ingress,
                               state = std::move(prepared.state)](std::exception_ptr error) {
                --udp_receive_loops;
                NotifyCompletion();
                if (stopping) {
                    if (error) {
                        try { std::rethrow_exception(error); }
                        catch (const IoSystemError& failure) {
                            if (failure.code() == net::error::operation_aborted) return;
                        } catch (...) {}
                        worker.ReportFailure(error);
                    }
                    return;
                }
                if (!slot || slot->udp.active.get() != committed_ingress ||
                    state->owner != committed_ingress) {
                    return; // Formal retirement; never affect a replacement socket.
                }
                if (!error) error = std::make_exception_ptr(
                    std::runtime_error("registered UDP receive loop stopped"));
                worker.ReportFailure(error);
            };
            ++udp_receive_loops;
            try {
                net::co_spawn(worker.runtime_->io_context.get_executor(),
                              std::move(prepared.receive), std::move(completion));
            } catch (...) {
                --udp_receive_loops;
                throw;
            }

            LOG_DEBUG("UDP listener ready worker={} key={} tag={} protocol={} accept=SO_REUSEPORT",
                      worker.id_, socket_key, binding.tag, binding.protocol);
        }
    } catch (...) {
        // A committed listener cannot be restored after a partial spawn.
        // Stop the entire runtime, but let every successful spawn complete.
        worker.ReportFailure(std::current_exception());
        throw;
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
    app::UdpIngress::SocketPtr sock,
    app::UdpIngress::SocketStatePtr socket_state,
    SlotPtr listener_slot,
    app::UdpIngress* expected_ingress) {
    auto is_owned = [this, listener_slot, expected_ingress](
                        const app::UdpIngress::SocketPtr& socket) noexcept {
        return !stopping && socket && socket->is_open() && listener_slot &&
            listener_slot->udp.active.get() == expected_ingress;
    };
    // 收包回调直接持有该 socket 的本地状态，每个数据报不再按字符串键查表。
    auto process_datagram = [&worker, socket_state = std::move(socket_state),
                            listener_slot = std::move(listener_slot), expected_ingress](
        const udp::endpoint& client_ep, std::span<const uint8_t> received) {
        if (!listener_slot || listener_slot->udp.active.get() != expected_ingress) return;
        const auto* receiver = listener_slot->handler
            ? &listener_slot->handler->ReceiverSettings() : nullptr;
        expected_ingress->ProcessDatagram(app::UdpDatagramContext{
            .socket = socket_state.get(),
            .client_endpoint = client_ep,
            .payload = received,
            .receiver = receiver,
            .io_context = worker.runtime_->io_context,
            .worker_id = worker.id_,
            .environment = listener_slot->datagram_environment,
        });
    };
    return transport::RunUdpReceiveLoop(
        std::move(sock), std::move(is_owned), std::move(process_datagram),
        [this]() noexcept { ++udp_resource_drops; });
}

}  // namespace app

