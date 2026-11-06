#include "acppnode/app/worker.hpp"
#include "acppnode/app/session_capabilities.hpp"
#include "acppnode/app/session_group_executor.hpp"
#include "worker/udp_receive_loop.hpp"
#include "worker/udp_association_reclaimer.hpp"
#include "worker/udp_resource_budget.hpp"
#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/traffic_types.hpp"
#include "acppnode/app/worker_runtime_config.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "../common/awaitable_task_group.hpp"
#include "../proxy/hysteria/hysteria_ingress.hpp"
#include "../proxy/inbound_admission.hpp"
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
#include "acppnode/app/proxyman/inbound/handler_registry.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "worker/tcp_listener.hpp"
#include "worker/udp_ingress.hpp"
#include "acppnode/app/proxyman/outbound/handler_registry.hpp"
#include "acppnode/app/session_tracking.hpp"
#include "acppnode/app/session_capabilities.hpp"
#include "acppnode/app/session_group_executor.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/dns/dns_worker.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "acppnode/transport/internet/datagram_socket.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/async_delay.hpp"
#include "../transport/internet/xhttp_session.hpp"
#include "acppnode/app/router/router.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/proxyman/inbound/handler.hpp"
#include "acppnode/proxy/inbound.hpp"

#include <asio/bind_executor.hpp>
#include <unordered_map>
#include <sys/socket.h>
#include <array>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstring>
#include <atomic>
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

namespace acpp {

struct Worker::ConnectionRecord {
    std::shared_ptr<ExecutionDomain> domain;
    std::shared_ptr<app::PhysicalSessionCapabilities> capabilities;
    std::string inbound_tag;
    std::string accounting_key;
    uint64_t conn_id = 0;
    std::atomic<bool> initialized{false};
    std::atomic<bool> finished{false};
    app::UserTrafficCounters completed_traffic;
    StatsSnapshot final_stats;
};

struct Worker::ListenerSlot {
    struct SocketBinding {
        uint16_t port;
        InboundListen listen;
        // Protocol/credentials are handler state and do not change the bound
        // socket; the slot key already fixes the tag.
        [[nodiscard]] bool UsesSameSocket(const PortBinding& candidate) const noexcept {
            return port == candidate.port && listen == candidate.listen;
        }
    };
    // Registry owns active slots; listener frames lease retired slots until
    // their native close completions finish. No per-request slot leases.
    std::shared_ptr<proxyman::inbound::Handler> handler;
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared;
    std::unique_ptr<worker_detail::TcpListenerOwner> tcp_listeners;
    std::unique_ptr<worker_detail::UdpIngress> udp_ingress;
    std::unique_ptr<proxy::hysteria::HysteriaIngress> quic_ingress;
    std::optional<SocketBinding> tcp_binding;
    std::optional<SocketBinding> udp_binding;
    // Keeps a stopped ingress alive until every native dispatch job completes.
    std::unique_ptr<worker_detail::UdpIngress> retiring_udp_ingress;
    std::unique_ptr<proxy::hysteria::HysteriaIngress> retiring_quic_ingress;
};

struct Worker::ListenerState : worker_detail::UdpReplySink {
    using SlotPtr = std::shared_ptr<ListenerSlot>;
    using ListenerSlotMap = memory::ThreadLocalUnorderedMap<
        memory::ThreadLocalString, SlotPtr, TransparentStringHash, TransparentStringEq>;
    using ListenerKeys = memory::ThreadLocalVector<memory::ThreadLocalString>;

    ListenerSlotMap listener_slots;
    [[nodiscard]] auto FindOrCreateSlot(std::string_view tag) {
        const auto existing = listener_slots.find(tag);
        if (existing != listener_slots.end()) return std::pair{existing, false};
        auto slot = memory::AllocateShared<ListenerSlot>();
        return listener_slots.try_emplace(memory::ThreadLocalString(tag), std::move(slot));
    }
    uint64_t udp_resource_drops = 0;
    size_t udp_receive_loops = 0;
    size_t tcp_tasks = 0;
    size_t udp_reply_sends = 0;
    bool stopping = false;
    struct TaskCancellation final
        : memory::ThreadAllocated
        , transport::CancellationSubscription {
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
        TcpStream* stream = nullptr;
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
    void Spawn(Worker& worker, net::awaitable<void> task, bool listener,
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
        } catch (...) { --tcp_tasks; throw; }
    }

    [[nodiscard]] bool StartListening(Worker& worker, const PortBinding& binding);
    void StopListening(std::string_view tag) noexcept;
    net::awaitable<bool> StartUdpListening(
        Worker& worker,
        const PortBinding& binding,
        std::unique_ptr<Inbound> handler);
    net::awaitable<bool> StartQuicListening(
        Worker& worker,
        const PortBinding& binding);
    net::awaitable<void> RetireUdpListening(std::string_view tag);

    net::awaitable<void> AcceptLoop(
        Worker& worker,
        memory::ThreadLocalString listener_key,
        memory::ThreadLocalString tag,
        worker_detail::TcpListenerOwner::AcceptorPtr acceptor,
        SlotPtr slot);

    static net::awaitable<void> ProcessReceivedConnection(
        std::shared_ptr<ConnectionRecord> record,
        tcp::socket socket, tcp::endpoint remote_ep,
        uint32_t accepted_worker);

    net::awaitable<void> UdpReceiveLoop(
        Worker& worker,
        memory::ThreadLocalString socket_key,
        worker_detail::UdpIngress::SocketPtr sock,
        SlotPtr listener_slot,
        worker_detail::UdpIngress* expected_ingress);

    [[nodiscard]] worker_detail::UdpIngress*
    FindUdpIngress(std::string_view socket_key) noexcept;
    [[nodiscard]] bool EnqueueUdpReply(
        std::string_view socket_key,
        udp::socket* sock,
        udp::endpoint endpoint,
        buf::MultiBuffer payload,
        uint32_t worker_id) override;
    void StartUdpReplySend(worker_detail::UdpIngress& ingress,
                           std::string_view socket_key,
                           worker_detail::UdpIngress::SocketPtr sock,
                           uint32_t worker_id);
    net::awaitable<void> SendUdpReplies(
        memory::ThreadLocalString socket_key,
        worker_detail::UdpIngress::SocketPtr sock,
        worker_detail::UdpIngress::PendingUdpReply packet,
        uint32_t worker_id);
};

// Worker-local capability owner. Constructs, starts and holds every live
// inbound/outbound/dns/udp/router/dispatcher instance for this Worker.
struct Worker::RuntimeState {
    RuntimeState(net::io_context& io_context,
                 const WorkerRuntimeConfig& runtime_config,
                 StatsShard& stats_ref,
                 app::dns::DNSWorker& dns_worker,
                 geo::GeoDatabase* geo_database_ref)
        : io_context(io_context)
        , startup_config(std::make_unique<WorkerRuntimeConfig>(runtime_config))
        , timeouts(runtime_config.timeouts)
        , initial_user_view(proxyman::inbound::UserStore::PrepareWorkerView(
              proxyman::inbound::UserStore::CaptureSnapshot()))
        , stats(stats_ref)
        , geo_database(geo_database_ref)
        , dns_worker(dns_worker)
        , listener_state(std::make_unique<ListenerState>(io_context))
        , dns_service(std::make_unique<app::dns::DNS>(dns_worker))
        {}

    ~RuntimeState() {
        if (udp_association_reclaimer) udp_association_reclaimer->Stop();
    }

    void Start(Worker& worker);

    net::io_context& io_context;
    // Prepared control-plane data is consumed once, never retained by requests
    // or copied to mirror the manager's live handler set.
    std::unique_ptr<const WorkerRuntimeConfig> startup_config;
    const TimeoutsConfig timeouts;
    proxyman::inbound::UserStore::WorkerView initial_user_view;
    StatsShard& stats;
    geo::GeoDatabase* geo_database = nullptr;
    std::shared_ptr<app::RequestLoadState> request_load;
    app::dns::DNSWorker& dns_worker;
    std::shared_ptr<const app::SessionConfiguration> session_configuration;
    std::unordered_map<ConnectionRecord*, std::shared_ptr<ConnectionRecord>> connections;

    void EraseConnection(uint32_t worker_id, const std::shared_ptr<ConnectionRecord>& record) {
        if (connections.erase(record.get()) == 0) return;
        if (record->domain && !record->domain->CanDestroyDirectlyOn(worker_id)) {
            auto* domain = record->domain.get();
            domain->Execute([cap = std::move(record->capabilities),
                             domain = std::move(record->domain)]() mutable {
                cap.reset();
                domain.reset();
            });
        }
    }

    // Constructed on this Worker's executor; outlives managers, retired
    // listeners and their request guards. Runtime teardown stays on that thread.
    std::shared_ptr<ConnectionLimiter> connection_limiter;

    // Declared before the row owners: Stop precedes their teardown, but the
    // reclaimer remains alive while all map-owned hooks are unlinked.
    std::unique_ptr<worker_detail::UdpAssociationReclaimer> udp_association_reclaimer;
    worker_detail::UdpResourceBudget udp_resource_budget;
    std::unique_ptr<ListenerState> listener_state;
    std::unique_ptr<proxyman::inbound::HandlerRegistry> inbound_handlers;
    std::unique_ptr<app::SessionTrackingState> session_tracking;
    std::unique_ptr<app::dns::DNS> dns_service;
    // Work that outlives one request (pooled AnyTLS physical sessions). It is
    // built on this Worker's executor, outlives every handler and is joined
    // after all request owners finish.
    std::unique_ptr<ResidentTaskGroup> outbound_tasks;
    std::unique_ptr<proxyman::outbound::HandlerRegistry> outbound_handlers;
    std::shared_ptr<app::router::Router> router;
    std::shared_ptr<rule::DetectRulePolicy> detect_rule_policy;
    std::unique_ptr<app::dispatcher::DefaultDispatcher> dispatcher;
    bool started = false;
    bool cold_mutation_active = false;
    WorkerMemoryReclaimer memory_reclaimer;
};

namespace {

constexpr auto kAcceptErrorBackoff = std::chrono::milliseconds(5);
constexpr auto kAcceptResourceBackoff = std::chrono::milliseconds(100);

template <typename State = void>
class ColdMutationGuard {
public:
    explicit ColdMutationGuard(bool& active, State* listener_state = nullptr)
        : active_(active)
        , listener_state_(listener_state) {
        if (active_) {
            throw std::system_error(
                std::make_error_code(std::errc::device_or_resource_busy),
                "Worker cold mutation busy");
        }
        active_ = true;
    }
    ~ColdMutationGuard() {
        active_ = false;
        if constexpr (!std::is_void_v<State>) {
            if (listener_state_) listener_state_->NotifyCompletion();
        }
    }
    ColdMutationGuard(const ColdMutationGuard&) = delete;
    ColdMutationGuard& operator=(const ColdMutationGuard&) = delete;

private:
    bool& active_;
    State* listener_state_ = nullptr;
};

memory::ThreadLocalString BuildListenerKey(std::string_view tag, std::string_view listen, uint16_t port) {
    memory::ThreadLocalString key;
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

// Socket keys are built only by BuildListenerKey; a malformed key matches no
// listener instead of being resolved by scanning other tags' sockets.
[[nodiscard]] std::optional<std::string_view> ExtractListenerTag(std::string_view key) noexcept {
    const auto port_sep = key.rfind('|');
    if (port_sep == std::string_view::npos || port_sep == 0) {
        return std::nullopt;
    }
    const auto listen_sep = key.rfind('|', port_sep - 1);
    if (listen_sep == std::string_view::npos) {
        return std::nullopt;
    }
    return key.substr(0, listen_sep);
}
}  // namespace

// ============================================================================
// Worker 构造 / 析构
// ============================================================================

Worker::Worker(uint32_t id, net::io_context& io_context,
               const WorkerRuntimeConfig& runtime_config, StatsShard& stats,
               app::dns::DNSWorker& dns_worker,
               geo::GeoDatabase* geo_database)
    : id_(id)
    , io_context_(io_context)
    , runtime_(std::make_unique<RuntimeState>(
          io_context, runtime_config, stats, dns_worker, geo_database))
    , mailbox_(std::make_unique<WorkerMailbox>(
          runtime_->io_context,
          defaults::kWorkerMailboxCapacity)) {}

Worker::~Worker() = default;

void Worker::SetGroupCoordinator(std::shared_ptr<GroupCoordinator> coordinator) {
    if (!coordinator || runtime_->started)
        throw std::logic_error("group coordinator must be installed before startup");
    group_coordinator_ = std::move(coordinator);
}

void Worker::StartRuntime() {
    if (stop_requested_.load(std::memory_order_acquire))
        throw IoSystemError(net::error::operation_aborted);
    if (!group_coordinator_) {
        group_coordinator_ = std::make_shared<GroupCoordinator>(io_context_);
        owns_group_coordinator_ = true;
    }
    runtime_->Start(*this);
    if (runtime_->initial_user_view) {
        proxyman::inbound::UserStore::InstallWorkerView(
            std::move(runtime_->initial_user_view));
    }
}

void Worker::SetFailureHandler(std::function<void(std::exception_ptr)> handler) {
    failure_handler_ = std::move(handler);
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
    if (failure_handler_) {
        try { failure_handler_(error); }
        catch (...) { FailRuntime("worker-failure", "cannot notify runtime owner"); }
    } else {
        FailRuntime("worker-failure", "no runtime failure owner");
    }
}

void Worker::RequestDrain() noexcept {
    if (drain_requested_.exchange(true, std::memory_order_acq_rel)) return;
    try {
        net::post(io_context_, [this] {
            BeginStopOnWorker();
            if (runtime_) runtime_->listener_state->NotifyCompletion();
        });
    } catch (...) {
        FailRuntime("worker-drain", "cannot post reserved lifecycle notification");
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
    memory::ThreadLocalVector<ListenerState::SlotPtr> slots;
    slots.reserve(listeners.listener_slots.size());
    for (auto& [tag, slot] : listeners.listener_slots) {
        (void)tag;
        if (slot) slots.push_back(slot);
    }
    for (const auto& slot : slots) {
        if (slot->udp_ingress) co_await slot->udp_ingress->AsyncJoin();
        if (slot->retiring_udp_ingress) co_await slot->retiring_udp_ingress->AsyncJoin();
        if (slot->quic_ingress) co_await slot->quic_ingress->AsyncJoin();
        if (slot->retiring_quic_ingress)
            co_await slot->retiring_quic_ingress->AsyncJoin();
    }
    while (listeners.tcp_tasks || listeners.udp_receive_loops || listeners.udp_reply_sends) {
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
        FailRuntime("worker-stop", "cannot post reserved lifecycle notification");
    }
}

void Worker::BeginStopOnWorker() noexcept {
    if (!runtime_) return;
    auto& listeners = *runtime_->listener_state;
    if (listeners.stopping) return;
    listeners.stopping = true;
    for (auto& [tag, slot] : listeners.listener_slots) {
        if (slot->tcp_listeners) slot->tcp_listeners->Close();
        if (slot->udp_ingress) slot->udp_ingress->RequestStop();
        if (slot->retiring_udp_ingress) slot->retiring_udp_ingress->RequestStop();
        if (slot->quic_ingress) slot->quic_ingress->RequestStop();
        if (slot->retiring_quic_ingress)
            slot->retiring_quic_ingress->RequestStop();
    }
    for (auto* task = listeners.tasks; task; task = task->next) {
        if (task->stream) task->stream->Cancel();
        task->signal.emit(net::cancellation_type::all);
    }
    for (const auto& [key, record] : runtime_->connections) {
        (void)key;
        try {
            record->domain->Execute([cap = record->capabilities] { cap->RequestStop(); });
        } catch (...) {
            FailRuntime("worker-drain", "cannot deliver domain cancellation");
        }
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
    if (runtime_->session_configuration)
        co_await runtime_->session_configuration->outbounds->AsyncJoinHosts();
    // No request can start outbound work any more; retiring handlers have only
    // cancelled theirs. Join before destroying the components they borrow.
    if (runtime_->outbound_tasks) co_await runtime_->outbound_tasks->AsyncJoin();
    co_await transport::internet::JoinXHttpClientTasks(io_context_);
    runtime_->memory_reclaimer.Stop();
    co_await TimeoutScheduler::AsyncReleaseForIoContext(io_context_);
    for (auto& [key, record] : runtime_->connections) {
        (void)key;
        if (record->domain && !record->domain->CanDestroyDirectlyOn(id_)) {
            auto* domain = record->domain.get();
            domain->Execute([cap = std::move(record->capabilities),
                             domain = std::move(record->domain)]() mutable {
                cap.reset();
                domain.reset();
            });
        }
    }
    runtime_->connections.clear();
    runtime_.reset();
    proxyman::inbound::UserStore::ClearWorkerView();
    if (owns_group_coordinator_ && group_coordinator_) {
        group_coordinator_->CloseAdmission();
        co_await group_coordinator_->AsyncJoin();
        group_coordinator_->ReleaseServices();
        co_await group_coordinator_->Finalize();
    }
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

    auto& scheduler = TimeoutScheduler::ForIoContext(io_context);
    memory_reclaimer.Start(scheduler);
    udp_association_reclaimer =
        std::make_unique<worker_detail::UdpAssociationReclaimer>(
            scheduler, &worker,
            +[](void* ctx, std::exception_ptr error) {
                static_cast<Worker*>(ctx)->ReportFailure(std::move(error));
            });
    session_tracking = std::make_unique<app::SessionTrackingState>();
    inbound_handlers = std::make_unique<proxyman::inbound::HandlerRegistry>(stats);
    outbound_tasks = std::make_unique<ResidentTaskGroup>(io_context.get_executor());
    outbound_handlers = std::make_unique<proxyman::outbound::HandlerRegistry>();
    detect_rule_policy = std::make_shared<rule::DetectRulePolicy>();
    const auto* config = startup_config.get();
    if (!connection_limiter) {
        connection_limiter = ConnectionLimiter::Acquire(RateLimitConfig{
            .max_connections = config->limits.max_connections,
            .max_conn_per_ip = config->limits.max_connections_per_ip,
        }, worker.group_coordinator_);
    }
    if (!request_load) {
        request_load = app::RequestLoadState::Acquire(
            config->pressure_threshold, config->pressure_idle_timeout,
            *worker.group_coordinator_);
    }
    const auto dial_timeout = timeouts.DialTimeout();
    for (const auto& prepared_outbound : config->outbounds) {
        auto handler = proxyman::outbound::NewHandler(
            prepared_outbound, io_context, *dns_service, dial_timeout,
            outbound_tasks->Tasks());
        if (!outbound_handlers->AddHandler(std::move(handler))) {
            throw std::logic_error(
                "failed to install prepared outbound '" +
                prepared_outbound.tag + "'");
        }
        LOG_DEBUG("registered outbound worker={} protocol={} tag={}",
                  worker.id_, prepared_outbound.protocol, prepared_outbound.tag);
    }
    router = std::make_shared<app::router::Router>(config->routing, geo_database);
    LOG_DEBUG("router initialized worker={} rules={}",
              worker.id_, config->routing.rules.size());
    dispatcher = std::make_unique<app::dispatcher::DefaultDispatcher>(
        *router, *outbound_handlers, *detect_rule_policy, *session_tracking,
        *dns_service, *request_load);
    session_configuration = std::make_shared<const app::SessionConfiguration>(
        *config, router, detect_rule_policy);
    session_configuration->outbounds->BindHosts(io_context, worker.id_,
        worker.group_coordinator_, dns_worker, timeouts.DialTimeout());
    started = true;
    startup_config.reset();
}

// ============================================================================
// SO_REUSEPORT 监听管理（仅在 Worker io_context 上调用）
// ============================================================================

bool Worker::ListenerState::StartListening(Worker& worker, const PortBinding& binding) {
    auto inbound_handler = worker.runtime_->inbound_handlers->GetHandler(binding.tag);
    if (!inbound_handler) {
        LOG_ERROR("TCP listener unavailable worker={} tag={} > no inbound handler",
                  worker.id_, binding.tag);
        return false;
    }

    for (const auto& [tag, slot] : listener_slots) {
        if (tag != std::string_view(binding.tag) && slot->tcp_binding &&
            slot->tcp_binding->port == binding.port &&
            slot->tcp_binding->listen.Overlaps(binding.listen)) {
            LOG_ERROR("TCP listener conflict worker={} tag={} owner={} port={}",
                      worker.id_, binding.tag, tag, binding.port);
            return false;
        }
    }

    auto existing_slot = listener_slots.find(binding.tag);
    const bool replacing = existing_slot != listener_slots.end() &&
        existing_slot->second->tcp_listeners != nullptr &&
        existing_slot->second->tcp_binding.has_value();
    if (replacing &&
        existing_slot->second->tcp_binding->UsesSameSocket(binding)) {
        return true;
    }

    ListenerSlot::SocketBinding committed_binding{binding.port, binding.listen};
    auto replacement_listeners = std::make_unique<worker_detail::TcpListenerOwner>();
    struct PreparedListener {
        memory::ThreadLocalString key;
        worker_detail::TcpListenerOwner::AcceptorPtr acceptor;
    };
    memory::ThreadLocalVector<PreparedListener> prepared_listeners;

    const auto listen_candidates = binding.listen.Candidates();
    prepared_listeners.reserve(listen_candidates.size());
    size_t bound_count = 0;

    for (const auto& addr : listen_candidates) {
        const iputil::AddressText listen_text(addr);
        const auto listen_addr = listen_text.View();
        IoErrorCode ec;

        tcp::endpoint ep(addr, binding.port);
        const auto listener_key = BuildListenerKey(binding.tag, listen_addr, binding.port);
        auto candidate_acceptor =
            replacement_listeners->CreateAcceptor(listener_key, worker.runtime_->io_context);
        if (!candidate_acceptor) {
            LOG_ERROR("failed to create TCP acceptor worker={} tag={} key={}",
                      worker.id_, binding.tag, listener_key);
            continue;
        }

        auto fail_candidate = [&](std::string_view op, std::string_view msg) -> bool {
            replacement_listeners->CloseAcceptor(listener_key);
            if (listen_candidates.size() > 1) {
                LOG_WARN("TCP listener operation failed worker={} operation={} endpoint={} > {}; continuing dual-stack bind",
                         worker.id_,
                         op,
                         iputil::FormatEndpointForLog(listen_addr, binding.port),
                         msg);
                return true;
            }
            LOG_ERROR("TCP listener operation failed worker={} operation={} endpoint={} > {}",
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


        prepared_listeners.push_back({listener_key, std::move(candidate_acceptor)});
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
    if (listener_slot.tcp_listeners) {
        listener_slot.tcp_listeners->Close();
    }

    listener_slot.tcp_listeners = std::move(replacement_listeners);
    listener_slot.tcp_binding = std::move(committed_binding);

    for (auto& prepared : prepared_listeners) {
        const auto& listener_key = prepared.key;
        auto registration = std::make_unique<TaskCancellation>(*this);
        Spawn(worker, AcceptLoop(worker, listener_key, memory::ThreadLocalString(binding.tag),
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
    if (slot_it->second->tcp_listeners) {
        slot_it->second->tcp_listeners->Close();
        slot_it->second->tcp_listeners.reset();
    }
    slot_it->second->tcp_binding.reset();
}

worker_detail::UdpIngress*
Worker::ListenerState::FindUdpIngress(std::string_view socket_key) noexcept {
    const auto tag = ExtractListenerTag(socket_key);
    if (!tag) return nullptr;
    auto slot_it = listener_slots.find(*tag);
    if (slot_it == listener_slots.end() || !slot_it->second) {
        return nullptr;
    }
    return slot_it->second->udp_ingress.get();
}

net::awaitable<void> Worker::ListenerState::RetireUdpListening(std::string_view tag) {
    auto slot_it = listener_slots.find(tag);
    if (slot_it != listener_slots.end() && slot_it->second->udp_ingress) {
        if (slot_it->second->retiring_udp_ingress) {
            FailRuntime("udp-retirement", "missing or occupied retiring UDP slot");
        }
        slot_it->second->retiring_udp_ingress = std::move(slot_it->second->udp_ingress);
    }
    if (slot_it != listener_slots.end() && slot_it->second->quic_ingress) {
        if (slot_it->second->retiring_quic_ingress) {
            FailRuntime("quic-retirement", "missing or occupied retiring QUIC slot");
        }
        slot_it->second->retiring_quic_ingress =
            std::move(slot_it->second->quic_ingress);
    }
    if (slot_it != listener_slots.end()) slot_it->second->udp_binding.reset();

    if (slot_it != listener_slots.end() && slot_it->second->retiring_udp_ingress) {
        auto& retiring = *slot_it->second->retiring_udp_ingress;
        retiring.RequestStop();
        try {
            co_await retiring.AsyncJoin();
        } catch (const std::exception& error) {
            FailRuntime("udp-join", error.what());
        } catch (...) {
            FailRuntime("udp-join", "unknown UDP native-job join failure");
        }
        slot_it->second->retiring_udp_ingress.reset();
    }
    if (slot_it != listener_slots.end() &&
        slot_it->second->retiring_quic_ingress) {
        auto& retiring = *slot_it->second->retiring_quic_ingress;
        retiring.RequestStop();
        try {
            co_await retiring.AsyncJoin();
        } catch (const std::exception& error) {
            FailRuntime("quic-join", error.what());
        } catch (...) {
            FailRuntime("quic-join", "unknown QUIC join failure");
        }
        slot_it->second->retiring_quic_ingress.reset();
    }
    co_return;
}

bool Worker::ListenerState::EnqueueUdpReply(
    std::string_view socket_key,
    udp::socket* sock,
    udp::endpoint endpoint,
    buf::MultiBuffer payload,
    uint32_t worker_id) {
    auto* ingress = FindUdpIngress(socket_key);
    if (!ingress || !sock || !sock->is_open() || payload.empty()) {
        return false;
    }
    auto owned_sock = ingress->FindSocket(socket_key);
    if (!owned_sock || owned_sock.get() != sock) {
        return false;
    }

    const auto admitted = ingress->EnqueueReply(
        socket_key, std::move(endpoint), std::move(payload));
    if (admitted == worker_detail::UdpIngress::ReplyEnqueueResult::Rejected) {
        return false;
    }
    if (admitted == worker_detail::UdpIngress::ReplyEnqueueResult::StartSend) {
        StartUdpReplySend(*ingress, socket_key, std::move(owned_sock), worker_id);
    }
    return true;
}

void Worker::ListenerState::StartUdpReplySend(worker_detail::UdpIngress& ingress,
                                              std::string_view socket_key,
                                              worker_detail::UdpIngress::SocketPtr sock,
                                              uint32_t worker_id) {
    try {
        auto packet = ingress.BeginReplySend(socket_key);
        if (!packet) return;
        ++udp_reply_sends;
        try {
            net::co_spawn(sock->get_executor(),
                SendUdpReplies(memory::ThreadLocalString{socket_key}, sock,
                               std::move(*packet), worker_id),
                [this, worker_id](std::exception_ptr failure) {
                    --udp_reply_sends;
                    NotifyCompletion();
                    if (!failure) return;
                    try {
                        try { std::rethrow_exception(failure); }
                        catch (const std::exception& error) {
                            LOG_NET_DEBUG("UDP reply sender failed worker={} > {}",
                                          worker_id, error.what());
                        } catch (...) {
                            LOG_NET_DEBUG("UDP reply sender failed worker={} > unknown error", worker_id);
                        }
                    } catch (...) {} // Reporting must not fail completion under memory pressure.
                });
        } catch (...) {
            --udp_reply_sends;
            NotifyCompletion();
            throw;
        }
    } catch (...) {
        // No active task can retry this burst. Drop its bounded queue rather
        // than retain payload and an armed sender marker until another packet.
        ingress.ClearReplyQueue(socket_key);
        throw;
    }
}

net::awaitable<void> Worker::ListenerState::SendUdpReplies(
    memory::ThreadLocalString socket_key,
    worker_detail::UdpIngress::SocketPtr sock,
    worker_detail::UdpIngress::PendingUdpReply packet,
    uint32_t worker_id) {
    try {
        for (;;) {
            // Construct this view only after the packet is in its stable frame.
            const auto buffers = packet.SendBuffers();
            const auto [ec, sent] = co_await sock->async_send_to(
                buffers, packet.endpoint, net::as_tuple(net::use_awaitable));
            (void)sent;
            // The ingress may be replaced or retired while the send is suspended.
            auto* ingress = FindUdpIngress(socket_key);
            if (!ingress || !ingress->OwnsSocket(socket_key, sock.get())) co_return;
            if (ec && ec != io_error::operation_aborted) {
                LOG_NET_DEBUG("UDP reply send failed worker={} tag={} > {}",
                              worker_id, socket_key, ec.message());
            }
            auto next = ingress->CompleteReplySend(socket_key, packet.id);
            if (!next) co_return;
            packet = std::move(*next);
        }
    } catch (...) {
        if (auto* ingress = FindUdpIngress(socket_key);
            ingress && ingress->OwnsSocket(socket_key, sock.get()))
            ingress->ClearReplyQueue(socket_key);
        throw;
    }
}

// ============================================================================
// AcceptLoop — 每个 TCP socket 一个协程，运行在 Worker io_context 上
// ============================================================================

net::awaitable<void> Worker::ListenerState::AcceptLoop(
    Worker& worker,
    memory::ThreadLocalString listener_key,
    memory::ThreadLocalString tag,
    worker_detail::TcpListenerOwner::AcceptorPtr acceptor,
    SlotPtr slot) {
    const auto owns_acceptor = [&]() {
        return !stopping && acceptor && slot && slot->tcp_listeners &&
            slot->tcp_listeners->OwnsAcceptor(listener_key, acceptor.get());
    };
    while (owns_acceptor()) {

        auto [ec, socket] = co_await acceptor->async_accept(
            net::as_tuple(net::use_awaitable));

        if (!owns_acceptor()) co_return;

        if (ec == io_error::operation_aborted) co_return;
        if (ec) {
            LOG_WARN("TCP accept failed worker={} tag={} > {}", worker.id_, tag, ec.message());
            const auto backoff = MapAsioError(ec) == ErrorCode::RESOURCE_EXHAUSTED
                ? kAcceptResourceBackoff
                : kAcceptErrorBackoff;
            AsyncDelay sleep(worker.runtime_->io_context);
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

        const auto& receiver = inbound_handler->ReceiverSettings();
        auto record = std::make_shared<ConnectionRecord>();
        record->inbound_tag = receiver.inbound_tag;
        record->accounting_key = receiver.accounting_key;
        record->capabilities = app::PhysicalSessionCapabilities::Create(
            worker.runtime_->session_configuration, worker.runtime_->connection_limiter,
            worker.runtime_->request_load, worker.runtime_->dns_worker,
            slot->prepared, inbound_handler->SharedReceiverSettings());
        record->domain = ExecutionDomain::Create(worker.io_context_, worker.id_,
            worker.io_context_.get_executor(), record->capabilities, worker.group_coordinator_);
        record->capabilities->BindDomain(record->domain);
        worker.runtime_->connections.emplace(record.get(), record);
        ++tcp_tasks;
        try {
            net::co_spawn(record->domain->Executor(),
                ProcessReceivedConnection(record, std::move(socket), remote_ep, worker.id_),
                net::bind_executor(worker.io_context_.get_executor(),
                    [this, &worker, record](std::exception_ptr error) {
                        record->finished.store(true, std::memory_order_release);
                        auto& stats = worker.runtime_->stats;
                        stats.hot.bytes_in += record->final_stats.bytes_in;
                        stats.hot.bytes_out += record->final_stats.bytes_out;
                        stats.cold.connections_total += record->final_stats.connections_total;
                        stats.cold.errors += record->final_stats.errors;
                        --tcp_tasks;
                        NotifyCompletion();
                        bool accounting_merged = false;
                        try {
                            worker.runtime_->session_tracking->MergeCompletedTraffic(
                                record->accounting_key, record->completed_traffic);
                            accounting_merged = true;
                        } catch (...) {
                            worker.ReportFailure(std::current_exception());
                        }
                        if (accounting_merged)
                            worker.runtime_->EraseConnection(worker.id_, record);
                        if (error) {
                            try {
                                try { std::rethrow_exception(error); }
                                catch (const IoSystemError& failure) {
                                    if (failure.code() != net::error::operation_aborted &&
                                        failure.code() != net::error::eof)
                                        LOG_CONN_WARN(record->conn_id, "session domain ended worker={} > {}", worker.id_, failure.what());
                                } catch (const std::exception& failure) {
                                    LOG_CONN_WARN(record->conn_id, "session domain ended worker={} > {}", worker.id_, failure.what());
                                } catch (...) {
                                    LOG_CONN_WARN(record->conn_id, "session domain ended worker={} > unknown error", worker.id_);
                                }
                            } catch (...) {} // Completion must remain safe when logging cannot allocate.
                        }
                    }));
        } catch (...) {
            --tcp_tasks;
            worker.runtime_->connections.erase(record.get());
            throw;
        }
    }
}

// ============================================================================
// ProcessReceivedConnection — per-connection 协程
// ============================================================================

net::awaitable<void> Worker::ListenerState::ProcessReceivedConnection(
    std::shared_ptr<ConnectionRecord> record, tcp::socket socket,
    tcp::endpoint remote_ep, uint32_t accepted_worker) {
    std::exception_ptr failure;
    record->conn_id = session::NewID(accepted_worker);
    try {
        record->capabilities->Initialize(record->domain->Reactor());
        record->initialized.store(true, std::memory_order_release);
        const auto& listener = record->capabilities->Receiver();
        auto tcp_stream = std::make_unique<TcpStream>(std::move(socket));
        session::Context ctx;
        ctx.conn_id = record->conn_id;
        ctx.worker_id = accepted_worker;
        ctx.inbound.tag = listener.inbound_tag;
        if (const auto* route_tags = listener.RouteInboundTags()) {
            ctx.inbound.tags.reserve(route_tags->size());
            for (const auto& tag : *route_tags) ctx.inbound.tags.emplace_back(tag);
        }
        const auto local_ep = tcp_stream->LocalEndpoint();
        if (!local_ep.address().is_unspecified()) {
            const auto local_addr = iputil::NormalizeAddress(local_ep.address());
            ctx.inbound.local_endpoint = tcp::endpoint(local_addr, local_ep.port());
        }
        const auto normalized_remote = iputil::NormalizeAddress(remote_ep.address());
        ctx.inbound.source_addr = normalized_remote;
        ctx.inbound.source_ip = iputil::AddressText(normalized_remote).View();
        ctx.inbound.source_port = remote_ep.port();
        LOG_CONN_DEBUG(ctx, "accepted TCP worker={} source={}:{}",
                       accepted_worker, ctx.inbound.source_ip, ctx.inbound.source_port);
        co_await record->capabilities->ProcessTCP(std::move(tcp_stream), ctx);
    } catch (...) { failure = std::current_exception(); }
    try { co_await record->capabilities->AsyncJoin(); }
    catch (...) { if (!failure) failure = std::current_exception(); }
    try {
        record->completed_traffic =
            record->capabilities->Tracking().ExtractAvailableTraffic(
                record->accounting_key);
    } catch (...) {
        if (!failure) failure = std::current_exception();
    }
    if (record->capabilities->Initialized())
        record->final_stats = record->capabilities->Stats().Snapshot();
    if (failure) std::rethrow_exception(failure);
}

// ============================================================================
// 冷路径控制面（主线程经 mailbox 投递到 Worker 线程执行）
// ============================================================================

bool Worker::AddListener(PortBinding binding) {
    if (stop_requested_.load(std::memory_order_acquire) ||
        drain_requested_.load(std::memory_order_relaxed) ||
        !runtime_ || runtime_->listener_state->stopping)
        throw IoSystemError(net::error::operation_aborted);
    ColdMutationGuard mutation(runtime_->cold_mutation_active, runtime_->listener_state.get());
    return runtime_->listener_state->StartListening(*this, binding);
}

bool Worker::RegisterInbound(
    proxyman::inbound::BuildRequest req,
    proxyman::inbound::ReceiverSettings receiver) {
    if (stop_requested_.load(std::memory_order_acquire) ||
        drain_requested_.load(std::memory_order_relaxed) ||
        !runtime_ || runtime_->listener_state->stopping)
        throw IoSystemError(net::error::operation_aborted);
    ColdMutationGuard mutation(runtime_->cold_mutation_active, runtime_->listener_state.get());
    if (receiver.stream_settings.IsXHttp()) {
        auto& key = receiver.stream_settings.xhttp.session_namespace;
        key.insert(0, receiver.inbound_tag + std::string(1, '\0'));
    }
    auto prepared = std::make_shared<const proxyman::inbound::BuildRequest>(req);
    auto handler = runtime_->inbound_handlers->NewHandler(
        runtime_->connection_limiter.get(), req);
    const bool quic_only =
        proxyman::inbound::RegisteredDatagramTransport(req.protocol) ==
        proxyman::inbound::DatagramTransport::Quic;
    if (!handler && !quic_only) {
        LOG_WARN("failed to create inbound handler worker={} tag={} protocol={}",
                 id_, receiver.inbound_tag, req.protocol);
        return false;
    }
    auto inbound_handler =
        std::make_unique<proxyman::inbound::Handler>(
            std::move(receiver), std::move(handler), *runtime_->connection_limiter);
    const auto& settings = inbound_handler->ReceiverSettings();
    const memory::ThreadLocalString key(settings.inbound_tag);
    auto [slot_it, slot_inserted] =
        runtime_->listener_state->FindOrCreateSlot(key);
    std::shared_ptr<proxyman::inbound::Handler> registered;
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
    slot_it->second->prepared = std::move(prepared);
    return true;
}

void Worker::AddOutbound(proxyman::outbound::PreparedOutboundConfig config) {
    if (stop_requested_.load(std::memory_order_acquire) ||
        drain_requested_.load(std::memory_order_relaxed) ||
        !runtime_ || runtime_->listener_state->stopping)
        throw IoSystemError(net::error::operation_aborted);
    ColdMutationGuard mutation(runtime_->cold_mutation_active, runtime_->listener_state.get());
    auto handler = proxyman::outbound::NewHandler(
        config, runtime_->io_context,
        *runtime_->dns_service,
        runtime_->timeouts.DialTimeout(),
        runtime_->outbound_tasks->Tasks());

    if (!handler) {
        throw std::logic_error(
            "failed to install dynamic outbound '" + config.tag + "'");
    }
    auto previous = runtime_->outbound_handlers->GetHandler(config.tag);
    if (!runtime_->outbound_handlers->ReplaceHandler(std::move(handler))) {
        throw std::logic_error(
            "failed to install dynamic outbound '" + config.tag + "'");
    }
    try {
        runtime_->session_configuration->outbounds->Replace(config);
    } catch (...) {
        if (previous) {
            runtime_->outbound_handlers->RestoreHandler(std::move(previous));
        } else {
            runtime_->outbound_handlers->RemoveHandler(config.tag);
        }
        throw;
    }

    LOG_DEBUG("registered dynamic outbound worker={} protocol={} tag={}",
              id_, config.protocol, config.tag);
}

void Worker::RemoveOutbound(std::string_view tag) {
    if (stop_requested_.load(std::memory_order_acquire) ||
        drain_requested_.load(std::memory_order_relaxed) ||
        !runtime_ || runtime_->listener_state->stopping)
        throw IoSystemError(net::error::operation_aborted);
    ColdMutationGuard mutation(runtime_->cold_mutation_active, runtime_->listener_state.get());
    runtime_->session_configuration->outbounds->Remove(tag);
    runtime_->outbound_handlers->RemoveHandler(tag);
}

void Worker::InstallUserView(proxyman::inbound::UserStore::WorkerView view) {
    if (stop_requested_.load(std::memory_order_relaxed) || !runtime_) return;
    proxyman::inbound::UserStore::InstallWorkerView(view);
    for (const auto& [key, record] : runtime_->connections) {
        (void)key;
        if (record->finished.load(std::memory_order_acquire) ||
            !record->domain || !record->capabilities) continue;
        record->domain->Execute([cap = record->capabilities, view] {
            cap->UpdateUserView(view);
        });
    }
}

net::awaitable<void> Worker::UnregisterListenerTask(std::string tag) {
    if (stop_requested_.load(std::memory_order_acquire) ||
        drain_requested_.load(std::memory_order_relaxed) ||
        !runtime_ || runtime_->listener_state->stopping)
        throw IoSystemError(net::error::operation_aborted);
    ColdMutationGuard mutation(runtime_->cold_mutation_active, runtime_->listener_state.get());
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
        FailRuntime("udp-retirement", error.what());
    } catch (...) {
        FailRuntime("udp-retirement", "unknown UDP retirement failure");
    }

    runtime_->inbound_handlers->RemoveHandler(tag);
    if (auto slot_it = runtime_->listener_state->listener_slots.find(tag);
            slot_it != runtime_->listener_state->listener_slots.end()) {
        slot_it->second->handler.reset();
        slot_it->second->prepared.reset();
        if (!slot_it->second->tcp_binding && !slot_it->second->udp_binding &&
            !slot_it->second->udp_ingress &&
            !slot_it->second->retiring_udp_ingress &&
            !slot_it->second->quic_ingress &&
            !slot_it->second->retiring_quic_ingress) {
            runtime_->listener_state->listener_slots.erase(slot_it);
        }
    }
    MaybeShrinkHashContainer(runtime_->listener_state->listener_slots, 8);
    co_await net::this_coro::throw_if_cancelled(cancel_throwing);
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(net::error::operation_aborted);
    }
    co_return;
}

void Worker::UpdateRule(std::string_view tag, const std::vector<rule::DetectRule>& rules) {
    if (stop_requested_.load(std::memory_order_acquire) ||
        drain_requested_.load(std::memory_order_relaxed) ||
        !runtime_ || runtime_->listener_state->stopping)
        throw IoSystemError(net::error::operation_aborted);
    runtime_->detect_rule_policy->UpdateRule(tag, rules);
}

// ============================================================================
// 数据收集（在 Worker 线程执行）
// ============================================================================

net::awaitable<app::UserTrafficSnapshot> Worker::SnapshotTraffic(std::string tag) {
    app::UserTrafficSnapshot result;
    auto worker_counters = runtime_->session_tracking->SnapshotTraffic(tag);
    result.users = std::move(worker_counters.users);
    // Source registry membership never changes when a group migrates. Each
    // logical domain is therefore sampled exactly once across all Workers.
    std::vector<std::shared_ptr<ConnectionRecord>> records;
    records.reserve(runtime_->connections.size());
    for (const auto& [key, record] : runtime_->connections) {
        (void)key;
        if (record->initialized.load(std::memory_order_acquire) &&
            !record->finished.load(std::memory_order_acquire) &&
            (tag.empty() || record->accounting_key == tag)) {
            records.push_back(record);
        }
    }
    for (const auto& record : records) {
        if (!runtime_->connections.contains(record.get()) ||
            !record->domain || !record->capabilities)
            continue;
        auto owner = record->capabilities->TrackingOwner();
        auto counters = co_await net::co_spawn(record->domain->Executor(),
            [owner, tag]() -> net::awaitable<app::UserTrafficCounters> {
                co_return owner->SnapshotTraffic(tag);
            }, net::use_awaitable);
        if (counters.empty()) continue;
        result.domains.push_back({
            std::move(owner),
            std::move(counters),
        });
    }
    co_return result;
}

net::awaitable<void> Worker::CommitTraffic(
    std::string tag, const app::UserTrafficSnapshot& snapshot) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    runtime_->session_tracking->CommitTraffic(tag, snapshot);
    for (const auto& token : snapshot.domains) {
        token.owner->CommitTraffic(tag, token.counters);
    }
}

net::awaitable<void> Worker::RollbackTraffic(
    std::string tag, const app::UserTrafficSnapshot& snapshot) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    runtime_->session_tracking->RollbackTraffic(tag, snapshot);
    for (const auto& token : snapshot.domains) {
        token.owner->RollbackTraffic(tag, token.counters);
        auto available = token.owner->ExtractAvailableTraffic(tag);
        runtime_->session_tracking->MergeCompletedTraffic(tag, available);
    }
}

net::awaitable<std::vector<OnlineDevice>> Worker::GetOnlineDevices(std::string tag) const {
    auto handler = runtime_->inbound_handlers->GetHandler(tag);
    std::vector<OnlineDevice> result;
    if (handler) {
        result = runtime_->inbound_handlers->GetOnlineDevices(handler->ReceiverSettings().protocol, tag);
    }
    std::vector<std::shared_ptr<ConnectionRecord>> records;
    records.reserve(runtime_->connections.size());
    for (const auto& [key, record] : runtime_->connections) {
        (void)key;
        if (!record->finished.load(std::memory_order_acquire) &&
            record->initialized.load(std::memory_order_acquire) &&
            record->inbound_tag == tag) {
            records.push_back(record);
        }
    }
    for (const auto& record : records) {
        if (!runtime_->connections.contains(record.get()) ||
            !record->domain || !record->capabilities)
            continue;
        auto devices = co_await net::co_spawn(record->domain->Executor(),
            [capabilities = record->capabilities, tag]() mutable -> net::awaitable<std::vector<OnlineDevice>> {
                auto online = capabilities->GetOnlineDevices(tag);
                capabilities.reset();
                co_return online;
            }, net::use_awaitable);
        result.insert(result.end(), std::make_move_iterator(devices.begin()),
                      std::make_move_iterator(devices.end()));
    }
    co_return result;
}

// ============================================================================
// 运行时资源计数，仅在 Worker executor 上读取。
// ============================================================================

WorkerRuntimeStatsSnapshot Worker::CollectNativeRuntimeStats(bool include_resources) const {
    WorkerRuntimeStatsSnapshot snapshot;
    // Sample this Worker-owned transport and pool state on its own event loop.
    snapshot.memory.udp_sockets = transport::internet::DatagramSocket::ActiveCount();
    const auto pool = memory::ThreadMemoryPool().GetFootprint();
    snapshot.memory.pool_mapped_bytes = pool.mapped_bytes;
    snapshot.memory.pool_direct_bytes = pool.direct_bytes;
    snapshot.memory.pool_idle_bytes = pool.idle_bytes;
    snapshot.memory.pool_chunks = pool.chunks;
    snapshot.stats = runtime_->stats.Snapshot();
    snapshot.worker_id = id_;
    snapshot.active_connections = 0;
    for (const auto& [key, record] : runtime_->connections) {
        (void)key;
        if (!record->finished.load(std::memory_order_acquire)) ++snapshot.active_connections;
    }
    if (!include_resources) return snapshot;
    auto& resources = snapshot.resources.emplace();
    resources.udp_resource_drops = runtime_->listener_state->udp_resource_drops;
    resources.udp_receive_loops = runtime_->listener_state->udp_receive_loops;
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
    for (const auto& [tag, slot] : runtime_->listener_state->listener_slots) {
        (void)tag;
        if (slot->udp_ingress) {
            resources.udp_listeners += slot->udp_ingress->SocketCount();
            collect_udp(slot->udp_ingress.get());
        }
        collect_udp(slot->retiring_udp_ingress.get());
    }
    const auto timeouts = TimeoutScheduler::ForIoContext(
        runtime_->io_context).GetResourceStats();
    resources.timeout_events = timeouts.active_events;
    resources.timeout_heap_capacity = timeouts.heap_capacity;
    resources.timeout_waiters = timeouts.wait_pending ? 1 : 0;
    return snapshot;
}

net::awaitable<WorkerRuntimeStatsSnapshot> Worker::CollectRuntimeStats(bool include_resources) const {
    auto result = CollectNativeRuntimeStats(include_resources);
    struct Sample {
        std::shared_ptr<ConnectionRecord> record;
        bool was_active = false;
    };
    std::vector<Sample> samples;
    samples.reserve(runtime_->connections.size());
    for (const auto& [key, record] : runtime_->connections) {
        (void)key;
        samples.push_back(Sample{
            .record = record,
            .was_active = !record->finished.load(std::memory_order_acquire),
        });
    }
    for (const auto& [record, was_active] : samples) {
        if (was_active && record->finished.load(std::memory_order_acquire)) {
            result.stats.connections_total += record->final_stats.connections_total;
            result.stats.bytes_in += record->final_stats.bytes_in;
            result.stats.bytes_out += record->final_stats.bytes_out;
            result.stats.errors += record->final_stats.errors;
            if (result.active_connections > 0) {
                --result.active_connections;
            }
            continue;
        }
        if (!record->initialized.load(std::memory_order_acquire) ||
            !runtime_->connections.contains(record.get()) ||
            !record->domain || !record->capabilities)
            continue;
        const bool include_stats = !record->finished.load(std::memory_order_acquire);
        const auto values = co_await net::co_spawn(record->domain->Executor(),
            [cap = record->capabilities, domain = record->domain, include_stats,
             include_resources]() mutable -> net::awaitable<WorkerRuntimeStatsSnapshot> {
                WorkerRuntimeStatsSnapshot snapshot;
                if (include_stats) snapshot.stats = cap->Stats().Snapshot();
                if (include_resources && include_stats && !cap->IsJoined()) {
                    const auto timers = TimeoutScheduler::ForIoContext(
                        domain->Reactor()).GetResourceStats();
                    auto& resources = snapshot.resources.emplace();
                    resources.timeout_events = timers.active_events;
                    resources.timeout_heap_capacity = timers.heap_capacity;
                    resources.timeout_waiters = timers.wait_pending ? 1 : 0;
                }
                cap.reset();
                domain.reset();
                co_return snapshot;
            }, net::use_awaitable);
        const bool still_active = !record->finished.load(std::memory_order_acquire);
        if (still_active) {
            result.stats.connections_total += values.stats.connections_total;
            result.stats.connections_active += values.stats.connections_active;
            result.stats.bytes_in += values.stats.bytes_in;
            result.stats.bytes_out += values.stats.bytes_out;
            result.stats.errors += values.stats.errors;
            if (values.resources) {
                result.resources->timeout_events += values.resources->timeout_events;
                result.resources->timeout_heap_capacity += values.resources->timeout_heap_capacity;
                result.resources->timeout_waiters += values.resources->timeout_waiters;
            }
        } else if (include_stats) {
            result.stats.connections_total += record->final_stats.connections_total;
            result.stats.bytes_in += record->final_stats.bytes_in;
            result.stats.bytes_out += record->final_stats.bytes_out;
            result.stats.errors += record->final_stats.errors;
            if (result.active_connections > 0) {
                --result.active_connections;
            }
        }
    }
    if (runtime_->session_configuration && runtime_->session_configuration->outbounds) {
        co_await runtime_->session_configuration->outbounds->CollectRuntimeStats(
            result, include_resources);
    }
    co_return result;
}

void Worker::CollectHeap() {
    memory::CollectBurst();
}

// ============================================================================
// UDP 监听（SO_REUSEPORT，与 TCP acceptor 同端口）
//
// 具体的解码、认证和 ban 逻辑委托给统一 Inbound；Worker 只维护监听
// socket 与当前 Worker-local UDP ingress 生命周期。
// ============================================================================

net::awaitable<bool> Worker::AddUdpListenerTask(
    PortBinding binding,
    proxyman::inbound::BuildRequest req) {
    if (stop_requested_.load(std::memory_order_acquire) ||
        drain_requested_.load(std::memory_order_relaxed) ||
        !runtime_ || runtime_->listener_state->stopping)
        throw IoSystemError(net::error::operation_aborted);
    ColdMutationGuard mutation(runtime_->cold_mutation_active, runtime_->listener_state.get());
    if (proxyman::inbound::RegisteredDatagramTransport(req.protocol) ==
        proxyman::inbound::DatagramTransport::Quic) {
        co_return co_await runtime_->listener_state->StartQuicListening(
            *this, binding);
    }
    auto result =
        runtime_->inbound_handlers->NewDatagramHandler(
            runtime_->connection_limiter.get(), req);
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


net::awaitable<bool> Worker::ListenerState::StartQuicListening(
    Worker& worker,
    const PortBinding& binding) {
    // A QUIC connection remains on one Worker for its whole lifetime. A single
    // owner socket lets kernel path migration reach that owner without
    // user-space packet forwarding or per-connection cross-Worker queues.
    if (worker.id_ != 0) co_return true;

    auto slot_it = listener_slots.find(binding.tag);
    if (slot_it == listener_slots.end() || !slot_it->second->handler ||
        !slot_it->second->prepared) {
        LOG_ERROR("QUIC listener unavailable worker={} tag={} > missing prepared inbound",
                  worker.id_, binding.tag);
        co_return false;
    }
    auto* runtime = dynamic_cast<proxy::UserOnlineProtocolRuntime*>(
        worker.runtime_->inbound_handlers->GetOrCreateRuntime(binding.protocol));
    if (!runtime) {
        LOG_ERROR("QUIC listener unavailable worker={} tag={} > invalid protocol runtime",
                  worker.id_, binding.tag);
        co_return false;
    }
    auto replacement = std::make_unique<proxy::hysteria::HysteriaIngress>(
        worker.id_, worker.runtime_->io_context, *worker.runtime_->dispatcher,
        worker.runtime_->stats, worker.runtime_->connection_limiter,
        runtime->validator, worker.runtime_->timeouts,
        slot_it->second->prepared,
        slot_it->second->handler->SharedReceiverSettings());

    size_t bound = 0;
    const auto candidates = binding.listen.Candidates();
    for (const auto& address : candidates) {
        const iputil::AddressText text(address);
        const auto listen_text = text.View();
        udp::endpoint endpoint(address, binding.port);
        auto socket = replacement->MakeSocket();
        IoErrorCode error;
        socket->open(endpoint.protocol(), error);
        if (!error && address.is_v6())
            socket->set_option(net::ip::v6_only(true), error);
        if (!error)
            socket->set_option(net::socket_base::reuse_address(true), error);
        if (!error) socket->bind(endpoint, error);
        if (error) {
            if (candidates.size() > 1) {
                LOG_WARN("QUIC listener bind failed worker={} endpoint={} > {}; continuing dual-stack bind",
                         worker.id_,
                         iputil::FormatEndpointForLog(listen_text, binding.port),
                         error.message());
                continue;
            }
            LOG_ERROR("QUIC listener bind failed worker={} endpoint={} > {}",
                      worker.id_,
                      iputil::FormatEndpointForLog(listen_text, binding.port),
                      error.message());
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
        LOG_DEBUG("QUIC listener ready worker={} key={} tag={} protocol={} owner=dedicated",
                  worker.id_, key, binding.tag, binding.protocol);
    }
    if (bound == 0) co_return false;

    if (slot_it->second->quic_ingress) {
        slot_it->second->retiring_quic_ingress =
            std::move(slot_it->second->quic_ingress);
        slot_it->second->retiring_quic_ingress->RequestStop();
        co_await slot_it->second->retiring_quic_ingress->AsyncJoin();
        slot_it->second->retiring_quic_ingress.reset();
    }
    replacement->Start();
    slot_it->second->quic_ingress = std::move(replacement);
    slot_it->second->udp_binding =
        ListenerSlot::SocketBinding{binding.port, binding.listen};
    co_return true;
}

net::awaitable<bool> Worker::ListenerState::StartUdpListening(
    Worker& worker,
    const PortBinding& binding,
    std::unique_ptr<Inbound> handler) {
    // TCP and UDP listeners both remain local to the Worker that bound them.
    for (const auto& [tag, slot] : listener_slots) {
        if (tag != std::string_view(binding.tag) && slot->udp_binding &&
            slot->udp_binding->port == binding.port &&
            slot->udp_binding->listen.Overlaps(binding.listen)) {
            LOG_ERROR("UDP listener conflict worker={} tag={} owner={} port={}",
                      worker.id_, binding.tag, tag, binding.port);
            co_return false;
        }
    }

    auto existing_slot = listener_slots.find(binding.tag);
    const bool replacing = existing_slot != listener_slots.end() &&
        existing_slot->second->udp_ingress != nullptr &&
        existing_slot->second->udp_binding.has_value();
    if (replacing &&
        existing_slot->second->udp_binding->UsesSameSocket(binding)) {
        auto cancellation = co_await net::this_coro::cancellation_state;
        if (stopping ||
            worker.stop_requested_.load(std::memory_order_acquire) ||
            worker.drain_requested_.load(std::memory_order_relaxed) ||
            cancellation.cancelled() != net::cancellation_type::none)
            throw IoSystemError(net::error::operation_aborted);
        const bool replaced = existing_slot->second->udp_ingress->ReplaceHandler(std::move(handler));
        if (stopping ||
            worker.stop_requested_.load(std::memory_order_acquire) ||
            worker.drain_requested_.load(std::memory_order_relaxed) ||
            cancellation.cancelled() != net::cancellation_type::none)
            throw IoSystemError(net::error::operation_aborted);
        co_return replaced;
    }

#ifdef CNODE_TEST_UDP_LISTENER_RUNTIME_FAULT
    worker_udp_listener_runtime_test::OnStage("prepare-listener", 0);
#endif
    if (!worker.runtime_->udp_association_reclaimer) {
        throw std::logic_error("UDP listener runtime is not started");
    }
    ListenerSlot::SocketBinding committed_binding{binding.port, binding.listen};
    auto replacement_ingress =
        std::make_unique<worker_detail::UdpIngress>(
            binding.tag, std::move(handler), *worker.runtime_->udp_association_reclaimer,
            worker.runtime_->udp_resource_budget, worker.runtime_->io_context);
    ListenerKeys prepared_socket_keys;

    const auto listen_candidates = binding.listen.Candidates();
    prepared_socket_keys.reserve(listen_candidates.size());
    size_t bound_count = 0;

    for (const auto& addr : listen_candidates) {
        const iputil::AddressText listen_text(addr);
        const auto listen_addr = listen_text.View();
        IoErrorCode ec;
        udp::endpoint ep(addr, binding.port);
        auto candidate_sock =
            replacement_ingress->MakeSocket(worker.runtime_->io_context);

        auto fail_candidate = [&](std::string_view op, std::string_view msg) -> bool {
            if (listen_candidates.size() > 1) {
                LOG_WARN("UDP listener operation failed worker={} operation={} endpoint={} > {}; continuing dual-stack bind",
                         worker.id_,
                         op,
                         iputil::FormatEndpointForLog(listen_addr, binding.port),
                         msg);
                return true;
            }
            LOG_ERROR("UDP listener operation failed worker={} operation={} endpoint={} > {}",
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

        // SO_REUSEPORT：每 Worker 独立绑定，内核负载均衡。
        int optval = 1;
        if (::setsockopt(candidate_sock->native_handle(), SOL_SOCKET, SO_REUSEPORT,
                         &optval, sizeof(optval)) < 0) {
            if (fail_candidate("SO_REUSEPORT", strerror(errno))) continue;
            break;
        }

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

        const auto socket_key = BuildListenerKey(binding.tag, listen_addr, binding.port);
        auto bound_sock =
            replacement_ingress->AttachSocket(socket_key, std::move(candidate_sock));
        if (!bound_sock) {
            LOG_ERROR("failed to attach UDP socket worker={} tag={} key={}",
                      worker.id_, binding.tag, socket_key);
            continue;
        }
        prepared_socket_keys.push_back(socket_key);
        ++bound_count;
    }

    if (bound_count == 0) {
        LOG_ERROR("no UDP listener bound worker={} tag={} protocol={}",
                  worker.id_, binding.tag, binding.protocol);
        co_return false;
    }

    struct PreparedReceive {
        memory::ThreadLocalString socket_key;
        worker_detail::UdpIngress::SocketPtr socket;
        net::awaitable<void> receive;
    };
    memory::ThreadLocalVector<PreparedReceive> prepared_receives;
    ListenerSlotMap::iterator slot_it;
    bool inserted_slot = false;
    try {
        auto slot_entry = FindOrCreateSlot(binding.tag);
        slot_it = slot_entry.first;
        inserted_slot = slot_entry.second;
        prepared_receives.reserve(prepared_socket_keys.size());
        for (const auto& socket_key : prepared_socket_keys) {
            auto socket = replacement_ingress->FindSocket(socket_key);
            if (!socket) throw std::logic_error("prepared UDP socket is missing");
            // Prepare frame and owned captures before retiring the old listener.
            auto receive = UdpReceiveLoop(
                worker, socket_key, socket, slot_it->second, replacement_ingress.get());
            prepared_receives.push_back({socket_key, std::move(socket), std::move(receive)});
        }
        if (replacing) {
            LOG_WARN("replacing existing UDP listeners worker={} tag={}", worker.id_, binding.tag);
        }
    } catch (...) {
        if (inserted_slot) listener_slots.erase(slot_it);
        throw;
    }
#ifdef CNODE_TEST_UDP_LISTENER_RUNTIME_FAULT
    worker_udp_listener_runtime_test::FinishPreparation();
#endif

    const bool has_retiring_worker = slot_it->second->udp_ingress != nullptr;
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
            FailRuntime("udp-retirement", error.what());
        } catch (...) {
            FailRuntime("udp-retirement", "unknown UDP retirement failure");
        }
    }
    if (stopping ||
        worker.stop_requested_.load(std::memory_order_acquire) ||
        worker.drain_requested_.load(std::memory_order_relaxed))
        throw IoSystemError(net::error::operation_aborted);
    try {
        auto& listener_slot = *slot_it->second;
        auto* committed_ingress = replacement_ingress.get();
        listener_slot.udp_ingress = std::move(replacement_ingress);
        listener_slot.udp_binding = std::move(committed_binding);
        for (size_t index = 0; index < prepared_receives.size(); ++index) {
            auto& prepared = prepared_receives[index];
            const auto& socket_key = prepared_socket_keys[index];
            auto completion = [this, &worker, slot = slot_it->second, committed_ingress,
                               socket_key = std::move(prepared.socket_key),
                               socket = std::move(prepared.socket)](std::exception_ptr error) {
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
                if (!slot || slot->udp_ingress.get() != committed_ingress ||
                    !committed_ingress->OwnsSocket(socket_key, socket.get())) {
                    return; // Formal retirement; never affect a replacement socket.
                }
                if (!error) error = std::make_exception_ptr(
                    std::runtime_error("registered UDP receive loop stopped"));
                worker.ReportFailure(error);
            };
            ++udp_receive_loops;
            try {
#ifdef CNODE_TEST_UDP_LISTENER_RUNTIME_FAULT
                worker_udp_listener_runtime_test::OnStage("spawn", index);
#endif
                net::co_spawn(worker.runtime_->io_context.get_executor(),
                              std::move(prepared.receive), std::move(completion));
            } catch (...) {
                --udp_receive_loops;
                throw;
            }
#ifdef CNODE_TEST_UDP_LISTENER_RUNTIME_FAULT
            worker_udp_listener_runtime_test::ReportSuccessfulSpawn(index);
            worker_udp_listener_runtime_test::OnStage("ready", index);
#endif

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
    memory::ThreadLocalString socket_key,
    worker_detail::UdpIngress::SocketPtr sock,
    SlotPtr listener_slot,
    worker_detail::UdpIngress* expected_ingress) {
    auto is_owned = [this, listener_slot, expected_ingress](
                        const worker_detail::UdpIngress::SocketPtr& socket) noexcept {
        return !stopping && socket && socket->is_open() && listener_slot &&
            listener_slot->udp_ingress.get() == expected_ingress;
    };
    auto process_datagram = [this, &worker, socket_key = std::move(socket_key),
                            socket = sock.get(), listener_slot = std::move(listener_slot),
                            expected_ingress](
        const udp::endpoint& client_ep, std::span<const uint8_t> received) {
        if (!listener_slot || listener_slot->udp_ingress.get() != expected_ingress) return;
        const auto* receiver = listener_slot->handler
            ? &listener_slot->handler->ReceiverSettings() : nullptr;
        expected_ingress->ProcessDatagram(worker_detail::UdpDatagramContext{
            .socket_key = socket_key,
            .sock = socket,
            .client_endpoint = client_ep,
            .payload = received,
            .receiver = receiver,
            .io_context = worker.runtime_->io_context,
            .dispatcher = *worker.runtime_->dispatcher,
            .stats = worker.runtime_->stats,
            .timeouts = worker.runtime_->timeouts,
            .worker_id = worker.id_,
            .reply_sink = *this,
        });
    };
    return worker_detail::RunUdpReceiveLoop(
        std::move(sock), std::move(is_owned), std::move(process_datagram), udp_resource_drops);
}

}  // namespace acpp
