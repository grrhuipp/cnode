#include "acppnode/runtime/runtime.hpp"
#include "listener/udp_receive_loop.hpp"
#include "listener/udp_association_reclaimer.hpp"
#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/traffic_types.hpp"
#include "acppnode/runtime/runtime_config.hpp"
#include "acppnode/runtime/runtime_stats.hpp"
#include "../common/awaitable_task_group.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/rule.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/dispatcher/default_dispatcher.hpp"
#include "acppnode/app/proxyman/inbound/manager.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "listener/tcp_listener.hpp"
#include "listener/udp_ingress.hpp"
#include "acppnode/app/proxyman/outbound/manager.hpp"
#include "acppnode/app/session_tracking.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/dns/dns_service.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "acppnode/transport/internet/datagram_socket.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
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
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <utility>
#include <asio/experimental/channel.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/strand.hpp>

namespace acpp {

struct Runtime::ListenerSlot {
    // Runtime 线程内稳定的 per-tag slot。AcceptLoop 持有 slot 指针；
    // 配置热更新只替换当前 inbound handler；每个已接受连接复制 shared_ptr，
    // 让受管理的 HTTP/2/gRPC/XHTTP 逻辑子流覆盖 handler 的完整生命周期。
    std::shared_ptr<proxyman::inbound::Handler> handler;
    std::unique_ptr<inbound_detail::TcpListenerOwner> tcp_owner;
    std::optional<PortBinding> tcp_binding;
    std::optional<PortBinding> udp_binding;
    // Keeps a stopped ingress alive until every native dispatch job completes.
    std::unique_ptr<inbound_detail::UdpIngress> retiring_udp;
};

struct Runtime::ListenerState {
    using ListenerSlotMap =
        memory::DataMap<std::string, ListenerSlot>;
    using ListenerKeys = memory::DataVector<std::string>;

    memory::DataUnorderedMap<std::string, std::string> tcp_listener_tags;
    ListenerSlotMap listener_slots;
    memory::DataUnorderedMap<std::string, std::string> udp_socket_tags;
    memory::DataUnorderedMap<std::string, std::unique_ptr<inbound_detail::UdpIngress>>
        udp_ingresses;
    uint64_t udp_resource_drops = 0;
    size_t udp_receive_loops = 0;

    [[nodiscard]] bool StartListening(Runtime& runtime, const PortBinding& binding);
    [[nodiscard]] ListenerKeys CollectTcpListenerKeys(const std::string& tag) const;
    void StopListening(const std::string& tag,
                       ListenerKeys listener_keys) noexcept;
    net::awaitable<bool> StartUdpListening(
        Runtime& runtime,
        const PortBinding& binding,
        std::unique_ptr<Inbound> handler);
    [[nodiscard]] ListenerKeys CollectUdpSocketKeys(const std::string& tag) const;
    net::awaitable<void> RetireUdpListening(
        const std::string& tag, ListenerKeys socket_keys);
    void StartTasks(Runtime& runtime, AwaitableTaskGroup& tasks);
    void SpawnUdpReceive(Runtime& runtime, net::awaitable<void> receive);

    net::awaitable<void> AcceptLoop(
        Runtime& runtime,
        std::string listener_key,
        std::string tag,
        inbound_detail::TcpListenerOwner::AcceptorPtr acceptor,
        ListenerSlot* slot);

    net::awaitable<StatsSnapshot> ProcessReceivedConnection(
        tcp::socket socket,
        tcp::endpoint remote_ep,
        std::shared_ptr<proxyman::inbound::Handler> inbound_handler,
        app::dispatcher::DefaultDispatcher& dispatcher,
        TimeoutsConfig timeouts,
        uint32_t pressure_idle_timeout,
        uint64_t conn_id,
        uint64_t runtime_generation,
        uint64_t config_generation);

    net::awaitable<void> UdpReceiveLoop(
        Runtime& runtime,
        std::string socket_key,
        inbound_detail::UdpIngress::SocketPtr sock,
        ListenerSlot* listener_slot);

    [[nodiscard]] inbound_detail::UdpIngress*
    FindUdpIngressBySocketKey(const std::string& socket_key) noexcept;
    [[nodiscard]] const inbound_detail::UdpIngress*
    FindUdpIngressBySocketKey(const std::string& socket_key) const noexcept;

};

// Runtime-local capability owner. Constructs, starts and holds every live
// inbound/outbound/dns/udp/router/dispatcher instance for this Runtime.
struct Runtime::RuntimeState {
    using EntryChannel =
        net::experimental::concurrent_channel<void(IoErrorCode)>;

    class EntryPermit {
    public:
        EntryPermit() noexcept = default;
        explicit EntryPermit(EntryChannel& channel) noexcept
            : channel_(&channel) {}
        EntryPermit(EntryPermit&& other) noexcept
            : channel_(std::exchange(other.channel_, nullptr)) {}
        EntryPermit& operator=(EntryPermit&& other) noexcept {
            if (this != &other) {
                Release();
                channel_ = std::exchange(other.channel_, nullptr);
            }
            return *this;
        }
        ~EntryPermit() { Release(); }
        EntryPermit(const EntryPermit&) = delete;
        EntryPermit& operator=(const EntryPermit&) = delete;

    private:
        void Release() noexcept {
            if (!channel_) return;
            const bool returned = channel_->try_send(IoErrorCode{});
            (void)returned;
            channel_ = nullptr;
        }
        EntryChannel* channel_ = nullptr;
    };

    RuntimeState(net::any_io_executor shared_executor,
                 const RuntimeConfig& runtime_config,
                 StatsShard& stats_ref,
                 app::dns::DNSService& dns_service,
                 geo::GeoManager* geo_manager_ref)
        : base_executor(std::move(shared_executor))
        , owner_executor(net::make_strand(base_executor))
        , runtime_snapshot(std::make_shared<RuntimeConfig>(runtime_config))
        , stats(stats_ref)
        , geo_manager(geo_manager_ref)
        , udp_association_quota()
        , listener_state(std::make_unique<ListenerState>())
        , inbound_manager(std::make_unique<proxyman::inbound::Manager>(
              owner_executor, base_executor))
        , session_tracking(std::make_unique<app::SessionTrackingState>(base_executor))
        , dns_service(std::make_unique<app::dns::DNS>(dns_service))
        , outbound_manager(std::make_unique<proxyman::outbound::Manager>(base_executor))
        , rule_manager(std::make_unique<rule::Manager>(base_executor))
        , dispatcher(std::make_unique<app::dispatcher::DefaultDispatcher>())
        , entries(owner_executor,
              runtime_config.entry_capacity == 0
                  ? defaults::kServiceChannelCapacity
                  : runtime_config.entry_capacity)
        , stop_entry(owner_executor, 1)
        , stop_signal(owner_executor, 1)
        , run_completion(owner_executor, 1)
        , stop_completion(owner_executor, 1) {
        const size_t capacity = entries.capacity();
        for (size_t i = 0; i < capacity; ++i) {
            if (!entries.try_send(IoErrorCode{})) {
                throw std::logic_error("failed to initialize Runtime entry capacity");
            }
        }
        if (!stop_entry.try_send(IoErrorCode{})) {
            throw std::logic_error("failed to initialize Runtime stop entry");
        }
    }

    ~RuntimeState() {
        if (udp_association_reclaimer) udp_association_reclaimer->Stop();
    }

    [[nodiscard]] std::shared_ptr<const RuntimeConfig> Snapshot() const {
        return runtime_snapshot;
    }

    void StoreSnapshot(std::shared_ptr<RuntimeConfig> snapshot) noexcept {
        const auto current = runtime_snapshot;
        if (current) {
            snapshot->runtime_generation = current->runtime_generation + 1;
            snapshot->config_generation = current->config_generation + 1;
        }
        runtime_snapshot = std::move(snapshot);
    }

    net::awaitable<void> Start();
    net::awaitable<void> InitOutbounds(
        const std::vector<proxyman::outbound::PreparedOutboundConfig>& outbounds);
    void InitRouter(const RoutingConfig& routing,
                    geo::GeoManager* geo_manager_ref);
    net::awaitable<void> StopOutbounds();

    [[nodiscard]] EntryPermit TryEnter() {
        EntryPermit permit;
        const bool received = entries.try_receive(
            [&](IoErrorCode error) {
                if (!error) permit = EntryPermit(entries);
            });
        if (!received) {
            throw IoSystemError(
                io_error::no_buffer_space,
                "Runtime entry capacity exhausted");
        }
        return permit;
    }

    net::awaitable<EntryPermit> EnterStop() {
        auto [error] = co_await stop_entry.async_receive(
            net::as_tuple(net::use_awaitable));
        if (error) throw IoSystemError(error, "Runtime stop entry closed");
        co_return EntryPermit(stop_entry);
    }

    net::any_io_executor base_executor;
    net::any_io_executor owner_executor;
    std::shared_ptr<const RuntimeConfig> runtime_snapshot;
    StatsShard& stats;
    geo::GeoManager* geo_manager = nullptr;

    // Declared before the row owners: Stop precedes their teardown, but the
    // reclaimer remains alive while all map-owned hooks are unlinked.
    std::unique_ptr<inbound_detail::UdpAssociationReclaimer> udp_association_reclaimer;
    inbound_detail::UdpAssociationQuota udp_association_quota;
    std::unique_ptr<ListenerState> listener_state;
    std::unique_ptr<proxyman::inbound::Manager> inbound_manager;
    std::unique_ptr<app::SessionTrackingState> session_tracking;
    std::unique_ptr<app::dns::DNS> dns_service;
    std::unique_ptr<proxyman::outbound::Manager> outbound_manager;
    std::unique_ptr<app::router::Router> router;
    std::unique_ptr<rule::Manager> rule_manager;
    std::unique_ptr<app::dispatcher::DefaultDispatcher> dispatcher;
    EntryChannel entries;
    EntryChannel stop_entry;
    net::experimental::channel<void(IoErrorCode)> stop_signal;
    net::experimental::channel<void(IoErrorCode)> run_completion;
    net::experimental::channel<void(IoErrorCode)> stop_completion;
    AwaitableTaskGroup* tasks = nullptr;
    uint64_t next_connection_sequence = 0;
    uint64_t next_transport_scope_id = 0;
    uint32_t active_connections = 0;
    bool started = false;
    bool run_started = false;
    bool run_finished = false;
    bool stopping = false;
    bool stop_finished = false;
    bool outbounds_stopped = false;
    std::exception_ptr stop_failure;
    bool cold_mutation_active = false;
};

namespace {

using RuntimeStopSignal = net::experimental::channel<void(IoErrorCode)>;

net::awaitable<void> WaitForRuntimeStop(RuntimeStopSignal* signal) {
    auto [error] = co_await signal->async_receive(
        net::as_tuple(net::use_awaitable));
    if (error && error != net::error::operation_aborted &&
        error != net::experimental::error::channel_closed) {
        throw IoSystemError(error);
    }
}

net::awaitable<void> TrackUdpReceive(
    size_t* receive_loops, net::awaitable<void> receive) {
    try {
        co_await std::move(receive);
    } catch (...) {
        --*receive_loops;
        throw;
    }
    --*receive_loops;
}

net::awaitable<void> TrackTcpConnection(
    StatsShard* stats, uint32_t* active_connections,
    net::any_io_executor session_executor,
    net::awaitable<StatsSnapshot> task) {
    try {
        const auto snapshot = co_await net::co_spawn(
            std::move(session_executor), std::move(task), net::use_awaitable);
        stats->hot.bytes_in += snapshot.bytes_in;
        stats->hot.bytes_out += snapshot.bytes_out;
        stats->cold.errors += snapshot.errors;
    } catch (const std::exception& error) {
        ++stats->cold.errors;
        LOG_ERROR("TCP connection coroutine failed: {}", error.what());
    } catch (...) {
        ++stats->cold.errors;
        LOG_ERROR("TCP connection coroutine failed: unknown");
    }
    if (*active_connections > 0) --*active_connections;
}

constexpr auto kAcceptErrorBackoff = std::chrono::milliseconds(5);
constexpr auto kAcceptResourceBackoff = std::chrono::milliseconds(100);

class ColdMutationGuard {
public:
    explicit ColdMutationGuard(bool& active) : active_(active) {
        if (active_) {
            throw std::system_error(
                std::make_error_code(std::errc::device_or_resource_busy),
                "Runtime cold mutation busy");
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

void RemoveInboundRuntimeFromSnapshot(RuntimeConfig& snapshot, std::string_view tag) {
    std::erase_if(snapshot.static_inbounds, [&](const StaticInboundRuntimeEntry& entry) {
        return entry.tag == tag;
    });
}

}  // namespace

// ============================================================================
// Runtime 构造 / 析构
// ============================================================================

Runtime::Runtime(net::any_io_executor shared_executor,
               const RuntimeConfig& runtime_config, StatsShard& stats,
               app::dns::DNSService& dns_service,
               geo::GeoManager* geo_manager)
    : runtime_(std::make_unique<RuntimeState>(
          std::move(shared_executor), runtime_config, stats, dns_service, geo_manager)) {}

Runtime::~Runtime() = default;

template <typename T>
net::awaitable<T> Runtime::Dispatch(net::awaitable<T> task) const {
    if ((co_await net::this_coro::cancellation_state).cancelled() !=
        net::cancellation_type::none) {
        throw IoSystemError(net::error::operation_aborted);
    }
    auto permit = runtime_->TryEnter();
    if constexpr (std::is_void_v<T>) {
        co_await net::co_spawn(
            runtime_->owner_executor, std::move(task), net::use_awaitable);
    } else {
        co_return co_await net::co_spawn(
            runtime_->owner_executor, std::move(task), net::use_awaitable);
    }
}

net::awaitable<void> Runtime::Initialize() {
    co_await Dispatch(InitializeOnOwner());
}

net::awaitable<void> Runtime::InitializeOnOwner() {
    co_await runtime_->Start();
}

net::awaitable<void> Runtime::Run() {
    co_await net::co_spawn(
        runtime_->owner_executor, RunOnOwner(), net::use_awaitable);
}

net::awaitable<void> Runtime::RunOnOwner() {
    if (runtime_->run_started) {
        throw std::logic_error("Runtime::Run may only be called once");
    }
    runtime_->run_started = true;
    std::exception_ptr failure;
    if (!runtime_->stopping) {
        try {
            co_await RunAwaitableTaskGroup(runtime_->owner_executor,
                [this](AwaitableTaskGroup& tasks) {
                    runtime_->tasks = &tasks;
                    runtime_->listener_state->StartTasks(*this, tasks);
                    tasks.Spawn(WaitForRuntimeStop(&runtime_->stop_signal));
                });
        } catch (...) {
            failure = std::current_exception();
        }
    }
    runtime_->tasks = nullptr;

    const bool throw_on_cancel = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    try {
        co_await runtime_->StopOutbounds();
    } catch (...) {
        if (!failure) failure = std::current_exception();
    }
    runtime_->run_finished = true;
    runtime_->run_completion.close();
    co_await net::this_coro::throw_if_cancelled(throw_on_cancel);
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> Runtime::Stop() {
    auto permit = co_await runtime_->EnterStop();
    const bool previous = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::exception_ptr failure;
    try {
        co_await net::co_spawn(
            runtime_->owner_executor, StopOnOwner(),
            net::bind_cancellation_slot(
                net::cancellation_slot{}, net::use_awaitable));
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::this_coro::throw_if_cancelled(previous);
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> Runtime::StopOnOwner() {
        if (runtime_->stopping) {
            while (!runtime_->stop_finished) {
                (void)co_await runtime_->stop_completion.async_receive(
                    net::as_tuple(net::bind_cancellation_slot(
                        net::cancellation_slot{}, net::use_awaitable)));
            }
            if (runtime_->stop_failure) {
                std::rethrow_exception(runtime_->stop_failure);
            }
            co_return;
        }
        runtime_->stopping = true;
        try {
            Runtime::ListenerState::ListenerKeys tags;
            tags.reserve(runtime_->listener_state->listener_slots.size());
            for (const auto& [tag, slot] : runtime_->listener_state->listener_slots) {
                (void)slot;
                tags.push_back(tag);
            }
            for (const auto& tag : tags) {
                runtime_->listener_state->StopListening(
                    tag, runtime_->listener_state->CollectTcpListenerKeys(tag));
            }
            for (const auto& tag : tags) {
                co_await runtime_->listener_state->RetireUdpListening(
                    tag, runtime_->listener_state->CollectUdpSocketKeys(tag));
            }
            if (runtime_->udp_association_reclaimer) {
                runtime_->udp_association_reclaimer->Stop();
            }
            runtime_->stop_signal.close();
            if (runtime_->tasks) runtime_->tasks->Cancel();
            while (runtime_->run_started && !runtime_->run_finished) {
                (void)co_await runtime_->run_completion.async_receive(
                    net::as_tuple(net::bind_cancellation_slot(
                        net::cancellation_slot{}, net::use_awaitable)));
            }
            co_await runtime_->StopOutbounds();
        } catch (...) {
            runtime_->stop_failure = std::current_exception();
        }
        runtime_->stop_finished = true;
        runtime_->stop_completion.close();
        if (runtime_->stop_failure) {
            std::rethrow_exception(runtime_->stop_failure);
        }
}

// ============================================================================
// 初始化
// ============================================================================

net::awaitable<void> Runtime::RuntimeState::Start() {
    if (started) {
        co_return;
    }

    auto& scheduler = TimeoutScheduler::ForExecutor(owner_executor);
    udp_association_reclaimer =
        std::make_unique<inbound_detail::UdpAssociationReclaimer>(
            scheduler, owner_executor);
    dispatcher->BindRequestPolicy(*rule_manager);
    dispatcher->BindSessionTracking(*session_tracking);
    dispatcher->BindDnsService(*dns_service);
    const auto config = Snapshot();
    co_await InitOutbounds(config->outbounds);
    dispatcher->BindOutboundManager(*outbound_manager);
    InitRouter(config->routing, geo_manager);
    started = true;
    co_return;
}

net::awaitable<void> Runtime::RuntimeState::InitOutbounds(
    const std::vector<proxyman::outbound::PreparedOutboundConfig>& outbounds) {
    const auto snapshot = Snapshot();
    const auto dial_timeout = snapshot->timeouts.DialTimeout();

    for (const auto& prepared_outbound : outbounds) {
        auto handler = proxyman::outbound::NewHandler(
            prepared_outbound, base_executor,
            *dns_service, dial_timeout);

        if (!(co_await outbound_manager->AddHandler(std::move(handler)))) {
            throw std::logic_error(
                "failed to install prepared outbound '" +
                prepared_outbound.tag + "'");
        }
        LOG_DEBUG("runtime registered {} outbound '{}'",
                  prepared_outbound.protocol, prepared_outbound.tag);
    }
    co_return;
}

net::awaitable<void> Runtime::RuntimeState::StopOutbounds() {
    if (outbounds_stopped) co_return;
    co_await outbound_manager->Clear();
    outbounds_stopped = true;
}

void Runtime::RuntimeState::InitRouter(
    const RoutingConfig& routing,
    geo::GeoManager* geo_manager_ref) {
    router = std::make_unique<app::router::Router>(routing, geo_manager_ref);
    dispatcher->BindRouter(*router);

    LOG_DEBUG("runtime router initialized, {} rules", routing.rules.size());
}

// ============================================================================
// Listener management runs only on the Runtime owner strand.
// ============================================================================

void Runtime::ListenerState::StartTasks(
    Runtime& runtime,
    AwaitableTaskGroup& tasks) {
    for (const auto& [listener_key, tag] : tcp_listener_tags) {
        auto slot_it = listener_slots.find(tag);
        if (slot_it == listener_slots.end() || !slot_it->second.tcp_owner) continue;
        auto acceptor = slot_it->second.tcp_owner->FindAcceptor(listener_key);
        if (!acceptor) continue;
        tasks.Spawn(AcceptLoop(
            runtime, listener_key, tag, std::move(acceptor), &slot_it->second));
    }
    for (const auto& [socket_key, tag] : udp_socket_tags) {
        auto slot_it = listener_slots.find(tag);
        auto ingress_it = udp_ingresses.find(tag);
        if (slot_it == listener_slots.end() || ingress_it == udp_ingresses.end() ||
            !ingress_it->second) continue;
        auto socket = ingress_it->second->FindSocket(socket_key);
        if (!socket) continue;
        SpawnUdpReceive(runtime, UdpReceiveLoop(
            runtime, socket_key, std::move(socket), &slot_it->second));
    }
}

void Runtime::ListenerState::SpawnUdpReceive(
    Runtime& runtime,
    net::awaitable<void> receive) {
    if (!runtime.runtime_->tasks) return;
    ++udp_receive_loops;
    try {
        runtime.runtime_->tasks->Spawn(
            TrackUdpReceive(&udp_receive_loops, std::move(receive)));
    } catch (...) {
        --udp_receive_loops;
        throw;
    }
}

bool Runtime::ListenerState::StartListening(Runtime& runtime, const PortBinding& binding) {
    auto inbound_handler = runtime.runtime_->inbound_manager->GetHandler(binding.tag);
    if (!inbound_handler) {
        LOG_ERROR("TCP listener tag={} has no inbound handler", binding.tag);
        return false;
    }

    for (const auto& [tag, slot] : listener_slots) {
        if (tag != binding.tag && slot.tcp_binding &&
            slot.tcp_binding->port == binding.port &&
            slot.tcp_binding->listen.Overlaps(binding.listen)) {
            LOG_ERROR("TCP listener conflict tag={} owner={} port={}",
                      binding.tag, tag, binding.port);
            return false;
        }
    }

    const bool replacing = std::ranges::any_of(
        tcp_listener_tags,
        [&](const auto& item) { return item.second == binding.tag; });
    auto existing_slot = listener_slots.find(binding.tag);
    if (replacing && existing_slot != listener_slots.end() &&
        existing_slot->second.tcp_owner &&
        existing_slot->second.tcp_binding &&
        existing_slot->second.tcp_binding->UsesSameSocket(binding)) {
        return true;
    }

    PortBinding committed_binding = binding;
    auto replacement_owner =
        std::make_unique<inbound_detail::TcpListenerOwner>(binding.tag);
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
            replacement_owner->CreateAcceptor(
                listener_key, runtime.runtime_->owner_executor);
        if (!candidate_acceptor) {
            LOG_ERROR("failed to create TCP acceptor tag={} key={}",
                      binding.tag, listener_key);
            return false;
        }

        auto fail_candidate = [&](std::string_view op, std::string_view msg) {
            LOG_ERROR("TCP {} {} failed: {}", op,
                      iputil::FormatEndpointForLog(listen_addr, binding.port), msg);
        };

        candidate_acceptor->open(ep.protocol(), ec);
        if (ec) {
            fail_candidate("open", ec.message());
            return false;
        }

        if (addr.is_v6()) {
            candidate_acceptor->set_option(net::ip::v6_only(true), ec);
            if (ec) {
                fail_candidate("set IPV6_V6ONLY", ec.message());
                return false;
            }
        }

        candidate_acceptor->set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            fail_candidate("set SO_REUSEADDR", ec.message());
            return false;
        }

        candidate_acceptor->bind(ep, ec);
        if (ec) {
            fail_candidate("bind", ec.message());
            return false;
        }

        candidate_acceptor->listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            fail_candidate("listen", ec.message());
            return false;
        }

        prepared_listener_keys.push_back(listener_key);
        prepared_listener_tags.emplace(listener_key, binding.tag);

        ++bound_count;
    }

    if (bound_count == 0) {
        LOG_ERROR("no TCP listener bound tag={} protocol={}",
                  binding.tag, binding.protocol);
        return false;
    }

    auto slot_it = listener_slots.try_emplace(binding.tag).first;
    tcp_listener_tags.reserve(
        tcp_listener_tags.size() + prepared_listener_tags.size());
    auto& listener_slot = slot_it->second;

    if (replacing) {
        LOG_WARN("replacing existing TCP listeners tag={}", binding.tag);
        StopListening(binding.tag, CollectTcpListenerKeys(binding.tag));
    } else if (listener_slot.tcp_owner) {
        listener_slot.tcp_owner->Close();
    }

    listener_slot.tcp_owner = std::move(replacement_owner);
    tcp_listener_tags.merge(prepared_listener_tags);
    listener_slot.tcp_binding = std::move(committed_binding);

    for (const auto& listener_key : prepared_listener_keys) {
        auto acceptor = listener_slot.tcp_owner->FindAcceptor(listener_key);
        if (!acceptor) {
            continue;
        }
        if (runtime.runtime_->tasks) {
            runtime.runtime_->tasks->Spawn(AcceptLoop(
                runtime, listener_key, binding.tag, acceptor, &listener_slot));
        }
        LOG_DEBUG("runtime.listener ready key={} tag={} protocol={}",
                  listener_key, binding.tag, binding.protocol);
    }
    return true;
}

Runtime::ListenerState::ListenerKeys
Runtime::ListenerState::CollectTcpListenerKeys(const std::string& tag) const {
    ListenerKeys listener_keys;
    for (const auto& [listener_key, listener_tag] : tcp_listener_tags) {
        if (listener_tag == tag) {
            listener_keys.push_back(listener_key);
        }
    }
    return listener_keys;
}

void Runtime::ListenerState::StopListening(
    const std::string& tag,
    ListenerKeys listener_keys) noexcept {
    if (listener_keys.empty()) return;

    auto slot_it = listener_slots.find(tag);
    for (const auto& listener_key : listener_keys) {
        if (slot_it != listener_slots.end() && slot_it->second.tcp_owner) {
            slot_it->second.tcp_owner->CloseAcceptor(listener_key);
        }
        tcp_listener_tags.erase(listener_key);
    }
    MaybeShrinkHashContainer(tcp_listener_tags, 8);
    if (slot_it != listener_slots.end()) {
        slot_it->second.tcp_binding.reset();
    }
}

inbound_detail::UdpIngress*
Runtime::ListenerState::FindUdpIngressBySocketKey(const std::string& socket_key) noexcept {
    auto tag_it = udp_socket_tags.find(socket_key);
    if (tag_it == udp_socket_tags.end()) {
        return nullptr;
    }
    auto ingress_it = udp_ingresses.find(tag_it->second);
    if (ingress_it == udp_ingresses.end() || !ingress_it->second) {
        return nullptr;
    }
    return ingress_it->second.get();
}

const inbound_detail::UdpIngress*
Runtime::ListenerState::FindUdpIngressBySocketKey(const std::string& socket_key) const noexcept {
    auto tag_it = udp_socket_tags.find(socket_key);
    if (tag_it == udp_socket_tags.end()) {
        return nullptr;
    }
    auto ingress_it = udp_ingresses.find(tag_it->second);
    if (ingress_it == udp_ingresses.end() || !ingress_it->second) {
        return nullptr;
    }
    return ingress_it->second.get();
}

Runtime::ListenerState::ListenerKeys
Runtime::ListenerState::CollectUdpSocketKeys(const std::string& tag) const {
    ListenerKeys socket_keys;
    for (const auto& [socket_key, socket_tag] : udp_socket_tags) {
        if (socket_tag == tag) {
            socket_keys.push_back(socket_key);
        }
    }
    return socket_keys;
}

net::awaitable<void> Runtime::ListenerState::RetireUdpListening(
    const std::string& tag, ListenerKeys socket_keys) {
    auto slot_it = listener_slots.find(tag);
    auto ingress_it = udp_ingresses.find(tag);
    if (ingress_it != udp_ingresses.end() && ingress_it->second) {
        if (slot_it == listener_slots.end() || slot_it->second.retiring_udp) {
            throw std::logic_error(
                "UDP listener retirement has no available owner slot");
        }
        slot_it->second.retiring_udp = std::move(ingress_it->second);
    }
    if (ingress_it != udp_ingresses.end()) ingress_it->second.reset();

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
        co_await retiring.AsyncJoin();
        slot_it->second.retiring_udp.reset();
    }
    co_return;
}

// ============================================================================
// AcceptLoop owns one accept operation on the listener strand. Each accepted
// socket is constructed directly on a fresh physical-session strand.
// ============================================================================

net::awaitable<void> Runtime::ListenerState::AcceptLoop(
    Runtime& runtime,
    std::string listener_key,
    std::string tag,
    inbound_detail::TcpListenerOwner::AcceptorPtr acceptor,
    ListenerSlot* slot) {
    const auto owns_acceptor = [&]() {
        return acceptor && slot && slot->tcp_owner &&
            slot->tcp_owner->OwnsAcceptor(listener_key, acceptor.get());
    };
    while (owns_acceptor()) {
        auto session_executor = net::make_strand(runtime.runtime_->base_executor);
        auto [ec, socket] = co_await acceptor->async_accept(
            session_executor,
            net::as_tuple(net::use_awaitable));

        if (!owns_acceptor()) co_return;

        if (ec == io_error::operation_aborted) co_return;
        if (ec) {
            LOG_WARN("runtime accept error tag={}: {}", tag, ec.message());
            const auto backoff = MapAsioError(ec) == ErrorCode::RESOURCE_EXHAUSTED
                ? kAcceptResourceBackoff
                : kAcceptErrorBackoff;
            AsyncDelay sleep(runtime.runtime_->owner_executor);
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
            LOG_ERROR("runtime has no inbound handler for tag={}", tag);
            socket.close();
            continue;
        }

        if (!runtime.runtime_->tasks || runtime.runtime_->stopping) {
            socket.close();
            continue;
        }
        if (runtime.runtime_->next_connection_sequence >=
            session::kMaxPhysicalSequence) {
            LOG_ERROR("connection id namespace exhausted");
            socket.close();
            continue;
        }
        const auto snapshot = runtime.runtime_->Snapshot();
        const uint64_t conn_id = session::PhysicalID(
            ++runtime.runtime_->next_connection_sequence);
        ++runtime.runtime_->active_connections;
        ++runtime.runtime_->stats.cold.connections_total;
        auto task = ProcessReceivedConnection(
            std::move(socket), remote_ep, std::move(inbound_handler),
            *runtime.runtime_->dispatcher, snapshot->timeouts,
            snapshot->pressure_idle_timeout, conn_id,
            snapshot->runtime_generation, snapshot->config_generation);
        try {
            runtime.runtime_->tasks->Spawn(TrackTcpConnection(
                &runtime.runtime_->stats, &runtime.runtime_->active_connections,
                session_executor, std::move(task)));
        } catch (...) {
            --runtime.runtime_->active_connections;
            throw;
        }
    }
}

// ============================================================================
// ProcessReceivedConnection — per-connection 协程
// ============================================================================

net::awaitable<StatsSnapshot> Runtime::ListenerState::ProcessReceivedConnection(
    tcp::socket socket,
    tcp::endpoint remote_ep,
    std::shared_ptr<proxyman::inbound::Handler> inbound_handler,
    app::dispatcher::DefaultDispatcher& dispatcher,
    TimeoutsConfig timeouts,
    uint32_t pressure_idle_timeout,
    uint64_t conn_id,
    uint64_t runtime_generation,
    uint64_t config_generation) {
    StatsShard stats;
    stats.OnConnectionAccepted();
    if (!inbound_handler) {
        LOG_ERROR("runtime has no inbound handler for accepted connection");
        socket.close();
        stats.OnError();
        stats.OnConnectionClosed();
        co_return stats.Snapshot();
    }
    const proxyman::inbound::ReceiverSettings& listener =
        inbound_handler->ReceiverSettings();

    auto tcp_stream = std::make_unique<TcpStream>(std::move(socket));
    const auto executor = co_await net::this_coro::executor;
    session::Context ctx(executor);
    ctx.conn_id = conn_id;
    ctx.runtime_generation = runtime_generation;
    ctx.config_generation = config_generation;
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
    LOG_CONN_DEBUG(ctx, "accepted TCP tag={} from {}:{}",
                   ctx.inbound.tag,
                   ctx.inbound.source_ip,
                   ctx.inbound.source_port);
    try {
        co_await inbound_handler->ProcessAcceptedTCP(
            executor, dispatcher, stats, pressure_idle_timeout,
            timeouts, std::move(tcp_stream), ctx);
    } catch (const std::exception& error) {
        stats.OnError();
        LOG_CONN_WARN(ctx, "inbound session failed: {}", error.what());
    } catch (...) {
        stats.OnError();
        LOG_CONN_WARN(ctx, "inbound session failed: unknown error");
    }
    stats.OnConnectionClosed();
    co_return stats.Snapshot();
}

// ============================================================================
// Bounded public entries and their owner-strand implementations.
// ============================================================================

net::awaitable<bool> Runtime::AddListener(PortBinding binding) {
    co_return co_await Dispatch(AddListenerOnOwner(std::move(binding)));
}

net::awaitable<bool> Runtime::AddListenerOnOwner(PortBinding binding) {
    ColdMutationGuard mutation(runtime_->cold_mutation_active);
    co_return runtime_->listener_state->StartListening(*this, binding);
}

bool Runtime::InstallInboundOnOwner(
    ConnectionLimiterPtr limiter,
    const proxyman::inbound::BuildRequest& req,
    proxyman::inbound::ReceiverSettings receiver) {
    auto handler = runtime_->inbound_manager->NewHandler(limiter, req);
    if (!handler) {
        LOG_WARN("failed to create inbound handler tag={} protocol={}",
                 receiver.inbound_tag, req.protocol);
        return false;
    }
    if (runtime_->next_transport_scope_id ==
        std::numeric_limits<uint64_t>::max()) {
        throw std::overflow_error("inbound transport scope id exhausted");
    }
    receiver.transport_scope_id = ++runtime_->next_transport_scope_id;
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
        LOG_WARN("failed to install inbound handler tag={}", key);
        return false;
    }
    slot_it->second.handler = registered;
    return true;
}

net::awaitable<bool> Runtime::RegisterInbound(
    ConnectionLimiterPtr limiter,
    proxyman::inbound::BuildRequest req,
    proxyman::inbound::ReceiverSettings receiver) {
    co_return co_await Dispatch(RegisterInboundOnOwner(
        std::move(limiter), std::move(req), std::move(receiver)));
}

net::awaitable<bool> Runtime::RegisterInboundOnOwner(
    ConnectionLimiterPtr limiter,
    proxyman::inbound::BuildRequest req,
    proxyman::inbound::ReceiverSettings receiver) {
    ColdMutationGuard mutation(runtime_->cold_mutation_active);
    co_return InstallInboundOnOwner(
        limiter, req, std::move(receiver));
}

net::awaitable<void> Runtime::AddOutbound(
    proxyman::outbound::PreparedOutboundConfig config) {
    co_await Dispatch(AddOutboundOnOwner(std::move(config)));
}

net::awaitable<void> Runtime::AddOutboundOnOwner(
    proxyman::outbound::PreparedOutboundConfig config) {
    ColdMutationGuard mutation(runtime_->cold_mutation_active);
    auto current_snapshot = runtime_->Snapshot();
    auto handler = proxyman::outbound::NewHandler(
        config, runtime_->base_executor,
        *runtime_->dns_service,
        current_snapshot->timeouts.DialTimeout());

    auto next_snapshot = memory::AllocateShared<RuntimeConfig>(*current_snapshot);
    std::erase_if(next_snapshot->outbounds,
                  [&](const auto& outbound) { return outbound.tag == config.tag; });
    next_snapshot->outbounds.push_back(std::move(config));
    const std::string_view installed_protocol = next_snapshot->outbounds.back().protocol;
    const std::string_view installed_tag = next_snapshot->outbounds.back().tag;

    if (!(co_await runtime_->outbound_manager->ReplaceHandler(std::move(handler)))) {
        throw std::logic_error(
            "failed to install dynamic outbound '" + std::string(installed_tag) + "'");
    }
    runtime_->StoreSnapshot(std::move(next_snapshot));

    LOG_DEBUG("registered dynamic {} outbound '{}'",
              installed_protocol, installed_tag);
}

net::awaitable<void> Runtime::RemoveOutbound(std::string tag) {
    co_await Dispatch(RemoveOutboundOnOwner(std::move(tag)));
}

net::awaitable<void> Runtime::RemoveOutboundOnOwner(std::string tag) {
    ColdMutationGuard mutation(runtime_->cold_mutation_active);
    auto current_snapshot = runtime_->Snapshot();
    auto next_snapshot = memory::AllocateShared<RuntimeConfig>(*current_snapshot);
    std::erase_if(next_snapshot->outbounds,
                  [&](const auto& outbound) { return outbound.tag == tag; });

    co_await runtime_->outbound_manager->RemoveHandler(tag);
    runtime_->StoreSnapshot(std::move(next_snapshot));
    co_return;
}

net::awaitable<void> Runtime::UnregisterListener(std::string tag) {
    co_await Dispatch(UnregisterListenerOnOwner(std::move(tag)));
}

net::awaitable<void> Runtime::UnregisterListenerOnOwner(std::string tag) {
    ColdMutationGuard mutation(runtime_->cold_mutation_active);
    auto current_snapshot = runtime_->Snapshot();
    auto next_snapshot = memory::AllocateShared<RuntimeConfig>(*current_snapshot);
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
    runtime_->listener_state->StopListening(tag, std::move(tcp_listener_keys));
    co_await runtime_->listener_state->RetireUdpListening(
        tag, std::move(udp_socket_keys));

    runtime_->listener_state->udp_ingresses.erase(tag);
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

net::awaitable<void> Runtime::UpdateRule(
    std::string tag,
    std::vector<rule::DetectRule> rules) {
    co_await Dispatch(UpdateRuleOnOwner(std::move(tag), std::move(rules)));
}

net::awaitable<void> Runtime::UpdateRuleOnOwner(
    std::string tag,
    std::vector<rule::DetectRule> rules) {
    co_await runtime_->rule_manager->UpdateRule(std::move(tag), std::move(rules));
}

// ============================================================================
// 数据收集协程（在 Runtime 线程执行，供 Spawn 从主线程调用）
// ============================================================================

net::awaitable<Runtime::UserTrafficSnapshot>
Runtime::GetTraffic(std::string tag) {
    co_return co_await Dispatch(GetTrafficOnOwner(std::move(tag)));
}

net::awaitable<Runtime::UserTrafficSnapshot>
Runtime::GetTrafficOnOwner(std::string tag) {
    co_return co_await runtime_->session_tracking->CollectAndResetTraffic(std::move(tag));
}

net::awaitable<std::vector<OnlineDevice>>
Runtime::GetOnlineDevices(std::string tag) {
    co_return co_await Dispatch(GetOnlineDevicesOnOwner(std::move(tag)));
}

net::awaitable<std::vector<OnlineDevice>>
Runtime::GetOnlineDevicesOnOwner(std::string tag) {
    auto handler = runtime_->inbound_manager->GetHandler(tag);
    if (!handler) {
        co_return std::vector<OnlineDevice>{};
    }
    co_return co_await runtime_->inbound_manager->GetOnlineDevices(std::move(tag));
}

net::awaitable<std::vector<rule::DetectResult>>
Runtime::GetDetectResults(std::string tag) {
    co_return co_await Dispatch(GetDetectResultsOnOwner(std::move(tag)));
}

net::awaitable<std::vector<rule::DetectResult>>
Runtime::GetDetectResultsOnOwner(std::string tag) {
    co_return co_await runtime_->rule_manager->GetDetectResult(std::move(tag));
}

// ============================================================================
// 运行时资源计数，仅通过 Runtime executor 上的收集任务读取。
// ============================================================================

Runtime::MemoryStats Runtime::GetMemoryStats() const {
    MemoryStats stats;
    stats.udp_sockets = runtime_->listener_state->udp_socket_tags.size();
    return stats;
}

net::awaitable<Runtime::RuntimeStatsSnapshot>
Runtime::CollectRuntimeStats(bool include_resources) const {
    co_return co_await Dispatch(CollectRuntimeStatsOnOwner(include_resources));
}

net::awaitable<Runtime::RuntimeStatsSnapshot>
Runtime::CollectRuntimeStatsOnOwner(bool include_resources) const {
    RuntimeStatsSnapshot snapshot;
    snapshot.memory = GetMemoryStats();
    snapshot.stats = runtime_->stats.Snapshot();
    snapshot.active_connections = runtime_->active_connections;
    snapshot.stats.connections_active = runtime_->active_connections;
    if (!include_resources) co_return snapshot;
    auto& resources = snapshot.resources.emplace();
    resources.udp_resource_drops = runtime_->listener_state->udp_resource_drops;
    resources.udp_receive_loops = runtime_->listener_state->udp_receive_loops;
    resources.udp_listeners = runtime_->listener_state->udp_socket_tags.size();
    auto collect_udp = [&](const inbound_detail::UdpIngress* ingress) {
        if (!ingress) return;
        const auto udp = ingress->GetResourceStats();
        resources.udp_associations += udp.associations;
        resources.udp_retiring_associations += udp.retiring_associations;
        resources.udp_input_datagrams += udp.input_datagrams;
        resources.udp_input_bytes += udp.input_bytes;
        resources.udp_reply_datagrams += udp.reply_datagrams;
        resources.udp_reply_bytes += udp.reply_bytes;
        resources.udp_reply_senders += udp.active_reply_senders;
        resources.udp_native_dispatches += udp.native_dispatches;
    };
    for (const auto& [tag, ingress] : runtime_->listener_state->udp_ingresses) {
        (void)tag;
        collect_udp(ingress.get());
    }
    for (const auto& [tag, slot] : runtime_->listener_state->listener_slots) {
        (void)tag;
        collect_udp(slot.retiring_udp.get());
    }
    const auto timeouts = co_await TimeoutScheduler::ForExecutor(
        runtime_->owner_executor).GetResourceStats();
    resources.timeout_events = timeouts.active_events;
    resources.timeout_heap_entries = timeouts.heap_entries;
    resources.timeout_heap_capacity = timeouts.heap_capacity;
    resources.timeout_event_buckets = timeouts.event_buckets;
    resources.timeout_ready_events = timeouts.ready_events;
    resources.timeout_waiters = timeouts.wait_pending ? 1 : 0;
    co_return snapshot;
}

// ============================================================================
// Native UDP listener ownership. Protocol parsing stays in Inbound; Runtime
// owns the socket generation and the ingress lifecycle on its owner strand.
// ============================================================================

net::awaitable<bool> Runtime::AddUdpListener(
    PortBinding binding,
    ConnectionLimiterPtr limiter,
    proxyman::inbound::BuildRequest req) {
    co_return co_await Dispatch(AddUdpListenerOnOwner(
        std::move(binding), std::move(limiter), std::move(req)));
}

net::awaitable<bool> Runtime::AddUdpListenerOnOwner(
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

net::awaitable<bool> Runtime::ListenerState::StartUdpListening(
    Runtime& runtime,
    const PortBinding& binding,
    std::unique_ptr<Inbound> handler) {
    for (const auto& [tag, slot] : listener_slots) {
        if (tag != binding.tag && slot.udp_binding &&
            slot.udp_binding->port == binding.port &&
            slot.udp_binding->listen.Overlaps(binding.listen)) {
            LOG_ERROR("UDP listener conflict tag={} owner={} port={}",
                      binding.tag, tag, binding.port);
            co_return false;
        }
    }

    const bool replacing = std::ranges::any_of(
        udp_socket_tags,
        [&](const auto& item) { return item.second == binding.tag; });
    auto existing_slot = listener_slots.find(binding.tag);
    auto existing_ingress = udp_ingresses.find(binding.tag);
    if (replacing && existing_slot != listener_slots.end() &&
        existing_slot->second.udp_binding &&
        existing_slot->second.udp_binding->UsesSameSocket(binding) &&
        existing_ingress != udp_ingresses.end() && existing_ingress->second) {
        auto cancellation = co_await net::this_coro::cancellation_state;
        if (cancellation.cancelled() != net::cancellation_type::none)
            throw IoSystemError(net::error::operation_aborted);
        const bool replaced = existing_ingress->second->ReplaceHandler(std::move(handler));
        if (cancellation.cancelled() != net::cancellation_type::none)
            throw IoSystemError(net::error::operation_aborted);
        co_return replaced;
    }

    if (!runtime.runtime_->udp_association_reclaimer) {
        throw std::logic_error("UDP listener runtime is not started");
    }
    PortBinding committed_binding = binding;
    auto replacement_ingress =
        std::make_unique<inbound_detail::UdpIngress>(
            binding.tag, std::move(handler), *runtime.runtime_->udp_association_reclaimer,
            runtime.runtime_->udp_association_quota,
            runtime.runtime_->owner_executor,
            runtime.runtime_->base_executor,
            runtime.runtime_->stats);
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
            replacement_ingress->MakeSocket(runtime.runtime_->owner_executor);

        auto fail_candidate = [&](std::string_view op, std::string_view msg) {
            LOG_ERROR("UDP {} {} failed: {}", op,
                      iputil::FormatEndpointForLog(listen_addr, binding.port), msg);
        };

        candidate_sock->open(ep.protocol(), ec);
        if (ec) {
            fail_candidate("open", ec.message());
            co_return false;
        }

        if (addr.is_v6()) {
            candidate_sock->set_option(net::ip::v6_only(true), ec);
            if (ec) {
                fail_candidate("set IPV6_V6ONLY", ec.message());
                co_return false;
            }
        }

        candidate_sock->set_option(net::socket_base::reuse_address(true), ec);
        if (ec) {
            fail_candidate("set SO_REUSEADDR", ec.message());
            co_return false;
        }

        // The OOM path must consume a datagram without allocating another
        // async operation. Asio's synchronous receive requires user-level
        // nonblocking mode, not merely native_non_blocking.
        candidate_sock->non_blocking(true, ec);
        if (ec) {
            fail_candidate("set nonblocking", ec.message());
            co_return false;
        }
        candidate_sock->bind(ep, ec);
        if (ec) {
            fail_candidate("bind", ec.message());
            co_return false;
        }

        const std::string socket_key = BuildListenerKey(binding.tag, listen_addr, binding.port);
        auto bound_sock =
            replacement_ingress->AttachSocket(socket_key, std::move(candidate_sock));
        if (!bound_sock) {
            LOG_ERROR("failed to attach UDP socket tag={} key={}",
                      binding.tag, socket_key);
            co_return false;
        }
        prepared_socket_keys.push_back(socket_key);
        prepared_socket_tags.emplace(socket_key, binding.tag);

        ++bound_count;
    }

    if (bound_count == 0) {
        LOG_ERROR("no UDP listener bound tag={} protocol={}",
                  binding.tag, binding.protocol);
        co_return false;
    }

    struct PreparedReceive {
        std::string socket_key;
        inbound_detail::UdpIngress::SocketPtr socket;
        net::awaitable<void> receive;
    };
    memory::DataVector<PreparedReceive> prepared_receives;
    auto retired_socket_keys =
        (replacing || (existing_ingress != udp_ingresses.end() && existing_ingress->second))
            ? CollectUdpSocketKeys(binding.tag) : ListenerKeys{};
    ListenerSlotMap::iterator slot_it;
    decltype(udp_ingresses)::iterator ingress_it;
    bool inserted_slot = false;
    bool inserted_ingress = false;
    try {
        auto slot_entry = listener_slots.try_emplace(binding.tag);
        slot_it = slot_entry.first;
        inserted_slot = slot_entry.second;
        auto ingress_entry = udp_ingresses.try_emplace(binding.tag);
        ingress_it = ingress_entry.first;
        inserted_ingress = ingress_entry.second;
        udp_socket_tags.reserve(udp_socket_tags.size() + prepared_socket_tags.size());
        prepared_receives.reserve(prepared_socket_keys.size());
        for (const auto& socket_key : prepared_socket_keys) {
            auto socket = replacement_ingress->FindSocket(socket_key);
            if (!socket) throw std::logic_error("prepared UDP socket is missing");
            // Prepare frame and owned captures before retiring the old listener.
            auto receive = UdpReceiveLoop(runtime, socket_key, socket, &slot_it->second);
            prepared_receives.push_back({socket_key, std::move(socket), std::move(receive)});
        }
        if (replacing) {
            LOG_WARN("replacing existing UDP listeners tag={}", binding.tag);
        }
    } catch (...) {
        if (inserted_ingress) udp_ingresses.erase(ingress_it);
        if (inserted_slot) listener_slots.erase(slot_it);
        throw;
    }

    const bool has_retiring_ingress = ingress_it->second != nullptr;
    const bool cancel_throwing = co_await net::this_coro::throw_if_cancelled();
    auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        if (inserted_ingress) udp_ingresses.erase(ingress_it);
        if (inserted_slot) listener_slots.erase(slot_it);
        throw IoSystemError(net::error::operation_aborted);
    }
    co_await net::this_coro::throw_if_cancelled(false);
    if (replacing || has_retiring_ingress) {
        co_await RetireUdpListening(binding.tag, std::move(retired_socket_keys));
    }
    std::exception_ptr commit_failure;
    try {
        ingress_it->second = std::move(replacement_ingress);
        udp_socket_tags.merge(prepared_socket_tags);
        auto& listener_slot = slot_it->second;
        listener_slot.udp_binding = std::move(committed_binding);

        for (size_t index = 0; index < prepared_receives.size(); ++index) {
            auto& prepared = prepared_receives[index];
            const auto& socket_key = prepared_socket_keys[index];
            SpawnUdpReceive(runtime, std::move(prepared.receive));

            LOG_DEBUG("runtime.udp_listener ready key={} tag={} protocol={}",
                      socket_key, binding.tag, binding.protocol);
        }
    } catch (...) {
        commit_failure = std::current_exception();
    }
    if (commit_failure) {
        for (const auto& socket_key : prepared_socket_keys) {
            udp_socket_tags.erase(socket_key);
        }
        if (ingress_it->second) {
            ingress_it->second->RequestStop();
            try {
                co_await ingress_it->second->AsyncJoin();
            } catch (...) {
                // Preserve the commit failure after completing best-effort
                // ownership cleanup. Runtime shutdown will observe any task
                // group failure from an already-started receive loop.
            }
            ingress_it->second.reset();
        }
        slot_it->second.udp_binding.reset();
        co_await net::this_coro::throw_if_cancelled(cancel_throwing);
        std::rethrow_exception(commit_failure);
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
// Runtime binds current-owner checks and the existing Ingress -> Dispatcher
// entry once. The private loop helper handles bytes only, not request policy.
// This is a normal factory, not a second listener-lifetime coroutine frame.
// ============================================================================

net::awaitable<void> Runtime::ListenerState::UdpReceiveLoop(
    Runtime& runtime,
    std::string socket_key,
    inbound_detail::UdpIngress::SocketPtr sock,
    ListenerSlot* listener_slot) {
    const auto runtime_snapshot = runtime.runtime_->Snapshot();
    auto is_owned = [this, socket_key](const inbound_detail::UdpIngress::SocketPtr& socket) noexcept {
        const auto* current = FindUdpIngressBySocketKey(socket_key);
        return current && current->OwnsSocket(socket_key, socket.get());
    };
    auto process_datagram = [this, &runtime, socket_key = std::move(socket_key),
                            socket = sock.get(), listener_slot,
                            runtime_snapshot](
        const udp::endpoint& client_ep, std::span<const uint8_t> received) {
        auto* ingress = FindUdpIngressBySocketKey(socket_key);
        if (!ingress || !ingress->OwnsSocket(socket_key, socket)) return;
        const auto* receiver = listener_slot && listener_slot->handler
            ? &listener_slot->handler->ReceiverSettings() : nullptr;
        uint64_t candidate_conn_id = 0;
        if (runtime.runtime_->next_connection_sequence <
            session::kMaxPhysicalSequence) {
            candidate_conn_id = session::PhysicalID(
                runtime.runtime_->next_connection_sequence + 1);
        }
        const bool created = ingress->ProcessDatagram(inbound_detail::UdpDatagramContext{
            .socket_key = socket_key,
            .socket = socket,
            .client_endpoint = client_ep,
            .payload = received,
            .receiver = receiver,
            .dispatcher = *runtime.runtime_->dispatcher,
            .timeouts = runtime_snapshot->timeouts,
            .candidate_conn_id = candidate_conn_id,
            .runtime_generation = runtime_snapshot->runtime_generation,
            .config_generation = runtime_snapshot->config_generation,
        });
        if (created) ++runtime.runtime_->next_connection_sequence;
    };
    return inbound_detail::RunUdpReceiveLoop(
        std::move(sock), std::move(is_owned), std::move(process_datagram), udp_resource_drops);
}

}  // namespace acpp
