#include "app/session_group_executor.hpp"
#include "infra/runtime_failure.hpp"
#include "infra/log.hpp"

#include <asio/associated_executor.hpp>
#include <asio/async_result.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <sys/eventfd.h>
#include <vector>
#include <unistd.h>
#include <cerrno>
#include <list>
#include <atomic>
#include <algorithm>
#include <stdexcept>
#include <system_error>

namespace {
thread_local ExecutionDomain* current_domain = nullptr;
thread_local bool validating_domain = false;
thread_local bool unwinding_native = false;
std::atomic<uint64_t> next_group_identity{1};

// Cold-published immutable routes live until coordinator retirement, after every
// domain and queued notification has drained. No published node is removed or
// mutated, so readers need neither a lock nor reclamation retries.
struct WorkerRoute {
    ExecutionDomain::HandoffTarget target;
    WorkerRoute* next = nullptr;
    explicit WorkerRoute(ExecutionDomain::HandoffTarget value)
        : target(std::move(value)) {}
};
struct LeaseIdentity {
    std::atomic<uint64_t> group;
    std::shared_ptr<void> keepalive;
    explicit LeaseIdentity(uint64_t value) : group(value) {}
};
}

struct GroupCoordinator::ReservedState {
    explicit ReservedState(net::io_context& io)
        : event(io), stopped(io, 1), domains_retired(io, 1) {
        const int descriptor = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (descriptor < 0) throw IoSystemError(IoErrorCode(errno, std::system_category()));
        IoErrorCode error;
        event.assign(descriptor, error);
        if (error) { ::close(descriptor); throw IoSystemError(error); }
    }
    net::posix::stream_descriptor event;
    SignalChannel stopped;
    SignalChannel domains_retired;
    std::atomic<size_t> live_domains{0};
    bool waiting_for_domains = false;
    std::atomic<ReservedOperation*> incoming{nullptr};
    std::atomic<bool> started{false};
    bool stopping = false;
    bool joined = false;
    std::atomic<WorkerRoute*> routes{nullptr};
    ~ReservedState() {
        auto* route = routes.load(std::memory_order_relaxed);
        while (route) {
            auto* next = route->next;
            delete route;
            route = next;
        }
    }
    static WorkerRoute* FindRoute(WorkerRoute* first,
                                 const ExecutionDomain::HandoffTarget& target) {
        if (!target.reactor || !target.executor)
            throw std::invalid_argument("handoff requires an actual receiving worker");
        for (auto* route = first; route; route = route->next) {
            if (route->target.worker_id != target.worker_id) continue;
            if (route->target.reactor != target.reactor ||
                route->target.executor != target.executor)
                throw std::invalid_argument("worker route changed within coordinator");
            return route;
        }
        return nullptr;
    }
    WorkerRoute* Route(const ExecutionDomain::HandoffTarget& target) const {
        auto* route = FindRoute(routes.load(std::memory_order_acquire), target);
        if (!route) throw std::logic_error("worker route was not registered before admission");
        return route;
    }
};

GroupCoordinator::GroupCoordinator(net::io_context& io, size_t capacity)
    : reactor_(io), mailbox_(io, capacity), merge_gate_(io, 1),
      reserved_(std::make_unique<ReservedState>(io)) {
    (void)merge_gate_.try_send(IoErrorCode{});
}
GroupCoordinator::~GroupCoordinator() {
    if (reserved_->started.load(std::memory_order_relaxed) && !reserved_->joined)
        FailRuntime("group-coordinator", "reserved controls were not joined");
    DrainReserved();
}

void GroupCoordinator::EnsureStarted() {
    if (reserved_->started.load(std::memory_order_relaxed) || reserved_->joined) return;
    ArmReserved();
    // Only the coordinator publishes successful arms. Release/acquire shares
    // readiness with Workers; an arm failure leaves the collector inactive.
    reserved_->started.store(true, std::memory_order_release);
}
void GroupCoordinator::Start() {
    if (reserved_->started.load(std::memory_order_acquire)) return;
    net::post(reactor_, [self = shared_from_this()] { self->EnsureStarted(); });
}

void GroupCoordinator::RegisterWorker(uint32_t worker_id, net::io_context& reactor,
                                      net::any_io_executor executor) {
    ExecutionDomain::HandoffTarget target{worker_id, &reactor, std::move(executor)};
    auto* previous = reserved_->routes.load(std::memory_order_acquire);
    std::unique_ptr<WorkerRoute> candidate;
    for (;;) {
        if (ReservedState::FindRoute(previous, target)) return;
        if (!candidate) candidate = std::make_unique<WorkerRoute>(target);
        candidate->next = previous;
        // Registration is cold and append-only. Acquire on failure observes a
        // concurrent registration before checking its immutable identity.
        if (reserved_->routes.compare_exchange_weak(previous, candidate.get(),
                std::memory_order_release, std::memory_order_acquire)) {
            (void)candidate.release();
            return;
        }
    }
}

void GroupCoordinator::PostReserved(std::unique_ptr<ReservedOperation> operation) noexcept {
    auto* node = operation.release();
    auto* previous = reserved_->incoming.load(std::memory_order_relaxed);
    do { node->next = previous; }
    while (!reserved_->incoming.compare_exchange_weak(previous, node,
        std::memory_order_release, std::memory_order_relaxed));
    const uint64_t one = 1;
    ssize_t written;
    do { written = ::write(reserved_->event.native_handle(), &one, sizeof(one)); }
    while (written < 0 && errno == EINTR);
    if (written < 0 && errno != EAGAIN)
        FailRuntime("group-coordinator", "cannot notify reserved return");
}
void GroupCoordinator::DrainReserved() noexcept {
    for (;;) {
        auto* batch = reserved_->incoming.exchange(nullptr, std::memory_order_acquire);
        if (!batch) return;
        ReservedOperation* fifo = nullptr;
        while (batch) {
            auto* next = batch->next;
            batch->next = fifo;
            fifo = batch;
            batch = next;
        }
        while (fifo) {
            std::unique_ptr<ReservedOperation> operation(fifo);
            fifo = fifo->next;
            operation->Invoke();
        }
    }
}
void GroupCoordinator::RetireDomain() noexcept {
    if (reserved_->live_domains.fetch_sub(1, std::memory_order_acq_rel) == 1 &&
        reserved_->waiting_for_domains)
        (void)reserved_->domains_retired.try_send(IoErrorCode{});
}
void GroupCoordinator::ArmReserved() {
    try {
        reserved_->event.async_wait(net::posix::stream_descriptor::wait_read,
            [this](IoErrorCode error) {
                uint64_t count;
                while (::read(reserved_->event.native_handle(), &count, sizeof(count)) > 0) {}
                DrainReserved();
                if (reserved_->stopping) {
                    (void)reserved_->stopped.try_send(IoErrorCode{});
                    return;
                }
                if (error) FailRuntime("group-coordinator", "reserved return readiness failed");
                ArmReserved();
            });
    } catch (...) {
        // The previous native completion has already been consumed. Neither
        // Start nor Finalize may assume a cancellation completion still exists.
        reserved_->started.store(false, std::memory_order_release);
        throw;
    }
}
net::awaitable<void> GroupCoordinator::AsyncJoin() {
    co_await mailbox_.AsyncJoinAccepted();
    DrainReserved();
}
net::awaitable<void> GroupCoordinator::Finalize() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (reserved_->joined) co_return;
    // Completion promises may become ready before their executor and the
    // enclosing Run callback release the last domain reference. Keep accepting
    // reserved retirements until those owners have actually gone away.
    if (reserved_->live_domains.load(std::memory_order_acquire) != 0)
        EnsureStarted();
    reserved_->waiting_for_domains = true;
    while (reserved_->live_domains.load(std::memory_order_acquire) != 0)
        co_await reserved_->domains_retired.async_receive(net::use_awaitable);
    reserved_->waiting_for_domains = false;
    reserved_->stopping = true;
    IoErrorCode error;
    if (reserved_->started.load(std::memory_order_relaxed)) {
        reserved_->event.cancel(error);
        co_await reserved_->stopped.async_receive(net::use_awaitable);
    }
    DrainReserved();
    // A retirement can be consumed between its producer's queue publication
    // and eventfd write. The producer retains this coordinator until that write
    // returns, so leave the descriptor open until the coordinator destructor.
    reserved_->joined = true;
}

struct ExecutionDomain::Group {
    struct Member {
        std::weak_ptr<ExecutionDomain> domain;
        std::shared_ptr<Group> group;
    };
    using Members = std::list<Member>;
    Members members;
    using Leases = std::list<std::weak_ptr<::LeaseIdentity>>;
    Leases leases;
    // Frozen snapshots pin every member until the complete group is thawed.
    // Native preparation borrows resources owned by these domains.
    std::vector<std::shared_ptr<ExecutionDomain>> frozen_members;
    const uint64_t identity = next_group_identity.fetch_add(1, std::memory_order_relaxed);
    unsigned rank = 0;
    bool permanently_shared = false;
};

struct ExecutionDomain::State {
    std::shared_ptr<Hooks> hooks;
    // group and membership are coordinator-only, except construction/destruction
    // while no callback can hold the domain. Hot-path identity is separate.
    std::shared_ptr<Group> group;
    std::shared_ptr<::LeaseIdentity> identity;
    std::atomic<WorkerRoute*> route;
    std::atomic<bool> frozen{false};
    std::weak_ptr<ExecutionDomain> attached_to;
    NativeResource* resources = nullptr;
    std::shared_ptr<GroupCoordinator> coordinator;
    std::unique_ptr<net::execution_context> services = std::make_unique<net::execution_context>();
    struct Retirement final : GroupCoordinator::ReservedOperation {
        std::shared_ptr<GroupCoordinator> coordinator;
        Group::Members::iterator position;
        void Invoke() noexcept override {
            auto group = position->group;
            group->members.erase(position);
            group->leases.remove_if([](const auto& identity) { return identity.expired(); });
            coordinator->RetireDomain();
        }
    };
    std::unique_ptr<Retirement> retirement;
    Group::Leases::iterator lease_position;
    std::atomic<Operation*> incoming{nullptr};
    Operation* ready = nullptr;
    std::atomic<bool> notified{false};
    State(WorkerRoute* r, std::shared_ptr<Hooks> h, std::shared_ptr<Group> g,
          std::shared_ptr<GroupCoordinator> c)
        : hooks(std::move(h)), group(std::move(g)),
          identity(std::make_shared<::LeaseIdentity>(group->identity)),
          route(r), coordinator(std::move(c)) {}
};

ExecutionDomain::ExecutionDomain(std::unique_ptr<State> state) : state_(std::move(state)) {}
ExecutionDomain::~ExecutionDomain() {
    if (state_->incoming.load(std::memory_order_acquire) || state_->ready)
        FailRuntime("session-domain", "destroying admitted domain completions");
    state_->hooks->Enter();
    state_->services.reset();
    state_->hooks->Leave();
    state_->hooks.reset();
    if (state_->resources)
        FailRuntime("session-domain", "destroying domain with registered native resources");
    if (state_->retirement) {
        state_->retirement->coordinator = std::move(state_->coordinator);
        auto* coordinator = state_->retirement->coordinator.get();
        coordinator->PostReserved(std::move(state_->retirement));
    }
}

std::shared_ptr<ExecutionDomain> ExecutionDomain::CreateSibling(
    std::shared_ptr<Hooks> hooks) const {
    const auto target = CurrentTarget();
    return Create(*target.reactor, target.worker_id, target.executor,
                  std::move(hooks), state_->coordinator);
}

std::shared_ptr<ExecutionDomain> ExecutionDomain::Create(
    net::io_context& reactor, uint32_t worker_id,
    net::any_io_executor worker_executor, std::shared_ptr<Hooks> hooks,
    std::shared_ptr<GroupCoordinator> coordinator) {
    if (!hooks || !coordinator)
        throw std::invalid_argument("execution domain requires host and coordinator");
    coordinator->Start();
    auto* route = coordinator->reserved_->Route({worker_id, &reactor, std::move(worker_executor)});
    auto group = std::make_shared<Group>();
    auto domain = std::shared_ptr<ExecutionDomain>(new ExecutionDomain(
        std::make_unique<State>(route, std::move(hooks), group, coordinator)),
        [](ExecutionDomain* retired) noexcept {
            // Before registration commits, the candidate still belongs to its
            // constructor; rollback cannot depend on a Worker ever starting.
            if (!retired->state_->retirement) {
                delete retired;
                return;
            }
            const auto* route = retired->state_->route.load(std::memory_order_acquire);
            if (route->target.reactor->get_executor().running_in_this_thread()) {
                delete retired;
                return;
            }
            // The last metadata reference can disappear on the coordinator.
            // Service teardown and allocator release still belong to the Worker.
            try {
                net::post(route->target.executor, [retired] { delete retired; });
            } catch (...) {
                FailRuntime("session-domain", "cannot deliver domain retirement");
            }
        });
    auto retirement = std::make_unique<State::Retirement>();
    group->leases.emplace_back(domain->state_->identity);
    domain->state_->lease_position = std::prev(group->leases.end());
    group->members.push_back({domain, group});
    retirement->position = std::prev(group->members.end());
    domain->state_->retirement = std::move(retirement);
    domain->state_->identity->keepalive = group;
    coordinator->reserved_->live_domains.fetch_add(1, std::memory_order_relaxed);
    return domain;
}

std::shared_ptr<const void> ExecutionDomain::LeaseIdentity() const noexcept {
    return state_->identity;
}
bool ExecutionDomain::SharesLeaseIdentity(const void* a, const void* b) noexcept {
    if (!a || !b) return false;
    return static_cast<const ::LeaseIdentity*>(a)->group.load(std::memory_order_acquire) ==
           static_cast<const ::LeaseIdentity*>(b)->group.load(std::memory_order_acquire);
}
net::any_io_executor ExecutionDomain::Executor() { return GroupExecutor(shared_from_this()); }
net::io_context& ExecutionDomain::Reactor() noexcept {
    return *state_->route.load(std::memory_order_acquire)->target.reactor;
}
ExecutionDomain::HandoffTarget ExecutionDomain::CurrentTarget() const {
    return state_->route.load(std::memory_order_acquire)->target;
}
net::execution_context& ExecutionDomain::Services() noexcept { return *state_->services; }
GroupCoordinator& ExecutionDomain::Coordinator() noexcept { return *state_->coordinator; }
uint32_t ExecutionDomain::OwnerId() const noexcept {
    return state_->route.load(std::memory_order_acquire)->target.worker_id;
}
bool ExecutionDomain::CanDestroyDirectlyOn(uint32_t worker_id) const noexcept {
    return OwnerId() == worker_id && !state_->frozen.load(std::memory_order_acquire);
}
bool ExecutionDomain::SharesGroup(const ExecutionDomain& other) const noexcept {
    return SharesLeaseIdentity(state_->identity.get(), other.state_->identity.get());
}
std::shared_ptr<ExecutionDomain> ExecutionDomain::Current() noexcept {
    return current_domain ? current_domain->shared_from_this() : nullptr;
}
bool ExecutionDomain::CanExecuteInline() const noexcept {
    return current_domain == this && !validating_domain;
}
ExecutionDomain::LocalLease::LocalLease(ExecutionDomain& domain) noexcept {
    if (current_domain || validating_domain) return;
    const auto* route = domain.state_->route.load(std::memory_order_acquire);
    if (!route->target.reactor->get_executor().running_in_this_thread() ||
        domain.state_->frozen.load(std::memory_order_seq_cst))
        return;
    // A handoff can publish a new route only after freezing on the old owner.
    // Recheck the route after frozen: an old-owner callback may observe thaw
    // following a completed handoff, but must not borrow the new owner's shard.
    if (domain.state_->route.load(std::memory_order_acquire) != route) return;
    domain_ = &domain;
    current_domain = domain_;
    domain_->state_->hooks->Enter();
}
ExecutionDomain::LocalLease::~LocalLease() {
    if (!domain_) return;
    domain_->state_->hooks->Leave();
    current_domain = nullptr;
}
ExecutionDomain::NativeResource::~NativeResource() {
    if (domain_) domain_->UnregisterResource(*this);
}
void ExecutionDomain::RegisterResource(NativeResource& resource) {
    if (state_->frozen.load(std::memory_order_acquire))
        throw std::logic_error("registering native resource during handoff");
    if (resource.domain_) throw std::logic_error("native resource already registered");
    resource.domain_ = this;
    resource.next_ = state_->resources;
    if (resource.next_) resource.next_->previous_ = &resource;
    state_->resources = &resource;
}
void ExecutionDomain::UnregisterResource(NativeResource& resource) noexcept {
    if (resource.domain_ != this) return;
    if (state_->frozen.load(std::memory_order_acquire) &&
        !(current_domain == this && unwinding_native))
        FailRuntime("session-domain", "destroying native resource during handoff");
    if (resource.previous_) resource.previous_->next_ = resource.next_;
    else state_->resources = resource.next_;
    if (resource.next_) resource.next_->previous_ = resource.previous_;
    resource.domain_ = nullptr;
    resource.previous_ = resource.next_ = nullptr;
}

void ExecutionDomain::Enqueue(std::unique_ptr<Operation> operation) {
    auto* node = operation.release();
    auto* previous = state_->incoming.load(std::memory_order_relaxed);
    do { node->next = previous; }
    while (!state_->incoming.compare_exchange_weak(previous, node,
        std::memory_order_seq_cst, std::memory_order_relaxed));
    Notify();
}
void ExecutionDomain::Notify(bool force) noexcept {
    const bool was_notified = state_->notified.exchange(true, std::memory_order_seq_cst);
    if (!force && was_notified) return;
    auto* route = state_->route.load(std::memory_order_acquire);
    try {
        auto notification = [self = shared_from_this(), route] { self->Run(route); };
        // Native reactors need no second function-erasure allocation. Preserve
        // custom executor semantics, deferred delivery and the captured route.
        if (const auto* native =
                route->target.executor.target<net::io_context::executor_type>()) {
            net::post(*native, std::move(notification));
        } else {
            net::post(route->target.executor, std::move(notification));
        }
    } catch (...) {
        FailRuntime("session-domain", "cannot deliver reserved readiness notification");
    }
}
void ExecutionDomain::Run(const void* scheduled_route) noexcept {
    if (state_->frozen.load(std::memory_order_seq_cst)) return;
    if (state_->route.load(std::memory_order_acquire) != scheduled_route) {
        Notify(true);
        return;
    }
    auto hooks = state_->hooks;
    auto* previous_domain = std::exchange(current_domain, this);
    hooks->Enter();
    for (unsigned turn = 0; turn != 64; ++turn) {
        if (!state_->ready) {
            auto* batch = state_->incoming.exchange(nullptr, std::memory_order_acquire);
            while (batch) {
                auto* next = batch->next;
                batch->next = state_->ready;
                state_->ready = batch;
                batch = next;
            }
        }
        if (!state_->ready) break;
        std::unique_ptr<Operation> operation(state_->ready);
        state_->ready = operation->next;
        operation->next = nullptr;
        try { operation->Invoke(); }
        catch (...) { hooks->OnFailure(std::current_exception()); }
        operation.reset();
    }
    hooks->Leave();
    current_domain = previous_domain;
    state_->notified.store(false, std::memory_order_seq_cst);
    if (state_->ready || state_->incoming.load(std::memory_order_seq_cst)) Notify();
}

net::awaitable<void> ExecutionDomain::Freeze(std::shared_ptr<ExecutionDomain> domain) {
    auto token = net::use_awaitable;
    co_await net::async_initiate<decltype(token), void()>(
        [domain](auto handler) {
            using Handler = decltype(handler);
            struct Acknowledge final : GroupCoordinator::ReservedOperation {
                Handler handler;
                explicit Acknowledge(Handler value) : handler(std::move(value)) {}
                void Invoke() noexcept override { std::move(handler)(); }
            };
            auto acknowledgement = std::make_unique<Acknowledge>(std::move(handler));
            auto* route = domain->state_->route.load(std::memory_order_acquire);
            // Capture strong members before leaving coordinator metadata.
            std::vector<std::shared_ptr<ExecutionDomain>> members;
            for (const auto& entry : domain->state_->group->members)
                if (auto member = entry.domain.lock()) members.push_back(std::move(member));
            auto group = domain->state_->group;
            group->frozen_members = std::move(members);
            try {
                net::post(route->target.executor,
                    [domain, group, acknowledgement = std::move(acknowledgement)]() mutable {
                        for (const auto& member : group->frozen_members)
                            member->state_->frozen.store(true, std::memory_order_seq_cst);
                        domain->Coordinator().PostReserved(std::move(acknowledgement));
                    });
            } catch (...) {
                std::vector<std::shared_ptr<ExecutionDomain>>{}.swap(group->frozen_members);
                throw;
            }
        }, token);
}
void ExecutionDomain::Thaw(const std::shared_ptr<Group>& first,
                           const std::shared_ptr<Group>& second) noexcept {
    // No resumed callback may borrow a still-frozen peer in the merged group.
    for (const auto& member : first->frozen_members)
        member->state_->frozen.store(false, std::memory_order_seq_cst);
    if (second) {
        for (const auto& member : second->frozen_members)
            member->state_->frozen.store(false, std::memory_order_seq_cst);
    }
    for (const auto& member : first->frozen_members) member->Notify(true);
    if (second) {
        for (const auto& member : second->frozen_members) member->Notify(true);
    }
    std::vector<std::shared_ptr<ExecutionDomain>>{}.swap(first->frozen_members);
    if (second)
        std::vector<std::shared_ptr<ExecutionDomain>>{}.swap(second->frozen_members);
}

net::awaitable<bool> ExecutionDomain::MergeGroups(
    std::shared_ptr<ExecutionDomain> first, std::shared_ptr<ExecutionDomain> second,
    bool exclusive) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    auto& coordinator = first->Coordinator();
    co_await coordinator.merge_gate_.async_receive(net::use_awaitable);
    struct Gate {
        SignalChannel& channel;
        ~Gate() { (void)channel.try_send(IoErrorCode{}); }
    } gate{coordinator.merge_gate_};
    auto a = first->state_->group;
    auto b = second->state_->group;
    const auto has_attached_member = [](const std::shared_ptr<Group>& group) {
        for (const auto& entry : group->members) {
            if (auto member = entry.domain.lock();
                member && !member->state_->attached_to.expired())
                return true;
        }
        return false;
    };
    if (exclusive) {
        if (a == b || !first->state_->attached_to.expired() ||
            !second->state_->attached_to.expired() || has_attached_member(b) ||
            b->members.size() != 1 || b->permanently_shared)
            throw std::logic_error("physical domain is not exclusively detachable");
        // Pool reuse is not a passive handoff trigger. This gate also excludes
        // a concurrent inbound handoff between the ownership check and attach.
        if (first->state_->route.load(std::memory_order_acquire) !=
            second->state_->route.load(std::memory_order_acquire))
            co_return false;
    } else {
        if (!first->state_->attached_to.expired() || !second->state_->attached_to.expired() ||
            has_attached_member(a) || has_attached_member(b))
            throw std::logic_error("permanent join cannot consume an exclusive physical lease");
        if (a == b) co_return true;
    }
    // Preserve XHTTP's established union-by-rank owner, without retaining any
    // retired parent nodes. Only cold membership metadata is rewritten.
    auto destination = exclusive || a->rank >= b->rank ? a : b;
    auto source = destination == a ? b : a;
    auto* route = (destination == a ? first : second)->state_->route.load(std::memory_order_acquire);
    std::exception_ptr failure;
    try {
        co_await Freeze(first);
        co_await Freeze(second);
        auto moved = destination == a ? second : first;
        if (moved->state_->route.load(std::memory_order_acquire) != route)
            co_await RebindFrozen(std::move(moved), route->target);
    } catch (...) { failure = std::current_exception(); }
    if (failure) {
        Thaw(a, b);
        std::rethrow_exception(failure);
    }
    for (auto& entry : source->members) {
        entry.group = destination;
        if (auto member = entry.domain.lock()) {
            member->state_->group = destination;
            member->state_->route.store(route, std::memory_order_release);
        }
    }
    destination->members.splice(destination->members.end(), source->members);
    source->leases.remove_if([](const auto& identity) { return identity.expired(); });
    destination->leases.remove_if([](const auto& identity) { return identity.expired(); });
    for (const auto& weak : source->leases) {
        if (auto identity = weak.lock()) {
            identity->keepalive = destination;
            identity->group.store(destination->identity, std::memory_order_release);
        }
    }
    destination->leases.splice(destination->leases.end(), source->leases);
    if (destination->rank == source->rank) ++destination->rank;
    if (exclusive) second->state_->attached_to = first;
    else destination->permanently_shared = true;
    Thaw(a, b);
    co_return true;
}

net::awaitable<void> ExecutionDomain::SplitGroup(
    std::shared_ptr<ExecutionDomain> first, std::shared_ptr<ExecutionDomain> second) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    auto& coordinator = first->Coordinator();
    co_await coordinator.merge_gate_.async_receive(net::use_awaitable);
    struct Gate {
        SignalChannel& channel;
        ~Gate() { (void)channel.try_send(IoErrorCode{}); }
    } gate{coordinator.merge_gate_};
    if (second->state_->attached_to.lock() != first ||
        first->state_->group != second->state_->group)
        throw std::logic_error("physical domain is not attached to this lease");
    auto independent = std::make_shared<Group>();
    auto original = first->state_->group;
    co_await Freeze(first);
    independent->members.splice(independent->members.end(), original->members,
                                second->state_->retirement->position);
    second->state_->retirement->position->group = independent;
    independent->leases.splice(independent->leases.end(), original->leases,
                               second->state_->lease_position);
    second->state_->identity->keepalive = independent;
    second->state_->group = independent;
    second->state_->identity->group.store(independent->identity, std::memory_order_release);
    second->state_->attached_to.reset();
    Thaw(original);
}

// A control coroutine can suspend on native readiness while the business
// executor is frozen. Scope is installed for each individual resume, never
// across an await. Inline business dispatch is disabled just as in validation.
struct ExecutionDomain::NativeExecutor {
    std::shared_ptr<ExecutionDomain> domain;
    net::any_io_executor native;
    net::execution_context& query(net::execution::context_t) const noexcept {
        return native.query(net::execution::context);
    }
    static constexpr auto query(net::execution::blocking_t) noexcept {
        return net::execution::blocking.never;
    }
    auto query(net::execution::outstanding_work_t) const noexcept {
        return net::query(native, net::execution::outstanding_work);
    }
    static constexpr auto query(net::execution::relationship_t) noexcept {
        return net::execution::relationship.fork;
    }
    NativeExecutor require(net::execution::blocking_t::never_t) const { return *this; }
    NativeExecutor prefer(net::execution::outstanding_work_t::tracked_t) const {
        return {domain, net::prefer(native, net::execution::outstanding_work.tracked)};
    }
    NativeExecutor prefer(net::execution::outstanding_work_t::untracked_t) const {
        return {domain, net::prefer(native, net::execution::outstanding_work.untracked)};
    }
    NativeExecutor prefer(net::execution::relationship_t::fork_t) const { return *this; }
    NativeExecutor prefer(net::execution::relationship_t::continuation_t) const { return *this; }
    template<class Function> void execute(Function&& function) const {
        net::post(native, [owner = domain, function = std::forward<Function>(function)]() mutable {
            auto* previous = std::exchange(current_domain, owner.get());
            const bool was_validating = std::exchange(validating_domain, true);
            owner->state_->hooks->Enter();
            struct Scope {
                ExecutionDomain& domain;
                ExecutionDomain* previous;
                bool validating;
                ~Scope() {
                    domain.state_->hooks->Leave();
                    current_domain = previous;
                    validating_domain = validating;
                }
            } scope{*owner, previous, was_validating};
            std::move(function)();
        });
    }
    friend bool operator==(const NativeExecutor& a, const NativeExecutor& b) noexcept {
        return a.domain == b.domain && a.native == b.native;
    }
};

struct ExecutionDomain::Handoff::Transaction {
    std::shared_ptr<ExecutionDomain> origin;
    std::shared_ptr<GroupCoordinator> coordinator;
    std::shared_ptr<Group> group;
    struct Prepared { ExecutionDomain* domain; NativeResource* resource; };
    std::vector<Prepared> prepared;
    WorkerRoute* old_route;
    WorkerRoute* target;
    bool complete = false;
    bool busy = false;
    explicit Transaction(std::shared_ptr<ExecutionDomain> domain, WorkerRoute* destination)
        : origin(std::move(domain)), coordinator(origin->state_->coordinator),
          group(origin->state_->group),
          old_route(origin->state_->route.load(std::memory_order_acquire)), target(destination) {}
    net::awaitable<void> PrepareResources() {
        size_t count = 0;
        for (const auto& member : group->frozen_members)
            for (auto* resource = member->state_->resources; resource; resource = resource->next_)
                ++count;
        prepared.reserve(count);
        std::exception_ptr failure;
        try {
            for (const auto& member : group->frozen_members) {
                for (auto* resource = member->state_->resources; resource; resource = resource->next_) {
                    prepared.push_back({member.get(), resource});
                    co_await net::co_spawn(
                        net::any_io_executor(NativeExecutor{member, old_route->target.executor}),
                        resource->PrepareHandoff(target->target), net::use_awaitable);
                }
            }
        } catch (...) { failure = std::current_exception(); }
        // co_spawn can deliver completion before NativeExecutor's scope exits.
        // Cross the source queue before exposing the domain to another Worker.
        co_await net::post(old_route->target.executor, net::use_awaitable);
        if (failure) std::rethrow_exception(failure);
    }
    net::awaitable<void> ReportFailure(ExecutionDomain* domain, std::exception_ptr failure) {
        const bool previous = std::exchange(unwinding_native, true);
        domain->state_->hooks->OnFailure(std::move(failure));
        unwinding_native = previous;
        co_return;
    }
    net::awaitable<void> CancelResources() {
        std::exception_ptr failure;
        for (auto it = prepared.rbegin(); it != prepared.rend(); ++it) {
            try {
                co_await net::co_spawn(net::any_io_executor(NativeExecutor{
                    it->domain->shared_from_this(), old_route->target.executor}),
                    it->resource->CancelHandoff(old_route->target), net::use_awaitable);
            }
            catch (...) { if (!failure) failure = std::current_exception(); }
        }
        if (failure) {
            // Every failed rollback has already made its resource terminal.
            // Cancel the complete association before releasing queued business
            // completions; do not expose a partially healthy session.
            for (const auto& member : group->frozen_members)
                co_await net::co_spawn(net::any_io_executor(NativeExecutor{
                    member, old_route->target.executor}),
                    ReportFailure(member.get(), failure), net::use_awaitable);
        }
        // Rollback completion must also outlive the final native execution lease.
        co_await net::post(old_route->target.executor, net::use_awaitable);
        if (failure) {
            std::rethrow_exception(failure);
        }
    }
    net::awaitable<void> CommitResources() {
        // One preallocated target dispatch: no allocation/suspension between
        // the first native commit and the last. Participant commits are noexcept.
        for (const auto& entry : prepared) {
            auto* previous = std::exchange(current_domain, entry.domain);
            const bool was_validating = std::exchange(validating_domain, true);
            entry.domain->state_->hooks->Enter();
            entry.resource->CommitHandoff(target->target);
            entry.domain->state_->hooks->Leave();
            validating_domain = was_validating;
            current_domain = previous;
        }
        co_return;
    }
    void Finish() noexcept {
        auto& coord = *coordinator;
        complete = true;
        prepared.clear();
        Thaw(group);
        origin.reset();
        (void)coord.merge_gate_.try_send(IoErrorCode{});
    }
    net::awaitable<void> Resolve(bool commit) {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        if (complete) co_return;
        if (busy) throw std::logic_error("handoff operation already in progress");
        busy = true;
        const size_t domain_count = group->frozen_members.size();
        std::exception_ptr failure;
        try {
            if (commit) {
                co_await net::co_spawn(target->target.executor, CommitResources(), net::use_awaitable);
                for (const auto& member : group->frozen_members)
                    member->state_->route.store(target, std::memory_order_release);
            } else {
                co_await net::co_spawn(old_route->target.executor, CancelResources(), net::use_awaitable);
            }
        } catch (...) { failure = std::current_exception(); }
        if (failure && commit) {
            // Failure to initiate the target dispatch precedes all commits.
            // Keep the initiating error; rollback failures are separately
            // delivered to the session hooks by CancelResources.
            try {
                co_await net::co_spawn(
                    old_route->target.executor, CancelResources(), net::use_awaitable);
            } catch (...) {}
        }
        Finish();
        busy = false;
        if (failure) std::rethrow_exception(failure);
        if (commit) {
            try {
                LOG_DEBUG("passive session handoff old_owner={} receiving_owner={} domains={}",
                    old_route->target.worker_id, target->target.worker_id, domain_count);
            } catch (...) {}
        }
    }
    net::awaitable<void> ValidateOnTarget(std::function<void()> validation) {
        auto* previous = std::exchange(current_domain, origin.get());
        const bool was_validating = std::exchange(validating_domain, true);
        origin->state_->hooks->Enter();
        std::exception_ptr failure;
        try { validation(); } catch (...) { failure = std::current_exception(); }
        origin->state_->hooks->Leave();
        validating_domain = was_validating;
        current_domain = previous;
        if (failure) std::rethrow_exception(failure);
        co_return;
    }
    net::awaitable<void> Validate(std::function<void()> validation) {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        if (complete || busy) throw std::logic_error("handoff is not available for validation");
        busy = true;
        std::exception_ptr failure;
        try {
            co_await net::co_spawn(target->target.executor,
                ValidateOnTarget(std::move(validation)), net::use_awaitable);
        } catch (...) { failure = std::current_exception(); }
        busy = false;
        if (failure) std::rethrow_exception(failure);
    }
};

net::awaitable<void> ExecutionDomain::RebindFrozen(
    std::shared_ptr<ExecutionDomain> domain, HandoffTarget target) {
    auto* route = domain->Coordinator().reserved_->Route(std::move(target));
    auto transaction = std::make_shared<Handoff::Transaction>(std::move(domain), route);
    std::exception_ptr failure;
    try {
        co_await net::co_spawn(transaction->old_route->target.executor,
            transaction->PrepareResources(), net::use_awaitable);
    } catch (...) { failure = std::current_exception(); }
    if (!failure) {
        try {
            co_await net::co_spawn(route->target.executor,
                transaction->CommitResources(), net::use_awaitable);
        } catch (...) { failure = std::current_exception(); }
    }
    if (failure) {
        try {
            co_await net::co_spawn(transaction->old_route->target.executor,
                transaction->CancelResources(), net::use_awaitable);
        } catch (...) {} // OnFailure already contains and reports rollback failure.
        std::rethrow_exception(failure);
    }
}

ExecutionDomain::Handoff::Handoff(std::shared_ptr<Transaction> transaction)
    : transaction_(std::move(transaction)) {}
ExecutionDomain::Handoff::~Handoff() {
    if (!transaction_->complete)
        FailRuntime("session-domain", "prepared handoff was not committed or cancelled");
}
net::awaitable<void> ExecutionDomain::Handoff::Validate(std::function<void()> validation) {
    auto transaction = transaction_;
    const bool throw_if_cancelled = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::exception_ptr failure;
    try {
        co_await net::co_spawn(transaction->coordinator->Reactor(),
            transaction->Validate(std::move(validation)),
            net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
    if (failure) std::rethrow_exception(failure);
}
net::awaitable<void> ExecutionDomain::Handoff::Commit() {
    auto transaction = transaction_;
    const bool throw_if_cancelled = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::exception_ptr failure;
    try {
        co_await net::co_spawn(transaction->coordinator->Reactor(),
            transaction->Resolve(true),
            net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
    if (failure) std::rethrow_exception(failure);
}
net::awaitable<void> ExecutionDomain::Handoff::Cancel() {
    auto transaction = transaction_;
    const bool throw_if_cancelled = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::exception_ptr failure;
    try {
        co_await net::co_spawn(transaction->coordinator->Reactor(),
            transaction->Resolve(false),
            net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<std::shared_ptr<ExecutionDomain::Handoff>> ExecutionDomain::Prepare(
    std::shared_ptr<ExecutionDomain> domain, HandoffTarget target) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    auto& coordinator = domain->Coordinator();
    auto* route = coordinator.reserved_->Route(std::move(target));
    co_await coordinator.merge_gate_.async_receive(net::use_awaitable);
    std::shared_ptr<Handoff::Transaction> transaction;
    std::shared_ptr<Handoff> handoff;
    std::exception_ptr failure;
    bool frozen = false;
    try {
        if (!domain->state_->attached_to.expired())
            throw std::logic_error("passive handoff must target the owning session, not its lease");
        co_await Freeze(domain);
        frozen = true;
        transaction = std::make_shared<Handoff::Transaction>(domain, route);
        handoff = std::shared_ptr<Handoff>(new Handoff(transaction));
        co_await net::co_spawn(transaction->old_route->target.executor,
            transaction->PrepareResources(), net::use_awaitable);
    } catch (...) { failure = std::current_exception(); }
    if (failure) {
        if (transaction) {
            try { co_await transaction->Resolve(false); }
            catch (...) {
                if (!transaction->complete) transaction->Finish();
            } // Preserve preparation error; rollback is reported to session hooks.
        } else {
            if (frozen) Thaw(domain->state_->group);
            (void)coordinator.merge_gate_.try_send(IoErrorCode{});
        }
        std::rethrow_exception(failure);
    }
    co_return handoff;
}
net::awaitable<std::shared_ptr<ExecutionDomain::Handoff>>
ExecutionDomain::PreparePassiveHandoff(HandoffTarget target) {
    if (auto current = Current(); current && current->SharesGroup(*this))
        throw std::logic_error("passive handoff must originate outside its frozen group");
    const bool throw_if_cancelled = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::shared_ptr<Handoff> handoff;
    std::exception_ptr failure;
    try {
        handoff = co_await net::co_spawn(co_await net::this_coro::executor,
            state_->coordinator->Post(Prepare(shared_from_this(), std::move(target))),
            net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
    if (failure) std::rethrow_exception(failure);
    co_return handoff;
}
net::awaitable<void> ExecutionDomain::Join(std::shared_ptr<ExecutionDomain> other) {
    if (!other || Current().get() != this || state_->coordinator != other->state_->coordinator)
        throw std::logic_error("group join requires compatible execution domains");
    if (other.get() == this) co_return;
    const bool throw_if_cancelled = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::exception_ptr failure;
    try {
        co_await net::co_spawn(co_await net::this_coro::executor,
            state_->coordinator->Post(MergeGroups(shared_from_this(), std::move(other))),
            net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
    if (failure) std::rethrow_exception(failure);
}
net::awaitable<bool> ExecutionDomain::AttachExclusive(std::shared_ptr<ExecutionDomain> other) {
    if (!other || Current().get() != this || state_->coordinator != other->state_->coordinator)
        throw std::logic_error("exclusive attachment requires compatible domains");
    const bool throw_if_cancelled = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    bool attached = false;
    std::exception_ptr failure;
    try {
        attached = co_await net::co_spawn(co_await net::this_coro::executor,
            state_->coordinator->Post(MergeGroups(shared_from_this(), std::move(other), true)),
            net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
    if (failure) std::rethrow_exception(failure);
    co_return attached;
}
net::awaitable<void> ExecutionDomain::DetachExclusive(std::shared_ptr<ExecutionDomain> other) {
    if (!other || Current().get() != this || state_->coordinator != other->state_->coordinator)
        throw std::logic_error("exclusive detachment requires compatible domains");
    const bool throw_if_cancelled = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::exception_ptr failure;
    try {
        co_await net::co_spawn(co_await net::this_coro::executor,
            state_->coordinator->Post(SplitGroup(shared_from_this(), std::move(other))),
            net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
    if (failure) std::rethrow_exception(failure);
}

