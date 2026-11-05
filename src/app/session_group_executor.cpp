#include "acppnode/app/session_group_executor.hpp"
#include "acppnode/infra/runtime_failure.hpp"
#include "acppnode/infra/log.hpp"

#include <asio/associated_executor.hpp>
#include <asio/async_result.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <sys/eventfd.h>
#include <unistd.h>
#include <cerrno>
#include <list>
#include <atomic>
#include <algorithm>
#include <stdexcept>
#include <system_error>

namespace acpp {
namespace {
thread_local ExecutionDomain* current_domain = nullptr;
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
    std::atomic<bool> start_posted{false};
    bool started = false;
    bool stopping = false;
    bool joined = false;
};

GroupCoordinator::GroupCoordinator(net::io_context& io, size_t capacity)
    : reactor_(io), mailbox_(io, capacity), merge_gate_(io, 1),
      reserved_(std::make_unique<ReservedState>(io)) {
    (void)merge_gate_.try_send(IoErrorCode{});
}
GroupCoordinator::~GroupCoordinator() {
    if (reserved_->started && !reserved_->joined)
        FailRuntime("group-coordinator", "reserved controls were not joined");
    DrainReserved();
}

void GroupCoordinator::EnsureStarted() {
    if (reserved_->started || reserved_->joined) return;
    ArmReserved();
    reserved_->started = true;
}
void GroupCoordinator::Start() {
    if (reserved_->start_posted.exchange(true, std::memory_order_acq_rel)) return;
    net::post(reactor_, [self = shared_from_this()] { self->EnsureStarted(); });
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
    reserved_->waiting_for_domains = true;
    while (reserved_->live_domains.load(std::memory_order_acquire) != 0)
        co_await reserved_->domains_retired.async_receive(net::use_awaitable);
    reserved_->waiting_for_domains = false;
    reserved_->stopping = true;
    IoErrorCode error;
    if (reserved_->started) {
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
    // The ancestry is immutable once published; parent_keepalive retains every
    // pointer a concurrently arriving native notification can have observed.
    std::atomic<Group*> parent{nullptr};
    std::shared_ptr<Group> parent_keepalive;
    const net::any_io_executor scheduler;
    const uint32_t owner;
    std::atomic<bool> frozen{false};
    // Membership is cold coordinator metadata. Allocation arenas independently
    // retain their outstanding blocks, never an entire retired request host.
    using Members = std::list<std::weak_ptr<ExecutionDomain>>;
    Members members;
    unsigned rank = 0;
    Group(uint32_t id, net::any_io_executor executor)
        : scheduler(std::move(executor)), owner(id) {}
};

struct ExecutionDomain::State {
    net::io_context& reactor;
    std::shared_ptr<Hooks> hooks;
    std::shared_ptr<Group> group;
    std::shared_ptr<GroupCoordinator> coordinator;
    std::unique_ptr<net::execution_context> services = std::make_unique<net::execution_context>();
    struct Retirement final : GroupCoordinator::ReservedOperation {
        std::shared_ptr<Group> group;
        GroupCoordinator* coordinator = nullptr;
        Group::Members::iterator position;
        void Invoke() noexcept override {
            auto* root = group.get();
            while (auto* parent = root->parent.load(std::memory_order_acquire)) root = parent;
            root->members.erase(position);
            coordinator->RetireDomain();
        }
    };
    std::unique_ptr<Retirement> retirement;
    // MPSC publication uses a reversed intrusive list. Only its current owner
    // reverses/drains nodes; native threads never read protocol state or pools.
    std::atomic<Operation*> incoming{nullptr};
    Operation* ready = nullptr;
    std::atomic<bool> notified{false};
    State(net::io_context& io, std::shared_ptr<Hooks> h, std::shared_ptr<Group> g,
          std::shared_ptr<GroupCoordinator> c)
        : reactor(io), hooks(std::move(h)), group(std::move(g)), coordinator(std::move(c)) {}
};

ExecutionDomain::ExecutionDomain(std::unique_ptr<State> state) : state_(std::move(state)) {}
ExecutionDomain::~ExecutionDomain() {
    if (state_->incoming.load(std::memory_order_acquire) || state_->ready)
        FailRuntime("session-domain", "destroying admitted domain completions");
    state_->hooks->Enter();
    state_->services.reset();
    state_->hooks->Leave();
    state_->hooks.reset();
    if (state_->retirement) {
        state_->retirement->group = state_->group;
        state_->coordinator->PostReserved(std::move(state_->retirement));
    }
}

std::shared_ptr<ExecutionDomain> ExecutionDomain::Create(
    net::io_context& reactor, uint32_t worker_id,
    net::any_io_executor worker_executor, std::shared_ptr<Hooks> hooks,
    std::shared_ptr<GroupCoordinator> coordinator) {
    if (!hooks || !coordinator)
        throw std::invalid_argument("execution domain requires host and coordinator");
    coordinator->Start();
    auto group = std::make_shared<Group>(worker_id, std::move(worker_executor));
    auto domain = std::shared_ptr<ExecutionDomain>(new ExecutionDomain(
        std::make_unique<State>(reactor, hooks, group, std::move(coordinator))));
    group->members.emplace_back(domain);
    domain->state_->retirement = std::make_unique<State::Retirement>();
    domain->state_->retirement->position = std::prev(group->members.end());
    domain->state_->retirement->coordinator = domain->state_->coordinator.get();
    domain->state_->coordinator->reserved_->live_domains.fetch_add(1, std::memory_order_relaxed);
    return domain;
}

std::shared_ptr<ExecutionDomain> ExecutionDomain::CreateSibling(std::shared_ptr<Hooks> hooks) {
    if (Current().get() != this) throw std::logic_error("sibling creation requires domain lease");
    auto* root = Root();
    return Create(state_->reactor, root->owner, root->scheduler,
                  std::move(hooks), state_->coordinator);
}

ExecutionDomain::Group* ExecutionDomain::Root() const noexcept {
    auto* group = state_->group.get();
    while (auto* parent = group->parent.load(std::memory_order_acquire)) group = parent;
    return group;
}
std::shared_ptr<const void> ExecutionDomain::LeaseIdentity() const noexcept {
    return state_->group;
}
bool ExecutionDomain::SharesLeaseIdentity(const void* a, const void* b) noexcept {
    auto root = [](const void* value) {
        auto* group = static_cast<const Group*>(value);
        while (auto* parent = group->parent.load(std::memory_order_acquire)) group = parent;
        return group;
    };
    return root(a) == root(b);
}
net::any_io_executor ExecutionDomain::Executor() { return GroupExecutor(shared_from_this()); }
net::io_context& ExecutionDomain::Reactor() noexcept { return state_->reactor; }
net::execution_context& ExecutionDomain::Services() noexcept { return *state_->services; }
GroupCoordinator& ExecutionDomain::Coordinator() noexcept { return *state_->coordinator; }
uint32_t ExecutionDomain::OwnerId() const noexcept { return Root()->owner; }
bool ExecutionDomain::SharesGroup(const ExecutionDomain& other) const noexcept {
    return Root() == other.Root();
}
std::shared_ptr<ExecutionDomain> ExecutionDomain::Current() noexcept {
    return current_domain ? current_domain->shared_from_this() : nullptr;
}

void ExecutionDomain::Enqueue(std::unique_ptr<Operation> operation) {
    auto* node = operation.release();
    auto* previous = state_->incoming.load(std::memory_order_relaxed);
    do { node->next = previous; }
    while (!state_->incoming.compare_exchange_weak(previous, node,
        std::memory_order_release, std::memory_order_relaxed));
    Notify();
}
void ExecutionDomain::Notify(bool force) noexcept {
    if (!force && state_->notified.exchange(true, std::memory_order_acq_rel)) return;
    auto* root = Root();
    try {
        net::post(root->scheduler, [self = shared_from_this(), owner = root->owner] {
            self->Run(owner);
        });
    } catch (...) {
        // An admitted native completion cannot be dropped even under OOM.
        FailRuntime("session-domain", "cannot deliver reserved readiness notification");
    }
}
void ExecutionDomain::Run(uint32_t scheduled_owner) noexcept {
    auto* root = Root();
    if (root->owner != scheduled_owner) { Notify(true); return; }
    // Freeze keeps the outstanding wake token. Commit force-notifies every
    // member, including arrivals racing this branch, so no wake can be lost.
    if (root->frozen.load(std::memory_order_acquire)) return;
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
    state_->notified.store(false, std::memory_order_release);
    if (state_->ready || state_->incoming.load(std::memory_order_acquire)) Notify();
}

net::awaitable<void> ExecutionDomain::MergeGroups(
    std::shared_ptr<ExecutionDomain> first, std::shared_ptr<ExecutionDomain> second) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    auto& coordinator = first->Coordinator();
    co_await coordinator.merge_gate_.async_receive(net::use_awaitable);
    struct Gate {
        SignalChannel& channel;
        ~Gate() { (void)channel.try_send(IoErrorCode{}); }
    } gate{coordinator.merge_gate_};
    auto* a = first->Root();
    auto* b = second->Root();
    if (a == b) co_return;
    // Union by rank keeps ancestry logarithmic; retired memberships are unlinked
    // by their preallocated coordinator return node, not a lookup-time scan.
    auto* destination = a->rank >= b->rank ? a : b;
    auto* source = destination == a ? b : a;
    auto freeze = [&coordinator](Group& group) -> net::awaitable<void> {
        auto token = net::use_awaitable;
        co_await net::async_initiate<decltype(token), void()>(
            [&group, &coordinator](auto handler) {
                using Handler = decltype(handler);
                struct Acknowledge final : GroupCoordinator::ReservedOperation {
                    Handler handler;
                    explicit Acknowledge(Handler value) : handler(std::move(value)) {}
                    void Invoke() noexcept override { std::move(handler)(); }
                };
                auto acknowledgement = std::make_unique<Acknowledge>(std::move(handler));
                net::post(group.scheduler,
                    [&group, &coordinator, acknowledgement = std::move(acknowledgement)]() mutable {
                        // All earlier user callbacks have retired on this
                        // owner. The reserved return cannot fail admission.
                        group.frozen.store(true, std::memory_order_release);
                        coordinator.PostReserved(std::move(acknowledgement));
                    });
            }, token);
    };
    std::exception_ptr failure;
    try {
        co_await freeze(*a);
        co_await freeze(*b);
    } catch (...) { failure = std::current_exception(); }
    if (failure) {
        a->frozen.store(false, std::memory_order_release);
        b->frozen.store(false, std::memory_order_release);
        for (const auto& member : a->members)
            if (auto domain = member.lock()) domain->Notify(true);
        for (const auto& member : b->members)
            if (auto domain = member.lock()) domain->Notify(true);
        std::rethrow_exception(failure);
    }
    // Both owners acknowledged quiescence. Already admitted native events only
    // publish nodes in the stable domain queues; no object is moved or rebound.
    auto destination_keepalive = destination == a
        ? first->state_->group : second->state_->group;
    while (destination_keepalive.get() != destination)
        destination_keepalive = destination_keepalive->parent_keepalive;
    source->parent_keepalive = std::move(destination_keepalive);
    destination->members.splice(destination->members.end(), source->members);
    if (destination->rank == source->rank) ++destination->rank;
    source->parent.store(destination, std::memory_order_release);
    destination->frozen.store(false, std::memory_order_release);
    LOG_DEBUG("Session group migrated owner={} -> {} domains={}",
              source->owner, destination->owner, destination->members.size());
    for (const auto& member : destination->members)
        if (auto domain = member.lock()) domain->Notify(true);
}

net::awaitable<void> ExecutionDomain::Join(std::shared_ptr<ExecutionDomain> other) {
    if (!other || Current().get() != this || state_->coordinator != other->state_->coordinator)
        throw std::logic_error("group join requires compatible execution domains");
    co_await state_->coordinator->Post(
        MergeGroups(shared_from_this(), std::move(other)));
}

} // namespace acpp
