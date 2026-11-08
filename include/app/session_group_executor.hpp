#pragma once

#include "common/asio_types.hpp"
#include "common/allocator.hpp"
#include "app/worker_mailbox.hpp"

#include <asio/execution.hpp>
#include <asio/any_io_executor.hpp>
#include <exception>
#include <memory>
#include <type_traits>
#include <functional>
#include <utility>


class GroupCoordinator : public std::enable_shared_from_this<GroupCoordinator> {
public:
    explicit GroupCoordinator(net::io_context& io, size_t capacity = 1024);
    ~GroupCoordinator();
    void Start();
    // Register fixed Worker routes before their request admission starts.
    void RegisterWorker(uint32_t worker_id, net::io_context& reactor,
                        net::any_io_executor executor);
    struct ReservedOperation {
        ReservedOperation* next = nullptr;
        virtual ~ReservedOperation() = default;
        virtual void Invoke() noexcept = 0;
    };
    void PostReserved(std::unique_ptr<ReservedOperation> operation) noexcept;
    template<class Function> auto PostCall(Function function) {
        return mailbox_.PostCall([this, function = std::move(function)]() mutable
            -> std::invoke_result_t<Function&> {
            EnsureStarted();
            DrainReserved();
            return std::invoke(function);
        });
    }
    template<class T> net::awaitable<T> Post(net::awaitable<T> task) {
        return mailbox_.Post(RunControl(std::move(task)));
    }
    [[nodiscard]] net::io_context& Reactor() noexcept { return reactor_; }
    [[nodiscard]] net::execution_context& Services() noexcept { return *services_; }
    void CloseAdmission() noexcept { mailbox_.CloseAdmission(); }
    net::awaitable<void> AsyncJoin();
    // After admission/accepted controls and service shutdown, with no new
    // domains being created. Joins the final native/executor-held domain roots
    // before stopping reserved notifications; owning reactors must keep running.
    net::awaitable<void> Finalize();
    // After admission closes and accepted controls join, on the coordinator.
    void ReleaseServices() noexcept { services_.reset(); }
private:
    friend class ExecutionDomain;
    struct ReservedState;
    void EnsureStarted();
    template<class T> net::awaitable<T> RunControl(net::awaitable<T> task) {
        EnsureStarted();
        DrainReserved();
        if constexpr (std::is_void_v<T>) co_await std::move(task);
        else co_return co_await std::move(task);
    }
    void ArmReserved();
    void DrainReserved() noexcept;
    void RetireDomain() noexcept;
    net::io_context& reactor_;
    WorkerMailbox mailbox_;
    SignalChannel merge_gate_;
    std::unique_ptr<ReservedState> reserved_;
    std::unique_ptr<net::execution_context> services_ =
        std::make_unique<net::execution_context>();
};

// A domain keeps its hosts, coroutine frames, and allocation arena at stable
// addresses. A group serializes all of its domains on one Worker. The native
// reactor only delivers readiness/completion notifications to this executor.
class ExecutionDomain final : public std::enable_shared_from_this<ExecutionDomain> {
public:
    struct Hooks {
        virtual ~Hooks() = default;
        virtual void Enter() noexcept = 0;
        virtual void Leave() noexcept = 0;
        virtual void OnFailure(std::exception_ptr error) noexcept = 0;
    };

    static std::shared_ptr<ExecutionDomain> Create(
        net::io_context& reactor, uint32_t worker_id,
        net::any_io_executor worker_executor, std::shared_ptr<Hooks> hooks,
        std::shared_ptr<GroupCoordinator> coordinator);
    ~ExecutionDomain();
    ExecutionDomain(const ExecutionDomain&) = delete;
    ExecutionDomain& operator=(const ExecutionDomain&) = delete;

    [[nodiscard]] net::any_io_executor Executor();
    [[nodiscard]] net::io_context& Reactor() noexcept;
    [[nodiscard]] net::execution_context& Services() noexcept;
    [[nodiscard]] GroupCoordinator& Coordinator() noexcept;
    [[nodiscard]] bool SharesGroup(const ExecutionDomain& other) const noexcept;
    [[nodiscard]] std::shared_ptr<const void> LeaseIdentity() const noexcept;
    [[nodiscard]] static bool SharesLeaseIdentity(const void* a, const void* b) noexcept;
    [[nodiscard]] uint32_t OwnerId() const noexcept;
    [[nodiscard]] bool CanDestroyDirectlyOn(uint32_t worker_id) const noexcept;
    [[nodiscard]] static std::shared_ptr<ExecutionDomain> Current() noexcept;
    [[nodiscard]] bool CanExecuteInline() const noexcept;
    // A synchronous borrow from the owning single-threaded reactor. Freeze is
    // acknowledged on that same reactor, so it cannot pass this scope. A frozen
    // or foreign domain must instead be entered through Executor(). Never hold
    // this scope across suspension or use it from a nested domain callback.
    class LocalLease final {
    public:
        explicit LocalLease(ExecutionDomain& domain) noexcept;
        ~LocalLease();
        LocalLease(const LocalLease&) = delete;
        LocalLease& operator=(const LocalLease&) = delete;
        [[nodiscard]] explicit operator bool() const noexcept { return domain_ != nullptr; }
    private:
        ExecutionDomain* domain_ = nullptr;
    };
    // Suspends the caller before freezing both execution groups. Completion
    // resumes only after both run tokens have drained and ownership is unified.
    net::awaitable<void> Join(std::shared_ptr<ExecutionDomain> other);

    // Only an actual receive-path observation may request a handoff. This is
    // not a load-balancing API. The target executor must belong to reactor.
    struct HandoffTarget {
        uint32_t worker_id;
        net::io_context* reactor;
        net::any_io_executor executor;
    };
    [[nodiscard]] HandoffTarget CurrentTarget() const;
    struct NativeResource {
        NativeResource() = default;
        NativeResource(const NativeResource&) = delete;
        NativeResource& operator=(const NativeResource&) = delete;
        virtual ~NativeResource();
        // Run on the old native owner, outside the frozen business domain.
        // Drain native backend callbacks, not queued business completions.
        virtual net::awaitable<void> PrepareHandoff(const HandoffTarget& target) = 0;
        virtual void CommitHandoff(const HandoffTarget& target) noexcept = 0;
        // A throwing rollback must first leave this resource terminal/closed.
        // The domain cancels its session, drains on the old owner, and reports
        // the failure; it never resumes a half-rebound live resource.
        virtual net::awaitable<void> CancelHandoff(const HandoffTarget& old_target) = 0;
    private:
        friend class ExecutionDomain;
        NativeResource* previous_ = nullptr;
        NativeResource* next_ = nullptr;
        ExecutionDomain* domain_ = nullptr;
    };
    // Borrowed registration: resource destruction/unregistration is serialized
    // by this domain. No resource may be destroyed while a handoff is prepared.
    void RegisterResource(NativeResource& resource);
    void UnregisterResource(NativeResource& resource) noexcept;

    class Handoff final {
    public:
        ~Handoff();
        Handoff(const Handoff&) = delete;
        Handoff& operator=(const Handoff&) = delete;
        // Restricted protocol validation only. Business callbacks remain queued;
        // validation may retain protocol changes, so Cancel never rewinds them.
        net::awaitable<void> Validate(std::function<void()> validation);
        net::awaitable<void> Commit();
        net::awaitable<void> Cancel();
    private:
        friend class ExecutionDomain;
        struct Transaction;
        explicit Handoff(std::shared_ptr<Transaction> transaction);
        std::shared_ptr<Transaction> transaction_;
    };
    // Must be awaited outside every domain in the affected group. The returned
    // transaction MUST explicitly Commit or Cancel, including exception paths.
    net::awaitable<std::shared_ptr<Handoff>> PreparePassiveHandoff(HandoffTarget target);
    // Attach an independent, exclusively leased physical domain. Detach moves
    // only that domain out, preserving its current native owner and identity.
    [[nodiscard]] net::awaitable<bool> AttachExclusive(std::shared_ptr<ExecutionDomain> other);
    net::awaitable<void> DetachExclusive(std::shared_ptr<ExecutionDomain> other);

    struct Operation {
        Operation* next = nullptr;
        std::shared_ptr<ExecutionDomain> domain;
        virtual ~Operation() = default;
        virtual void Invoke() = 0;
    };
    template<class Function>
    void Execute(Function&& function) {
        struct Call final : Operation {
            std::decay_t<Function> function;
            explicit Call(Function&& value) : function(std::forward<Function>(value)) {}
            void Invoke() override { std::move(function)(); }
        };
        memory::ScopedWorkerAllocation worker_allocation;
        auto call = std::make_unique<Call>(std::forward<Function>(function));
        call->domain = shared_from_this();
        Enqueue(std::move(call));
    }

    [[nodiscard]] std::shared_ptr<ExecutionDomain> CreateSibling(
        std::shared_ptr<Hooks> hooks) const;
private:
    struct State;
    struct Group;
    struct NativeExecutor;
    void Notify(bool force = false) noexcept;
    void Run(const void* scheduled_route) noexcept;
    static net::awaitable<bool> MergeGroups(std::shared_ptr<ExecutionDomain> first,
                                           std::shared_ptr<ExecutionDomain> second,
                                           bool exclusive = false);
    static net::awaitable<void> SplitGroup(std::shared_ptr<ExecutionDomain> first,
                                         std::shared_ptr<ExecutionDomain> second);
    static net::awaitable<void> Freeze(std::shared_ptr<ExecutionDomain> domain);
    static void Thaw(const std::shared_ptr<Group>& first,
                     const std::shared_ptr<Group>& second = {}) noexcept;
    static net::awaitable<void> RebindFrozen(
        std::shared_ptr<ExecutionDomain> domain, HandoffTarget target);
    static net::awaitable<std::shared_ptr<Handoff>> Prepare(
        std::shared_ptr<ExecutionDomain> domain, HandoffTarget target);
    explicit ExecutionDomain(std::unique_ptr<State> state);
    void Enqueue(std::unique_ptr<Operation> operation);
    std::unique_ptr<State> state_;
};

class GroupExecutor {
public:
    explicit GroupExecutor(std::shared_ptr<ExecutionDomain> domain)
        : domain_(std::move(domain)) {}

    net::execution_context& query(net::execution::context_t) const noexcept {
        return domain_->Reactor();
    }
    auto query(net::execution::blocking_t) const noexcept {
        return never_inline_ ? net::execution::blocking_t(net::execution::blocking.never)
                             : net::execution::blocking_t(net::execution::blocking.possibly);
    }
    auto query(net::execution::outstanding_work_t) const noexcept {
        return work_ ? net::execution::outstanding_work_t(net::execution::outstanding_work.tracked)
                     : net::execution::outstanding_work_t(net::execution::outstanding_work.untracked);
    }
    static constexpr auto query(net::execution::relationship_t) noexcept {
        return net::execution::relationship.fork;
    }
    GroupExecutor require(net::execution::blocking_t::never_t) const {
        auto copy = *this;
        copy.never_inline_ = true;
        return copy;
    }
    GroupExecutor prefer(net::execution::blocking_t::possibly_t) const {
        auto copy = *this;
        copy.never_inline_ = false;
        return copy;
    }
    GroupExecutor prefer(net::execution::relationship_t::fork_t) const { return *this; }
    GroupExecutor prefer(net::execution::relationship_t::continuation_t) const { return *this; }
    GroupExecutor prefer(net::execution::outstanding_work_t::tracked_t) const {
        auto copy = *this;
        if (!copy.work_) copy.work_ = std::make_shared<Work>(domain_->Reactor());
        return copy;
    }
    GroupExecutor prefer(net::execution::outstanding_work_t::untracked_t) const {
        GroupExecutor copy(domain_);
        copy.never_inline_ = never_inline_;
        return copy;
    }
    template<class Function> void execute(Function&& function) const {
        if (!never_inline_ && domain_->CanExecuteInline()) {
            std::forward<Function>(function)();
            return;
        }
        domain_->Execute(std::forward<Function>(function));
    }
    friend bool operator==(const GroupExecutor& a, const GroupExecutor& b) noexcept {
        return a.domain_ == b.domain_ && bool(a.work_) == bool(b.work_) &&
               a.never_inline_ == b.never_inline_;
    }
private:
    struct Work {
        net::io_context::executor_type executor;
        explicit Work(net::io_context& reactor) : executor(reactor.get_executor()) {
            executor.on_work_started();
        }
        ~Work() { executor.on_work_finished(); }
    };
    std::shared_ptr<ExecutionDomain> domain_;
    std::shared_ptr<Work> work_;
    bool never_inline_ = false;
};

