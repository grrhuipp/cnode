#include <gtest/gtest.h>

#include "app/session_group_executor.hpp"

#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/use_future.hpp>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <exception>
#include <future>
#include <memory>
#include <stdexcept>

namespace {
using TrackedExecutor = decltype(net::prefer(
    std::declval<GroupExecutor>(), net::execution::outstanding_work.tracked));
constexpr std::size_t kLifecycleWarmup = 4096;
constexpr std::size_t kLifecycleIterations = 262144;
constexpr std::size_t kPostWarmup = 128;
constexpr std::size_t kPostIterations = 4096;

int64_t CpuNanoseconds(const timespec& value) {
    return static_cast<int64_t>(value.tv_sec) * 1000000000 + value.tv_nsec;
}

struct Measurement {
    double wall_ns;
    double cpu_ns;
};

template<class Function>
Measurement Measure(Function&& function) {
    timespec cpu_start{}, cpu_end{};
    if (::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_start) != 0)
        throw std::runtime_error("cannot read process CPU clock");
    const auto start = std::chrono::steady_clock::now();
    function();
    const auto finish = std::chrono::steady_clock::now();
    if (::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_end) != 0)
        throw std::runtime_error("cannot read process CPU clock");
    return {std::chrono::duration<double, std::nano>(finish - start).count(),
            static_cast<double>(CpuNanoseconds(cpu_end) - CpuNanoseconds(cpu_start))};
}

// Match the existing benchmarks' compiler barrier so property wrappers, copies,
// and their release remain observable under optimization and ThinLTO.
void Observe(const net::any_io_executor& executor) {
    asm volatile("" : : "g"(&executor) : "memory");
}

struct BenchmarkHooks final : ExecutionDomain::Hooks {
    void Enter() noexcept override {
        valid = valid && !entered;
        entered = true;
        ++entries;
    }
    void Leave() noexcept override {
        valid = valid && entered;
        entered = false;
        ++leaves;
    }
    void OnFailure(std::exception_ptr) noexcept override { ++failures; }
    bool entered = false;
    bool valid = true;
    std::size_t entries = 0;
    std::size_t leaves = 0;
    std::size_t failures = 0;
};

class ExecutorBenchmark : public testing::Test {
protected:
    void SetUp() override {
        // Keep the coordinator's reserved notification work off the measured
        // reactor, so stopped() can observe GroupExecutor's public work lifetime.
        coordinator = std::make_shared<GroupCoordinator>(control, 1);
        coordinator->RegisterWorker(0, worker, worker.get_executor());
        hooks = std::make_shared<BenchmarkHooks>();
        domain = ExecutionDomain::Create(worker, 0, worker.get_executor(), hooks, coordinator);
        control.poll();
    }

    void TearDown() override {
        domain.reset();
        worker.restart();
        worker.poll();
        coordinator->CloseAdmission();
        auto closed = net::co_spawn(control, [this]() -> net::awaitable<void> {
            co_await coordinator->AsyncJoin();
            coordinator->ReleaseServices();
            co_await coordinator->Finalize();
        }, net::use_future);
        control.restart();
        control.run();
        closed.get();
        EXPECT_TRUE(worker.stopped());
        EXPECT_TRUE(hooks->valid);
        EXPECT_FALSE(hooks->entered);
        EXPECT_EQ(hooks->entries, hooks->leaves);
        EXPECT_EQ(hooks->failures, 0u);
        coordinator.reset();
    }

    net::io_context control;
    net::io_context worker;
    std::shared_ptr<GroupCoordinator> coordinator;
    std::shared_ptr<BenchmarkHooks> hooks;
    std::shared_ptr<ExecutionDomain> domain;
};

void AdaptProperties(const std::shared_ptr<ExecutionDomain>& domain) {
    net::any_io_executor erased{GroupExecutor(domain)};
    auto never = net::require(erased, net::execution::blocking.never);
    auto possible = net::prefer(never, net::execution::blocking.possibly);
    auto continuation = net::prefer(possible, net::execution::relationship.continuation);
    auto fork = net::prefer(continuation, net::execution::relationship.fork);
    Observe(erased);
    Observe(never);
    Observe(possible);
    Observe(continuation);
    Observe(fork);
    // All five wrappers are released inside the measured operation.
}

TEST_F(ExecutorBenchmark, PropertyAdaptation) {
    {
        auto base = domain->Executor();
        auto never = net::require(base, net::execution::blocking.never);
        EXPECT_EQ(net::query(never, net::execution::blocking), net::execution::blocking.never);
        auto possible = net::prefer(never, net::execution::blocking.possibly);
        EXPECT_EQ(net::query(possible, net::execution::blocking), net::execution::blocking.possibly);
    }
    for (std::size_t iteration = 0; iteration < kLifecycleWarmup; ++iteration)
        AdaptProperties(domain);
    const auto measured = Measure([&] {
        for (std::size_t iteration = 0; iteration < kLifecycleIterations; ++iteration)
            AdaptProperties(domain);
    });
    worker.restart();
    EXPECT_EQ(worker.poll(), 0u);
    EXPECT_TRUE(worker.stopped());
    // Process CPU includes type erasure, four property adaptations, compiler
    // barriers, loop overhead and all wrapper destruction; no event loop runs.
    std::printf("executor-benchmark phase=property-adaptation "
                "cpu_scope=erase_adapt_release_loop group_executor_bytes=%zu "
                "tracked_executor_bytes=%zu allocator=mimalloc "
                "warmup=%zu iterations=%zu wall_ns_per_operation=%.3f cpu_ns_per_operation=%.3f\n",
        sizeof(GroupExecutor), sizeof(TrackedExecutor), kLifecycleWarmup, kLifecycleIterations,
        measured.wall_ns / kLifecycleIterations, measured.cpu_ns / kLifecycleIterations);
}

void TrackCopyAndRelease(const net::any_io_executor& base) {
    auto tracked = net::prefer(base, net::execution::outstanding_work.tracked);
    auto tracked_again = net::prefer(tracked, net::execution::outstanding_work.tracked);
    net::any_io_executor copy(tracked_again);
    net::any_io_executor assigned;
    assigned = copy;
    auto untracked = net::prefer(assigned, net::execution::outstanding_work.untracked);
    Observe(tracked);
    Observe(tracked_again);
    Observe(copy);
    Observe(assigned);
    Observe(untracked);
    // Destruction includes the last tracked reference and native work release.
}

TEST_F(ExecutorBenchmark, TrackingCopiesAndRelease) {
    auto base = domain->Executor();
    {
        auto tracked = net::prefer(base, net::execution::outstanding_work.tracked);
        auto tracked_again = net::prefer(tracked, net::execution::outstanding_work.tracked);
        net::any_io_executor copy(tracked_again);
        net::any_io_executor assigned;
        assigned = copy;
        auto untracked = net::prefer(assigned, net::execution::outstanding_work.untracked);
        EXPECT_EQ(net::query(tracked, net::execution::outstanding_work),
                  net::execution::outstanding_work.tracked);
        EXPECT_EQ(net::query(untracked, net::execution::outstanding_work),
                  net::execution::outstanding_work.untracked);
        worker.restart();
        EXPECT_EQ(worker.poll(), 0u);
        EXPECT_FALSE(worker.stopped());
        tracked = {};
        tracked_again = {};
        copy = {};
        EXPECT_EQ(worker.poll(), 0u);
        EXPECT_FALSE(worker.stopped());
        assigned = {};
        EXPECT_EQ(worker.poll(), 0u);
        // The untracked adaptation is still alive and must not retain work.
        EXPECT_TRUE(worker.stopped());
        Observe(untracked);
    }
    Measurement measured;
    {
        // Production worker loops retain their own work while executor copies
        // come and go; do not benchmark stopping the reactor on every release.
        auto worker_work = net::make_work_guard(worker);
        for (std::size_t iteration = 0; iteration < kLifecycleWarmup; ++iteration)
            TrackCopyAndRelease(base);
        measured = Measure([&] {
            for (std::size_t iteration = 0; iteration < kLifecycleIterations; ++iteration)
                TrackCopyAndRelease(base);
        });
    }
    worker.restart();
    EXPECT_EQ(worker.poll(), 0u);
    EXPECT_TRUE(worker.stopped());
    // Process CPU includes tracking/re-tracking, copy construction/assignment,
    // untracking, barriers, loop overhead and every temporary's destruction.
    // The initial erased executor and correctness probes are outside timing.
    std::printf("executor-benchmark phase=tracking-copy-release "
                "cpu_scope=track_retrack_copy_untrack_release_loop group_executor_bytes=%zu "
                "tracked_executor_bytes=%zu allocator=mimalloc "
                "warmup=%zu iterations=%zu wall_ns_per_operation=%.3f cpu_ns_per_operation=%.3f\n",
        sizeof(GroupExecutor), sizeof(TrackedExecutor), kLifecycleWarmup, kLifecycleIterations,
        measured.wall_ns / kLifecycleIterations, measured.cpu_ns / kLifecycleIterations);
}

uint64_t AppendChecksum(uint64_t checksum, std::size_t sequence) {
    return checksum * UINT64_C(1099511628211) + static_cast<uint64_t>(sequence) + 1;
}

struct CompletionState {
    std::size_t completed = 0;
    std::size_t native_callbacks = 0;
    uint64_t checksum = 0;
    bool ordered = true;
    bool in_domain = true;
};

TEST_F(ExecutorBenchmark, BoundedPostAndRun) {
    const auto executor = domain->Executor();
    for (const std::size_t batch : {1u, 8u, 64u}) {
        SCOPED_TRACE(batch);
        CompletionState state;
        auto run_batches = [&](std::size_t iterations) {
            for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
                worker.restart();
                for (std::size_t item = 0; item < batch; ++item) {
                    const auto sequence = iteration * batch + item;
                    net::post(executor, [&, sequence] {
                        state.ordered = state.ordered && state.completed == sequence;
                        state.in_domain = state.in_domain && hooks->entered &&
                            ExecutionDomain::Current().get() == domain.get();
                        state.checksum = AppendChecksum(state.checksum, sequence);
                        ++state.completed;
                    });
                }
                // Drain this batch before admitting another: at most 64 queued
                // business callbacks, one thread, no external work guard/pool.
                state.native_callbacks += worker.run();
            }
        };
        run_batches(kPostWarmup);
        ASSERT_EQ(state.completed, kPostWarmup * batch);
        ASSERT_TRUE(state.ordered);
        ASSERT_TRUE(state.in_domain);
        state = {};
        const auto measured = Measure([&] { run_batches(kPostIterations); });
        const std::size_t operations = kPostIterations * batch;
        uint64_t expected_checksum = 0;
        for (std::size_t sequence = 0; sequence < operations; ++sequence)
            expected_checksum = AppendChecksum(expected_checksum, sequence);
        EXPECT_EQ(state.completed, operations);
        EXPECT_EQ(state.checksum, expected_checksum);
        EXPECT_TRUE(state.ordered);
        EXPECT_TRUE(state.in_domain);
        EXPECT_TRUE(worker.stopped());
        EXPECT_EQ(hooks->failures, 0u);
        // Process CPU includes post/property handling, queue allocation/release,
        // restart/run, domain hooks and handlers' order/domain/checksum checks.
        // Setup, warmup, expected-checksum calculation and GTest are excluded.
        // This is local executor cost, not network or end-to-end throughput.
        std::printf("executor-benchmark phase=bounded-post-run "
                    "cpu_scope=post_queue_restart_run_hooks_verify_release_loop "
                    "group_executor_bytes=%zu tracked_executor_bytes=%zu allocator=mimalloc "
                    "batch=%zu warmup_batches=%zu batches=%zu "
                    "operations=%zu completed=%zu native_callbacks=%zu checksum=%" PRIu64 " "
                    "wall_ns_per_operation=%.3f cpu_ns_per_operation=%.3f\n",
            sizeof(GroupExecutor), sizeof(TrackedExecutor), batch, kPostWarmup, kPostIterations, operations,
            state.completed, state.native_callbacks, state.checksum,
            measured.wall_ns / operations, measured.cpu_ns / operations);
    }
}
} // namespace
