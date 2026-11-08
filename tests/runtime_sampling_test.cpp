#include <gtest/gtest.h>

#include "runtime_sampling_fixture.hpp"
#include "app/session_group_executor.hpp"
#include "common/allocator.hpp"
#include "proxy/inbound.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/executor_work_guard.hpp>
#include <thread>

namespace {
using runtime_sampling::Require;
using namespace std::chrono_literals;

TEST(RuntimeSampling, CreationFinishAndShutdownPreserveEveryTail) {
    memory::ConfigureProcessAllocator();
    runtime_sampling::Fixture fixture;
    fixture.Run([&]() -> net::awaitable<void> {
        constexpr size_t sessions = 8;
        for (size_t index = 0; index < sessions; ++index) {
            auto opening = net::co_spawn(fixture.io, fixture.Open(), net::use_future);
            // Collection overlaps admission, domain initialization and the real
            // authentication/dial. No private registry or snapshot is injected.
            while (opening.wait_for(0s) != std::future_status::ready) {
                const auto sample = co_await fixture.worker.CollectRuntimeStats(false);
                EXPECT_FALSE(sample.resources.has_value());
                EXPECT_GE(sample.stats.connections_total, index);
                EXPECT_LE(sample.stats.connections_total, index + 1);
                EXPECT_LE(sample.active_connections, index + 1);
                co_await net::post(net::use_awaitable);
            }
            opening.get();
            const auto sample = co_await fixture.worker.CollectRuntimeStats(true);
            EXPECT_TRUE(sample.resources.has_value());
            EXPECT_EQ(sample.active_connections, index + 1);
            EXPECT_EQ(sample.stats.connections_total, index + 1);
            EXPECT_EQ(sample.stats.connections_active, index + 1);
            co_await fixture.Transfer(index, 997, 509);
        }
        for (size_t index = 0; index < sessions / 2; ++index) {
            fixture.clients[index].close();
            fixture.peers[index].close();
        }
        const auto half = co_await fixture.WaitActive(sessions / 2);
        EXPECT_EQ(half.stats.connections_total, sessions);
        EXPECT_EQ(half.stats.connections_active, sessions / 2);
        // The payload is below the relay batch threshold. These bounds require
        // the retiring half's final accumulator flush to survive collection.
        EXPECT_GE(half.stats.bytes_out, (sessions / 2) * 998);
        EXPECT_GE(half.stats.bytes_in, (sessions / 2) * 510);
        EXPECT_LE(half.stats.bytes_out, sessions * 998);
        EXPECT_LE(half.stats.bytes_in, sessions * 510);
        fixture.worker.RequestStop();
        const auto stopped = co_await fixture.WaitActive(0);
        EXPECT_EQ(stopped.stats.connections_total, sessions);
        EXPECT_EQ(stopped.stats.connections_active, 0u);
        EXPECT_EQ(stopped.stats.bytes_out, sessions * 998);
        EXPECT_EQ(stopped.stats.bytes_in, sessions * 510);
        for (unsigned round = 0; round < 4; ++round) {
            const auto again = co_await fixture.worker.CollectRuntimeStats(round % 2 == 0);
            EXPECT_EQ(again.stats.bytes_in, stopped.stats.bytes_in);
            EXPECT_EQ(again.stats.bytes_out, stopped.stats.bytes_out);
            EXPECT_EQ(again.stats.connections_total, sessions);
            EXPECT_EQ(again.stats.connections_active, 0u);
            EXPECT_EQ(again.resources.has_value(), round % 2 == 0);
        }
    });
    EXPECT_EQ(fixture.totals.Snapshot().connections_total, 8u);
    EXPECT_EQ(fixture.totals.Snapshot().bytes_out, 8u * 998);
    EXPECT_EQ(fixture.totals.Snapshot().bytes_in, 8u * 510);
}

thread_local std::vector<std::weak_ptr<ExecutionDomain>>* observed_domains = nullptr;
constexpr std::string_view kObservedProtocol = "sampling-observed-vless";

void RegisterObservedVless() {
    static const bool registered = [] {
        proxyman::inbound::RegisterProxy(kObservedProtocol, {
            .user_protocol = proxyman::inbound::UserProtocol::Vless,
            .create_runtime = [] { return proxyman::inbound::NewProtocolRuntime("vless"); },
            .create_tcp_handler = [](proxyman::inbound::ProtocolRuntime& runtime, StatsShard& stats,
                                     ConnectionLimiter* limiter, const proxyman::inbound::BuildRequest& request) {
                if (observed_domains) {
                    if (auto domain = ExecutionDomain::Current()) observed_domains->push_back(domain);
                }
                return proxyman::inbound::NewHandler("vless", runtime, stats, limiter, request);
            },
            .build_users = [](const proxyman::inbound::BuildRequest& request,
                              std::span<const InboundUserSpec> users) {
                auto vless = request;
                vless.protocol = "vless";
                return proxyman::inbound::BuildUsers(vless, users);
            },
        });
        return true;
    }();
    (void)registered;
}

class ReceivingReactor final {
public:
    ReceivingReactor() : work(net::make_work_guard(io)), thread([this] { io.run(); }) {}
    ~ReceivingReactor() {
        work.reset();
        thread.join();
    }
    net::io_context io;
private:
    net::executor_work_guard<net::io_context::executor_type> work;
    std::thread thread;
};

net::awaitable<WorkerRuntimeStatsSnapshot> BeginSample(
    Worker& worker, std::shared_ptr<bool> started) {
    *started = true;
    co_return co_await worker.CollectRuntimeStats(true);
}

TEST(RuntimeSampling, FrozenCancelledAndCommittedDomainsRetainAccountingAuthority) {
    memory::ConfigureProcessAllocator();
    RegisterObservedVless();
    ReceivingReactor receiving;
    runtime_sampling::Fixture fixture(kObservedProtocol);
    std::vector<std::weak_ptr<ExecutionDomain>> domains;
    observed_domains = &domains;
    struct ClearObserver {
        ~ClearObserver() { observed_domains = nullptr; }
    } clear_observer;
    fixture.Run([&]() -> net::awaitable<void> {
        co_await fixture.Open();
        Require(domains.size() == 1, "physical domain was not observed");
        auto domain = domains.front().lock();
        Require(domain != nullptr, "physical domain expired before collection");
        domain->Coordinator().RegisterWorker(1, receiving.io, receiving.io.get_executor());
        const ExecutionDomain::HandoffTarget target{1, &receiving.io, receiving.io.get_executor()};
        {
            ExecutionDomain::LocalLease lease(*domain);
            EXPECT_TRUE(static_cast<bool>(lease));
            EXPECT_EQ(ExecutionDomain::Current(), domain);
            ExecutionDomain::LocalLease nested(*domain);
            EXPECT_FALSE(static_cast<bool>(nested));
        }
        EXPECT_FALSE(ExecutionDomain::Current());
        // Exercise the public handoff boundary with live native resources. This
        // is a controlled execution-domain transition, not a TCP rebalance rule
        // or a substitute for the QUIC receive path's identity validation.
        auto handoff = co_await domain->PreparePassiveHandoff(target);
        {
            ExecutionDomain::LocalLease frozen(*domain);
            EXPECT_FALSE(static_cast<bool>(frozen));
        }
        auto started = std::make_shared<bool>(false);
        auto pending = net::co_spawn(fixture.io, BeginSample(fixture.worker, started), net::use_future);
        while (!*started) co_await net::post(net::use_awaitable);
        co_await net::post(net::use_awaitable);
        EXPECT_NE(pending.wait_for(0s), std::future_status::ready);
        co_await handoff->Cancel();
        handoff.reset();
        while (pending.wait_for(0s) != std::future_status::ready)
            co_await net::post(net::use_awaitable);
        const auto sampled = pending.get();
        EXPECT_EQ(sampled.active_connections, 1u);
        EXPECT_EQ(sampled.stats.connections_total, 1u);
        EXPECT_TRUE(sampled.resources.has_value());
        {
            ExecutionDomain::LocalLease resumed(*domain);
            EXPECT_TRUE(static_cast<bool>(resumed));
        }

        handoff = co_await domain->PreparePassiveHandoff(target);
        *started = false;
        net::cancellation_signal cancel_sample;
        pending = net::co_spawn(fixture.io, BeginSample(fixture.worker, started),
            net::bind_cancellation_slot(cancel_sample.slot(), net::use_future));
        while (!*started) co_await net::post(net::use_awaitable);
        co_await net::post(net::use_awaitable);
        EXPECT_NE(pending.wait_for(0s), std::future_status::ready);
        cancel_sample.emit(net::cancellation_type::terminal);
        co_await handoff->Commit();
        handoff.reset();
        while (pending.wait_for(0s) != std::future_status::ready)
            co_await net::post(net::use_awaitable);
        try { (void)pending.get(); }
        catch (const IoSystemError& error) { EXPECT_EQ(error.code(), net::error::operation_aborted); }
        EXPECT_EQ(domain->OwnerId(), 1u);
        {
            ExecutionDomain::LocalLease foreign(*domain);
            EXPECT_FALSE(static_cast<bool>(foreign));
        }
        const auto target_lease = co_await net::co_spawn(receiving.io,
            [domain]() -> net::awaitable<bool> {
                ExecutionDomain::LocalLease local(*domain);
                co_return static_cast<bool>(local) && ExecutionDomain::Current() == domain;
            }, net::use_awaitable);
        EXPECT_TRUE(target_lease);
        const auto moved = co_await fixture.worker.CollectRuntimeStats(false);
        EXPECT_EQ(moved.active_connections, 1u);
        EXPECT_EQ(moved.stats.connections_total, 1u);
        EXPECT_FALSE(moved.resources.has_value());
        co_await fixture.Transfer(0, 7919, 3571);
        // Drop all external domain roots before Worker shutdown joins them.
        domain.reset();
        fixture.clients[0].close();
        fixture.peers[0].close();
        const auto final = co_await fixture.WaitActive(0);
        EXPECT_EQ(final.stats.connections_total, 1u);
        EXPECT_EQ(final.stats.connections_active, 0u);
        EXPECT_EQ(final.stats.bytes_out, 7920u);
        EXPECT_EQ(final.stats.bytes_in, 3572u);
        const auto repeated = co_await fixture.worker.CollectRuntimeStats(true);
        EXPECT_EQ(repeated.stats.connections_total, final.stats.connections_total);
        EXPECT_EQ(repeated.stats.bytes_out, final.stats.bytes_out);
        EXPECT_EQ(repeated.stats.bytes_in, final.stats.bytes_in);
    });
    EXPECT_TRUE(domains.front().expired());
    EXPECT_EQ(fixture.totals.Snapshot().connections_total, 1u);
    EXPECT_EQ(fixture.totals.Snapshot().bytes_out, 7920u);
    EXPECT_EQ(fixture.totals.Snapshot().bytes_in, 3572u);
}
} // namespace
