#include <gtest/gtest.h>

#include "app/dns.hpp"
#include "app/relay.hpp"
#include "app/prepared_inbound.hpp"
#include "app/inbound_handler.hpp"
#include "app/rate_limiter.hpp"
#include "app/stats.hpp"
#include "app/worker.hpp"
#include "worker_coordinator_fixture.hpp"
#include "common/allocator.hpp"
#include "proxy/inbound.hpp"
#include "transport/async_stream.hpp"

#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <array>
#include <atomic>
#include <chrono>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
using namespace std::chrono_literals;
constexpr std::string_view kProtocol = "worker-budget-fixture";


struct FixtureState {
    std::thread::id owner = std::this_thread::get_id();
    unsigned created = 0;
    unsigned destroyed = 0;
    bool wrong_thread = false;
    std::weak_ptr<app::ConnectionLimiter> limiter;
};
thread_local FixtureState* fixture = nullptr;


// Observe actor identity without extending its lifetime. Request admission still
// travels through the real Worker handlers and physical session capabilities.
class HoldingInbound final : public proxy::Inbound {
public:
    explicit HoldingInbound(FixtureState& state)
        : state_(state) { ++state_.created; }
    ~HoldingInbound() override {
        state_.wrong_thread |= std::this_thread::get_id() != state_.owner;
        ++state_.destroyed;
    }
    net::awaitable<app::RelayResult> Process(
        std::unique_ptr<transport::AsyncStream> stream, routing::Dispatcher&,
        const app::ReceiverSettings&, net::io_context&,
        common::Context&, const infra::TimeoutsConfig&, uint32_t) override {
        const std::array<char, 1> admitted{'A'};
        co_await stream->AsyncWrite(net::buffer(admitted));
        std::array<char, 1> input{};
        while (co_await stream->AsyncRead(net::buffer(input)) != 0) {}
        co_return app::RelayResult{};
    }
private:
    FixtureState& state_;
};

void RegisterProtocol() {
    app::RegisterProxy(kProtocol, {
        .user_protocol = std::nullopt,
        .create_tcp_handler = [](const app::AdmissionEnvironment& environment,
                                 const app::BuildRequest&) -> std::unique_ptr<proxy::Inbound> {
            auto* limiter = &environment.limiter;
            EXPECT_TRUE(fixture) << "factory did not receive the shared limiter";
            if (!fixture) throw std::runtime_error("missing admission fixture");
            if (fixture->created == 0) {
                fixture->limiter = limiter->weak_from_this();
            } else {
                EXPECT_EQ(fixture->limiter.lock().get(), limiter) << "handler replacement changed the live admission actor";
            }
            return std::make_unique<HoldingInbound>(*fixture);
        },
    });
}

net::awaitable<void> Pause(net::io_context& io) {
    net::steady_timer timer(io, 1ms);
    co_await timer.async_wait(net::use_awaitable);
}

void Register(app::Worker& worker, std::string tag) {
    app::BuildRequest request{
        .tag = tag, .protocol = std::string(kProtocol), .settings = {}};
    app::ReceiverSettings receiver{
        .inbound_tag = tag, .inbound_tags = {}, .protocol = std::string(kProtocol),
        .stream_settings = {},
        .dispatch_policy = {{}, routing::ForceOutbound{"unused"}},
        .proxy_protocol = transport::ProxyProtocolMode::Off};
    const bool registered = worker.RegisterInbound(std::move(request), std::move(receiver));
    EXPECT_TRUE(registered);
    if (!registered) throw std::runtime_error("inbound fixture registration failed");
}

net::awaitable<uint16_t> Listen(net::io_context& io, app::Worker& worker, std::string tag) {
    Register(worker, tag);
    tcp::acceptor reservation(io, {net::ip::address_v4::loopback(), 0});
    const auto port = reservation.local_endpoint().port();
    reservation.close();
    const auto listen = transport::InboundListen::Parse("127.0.0.1");
    EXPECT_TRUE((listen.has_value())) << "loopback listen parsing failed";
    if (!listen) throw std::runtime_error("invalid loopback fixture address");
    const bool listening = worker.AddListener(
        app::PortBinding{.port = port, .protocol = std::string(kProtocol), .tag = tag, .listen = *listen});
    EXPECT_TRUE(listening);
    if (!listening) throw std::runtime_error("TCP fixture listener failed");
    co_return port;
}

net::awaitable<tcp::socket> Connect(net::io_context& io, uint16_t port, bool admitted) {
    tcp::socket client(io);
    co_await client.async_connect({net::ip::address_v4::loopback(), port}, net::use_awaitable);
    client.non_blocking(true);
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    for (;;) {
        std::array<char, 1> marker{};
        IoErrorCode ec;
        const auto count = client.read_some(net::buffer(marker), ec);
        if (ec == net::error::would_block || ec == net::error::try_again) {
            EXPECT_LT(std::chrono::steady_clock::now(), deadline) << "admission response timed out";
            if (std::chrono::steady_clock::now() >= deadline) {
                throw std::runtime_error("admission response timed out");
            }
            co_await Pause(io);
            continue;
        }
        if (admitted) {
            EXPECT_FALSE(ec);
            EXPECT_EQ(count, 1u);
            EXPECT_EQ(marker[0], 'A');
        } else {
            EXPECT_TRUE((count == 0 && (ec == net::error::eof || ec == net::error::connection_reset))) << "different inbound tag bypassed the shared connection budget";
        }
        co_return std::move(client);
    }
}

net::awaitable<void> WaitActive(net::io_context& io, app::Worker& worker, uint32_t expected) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (worker.CollectRuntimeStats(false).active_connections != expected) {
        EXPECT_LT(std::chrono::steady_clock::now(), deadline) << "active request guards did not drain";
        if (std::chrono::steady_clock::now() >= deadline) {
            throw std::runtime_error("active request guards did not drain");
        }
        co_await Pause(io);
    }
}

net::awaitable<void> Exercise(net::io_context& io, app::Worker& worker, FixtureState& state,
                             std::atomic<unsigned>& ready, bool limited, bool replace_handler) {
    std::exception_ptr failure;
    std::optional<tcp::socket> shutdown_client;
    try {
        worker.StartRuntime();
        const auto first_port = co_await Listen(io, worker, "first");
        const auto second_port = co_await Listen(io, worker, "second");
        auto first = co_await Connect(io, first_port, true);
        ready.fetch_add(1, std::memory_order_release);
        const auto deadline = std::chrono::steady_clock::now() + 3s;
        while (ready.load(std::memory_order_acquire) < 2) {
            EXPECT_LT(std::chrono::steady_clock::now(), deadline) << "another Worker could not consume its shared admission slot";
            if (std::chrono::steady_clock::now() >= deadline) {
                throw std::runtime_error("other Worker did not reach admission barrier");
            }
            co_await Pause(io);
        }
        auto second = co_await Connect(io, second_port, !limited);
        second.close();
        co_await WaitActive(io, worker, 1);

        if (replace_handler) {
            // Reconfiguration must preserve reservations held by live sessions.
            worker.StartRuntime();
            Register(worker, "first");
            co_await worker.UnregisterListenerTask("first");
            co_await WaitActive(io, worker, 1);
            auto after_remove = co_await Connect(io, second_port, !limited);
            after_remove.close();
            co_await WaitActive(io, worker, 1);
        }
        ready.fetch_add(1, std::memory_order_release);
        const auto rejection_deadline = std::chrono::steady_clock::now() + 3s;
        while (ready.load(std::memory_order_acquire) < 4) {
            EXPECT_LT(std::chrono::steady_clock::now(), rejection_deadline) << "another Worker did not finish its shared-budget rejection checks";
            if (std::chrono::steady_clock::now() >= rejection_deadline) {
                throw std::runtime_error("other Worker did not reach release barrier");
            }
            co_await Pause(io);
        }

        first.close();
        co_await WaitActive(io, worker, 0);
        shutdown_client.emplace(co_await Connect(io, second_port, true));
        Register(worker, "idle");
    } catch (...) {
        failure = std::current_exception();
    }
    worker.RequestStop();
    co_await worker.AsyncJoin();
    co_await worker.AsyncJoin();
    EXPECT_EQ(state.created, state.destroyed);
    EXPECT_FALSE(state.wrong_thread);
    if (failure) std::rethrow_exception(failure);
    std::array<char, 1> byte{};
    IoErrorCode error;
    shutdown_client->read_some(net::buffer(byte), error);
    EXPECT_TRUE((error == net::error::eof || error == net::error::connection_reset)) << "Worker join left the physical TCP read alive";
}

void ExerciseWorkers(app::DNSWorker& dns, uint32_t global, uint32_t per_ip,
                     bool limited, bool replace_handler) {
    net::io_context control;
    WorkerCoordinatorFixture control_fixture(control);
    auto coordinator = control_fixture.Get();
    coordinator->Start();
    std::exception_ptr control_failure;
    std::thread control_thread([&] {
        try { control.run(); }
        catch (...) { control_failure = std::current_exception(); }
    });
    std::atomic<unsigned> ready{0};
    std::array<std::exception_ptr, 2> failures{};
    std::array<std::weak_ptr<app::ConnectionLimiter>, 2> limiter_identities;
    std::array<std::thread, 2> threads;
    for (uint32_t id = 0; id < threads.size(); ++id) {
        threads[id] = std::thread([&, id] {
            try {
                net::io_context io;
                app::StatsShard stats;
                FixtureState state;
                fixture = &state;
                struct ResetFixture {
                    ~ResetFixture() { fixture = nullptr; }
                } reset_fixture;
                app::WorkerRuntimeConfig config;
                config.workers = 2;
                config.limits.max_connections = global;
                config.limits.max_connections_per_ip = per_ip;
                config.timeouts.idle = 0;
                config.timeouts.read = 0;
                auto worker = std::make_unique<app::Worker>(id, io, config, stats, dns, coordinator);
                net::co_spawn(io, Exercise(io, *worker, state, ready, limited, replace_handler),
                    [&](std::exception_ptr error) { failures[id] = error; });
                io.run();
                worker.reset();
                io.restart();
                while (io.poll() != 0) {}
                EXPECT_EQ(state.created, state.destroyed);
                EXPECT_FALSE(state.wrong_thread);
                limiter_identities[id] = state.limiter;
            } catch (...) {
                failures[id] = std::current_exception();
            }
        });
    }
    for (auto& thread : threads) thread.join();
    net::co_spawn(control, [](std::shared_ptr<app::GroupCoordinator> owner) -> net::awaitable<void> {
        owner->CloseAdmission();
        co_await owner->AsyncJoin();
        owner->ReleaseServices();
        co_await owner->Finalize();
    }(coordinator), [&](std::exception_ptr error) {
        if (error) control_failure = error;
    });
    control_thread.join();
    if (control_failure) std::rethrow_exception(control_failure);
    for (const auto& failure : failures) if (failure) std::rethrow_exception(failure);
    EXPECT_TRUE((!limiter_identities[0].owner_before(limiter_identities[1]) &&
            !limiter_identities[1].owner_before(limiter_identities[0]))) << "Workers did not share the same admission actor";
    for (const auto& limiter : limiter_identities) {
        EXPECT_TRUE((limiter.expired())) << "coordinator shutdown retained an admission actor or reservation return";
    }
}
} // namespace

namespace {
struct LimitMode { uint32_t global; uint32_t per_ip; bool limited; const char* name; };
class WorkerConnectionLimitRuntime : public testing::TestWithParam<LimitMode> {
protected:
    static void SetUpTestSuite() { RegisterProtocol(); }
    net::io_context control;
    app::DnsConfig config{.servers = {{net::ip::address_v4::loopback(), 53}}};
    app::DNSWorker dns{control, config, 8};
};
TEST_P(WorkerConnectionLimitRuntime, SharesBudgetAcrossWorkersAndTagsAndReturnsReleasedSlots) {
    const auto mode = GetParam();
    ExerciseWorkers(dns, mode.global, mode.per_ip, mode.limited, false);
}
TEST_P(WorkerConnectionLimitRuntime, HandlerReplacementPreservesLiveReservationsAndJoinReleasesOwners) {
    const auto mode = GetParam();
    ExerciseWorkers(dns, mode.global, mode.per_ip, mode.limited, true);
}
INSTANTIATE_TEST_SUITE_P(Limits, WorkerConnectionLimitRuntime, testing::Values(
    LimitMode{2, 0, true, "Global"}, LimitMode{0, 2, true, "PerIp"},
    LimitMode{0, 0, false, "Unlimited"},
    LimitMode{std::numeric_limits<uint32_t>::max(), 0, false, "MaximumGlobal"},
    LimitMode{0, std::numeric_limits<uint32_t>::max(), false, "MaximumPerIp"}),
    [](const testing::TestParamInfo<LimitMode>& info) { return info.param.name; });
}
