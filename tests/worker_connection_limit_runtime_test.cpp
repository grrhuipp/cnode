#include <gtest/gtest.h>

#include "app/dns/dns_worker.hpp"
#include "app/port_binding.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/rate_limiter.hpp"
#include "app/stats.hpp"
#include "app/worker.hpp"
#include "app/worker_runtime_config.hpp"
#include "app/worker_stats.hpp"
#include "common/allocator.hpp"
#include "proxy/inbound.hpp"
#include "transport/async_stream.hpp"

#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <array>
#include <atomic>
#include <chrono>
#include <exception>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
using namespace std::chrono_literals;
constexpr std::string_view kProtocol = "worker-budget-fixture";

void Require(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

struct FixtureState {
    std::thread::id owner = std::this_thread::get_id();
    unsigned created = 0;
    unsigned destroyed = 0;
    bool wrong_thread = false;
    std::weak_ptr<ConnectionLimiter> limiter;
};
thread_local FixtureState* fixture = nullptr;

class Runtime final : public proxyman::inbound::ProtocolRuntime {
public:
    std::vector<OnlineDevice> GetOnlineDevices(std::string_view) const override { return {}; }
};

// Observe actor identity without extending its lifetime. Request admission still
// travels through the real Worker handlers and physical session capabilities.
class HoldingInbound final : public Inbound {
public:
    explicit HoldingInbound(FixtureState& state)
        : state_(state) { ++state_.created; }
    ~HoldingInbound() override {
        state_.wrong_thread |= std::this_thread::get_id() != state_.owner;
        ++state_.destroyed;
    }
    net::awaitable<RelayResult> Process(
        std::unique_ptr<AsyncStream> stream, routing::Dispatcher&,
        const proxyman::inbound::ReceiverSettings&, net::io_context&,
        session::Context&, const TimeoutsConfig&, uint32_t) override {
        const std::array<char, 1> admitted{'A'};
        co_await stream->AsyncWrite(net::buffer(admitted));
        std::array<char, 1> input{};
        while (co_await stream->AsyncRead(net::buffer(input)) != 0) {}
        co_return RelayResult{};
    }
private:
    FixtureState& state_;
};

void RegisterProtocol() {
    proxyman::inbound::RegisterProxy(kProtocol, {
        .user_protocol = std::nullopt,
        .create_runtime = []() -> std::unique_ptr<proxyman::inbound::ProtocolRuntime> {
            return std::make_unique<Runtime>();
        },
        .create_tcp_handler = [](proxyman::inbound::ProtocolRuntime&, StatsShard&,
                                 ConnectionLimiter* limiter,
                                 const proxyman::inbound::BuildRequest&) -> std::unique_ptr<Inbound> {
            Require(fixture && limiter, "factory did not receive the shared limiter");
            if (fixture->created == 0) {
                fixture->limiter = limiter->weak_from_this();
            } else {
                Require(fixture->limiter.lock().get() == limiter,
                        "handler replacement changed the live admission actor");
            }
            return std::make_unique<HoldingInbound>(*fixture);
        },
    });
}

net::awaitable<void> Pause(net::io_context& io) {
    net::steady_timer timer(io, 1ms);
    co_await timer.async_wait(net::use_awaitable);
}

void Register(Worker& worker, std::string tag) {
    proxyman::inbound::BuildRequest request{
        .tag = tag, .protocol = std::string(kProtocol), .settings = {}};
    proxyman::inbound::ReceiverSettings receiver{
        .inbound_tag = tag, .inbound_tags = {}, .protocol = std::string(kProtocol),
        .stream_settings = {},
        .dispatch_policy = {{}, routing::ForceOutbound{"unused"}},
        .proxy_protocol = ProxyProtocolMode::Off};
    Require(worker.RegisterInbound(std::move(request), std::move(receiver)),
            "inbound registration failed");
}

net::awaitable<uint16_t> Listen(net::io_context& io, Worker& worker, std::string tag) {
    Register(worker, tag);
    tcp::acceptor reservation(io, {net::ip::address_v4::loopback(), 0});
    const auto port = reservation.local_endpoint().port();
    reservation.close();
    const auto listen = InboundListen::Parse("127.0.0.1");
    Require(listen.has_value(), "loopback listen parsing failed");
    Require(worker.AddListener(
                PortBinding{.port = port, .protocol = std::string(kProtocol), .tag = tag, .listen = *listen}),
            "TCP listener failed");
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
            Require(std::chrono::steady_clock::now() < deadline, "admission response timed out");
            co_await Pause(io);
            continue;
        }
        if (admitted) {
            Require(!ec && count == 1 && marker[0] == 'A', "connection budget rejected an eligible request");
        } else {
            Require(count == 0 && (ec == net::error::eof || ec == net::error::connection_reset),
                    "different inbound tag bypassed the shared connection budget");
        }
        co_return std::move(client);
    }
}

net::awaitable<void> WaitActive(net::io_context& io, Worker& worker, uint32_t expected) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while ((co_await worker.CollectRuntimeStats(false)).active_connections != expected) {
        Require(std::chrono::steady_clock::now() < deadline, "active request guards did not drain");
        co_await Pause(io);
    }
}

net::awaitable<void> Exercise(net::io_context& io, Worker& worker, FixtureState& state,
                             std::atomic<unsigned>& ready, bool limited) {
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
            Require(std::chrono::steady_clock::now() < deadline,
                    "another Worker could not consume its shared admission slot");
            co_await Pause(io);
        }
        auto second = co_await Connect(io, second_port, !limited);
        second.close();
        co_await WaitActive(io, worker, 1);

        // Repeated startup and a handler replacement must not reset live counts.
        worker.StartRuntime();
        Register(worker, "first");
        co_await worker.UnregisterListenerTask("first");
        co_await WaitActive(io, worker, 1);
        auto after_remove = co_await Connect(io, second_port, !limited);
        after_remove.close();
        co_await WaitActive(io, worker, 1);
        ready.fetch_add(1, std::memory_order_release);
        const auto rejection_deadline = std::chrono::steady_clock::now() + 3s;
        while (ready.load(std::memory_order_acquire) < 4) {
            Require(std::chrono::steady_clock::now() < rejection_deadline,
                    "another Worker did not finish its shared-budget rejection checks");
            co_await Pause(io);
        }

        first.close();
        co_await WaitActive(io, worker, 0);
        shutdown_client.emplace(co_await Connect(io, second_port, true));
    } catch (...) {
        failure = std::current_exception();
    }
    if (!failure) Register(worker, "idle");
    worker.RequestStop();
    co_await worker.AsyncJoin();
    co_await worker.AsyncJoin();
    Require(state.created == state.destroyed && !state.wrong_thread,
            "Worker join returned before owner-thread handler completion");
    if (failure) std::rethrow_exception(failure);
    std::array<char, 1> byte{};
    IoErrorCode error;
    shutdown_client->read_some(net::buffer(byte), error);
    Require(error == net::error::eof || error == net::error::connection_reset,
            "Worker join left the physical TCP read alive");
}

void RunCase(app::dns::DNSWorker& dns, uint32_t global, uint32_t per_ip, bool limited) {
    net::io_context control;
    auto coordinator = std::make_shared<GroupCoordinator>(control);
    coordinator->Start();
    std::exception_ptr control_failure;
    std::thread control_thread([&] {
        try { control.run(); }
        catch (...) { control_failure = std::current_exception(); }
    });
    std::atomic<unsigned> ready{0};
    std::array<std::exception_ptr, 2> failures{};
    std::array<std::weak_ptr<ConnectionLimiter>, 2> limiter_identities;
    std::array<std::thread, 2> threads;
    for (uint32_t id = 0; id < threads.size(); ++id) {
        threads[id] = std::thread([&, id] {
            try {
                net::io_context io;
                StatsShard stats;
                FixtureState state;
                fixture = &state;
                WorkerRuntimeConfig config;
                config.workers = 2;
                config.limits.max_connections = global;
                config.limits.max_connections_per_ip = per_ip;
                config.timeouts.idle = 0;
                config.timeouts.read = 0;
                auto worker = std::make_unique<Worker>(id, io, config, stats, dns);
                worker->SetGroupCoordinator(coordinator);
                net::co_spawn(io, Exercise(io, *worker, state, ready, limited),
                    [&](std::exception_ptr error) { failures[id] = error; });
                io.run();
                worker.reset();
                io.restart();
                while (io.poll() != 0) {}
                Require(state.created == state.destroyed && !state.wrong_thread,
                        "handler teardown lost its owning execution domain");
                limiter_identities[id] = state.limiter;
                fixture = nullptr;
            } catch (...) {
                failures[id] = std::current_exception();
            }
        });
    }
    for (auto& thread : threads) thread.join();
    net::co_spawn(control, [](std::shared_ptr<GroupCoordinator> owner) -> net::awaitable<void> {
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
    Require(!limiter_identities[0].owner_before(limiter_identities[1]) &&
            !limiter_identities[1].owner_before(limiter_identities[0]),
            "Workers did not share the same admission actor");
    for (const auto& limiter : limiter_identities) {
        Require(limiter.expired(),
                "coordinator shutdown retained an admission actor or reservation return");
    }
}
} // namespace

TEST(WorkerConnectionLimitRuntime, Contract) {
    try {
        memory::ConfigureProcessAllocator();
        RegisterProtocol();
        net::io_context control;
        app::dns::Config config{.servers = {{net::ip::address_v4::loopback(), 53}}};
        app::dns::DNSWorker dns(control, config, 8);
        RunCase(dns, 2, 0, true);
        RunCase(dns, 0, 2, true);
        RunCase(dns, 0, 0, false);
        RunCase(dns, std::numeric_limits<uint32_t>::max(), 0, false);
        RunCase(dns, 0, std::numeric_limits<uint32_t>::max(), false);
        return;
    } catch (const std::exception& error) {
        std::cerr << "Worker connection ownership: " << error.what() << '\n';
        FAIL() << error.what();
    }
}
