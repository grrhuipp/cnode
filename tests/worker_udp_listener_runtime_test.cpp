#include "worker_udp_listener_runtime_fault.hpp"

#include "acppnode/app/dns/dns_worker.hpp"
#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/app/worker_runtime_config.hpp"
#include "acppnode/app/worker_stats.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/proxy/inbound_datagram.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/inbound_listen.hpp"

#include <asio/buffer.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/redirect_error.hpp>
#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <future>
#include <thread>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
using namespace std::chrono_literals;
constexpr std::string_view kTag = "udp-runtime-fixture";
constexpr std::string_view kProtocol = "worker-udp-runtime-test";

struct Observation {
    unsigned handler = 0;
    uint8_t nonce = 0;
};
struct FixtureState {
    std::vector<Observation> observations;
    unsigned responses_created = 0;
    unsigned responses_destroyed = 0;
};

class TrackedResponse final : public acpp::InboundDatagramResponse {
public:
    explicit TrackedResponse(FixtureState& state) : state_(state) { ++state_.responses_created; }
    ~TrackedResponse() override { ++state_.responses_destroyed; }
    acpp::buf::MultiBuffer Encode(acpp::UDPPacketView) override { return {}; }
private:
    FixtureState& state_;
};

struct TokenSettings final : acpp::proxyman::inbound::ProtocolSettings {
    explicit TokenSettings(unsigned value, bool association = false)
        : token(value), create_association(association) {}
    unsigned token;
    bool create_association;
};

struct Runtime final : acpp::proxyman::inbound::ProtocolRuntime {
    std::vector<acpp::OnlineDevice> GetOnlineDevices(std::string_view) const override {
        return {};
    }
};

class Datagram final : public acpp::Inbound {
public:
    Datagram(FixtureState& state, unsigned token, bool association)
        : state_(state), token_(token), create_association_(association) {}

    acpp::net::awaitable<acpp::RelayResult> Process(
        std::unique_ptr<acpp::AsyncStream>, acpp::routing::Dispatcher&,
        const acpp::proxyman::inbound::ReceiverSettings&, acpp::net::io_context&,
        acpp::session::Context&, const acpp::TimeoutsConfig&, uint32_t) override {
        co_return acpp::RelayResult{};
    }

    std::expected<acpp::InboundDatagramResult, acpp::ErrorCode> Process(
        const acpp::InboundDatagramRequest& request) override {
        if (!request.payload.empty())
            state_.observations.push_back({token_, request.payload.front()});
        if (!create_association_ || request.payload.empty())
            return std::unexpected(acpp::ErrorCode::PROTOCOL_AUTH_FAILED);
        acpp::InboundDatagramResult decoded;
        const std::array<uint8_t, 1> owner{1};
        if (!decoded.session_owner.Assign(owner)) throw std::bad_alloc();
        decoded.session_key = std::to_string(request.payload.front());
        decoded.response = acpp::memory::AllocateShared<TrackedResponse>(state_);
        decoded.target = acpp::TargetAddress(acpp::net::ip::address_v4::loopback(), 9);
        acpp::buf::BufferGuard payload(acpp::buf::Buffer::New());
        if (!payload) throw std::bad_alloc();
        payload->data[0] = request.payload.front();
        payload->Produce(1);
        decoded.payload.push_back(std::move(payload));
        return decoded;
    }

private:
    FixtureState& state_;
    unsigned token_;
    bool create_association_;
};

thread_local FixtureState* g_state = nullptr;

std::unique_ptr<acpp::proxyman::inbound::ProtocolRuntime> MakeRuntime() {
    return std::make_unique<Runtime>();
}
const TokenSettings& Settings(const acpp::proxyman::inbound::BuildRequest& request) {
    const auto settings =
        std::dynamic_pointer_cast<const TokenSettings>(request.settings);
    if (!settings) throw std::logic_error("fixture protocol settings missing");
    return *settings;
}
std::unique_ptr<acpp::Inbound> MakeTcp(
    acpp::proxyman::inbound::ProtocolRuntime&, acpp::StatsShard&,
    acpp::ConnectionLimiterPtr,
    const acpp::proxyman::inbound::BuildRequest& request) {
    const auto& settings = Settings(request);
    return std::make_unique<Datagram>(*g_state, settings.token, settings.create_association);
}
std::unique_ptr<acpp::Inbound> MakeUdp(
    acpp::proxyman::inbound::ProtocolRuntime&, acpp::StatsShard&,
    acpp::ConnectionLimiterPtr,
    const acpp::proxyman::inbound::BuildRequest& request) {
    const auto& settings = Settings(request);
    return std::make_unique<Datagram>(*g_state, settings.token, settings.create_association);
}

void RegisterFixtureProtocol() {
    static const bool registered = [] {
        acpp::proxyman::inbound::RegisterProxy(kProtocol, {
            .create_runtime = MakeRuntime,
            .create_tcp_handler = MakeTcp,
            .create_datagram_handler = MakeUdp,
        });
        return true;
    }();
    (void)registered;
}

[[noreturn]] void Fail(std::string_view message) {
    throw std::runtime_error(std::string(message));
}

uint16_t ReservePort(acpp::net::io_context& io) {
    acpp::udp::socket reservation(io);
    acpp::IoErrorCode ec;
    reservation.open(acpp::udp::v4(), ec);
    if (ec) Fail("could not open UDP port reservation socket");
    reservation.bind({acpp::net::ip::address_v4::loopback(), 0}, ec);
    if (ec) Fail("could not bind UDP port reservation socket");
    const auto port = reservation.local_endpoint(ec).port();
    if (ec) Fail("could not query UDP reservation port");
    reservation.close(ec);
    if (ec) Fail("could not release UDP reservation port");
    return port;
}

bool IPv6Available(acpp::net::io_context& io) {
    acpp::udp::socket probe(io);
    acpp::IoErrorCode ec;
    probe.open(acpp::udp::v6(), ec);
    if (ec) return false;
    probe.set_option(acpp::net::ip::v6_only(true), ec);
    if (ec) return false;
    probe.bind({acpp::net::ip::address_v6::any(), 0}, ec);
    return !ec;
}

acpp::proxyman::inbound::BuildRequest BuildRequest(unsigned token, bool association = false) {
    return {.tag = std::string(kTag),
            .protocol = std::string(kProtocol),
            .settings = std::make_shared<TokenSettings>(token, association)};
}

acpp::proxyman::inbound::ReceiverSettings BuildReceiver() {
    return {.inbound_tag = std::string(kTag),
            .protocol = std::string(kProtocol),
            .dispatch_policy = {
                .outbound = acpp::routing::ForceOutbound{"unused-fixture-target"}}};
}

acpp::net::awaitable<void> Pause(acpp::net::io_context& io,
                                 std::chrono::milliseconds delay = 5ms) {
    acpp::net::steady_timer timer(io, delay);
    co_await timer.async_wait(acpp::net::use_awaitable);
}

acpp::net::awaitable<acpp::Worker::RuntimeStatsSnapshot> Snapshot(
    acpp::Worker& worker) {
    co_return co_await worker.CollectRuntimeStatsTask(true);
}

acpp::net::awaitable<void> WaitForObservation(
    acpp::net::io_context& io, const FixtureState& state, std::size_t previous_count,
    unsigned expected_handler, uint8_t expected_nonce) {
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (state.observations.size() <= previous_count &&
           std::chrono::steady_clock::now() < deadline) co_await Pause(io);
    if (state.observations.size() <= previous_count)
        Fail("real Worker UDP listener did not process datagram before timeout");
    const auto& observation = state.observations.back();
    if (observation.handler != expected_handler || observation.nonce != expected_nonce)
        Fail("datagram was not processed by the expected old/new protocol handler");
}

void Send(acpp::udp::socket& sender, uint16_t port, uint8_t nonce) {
    const std::array<uint8_t, 1> bytes{nonce};
    acpp::IoErrorCode ec;
    sender.send_to(asio::buffer(bytes),
                   {acpp::net::ip::address_v4::loopback(), port}, 0, ec);
    if (ec) Fail("loopback UDP send failed");
}

acpp::net::awaitable<void> SendAndVerify(
    acpp::net::io_context& io, acpp::udp::socket& sender, uint16_t port,
    FixtureState& state, unsigned handler, uint8_t nonce) {
    const auto previous_count = state.observations.size();
    Send(sender, port, nonce);
    co_await WaitForObservation(io, state, previous_count, handler, nonce);
}

acpp::net::awaitable<void> WaitForListenerCounts(
    acpp::net::io_context& io, acpp::Worker& worker,
    std::size_t listeners, std::size_t loops) {
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto snapshot = co_await Snapshot(worker);
        if (snapshot.resources &&
            snapshot.resources->udp_listeners == listeners &&
            snapshot.resources->udp_receive_loops == loops) co_return;
        co_await Pause(io);
    }
    Fail("UDP listener and receive-loop counts did not drain to the expected values");
}

acpp::net::awaitable<void> DrainWorker(
    acpp::net::io_context& io, std::unique_ptr<acpp::Worker>& worker) {
    if (!worker) co_return;
    co_await worker->UnregisterListenerTask(std::string(kTag));
    co_await WaitForListenerCounts(io, *worker, 0, 0);
    worker.reset();
}

struct TwoWorkerResult {
    bool ok = false;
    acpp::WorkerResourceStats resources{};
    unsigned responses_created = 0;
    unsigned responses_destroyed = 0;
    std::string error;
};

acpp::net::awaitable<void> RunAssociationWorker(
    acpp::net::io_context& io, acpp::Worker& worker, FixtureState& state,
    uint16_t port, std::promise<bool>& ready, std::promise<TwoWorkerResult>& done,
    std::shared_future<void> packets_sent) {
    TwoWorkerResult result;
    bool ready_published = false;
    bool listener_registered = false;
    try {
        co_await worker.StartRuntimeTask();
        const auto request = BuildRequest(worker.Id() + 1, true);
        if (!co_await worker.RegisterInboundTask({}, request, BuildReceiver()))
            Fail("two-worker inbound registration failed");
        const auto listen = acpp::InboundListen::Parse("0.0.0.0");
        if (!listen) Fail("could not prepare shared IPv4 listener");
        const auto binding = acpp::MakePortBinding(
            port, std::string(kProtocol), std::string(kTag), *listen);
        if (!co_await worker.AddUdpListenerTask(binding, {}, request))
            Fail("two-worker UDP listener registration failed");
        listener_registered = true;
        auto initial = co_await Snapshot(worker);
        if (!initial.resources || initial.resources->udp_listeners == 0 ||
            initial.resources->udp_listeners > 2 ||
            initial.resources->udp_receive_loops != initial.resources->udp_listeners)
            Fail("two-worker listener did not register its expected receive loops");
        ready.set_value(true);
        ready_published = true;
        // Test-only cold barrier: receive loops and their sockets are owned by
        // this thread; packets wait in the kernel until both workers are ready.
        packets_sent.wait();
        co_await Pause(io, 900ms);

        // This is the sole final owner-thread collection. No monitoring,
        // intermediate stats, explicit cleanup or new packets during silence.
        const auto final = co_await Snapshot(worker);
        if (!final.resources || final.resources->udp_listeners == 0 ||
            final.resources->udp_listeners > 2 ||
            final.resources->udp_receive_loops != final.resources->udp_listeners ||
            final.resources->udp_associations != 0 ||
            final.resources->udp_closed_associations != 0 ||
            final.resources->udp_input_datagrams != 0 ||
            final.active_connections != 0)
            Fail("two-worker association rows or listener ownership did not drain naturally");
        result.resources = *final.resources;
        result.responses_created = state.responses_created;
        result.responses_destroyed = state.responses_destroyed;
        if (result.responses_created != result.responses_destroyed)
            Fail("two-worker response owners survived natural association reclamation");

        co_await worker.UnregisterListenerTask(std::string(kTag));
        for (unsigned attempt = 0; ; ++attempt) {
            const auto retired = co_await Snapshot(worker);
            if (retired.resources && retired.resources->udp_listeners == 0 &&
                retired.resources->udp_receive_loops == 0) break;
            if (attempt == 100) Fail("two-worker retired receive loops did not finish");
            co_await Pause(io, 2ms);
        }
        result.ok = true;
    } catch (const std::exception& e) {
        result.error = e.what();
        if (!ready_published) {
            try { ready.set_value(false); } catch (...) {}
            ready_published = true;
        }
    } catch (...) {
        result.error = "unknown two-worker setup/runtime exception";
        if (!ready_published) {
            try { ready.set_value(false); } catch (...) {}
            ready_published = true;
        }
    }
    if (!result.ok && listener_registered) {
        try {
            co_await worker.UnregisterListenerTask(std::string(kTag));
            co_await Pause(io, 10ms);
        } catch (...) {}
    }
    done.set_value(std::move(result));
}

void RunTwoWorkerAssociations(acpp::app::dns::DNSWorker& dns,
                              const acpp::WorkerRuntimeConfig& base_config,
                              uint16_t port) {
    std::array<std::promise<bool>, 2> ready_promises;
    std::array<std::future<bool>, 2> ready;
    std::array<std::promise<TwoWorkerResult>, 2> done_promises;
    std::array<std::future<TwoWorkerResult>, 2> done;
    for (std::size_t i = 0; i != 2; ++i) {
        ready[i] = ready_promises[i].get_future();
        done[i] = done_promises[i].get_future();
    }
    std::promise<void> sent_promise;
    const auto packets_sent = sent_promise.get_future().share();
    std::array<std::thread, 2> workers;
    for (std::size_t i = 0; i != 2; ++i) {
        workers[i] = std::thread([&, i, config = base_config]() mutable {
            try {
                acpp::net::io_context io;
                acpp::StatsShard stats;
                FixtureState state;
                g_state = &state;
                auto worker = std::make_unique<acpp::Worker>(
                    static_cast<uint32_t>(i), io, config, stats, dns);
                acpp::net::co_spawn(io,
                    RunAssociationWorker(io, *worker, state, port,
                                         ready_promises[i], done_promises[i], packets_sent),
                    [&worker, &ready_promise = ready_promises[i],
                     &done_promise = done_promises[i]](std::exception_ptr error) {
                        if (!error) return;
                        worker.reset();
                        try { ready_promise.set_value(false); } catch (...) {}
                        try {
                            TwoWorkerResult failure;
                            failure.error = "two-worker coroutine escaped with an exception";
                            done_promise.set_value(std::move(failure));
                        } catch (...) {}
                    });
                io.run();
                if (worker) worker.reset();
                io.restart();
                while (io.poll() != 0) {}
            } catch (const std::exception& e) {
                try { ready_promises[i].set_value(false); } catch (...) {}
                try {
                    TwoWorkerResult failure;
                    failure.error = e.what();
                    done_promises[i].set_value(std::move(failure));
                } catch (...) {}
            } catch (...) {
                try { ready_promises[i].set_value(false); } catch (...) {}
                try {
                    TwoWorkerResult failure;
                    failure.error = "unknown worker thread setup exception";
                    done_promises[i].set_value(std::move(failure));
                } catch (...) {}
            }
        });
    }

    for (auto& future : ready) {
        if (!future.get()) {
            sent_promise.set_value(); // release any successfully started peer
            for (auto& thread : workers) if (thread.joinable()) thread.join();
            Fail("a two-worker runtime failed before becoming ready");
        }
    }
    acpp::net::io_context sender_io;
    acpp::udp::socket sender(sender_io, acpp::udp::v4());
    for (uint8_t nonce = 1; nonce <= 30; ++nonce) Send(sender, port, nonce);
    sent_promise.set_value(); // the common post-send quiet interval starts here
    std::array<TwoWorkerResult, 2> results;
    for (std::size_t i = 0; i != 2; ++i) results[i] = done[i].get();
    for (auto& thread : workers) if (thread.joinable()) thread.join();
    for (const auto& result : results)
        if (!result.ok) Fail(result.error.empty() ? "two-worker runtime failed" : result.error);
    const unsigned created = results[0].responses_created + results[1].responses_created;
    const unsigned destroyed = results[0].responses_destroyed + results[1].responses_destroyed;
    if (created != 30 || destroyed != 30)
        Fail("the two Workers did not reclaim all 30 association responses");
}

acpp::net::awaitable<bool> CancelledSameSocketUpdate(
    acpp::Worker& worker, acpp::PortBinding binding,
    acpp::proxyman::inbound::BuildRequest request,
    acpp::net::steady_timer& gate, bool& started) {
    co_await acpp::net::this_coro::throw_if_cancelled(false);
    started = true;
    acpp::IoErrorCode ec;
    co_await gate.async_wait(acpp::net::bind_cancellation_slot(
        acpp::net::cancellation_slot{},
        acpp::net::redirect_error(acpp::net::use_awaitable, ec)));
    if (ec != acpp::net::error::operation_aborted)
        Fail("same-socket cancellation gate was not explicitly released");
    co_return co_await worker.AddUdpListenerTask(std::move(binding), {}, std::move(request));
}

acpp::net::awaitable<void> VerifyCancelledSameSocket(
    acpp::net::io_context& io, acpp::Worker& worker,
    acpp::PortBinding binding, acpp::proxyman::inbound::BuildRequest request) {
    acpp::net::steady_timer gate(io);
    gate.expires_at(acpp::net::steady_timer::time_point::max());
    acpp::net::cancellation_signal cancellation;
    bool started = false;
    bool finished = false;
    bool cancelled = false;
    acpp::net::co_spawn(io,
        CancelledSameSocketUpdate(worker, std::move(binding), std::move(request), gate, started),
        acpp::net::bind_cancellation_slot(cancellation.slot(),
            [&](std::exception_ptr error, bool) {
                finished = true;
                if (!error) return;
                try { std::rethrow_exception(error); }
                catch (const acpp::IoSystemError& e) {
                    cancelled = e.code() == acpp::net::error::operation_aborted;
                } catch (...) {}
            }));
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!started && std::chrono::steady_clock::now() < deadline) co_await Pause(io);
    if (!started) Fail("same-socket cancellation child did not start");
    cancellation.emit(acpp::net::cancellation_type::terminal);
    gate.cancel();
    while (!finished && std::chrono::steady_clock::now() < deadline) co_await Pause(io);
    if (!finished || !cancelled)
        Fail("already-cancelled same-socket update returned success with automatic throwing disabled");
}

enum class Mode { Success, PrepareStandard, PreparePmr, Spawn, Ready, SameSocketCancel,
                  Associations, TwoWorkersAssociations, Maintenance };
struct Options {
    Mode mode = Mode::Success;
    std::size_t budget_or_index = 0;
};

acpp::net::awaitable<void> RunCases(
    acpp::net::io_context& io, acpp::Worker& worker,
    std::unique_ptr<acpp::Worker>& worker_owner,
    FixtureState& state, uint16_t port, Options options, int& result) {
    try {
        co_await worker.StartRuntimeTask();
        const auto auto_listen = acpp::InboundListen::Parse("auto");
        const auto ipv4_wildcard = acpp::InboundListen::Parse("0.0.0.0");
        if (!auto_listen || !ipv4_wildcard) Fail("could not prepare listener endpoints");

        auto old_request = BuildRequest(1,
            options.mode == Mode::Associations || options.mode == Mode::Maintenance);
        if (!co_await worker.RegisterInboundTask({}, old_request, BuildReceiver()))
            Fail("Worker::RegisterInboundTask failed");
        const auto old_listen = (options.mode == Mode::Spawn || options.mode == Mode::Ready)
            ? *ipv4_wildcard : *auto_listen;
        const auto old_binding = acpp::MakePortBinding(
            port, std::string(kProtocol), std::string(kTag), old_listen);
        if (!co_await worker.AddUdpListenerTask(old_binding, {}, old_request))
            Fail("initial Worker::AddUdpListenerTask failed");

        acpp::udp::socket sender(io, acpp::udp::v4());
        const auto initial = co_await Snapshot(worker);
        if (!initial.resources || initial.resources->udp_listeners == 0 ||
            initial.resources->udp_receive_loops != initial.resources->udp_listeners)
            Fail("initial real listener and receive-loop metrics are inconsistent");
        if (options.mode == Mode::Maintenance) {
            worker_udp_listener_runtime_test::Configure(
                "udp-maintenance", static_cast<int>(options.budget_or_index),
                worker_udp_listener_runtime_test::FaultKind::Pmr);
            // A burst exceeding one global batch keeps rows for a genuine
            // callback rearm, not a fake throw or a packet-triggered cleanup.
            for (uint8_t nonce = 1; nonce <= 130; ++nonce) Send(sender, port, nonce);
            co_await Pause(io, 1s);
            Fail("configured maintenance allocation fault did not terminate scheduling");
        }
        if (options.mode == Mode::Associations) {
            for (uint8_t nonce = 1; nonce <= 30; ++nonce)
                co_await SendAndVerify(io, sender, port, state, 1, nonce);
            // No monitoring, intermediate stats, cleanup, collection or new
            // packet during this quiet period. Only maintenance may erase rows.
            co_await Pause(io, 350ms);
            const auto final = co_await Snapshot(worker);
            if (!final.resources || final.resources->udp_associations != 0 ||
                final.resources->udp_closed_associations != 0 ||
                final.resources->udp_input_datagrams != 0 ||
                final.resources->udp_input_bytes != 0)
                Fail("closed native associations were retained without new packets");
            if (state.responses_created != 30 || state.responses_destroyed != 30)
                Fail("association response owners did not finish after natural row reclamation");
            co_await DrainWorker(io, worker_owner);
            result = 0;
            co_return;
        }
        co_await SendAndVerify(io, sender, port, state, 1, 0x31);

        if (options.mode == Mode::SameSocketCancel) {
            co_await VerifyCancelledSameSocket(io, worker,
                acpp::MakePortBinding(port, std::string(kProtocol), std::string(kTag), old_listen),
                BuildRequest(2));
            co_await SendAndVerify(io, sender, port, state, 1, 0x32);
            co_await DrainWorker(io, worker_owner);
            result = 0;
            co_return;
        }

        if (((options.mode == Mode::Spawn && options.budget_or_index == 1) ||
             options.mode == Mode::Ready) && !IPv6Available(io)) {
            std::fprintf(stderr, "SKIP: IPv6 unavailable; cannot exercise spawn index 1\n");
            co_await DrainWorker(io, worker_owner);
            result = 77;
            co_return;
        }

        auto replacement_request = BuildRequest(2);
        const auto new_listen = (options.mode == Mode::Spawn || options.mode == Mode::Ready)
            ? *auto_listen : *ipv4_wildcard;
        const auto replacement = acpp::MakePortBinding(
            port, std::string(kProtocol), std::string(kTag), new_listen);

        if (options.mode == Mode::PrepareStandard) {
            worker_udp_listener_runtime_test::Configure(
                "prepare-listener", 0,
                worker_udp_listener_runtime_test::FaultKind::Standard,
                options.budget_or_index);
        } else if (options.mode == Mode::PreparePmr) {
            worker_udp_listener_runtime_test::Configure(
                "prepare-listener", 0,
                worker_udp_listener_runtime_test::FaultKind::Pmr);
        } else if (options.mode == Mode::Spawn) {
            worker_udp_listener_runtime_test::Configure(
                "spawn", static_cast<int>(options.budget_or_index),
                worker_udp_listener_runtime_test::FaultKind::Standard);
        } else if (options.mode == Mode::Ready) {
            worker_udp_listener_runtime_test::Configure(
                "ready", 0, worker_udp_listener_runtime_test::FaultKind::Standard);
        }

        if (options.mode == Mode::PrepareStandard || options.mode == Mode::PreparePmr) {
            bool threw_bad_alloc = false;
            try {
                (void)co_await worker.AddUdpListenerTask(
                    replacement, {}, replacement_request);
            } catch (const std::bad_alloc&) {
                threw_bad_alloc = true;
            }
            worker_udp_listener_runtime_test::ReportPmrConsumption();
            if (options.mode == Mode::PrepareStandard && !threw_bad_alloc &&
                worker_udp_listener_runtime_test::fault.preparation_finished &&
                !worker_udp_listener_runtime_test::fault.consumed) {
                // The first budget beyond the complete cold allocation window
                // finishes the sweep. It must now serve the replacement.
                co_await WaitForListenerCounts(io, worker, 1, 1);
                co_await SendAndVerify(io, sender, port, state, 2, 0x43);
                std::fprintf(stderr,
                    "udp-listener-prepare-sweep complete allocations=%zu budget=%zu\n",
                    worker_udp_listener_runtime_test::fault.hooks_after_arm,
                    options.budget_or_index);
                co_await DrainWorker(io, worker_owner);
                result = 0;
                co_return;
            }
            if (!threw_bad_alloc || !worker_udp_listener_runtime_test::fault.consumed)
                Fail("precommit allocation fault was not consumed by the real allocator");
            if (options.mode == Mode::PrepareStandard &&
                worker_udp_listener_runtime_test::fault.hooks_after_arm !=
                    options.budget_or_index + 1)
                Fail("standard allocation budget did not fail at the requested hook");
            const auto after_failure = co_await Snapshot(worker);
            if (!after_failure.resources ||
                after_failure.resources->udp_listeners != initial.resources->udp_listeners ||
                after_failure.resources->udp_receive_loops != initial.resources->udp_receive_loops)
                Fail("precommit failure changed live listener or receive-loop counts");
            co_await SendAndVerify(io, sender, port, state, 1, 0x32);
            co_await DrainWorker(io, worker_owner);
            result = 0;
            co_return;
        }

        // Spawn failures are intentionally fatal in Worker::StartUdpListening;
        // the CTest subprocess asserts the production phase and exit status.
        if (!co_await worker.AddUdpListenerTask(replacement, {}, replacement_request))
            Fail("replacement Worker::AddUdpListenerTask failed");
        if (options.mode == Mode::Success) {
            co_await WaitForListenerCounts(io, worker, 1, 1);
            co_await SendAndVerify(io, sender, port, state, 2, 0x42);
            co_await worker.UnregisterListenerTask(std::string(kTag));
            co_await WaitForListenerCounts(io, worker, 0, 0);
            worker_owner.reset();
            result = 0;
            co_return;
        }

        Fail("configured spawn fault did not terminate during the real co_spawn call");
    } catch (const std::exception& error) {
        std::cerr << "worker UDP runtime fixture: " << error.what() << '\n';
        result = 2;
    } catch (...) {
        std::cerr << "worker UDP runtime fixture: unknown exception\n";
        result = 2;
    }
    if (worker_owner) {
        try {
            co_await DrainWorker(io, worker_owner);
        } catch (const std::exception& cleanup_error) {
            std::cerr << "worker UDP cleanup: " << cleanup_error.what() << '\n';
            result = 2;
        } catch (...) {
            std::cerr << "worker UDP cleanup: unknown exception\n";
            result = 2;
        }
    }
}

bool ParseOptions(int argc, char** argv, Options& options) {
    if (argc == 1) return true;
    if (argc == 2 && std::string_view(argv[1]) == "--associations") {
        options.mode = Mode::Associations;
        return true;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--two-workers-associations") {
        options.mode = Mode::TwoWorkersAssociations;
        return true;
    }
    if (argc == 3 && std::string_view(argv[1]) == "--prepare-fault-std") {
        options.mode = Mode::PrepareStandard;
        options.budget_or_index = static_cast<std::size_t>(std::strtoul(argv[2], nullptr, 10));
        return true;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--prepare-fault-pmr") {
        options.mode = Mode::PreparePmr;
        return true;
    }
    if (argc == 3 && std::string_view(argv[1]) == "--maintenance-fault") {
        options.mode = Mode::Maintenance;
        options.budget_or_index = static_cast<std::size_t>(std::strtoul(argv[2], nullptr, 10));
        return options.budget_or_index <= 1;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--ready-fault") {
        options.mode = Mode::Ready;
        return true;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--same-socket-cancel") {
        options.mode = Mode::SameSocketCancel;
        return true;
    }
    if (argc == 3 && std::string_view(argv[1]) == "--spawn-fault") {
        options.mode = Mode::Spawn;
        options.budget_or_index = static_cast<std::size_t>(std::strtoul(argv[2], nullptr, 10));
        return options.budget_or_index <= 1;
    }
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    std::set_terminate([] {
        try {
            if (const auto error = std::current_exception()) std::rethrow_exception(error);
        } catch (const std::exception& error) {
            std::fprintf(stderr, "worker UDP fixture terminated: %s\n", error.what());
        } catch (...) {
            std::fprintf(stderr, "worker UDP fixture terminated: unknown exception\n");
        }
        std::fflush(stderr);
        std::_Exit(99);
    });
    Options options;
    if (!ParseOptions(argc, argv, options)) {
        std::cerr << "usage: worker_udp_listener_runtime_test [--prepare-fault-std BUDGET | --prepare-fault-pmr | --spawn-fault INDEX | --ready-fault | --same-socket-cancel | --maintenance-fault INDEX | --associations | --two-workers-associations]\n";
        return 64;
    }

    acpp::memory::ConfigureProcessAllocator();
    RegisterFixtureProtocol();
    if (options.mode == Mode::Ready &&
        !acpp::Log::Init("debug", ".", 15, {}, {}, false, false)) {
        std::cerr << "readiness formatting fault requires debug logging\n";
        return 2;
    }
    acpp::net::io_context io;
    acpp::app::dns::Config dns_config{
        .servers = {{acpp::net::ip::address_v4::loopback(), 53}}};
    acpp::app::dns::DNSWorker dns(io, dns_config, 8);
    acpp::StatsShard stats;
    acpp::WorkerRuntimeConfig runtime_config;
    runtime_config.mailbox_capacity = 8;
    FixtureState state;
    g_state = &state;
    const uint16_t port = ReservePort(io);
    if (options.mode == Mode::TwoWorkersAssociations) {
        try {
            RunTwoWorkerAssociations(dns, runtime_config, port);
            return 0;
        } catch (const std::exception& error) {
            std::cerr << "two-worker UDP associations: " << error.what() << '\n';
            return 2;
        }
    }
    auto worker = std::make_unique<acpp::Worker>(0, io, runtime_config, stats, dns);
    int result = 2;
    acpp::net::co_spawn(
        io, RunCases(io, *worker, worker, state, port, options, result),
        [&result](std::exception_ptr error) {
            if (!error) return;
            try {
                std::rethrow_exception(error);
            } catch (const std::exception& e) {
                std::cerr << "worker UDP runtime fixture completion: " << e.what() << '\n';
            } catch (...) {
                std::cerr << "worker UDP runtime fixture completion: unknown exception\n";
            }
            result = 2;
        });
    io.run();
    if (worker) {
        // RunCases must perform same-thread unregister, receive-loop drain, and
        // destruction; reaching here with a live Worker means cleanup failed.
        std::cerr << "worker UDP runtime fixture left Worker runtime alive\n";
        worker.reset();
        return 2;
    }
    return result;
}
