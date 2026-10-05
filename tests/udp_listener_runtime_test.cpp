#include "runtime_services_fixture.hpp"

#include "acppnode/app/dns/dns_service.hpp"
#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/runtime/runtime.hpp"
#include "acppnode/runtime/runtime_config.hpp"
#include "acppnode/runtime/runtime_stats.hpp"
#include "acppnode/common/allocator.hpp"
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
#include <exception>
#include <iostream>
#include <memory>
#include <thread>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
using namespace std::chrono_literals;
constexpr std::string_view kTag = "udp-runtime-fixture";
constexpr std::string_view kProtocol = "runtime-udp-runtime-test";

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

struct FixtureProtocolRuntime final : acpp::proxyman::inbound::ProtocolRuntime {};

class Datagram final : public acpp::Inbound {
public:
    Datagram(FixtureState& state, unsigned token, bool association,
             acpp::UserOnlineTracker& online)
        : Inbound(online), state_(state), token_(token),
          create_association_(association) {}

    acpp::net::awaitable<acpp::RelayResult> ProcessSession(
        std::unique_ptr<acpp::AsyncStream>, acpp::routing::Dispatcher&,
        const acpp::proxyman::inbound::ReceiverSettings&, acpp::net::any_io_executor,
        acpp::session::Context&, acpp::StatsShard&, acpp::UserOnlineLease&,
        const acpp::TimeoutsConfig&, uint32_t) override {
        co_return acpp::RelayResult{};
    }

    tl::expected<acpp::InboundDatagramResult, acpp::ErrorCode> Process(
        const acpp::InboundDatagramRequest& request) override {
        if (!request.payload.empty())
            state_.observations.push_back({token_, request.payload.front()});
        if (!create_association_ || request.payload.empty())
            return tl::unexpected(acpp::ErrorCode::PROTOCOL_AUTH_FAILED);
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

FixtureState* g_state = nullptr;

std::unique_ptr<acpp::proxyman::inbound::ProtocolRuntime> MakeRuntime(
    acpp::net::any_io_executor) {
    return std::make_unique<FixtureProtocolRuntime>();
}
const TokenSettings& Settings(const acpp::proxyman::inbound::BuildRequest& request) {
    const auto settings =
        std::dynamic_pointer_cast<const TokenSettings>(request.settings);
    if (!settings) throw std::logic_error("fixture protocol settings missing");
    return *settings;
}
std::unique_ptr<acpp::Inbound> MakeTcp(
    acpp::proxyman::inbound::ProtocolRuntime&, acpp::UserOnlineTracker& online,
    acpp::ConnectionLimiterPtr,
    const acpp::proxyman::inbound::BuildRequest& request) {
    const auto& settings = Settings(request);
    return std::make_unique<Datagram>(
        *g_state, settings.token, settings.create_association, online);
}
std::unique_ptr<acpp::Inbound> MakeUdp(
    acpp::proxyman::inbound::ProtocolRuntime&, acpp::UserOnlineTracker& online,
    acpp::ConnectionLimiterPtr,
    const acpp::proxyman::inbound::BuildRequest& request) {
    const auto& settings = Settings(request);
    return std::make_unique<Datagram>(
        *g_state, settings.token, settings.create_association, online);
}

void RegisterFixtureProtocol() {
    static const bool registered = [] {
        acpp::proxyman::inbound::RegisterProxy(kProtocol, {
            .user_protocol = {},
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

uint16_t ReservePort(acpp::net::any_io_executor executor) {
    acpp::udp::socket reservation(executor);
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

acpp::proxyman::inbound::BuildRequest BuildRequest(unsigned token, bool association = false) {
    return {.tag = std::string(kTag),
            .protocol = std::string(kProtocol),
            .settings = std::make_shared<TokenSettings>(token, association)};
}

acpp::proxyman::inbound::ReceiverSettings BuildReceiver() {
    return {.inbound_tag = std::string(kTag),
            .inbound_tags = {},
            .protocol = std::string(kProtocol),
            .stream_settings = {},
            .dispatch_policy = {
                .sniffing = {},
                .outbound = acpp::routing::ForceOutbound{"unused-fixture-target"}}};
}

acpp::net::awaitable<void> Pause(acpp::net::any_io_executor executor,
                                 std::chrono::milliseconds delay = 5ms) {
    acpp::net::steady_timer timer(executor, delay);
    co_await timer.async_wait(acpp::net::use_awaitable);
}

acpp::net::awaitable<acpp::Runtime::RuntimeStatsSnapshot> Snapshot(
    acpp::Runtime& runtime) {
    co_return co_await runtime.CollectRuntimeStats(true);
}

acpp::net::awaitable<void> WaitForObservation(
    acpp::net::any_io_executor executor, const FixtureState& state, std::size_t previous_count,
    unsigned expected_handler, uint8_t expected_nonce) {
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (state.observations.size() <= previous_count &&
           std::chrono::steady_clock::now() < deadline) co_await Pause(executor);
    if (state.observations.size() <= previous_count)
        Fail("real Runtime UDP listener did not process datagram before timeout");
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
    acpp::net::any_io_executor executor, acpp::udp::socket& sender, uint16_t port,
    FixtureState& state, unsigned handler, uint8_t nonce) {
    const auto previous_count = state.observations.size();
    Send(sender, port, nonce);
    co_await WaitForObservation(executor, state, previous_count, handler, nonce);
}

acpp::net::awaitable<void> WaitForListenerCounts(
    acpp::net::any_io_executor executor, acpp::Runtime& runtime,
    std::size_t listeners, std::size_t loops) {
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto snapshot = co_await Snapshot(runtime);
        if (snapshot.resources &&
            snapshot.resources->udp_listeners == listeners &&
            snapshot.resources->udp_receive_loops == loops) co_return;
        co_await Pause(executor);
    }
    Fail("UDP listener and receive-loop counts did not drain to the expected values");
}

struct RuntimeRun {
    bool started = false;
    bool finished = false;
    std::exception_ptr error;
};

acpp::net::awaitable<void> DrainRuntime(
    acpp::net::any_io_executor executor, std::unique_ptr<acpp::Runtime>& runtime,
    RuntimeRun& run) {
    if (!runtime) co_return;
    co_await runtime->UnregisterListener(std::string(kTag));
    co_await WaitForListenerCounts(executor, *runtime, 0, 0);
    co_await runtime->Stop();
    if (run.started) {
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (!run.finished && std::chrono::steady_clock::now() < deadline)
            co_await Pause(executor);
        if (!run.finished) Fail("Runtime::Run did not finish after Stop");
        if (run.error) std::rethrow_exception(run.error);
    }
    runtime.reset();
}

acpp::net::awaitable<bool> CancelledSameSocketUpdate(
    acpp::Runtime& runtime, acpp::PortBinding binding,
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
    co_return co_await runtime.AddUdpListener(std::move(binding), {}, std::move(request));
}

acpp::net::awaitable<void> VerifyCancelledSameSocket(
    acpp::net::any_io_executor executor, acpp::Runtime& runtime,
    acpp::PortBinding binding, acpp::proxyman::inbound::BuildRequest request) {
    acpp::net::steady_timer gate(executor);
    gate.expires_at(acpp::net::steady_timer::time_point::max());
    acpp::net::cancellation_signal cancellation;
    bool started = false;
    bool finished = false;
    bool cancelled = false;
    acpp::net::co_spawn(executor,
        CancelledSameSocketUpdate(runtime, std::move(binding), std::move(request), gate, started),
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
    while (!started && std::chrono::steady_clock::now() < deadline) co_await Pause(executor);
    if (!started) Fail("same-socket cancellation child did not start");
    cancellation.emit(acpp::net::cancellation_type::terminal);
    gate.cancel();
    while (!finished && std::chrono::steady_clock::now() < deadline) co_await Pause(executor);
    if (!finished || !cancelled)
        Fail("already-cancelled same-socket update returned success with automatic throwing disabled");
}

enum class Mode { Success, Associations, SameSocketCancel, StartFailure };
struct Options {
    Mode mode = Mode::Success;
};

acpp::net::awaitable<void> RunCases(
    acpp::net::any_io_executor executor, acpp::Runtime& runtime,
    std::unique_ptr<acpp::Runtime>& runtime_owner,
    FixtureState& state, uint16_t port, Options options, int& result) {
    RuntimeRun run;
    try {
        co_await runtime.Initialize();
        acpp::net::co_spawn(executor, runtime.Run(), [&run](std::exception_ptr error) {
            run.error = std::move(error);
            run.finished = true;
        });
        run.started = true;
        const auto auto_listen = acpp::InboundListen::Parse("auto");
        const auto ipv4_wildcard = acpp::InboundListen::Parse("0.0.0.0");
        if (!auto_listen || !ipv4_wildcard) Fail("could not prepare listener endpoints");

        auto old_request = BuildRequest(1, options.mode == Mode::Associations);
        if (!co_await runtime.RegisterInbound({}, old_request, BuildReceiver()))
            Fail("Runtime::RegisterInbound failed");
        const auto old_binding = acpp::MakePortBinding(
            port, std::string(kProtocol), std::string(kTag), *auto_listen);
        if (options.mode == Mode::StartFailure) {
            acpp::udp::socket blocker(executor, acpp::udp::v4());
            acpp::IoErrorCode ec;
            blocker.bind({acpp::net::ip::address_v4::any(), port}, ec);
            if (ec) Fail("could not occupy UDP port for startup failure test");
            const auto collision_binding = acpp::MakePortBinding(
                port, std::string(kProtocol), std::string(kTag), *ipv4_wildcard);
            if (co_await runtime.AddUdpListener(collision_binding, {}, old_request))
                Fail("UDP listener unexpectedly started on occupied port");
            const auto failed = co_await Snapshot(runtime);
            if (!failed.resources || failed.resources->udp_listeners != 0 ||
                failed.resources->udp_receive_loops != 0)
                Fail("failed UDP listener startup changed live resources");
            co_await DrainRuntime(executor, runtime_owner, run);
            result = 0;
            co_return;
        }
        if (!co_await runtime.AddUdpListener(old_binding, {}, old_request))
            Fail("initial Runtime::AddUdpListener failed");

        acpp::udp::socket sender(executor, acpp::udp::v4());
        const auto initial = co_await Snapshot(runtime);
        if (!initial.resources || initial.resources->udp_listeners == 0 ||
            initial.resources->udp_receive_loops != initial.resources->udp_listeners)
            Fail("initial real listener and receive-loop metrics are inconsistent");
        if (options.mode == Mode::Associations) {
            for (uint8_t nonce = 1; nonce <= 30; ++nonce)
                co_await SendAndVerify(executor, sender, port, state, 1, nonce);
            // No monitoring, intermediate cleanup or new packet during this
            // quiet period; closed associations must be reclaimed on their own.
            co_await Pause(executor, 350ms);
            const auto final = co_await Snapshot(runtime);
            if (!final.resources || final.resources->udp_associations != 0 ||
                final.resources->udp_retiring_associations != 0)
                Fail("closed native associations were retained without new packets");
            if (final.resources->udp_input_datagrams != 30 ||
                final.resources->udp_input_bytes != 30)
                Fail("reclaiming associations discarded cumulative input statistics");
            if (state.responses_created != 30 || state.responses_destroyed != 30)
                Fail("association response owners did not finish after natural row reclamation");
            co_await DrainRuntime(executor, runtime_owner, run);
            result = 0;
            co_return;
        }
        co_await SendAndVerify(executor, sender, port, state, 1, 0x31);

        if (options.mode == Mode::SameSocketCancel) {
            co_await VerifyCancelledSameSocket(executor, runtime,
                acpp::MakePortBinding(port, std::string(kProtocol), std::string(kTag), *auto_listen),
                BuildRequest(2));
            co_await SendAndVerify(executor, sender, port, state, 1, 0x32);
            co_await DrainRuntime(executor, runtime_owner, run);
            result = 0;
            co_return;
        }

        auto replacement_request = BuildRequest(2);
        const auto replacement = acpp::MakePortBinding(
            port, std::string(kProtocol), std::string(kTag), *ipv4_wildcard);
        if (!co_await runtime.AddUdpListener(replacement, {}, replacement_request))
            Fail("replacement Runtime::AddUdpListener failed");
        if (options.mode == Mode::Success) {
            co_await WaitForListenerCounts(executor, runtime, 1, 1);
            co_await SendAndVerify(executor, sender, port, state, 2, 0x42);
            co_await runtime.UnregisterListener(std::string(kTag));
            co_await WaitForListenerCounts(executor, runtime, 0, 0);
            co_await DrainRuntime(executor, runtime_owner, run);
            result = 0;
            co_return;
        }

    } catch (const std::exception& error) {
        std::cerr << "runtime UDP runtime fixture: " << error.what() << '\n';
        result = 2;
    } catch (...) {
        std::cerr << "runtime UDP runtime fixture: unknown exception\n";
        result = 2;
    }
    if (runtime_owner) {
        try {
            co_await DrainRuntime(executor, runtime_owner, run);
        } catch (const std::exception& cleanup_error) {
            std::cerr << "runtime UDP cleanup: " << cleanup_error.what() << '\n';
            result = 2;
        } catch (...) {
            std::cerr << "runtime UDP cleanup: unknown exception\n";
            result = 2;
        }
    }
}

bool ParseOptions(int argc, char** argv, Options& options) {
    if (argc == 1) return true;
    if (argc != 2) return false;
    const std::string_view mode(argv[1]);
    if (mode == "--associations") options.mode = Mode::Associations;
    else if (mode == "--same-socket-cancel") options.mode = Mode::SameSocketCancel;
    else if (mode == "--start-failure") options.mode = Mode::StartFailure;
    else return false;
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!ParseOptions(argc, argv, options)) {
        std::cerr << "usage: udp_listener_runtime_test [--associations | --same-socket-cancel | --start-failure]\n";
        return 64;
    }

    acpp::memory::ConfigureProcessAllocator();
    RegisterFixtureProtocol();
    acpp::net::io_context io;
    acpp::tests::RuntimeServicesFixture runtime_services(io.get_executor());
    acpp::app::dns::Config dns_config{
        .servers = {{acpp::net::ip::address_v4::loopback(), 53}}};
    acpp::app::dns::DNSService dns(io.get_executor(), dns_config, 8);
    acpp::StatsShard stats;
    acpp::RuntimeConfig runtime_config;
    runtime_config.entry_capacity = 8;
    FixtureState state;
    g_state = &state;
    const uint16_t port = ReservePort(io.get_executor());
    auto runtime = std::make_unique<acpp::Runtime>(io.get_executor(), runtime_config, stats, dns);
    int result = 2;
    acpp::net::co_spawn(
        io, RunCases(io.get_executor(), *runtime, runtime, state, port, options, result),
        [&result](std::exception_ptr error) {
            if (!error) return;
            try {
                std::rethrow_exception(error);
            } catch (const std::exception& e) {
                std::cerr << "runtime UDP runtime fixture completion: " << e.what() << '\n';
            } catch (...) {
                std::cerr << "runtime UDP runtime fixture completion: unknown exception\n";
            }
            result = 2;
        });
    io.run();
    if (runtime) {
        // RunCases must perform same-thread unregister, receive-loop drain, and
        // destruction; reaching here with a live Runtime means cleanup failed.
        std::cerr << "runtime UDP runtime fixture left Runtime runtime alive\n";
        runtime.reset();
        return 2;
    }
    return result;
}
