#include "acppnode/app/dns/dns_worker.hpp"
#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "../src/app/proxyman/outbound/registration.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/app/worker_runtime_config.hpp"
#include "acppnode/app/worker_stats.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/outbound_source_config.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/proxy/inbound_datagram.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/inbound_listen.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/buffer.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <future>
#include <iostream>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace {
using namespace std::chrono_literals;
constexpr std::string_view kTag = "udp-retirement-native";
constexpr std::string_view kProtocol = "udp-retirement-fixture";
constexpr std::string_view kDomain = "nativeJoin.example";
constexpr uint8_t kMarker = 0xd7;
constexpr std::string_view kAfterDrainTag = "delayed-after-drain";

enum class RuntimeMode { Dns, DelayedRetirement };

struct ProcessEntered {
    bool first_payload_ok = false;
    std::string inbound_tag;
    std::string outbound_tag;
    std::string outbound_handler_tag;
    int64_t user_id = 0;
    std::string user_email;
};

[[noreturn]] void Fail(std::string_view what) {
    throw std::runtime_error(std::string(what));
}

struct FixtureState {
    unsigned created = 0;
    unsigned destroyed = 0;
    bool wrong_destructor_thread = false;
    std::thread::id owner;
    uint16_t target_port = 0;
    bool delayed_mode = false;
    acpp::net::io_context* owner_io = nullptr;
    std::unique_ptr<acpp::net::steady_timer> shutdown_signal;
    std::unique_ptr<acpp::net::steady_timer> cleanup_gate;
    std::promise<ProcessEntered> process_entered;
    ProcessEntered entered_metadata;
    bool gate_waiting = false;
    bool stop_observed = false;
    bool unregister_started = false;
    bool unregister_done = false;
    std::exception_ptr unregister_error;
    acpp::net::cancellation_signal unregister_cancel;
};

struct DelayedRetirementResult {
    ProcessEntered process;
    acpp::WorkerRuntimeStatsSnapshot held_stats;
    acpp::WorkerRuntimeStatsSnapshot final_stats;
    unsigned response_created_before_release = 0;
    unsigned response_destroyed_before_release = 0;
    unsigned response_created_after_join = 0;
    unsigned response_destroyed_after_join = 0;
    bool same_tag_mutation_busy = false;
    bool other_tag_mutation_busy = false;
    bool still_joining_after_cancel = false;
    bool stop_observed = false;
    bool cancel_committed_then_aborted = false;
    bool post_drain_mutations_succeeded = false;
};

class TrackedResponse final : public acpp::InboundDatagramResponse {
public:
    explicit TrackedResponse(FixtureState& state) : state_(state) {
        ++state_.created;
    }
    ~TrackedResponse() override {
        if (std::this_thread::get_id() != state_.owner)
            state_.wrong_destructor_thread = true;
        ++state_.destroyed;
    }
    acpp::buf::MultiBuffer Encode(acpp::UDPPacketView) override { return {}; }
private:
    FixtureState& state_;
};

struct Settings final : acpp::proxyman::inbound::ProtocolSettings {};
struct Runtime final : acpp::proxyman::inbound::ProtocolRuntime {
    std::vector<acpp::OnlineDevice> GetOnlineDevices(std::string_view) const override {
        return {};
    }
};

class NativeDecoder final : public acpp::Inbound {
public:
    explicit NativeDecoder(FixtureState& state) : state_(state) {}
    acpp::net::awaitable<acpp::RelayResult> Process(
        std::unique_ptr<acpp::AsyncStream>, acpp::routing::Dispatcher&,
        const acpp::proxyman::inbound::ReceiverSettings&, acpp::net::io_context&,
        acpp::session::Context&, const acpp::TimeoutsConfig&, uint32_t) override {
        co_return acpp::RelayResult{};
    }
    std::expected<acpp::InboundDatagramResult, acpp::ErrorCode> Process(
        const acpp::InboundDatagramRequest& request) override {
        if (request.payload.size() != 1 || request.payload.front() != kMarker)
            return std::unexpected(acpp::ErrorCode::PROTOCOL_AUTH_FAILED);
        acpp::InboundDatagramResult decoded;
        decoded.target = state_.delayed_mode
            ? acpp::TargetAddress(acpp::net::ip::address_v4::loopback(), state_.target_port)
            : acpp::TargetAddress(kDomain, state_.target_port);
        decoded.session_key = "cancel-while-resolving";
        const std::array<uint8_t, 8> owner{0x44, 0x4e, 0x53, 0x2d, 0x6f, 0x77, 0x6e, 0x72};
        if (!decoded.session_owner.Assign(owner)) throw std::bad_alloc();
        decoded.user_id = 71;
        decoded.user_email = "udp-owner@example.test";
        decoded.response = acpp::memory::AllocateShared<TrackedResponse>(state_);
        auto* first = acpp::buf::Buffer::New();
        if (!first) throw std::bad_alloc();
        first->data[0] = 0x51;
        first->data[1] = 0x52;
        first->Produce(2);
        decoded.payload.push_back(acpp::buf::BufferGuard(first));
        return decoded;
    }
private:
    FixtureState& state_;
};

thread_local FixtureState* g_state = nullptr;
std::unique_ptr<acpp::proxyman::inbound::ProtocolRuntime> MakeRuntime() {
    return std::make_unique<Runtime>();
}
std::unique_ptr<acpp::Inbound> MakeHandler(
    acpp::proxyman::inbound::ProtocolRuntime&, acpp::StatsShard&,
    acpp::ConnectionLimiterPtr,
    const acpp::proxyman::inbound::BuildRequest&) {
    if (!g_state) throw std::logic_error("fixture state not installed on Worker thread");
    return std::make_unique<NativeDecoder>(*g_state);
}
void RegisterProtocol() {
    static const bool registered = [] {
        acpp::proxyman::inbound::RegisterProxy(kProtocol, {
            .create_runtime = MakeRuntime,
            .create_tcp_handler = MakeHandler,
            .create_datagram_handler = MakeHandler,
        });
        return true;
    }();
    (void)registered;
}

void ObserveLinkStop(void* raw, acpp::transport::Cancellation) noexcept {
    static_cast<FixtureState*>(raw)->stop_observed = true;
}

class DelayedOutbound final : public acpp::Outbound {
public:
    DelayedOutbound(std::string tag, FixtureState& state)
        : tag_(std::move(tag)), state_(state) {}

    std::string_view Tag() const noexcept override { return tag_; }

    acpp::net::awaitable<acpp::OutboundProcessResult> Process(
        acpp::net::io_context&, const acpp::tcp::endpoint*,
        acpp::session::Context& ctx, const acpp::TimeoutsConfig&,
        acpp::transport::Link inbound, acpp::StatsShard&,
        const acpp::RelayConfig&, acpp::buf::MultiBuffer first_payload,
        std::chrono::seconds, std::chrono::seconds) override {
        if (!inbound.reader || !state_.cleanup_gate)
            throw std::logic_error("delayed outbound missing owner-local link/gate");
        std::array<uint8_t, 2> bytes{};
        const bool payload_ok = first_payload.size() == 1 &&
            first_payload.CopyPrefixTo(bytes) == bytes.size() &&
            bytes[0] == 0x51 && bytes[1] == 0x52;
        const ProcessEntered entered{
            .first_payload_ok = payload_ok,
            .inbound_tag = std::string(ctx.inbound.tag),
            .outbound_tag = std::string(ctx.outbound.tag),
            .outbound_handler_tag = std::string(Tag()),
            .user_id = ctx.inbound.user_id,
            .user_email = std::string(ctx.inbound.user_email),
        };
        acpp::transport::CancellationSubscription stop_subscription(
            inbound.reader->Cancellation(), ObserveLinkStop, &state_);
        state_.entered_metadata = entered;
        state_.process_entered.set_value(entered);
        state_.gate_waiting = true;

        const bool previous_throw_setting =
            co_await acpp::net::this_coro::throw_if_cancelled();
        co_await acpp::net::this_coro::throw_if_cancelled(false);
        std::exception_ptr wait_failure;
        acpp::IoErrorCode wait_error;
        try {
            co_await state_.cleanup_gate->async_wait(
                asio::bind_cancellation_slot(asio::cancellation_slot{},
                    asio::redirect_error(asio::use_awaitable, wait_error)));
            if (!wait_error)
                wait_failure = std::make_exception_ptr(
                    std::logic_error("cleanup gate expired without explicit release"));
        } catch (...) {
            wait_failure = std::current_exception();
        }
        co_await acpp::net::this_coro::throw_if_cancelled(previous_throw_setting);
        if (wait_failure) std::rethrow_exception(wait_failure);
        const auto cancellation = co_await acpp::net::this_coro::cancellation_state;
        if (state_.stop_observed ||
            cancellation.cancelled() != acpp::net::cancellation_type::none)
            co_return std::unexpected(acpp::ErrorCode::CANCELLED);
        co_return acpp::RelayResult{};
    }

private:
    std::string tag_;
    FixtureState& state_;
};

acpp::proxyman::outbound::PreparedOutboundConfig MakeDelayedOutbound(
    FixtureState& state, std::string tag) {
    auto* owner_state = &state;
    const std::string prepared_tag = tag;
    return {
        .tag = std::move(tag),
        .protocol = "test-delayed-completion",
        .create = [owner_state, prepared_tag](
            std::string_view requested_tag, acpp::net::io_context&,
            acpp::app::dns::DNS&, std::chrono::seconds) {
            if (requested_tag != prepared_tag)
                throw std::logic_error("prepared delayed outbound tag mismatch");
            return std::make_unique<DelayedOutbound>(
                std::string(requested_tag), *owner_state);
        },
    };
}

struct DnsPacket {
    std::array<uint8_t, 512> bytes{};
    std::size_t size = 0;
    acpp::udp::endpoint peer;
};

// DNS peer receives the real question and deliberately retains the unanswered
// transaction. Its socket and coroutine both belong to the control executor.
acpp::net::awaitable<DnsPacket> ReceiveQuery(acpp::udp::socket& socket) {
    DnsPacket packet;
    packet.size = co_await socket.async_receive_from(
        asio::buffer(packet.bytes), packet.peer, asio::use_awaitable);
    if (packet.size < 12 || packet.bytes[2] != 1 || packet.bytes[3] != 0)
        Fail("control DNS peer did not receive a valid standard DNS query");
    co_return packet;
}

void SendLateDnsReply(acpp::udp::socket& socket, DnsPacket& query) {
    if (query.size < 12) Fail("missing held DNS query");
    // Copy question from the actual request; answer nativeJoin.example as
    // loopback, allowing a late response to produce an observable UDP attempt.
    std::array<uint8_t, 512> reply{};
    const auto question_end = query.size;
    if (question_end + 16 > reply.size()) Fail("DNS question unexpectedly large");
    std::copy_n(query.bytes.begin(), question_end, reply.begin());
    reply[2] = 0x81; reply[3] = 0x80;
    reply[6] = 0; reply[7] = 1;
    auto p = question_end;
    reply[p++] = 0xc0; reply[p++] = 0x0c; // answer name pointer
    reply[p++] = 0; reply[p++] = 1;       // A
    reply[p++] = 0; reply[p++] = 1;       // IN
    reply[p++] = 0; reply[p++] = 0; reply[p++] = 0; reply[p++] = 30;
    reply[p++] = 0; reply[p++] = 4;
    reply[p++] = 127; reply[p++] = 0; reply[p++] = 0; reply[p++] = 1;
    acpp::IoErrorCode ec;
    socket.send_to(asio::buffer(reply.data(), p), query.peer, 0, ec);
    if (ec) Fail("sending delayed DNS response failed");
}

acpp::net::awaitable<void> Pause(acpp::net::io_context& io,
                                  std::chrono::milliseconds duration) {
    acpp::net::steady_timer timer(io, duration);
    co_await timer.async_wait(acpp::net::use_awaitable);
}

acpp::net::awaitable<void> WorkerJob(
    acpp::net::io_context& io, acpp::Worker& worker, FixtureState& state,
    uint16_t inbound_port, uint16_t target_port, RuntimeMode mode,
    std::promise<std::future<ProcessEntered>>& entered_handoff,
    std::promise<void>& ready) {
    state.owner = std::this_thread::get_id();
    state.target_port = target_port;
    state.delayed_mode = mode == RuntimeMode::DelayedRetirement;
    state.owner_io = &io;
    state.shutdown_signal = std::make_unique<acpp::net::steady_timer>(io);
    if (state.delayed_mode) {
        state.cleanup_gate = std::make_unique<acpp::net::steady_timer>(io);
        state.cleanup_gate->expires_at(acpp::net::steady_timer::time_point::max());
        entered_handoff.set_value(state.process_entered.get_future());
    }
    g_state = &state;
    co_await worker.StartRuntimeTask();
    if (state.delayed_mode) {
        co_await worker.AddOutboundTask(MakeDelayedOutbound(state, "native-test"));
    } else {
        auto outbound_source = acpp::infra::OutboundSourceConfig{};
        outbound_source.tag = "native-test";
        outbound_source.protocol = "freedom";
        outbound_source.settings["domainStrategy"] = "UseIP";
        auto prepared = acpp::proxyman::outbound::PrepareOutboundConfig(outbound_source);
        if (!prepared) Fail("production Freedom outbound preparation failed");
        co_await worker.AddOutboundTask(std::move(*prepared));
    }

    acpp::proxyman::inbound::BuildRequest request{
        .tag = std::string(kTag), .protocol = std::string(kProtocol),
        .settings = std::make_shared<Settings>()};
    acpp::proxyman::inbound::ReceiverSettings receiver{
        .inbound_tag = std::string(kTag), .protocol = std::string(kProtocol),
        .dispatch_policy = {.outbound = acpp::routing::ForceOutbound{"native-test"}}};
    if (!co_await worker.RegisterInboundTask({}, request, receiver))
        Fail("real native inbound registration failed");
    const auto listen = acpp::InboundListen::Parse("127.0.0.1");
    if (!listen) Fail("loopback inbound address could not be parsed");
    if (!co_await worker.AddUdpListenerTask(
            acpp::MakePortBinding(inbound_port, std::string(kProtocol),
                                  std::string(kTag), *listen), {}, request))
        Fail("real native UDP listener failed to bind");
    state.shutdown_signal->expires_at(acpp::net::steady_timer::time_point::max());
    ready.set_value();
    acpp::IoErrorCode ec;
    co_await state.shutdown_signal->async_wait(
        asio::redirect_error(asio::use_awaitable, ec));
    if (ec != acpp::net::error::operation_aborted)
        Fail("Worker shutdown signal ended without explicit cancellation");
}

struct WorkerExit {
    bool clean = false;
    std::string error;
    unsigned responses_created = 0;
    unsigned responses_destroyed = 0;
    bool wrong_destructor_thread = false;
};

acpp::net::awaitable<acpp::WorkerRuntimeStatsSnapshot> Snapshot(acpp::Worker& worker) {
    co_return co_await worker.CollectRuntimeStatsTask(true);
}

template <typename Predicate>
acpp::net::awaitable<void> WaitTestPredicate(
    acpp::net::io_context& io, Predicate predicate,
    std::chrono::milliseconds limit, std::string_view failure) {
    auto expired = std::make_shared<bool>(false);
    acpp::net::steady_timer deadline(io);
    deadline.expires_after(limit);
    deadline.async_wait([expired](const acpp::IoErrorCode& ec) {
        if (!ec) *expired = true;
    });
    while (!predicate()) {
        if (*expired) Fail(failure);
        co_await Pause(io, 2ms);
    }
    acpp::IoErrorCode ignored;
    deadline.cancel(ignored);
}

acpp::proxyman::inbound::BuildRequest BuildFixtureRequest(std::string tag) {
    return {.tag = std::move(tag), .protocol = std::string(kProtocol),
            .settings = std::make_shared<Settings>()};
}

acpp::proxyman::inbound::ReceiverSettings BuildFixtureReceiver(
    std::string tag, std::string outbound_tag) {
    return {.inbound_tag = std::move(tag), .protocol = std::string(kProtocol),
            .dispatch_policy = {
                .outbound = acpp::routing::ForceOutbound(std::move(outbound_tag))}};
}

bool IsBusy(const std::exception_ptr& error) {
    if (!error) return false;
    try { std::rethrow_exception(error); }
    catch (const std::system_error& e) {
        return e.code() == std::make_error_code(std::errc::device_or_resource_busy);
    } catch (...) { return false; }
}

struct UnregisterCompletion {
    FixtureState* state;
    void operator()(std::exception_ptr error) const noexcept {
        state->unregister_error = std::move(error);
        state->unregister_done = true;
    }
};

acpp::net::awaitable<DelayedRetirementResult> RunDelayedRetirementOwner(
    acpp::Worker& worker) {
    if (!g_state || !g_state->owner_io || !g_state->cleanup_gate)
        Fail("delayed fixture state is not initialized on Worker owner");
    FixtureState& state = *g_state;
    DelayedRetirementResult result;
    result.process = state.entered_metadata;
    if (!result.process.first_payload_ok ||
        result.process.inbound_tag != kTag ||
        result.process.outbound_tag != "native-test" ||
        result.process.outbound_handler_tag != "native-test" ||
        result.process.user_id != 71 ||
        result.process.user_email != "udp-owner@example.test")
        Fail("DefaultDispatcher did not preserve the initial payload and session metadata");

    state.unregister_started = true;
    acpp::net::co_spawn(*state.owner_io,
        worker.UnregisterListenerTask(std::string(kTag)),
        asio::bind_cancellation_slot(state.unregister_cancel.slot(),
            UnregisterCompletion{&state}));
    co_await WaitTestPredicate(*state.owner_io,
        [&state] { return state.stop_observed && state.gate_waiting; },
        3s, "listener retirement did not stop the active native Link job");

    result.held_stats = co_await Snapshot(worker);
    if (!result.held_stats.resources ||
        result.held_stats.resources->udp_associations != 0 ||
        result.held_stats.resources->udp_native_dispatches != 1 ||
        result.held_stats.resources->udp_listeners != 0)
        Fail("retirement did not expose drained RX with its native dispatch still pending");
    result.response_created_before_release = state.created;
    result.response_destroyed_before_release = state.destroyed;
    if (state.created == 0 || state.destroyed != 0)
        Fail("native response owner was reclaimed before the held outbound completed");

    std::exception_ptr same_tag_error;
    try {
        (void)co_await worker.RegisterInboundTask({},
            BuildFixtureRequest(std::string(kTag)),
            BuildFixtureReceiver(std::string(kTag), "native-test"));
    } catch (...) { same_tag_error = std::current_exception(); }
    result.same_tag_mutation_busy = IsBusy(same_tag_error);

    std::exception_ptr other_tag_error;
    try {
        co_await worker.AddOutboundTask(
            MakeDelayedOutbound(state, "cross-tag-busy"));
    } catch (...) { other_tag_error = std::current_exception(); }
    result.other_tag_mutation_busy = IsBusy(other_tag_error);
    if (!result.same_tag_mutation_busy || !result.other_tag_mutation_busy)
        Fail("Worker cold mutation gate admitted a write while retirement was suspended");

    // Parent cancellation is delivered on the owner executor while the
    // outbound's empty-slot gate remains held; join must still await cleanup.
    state.unregister_cancel.emit(acpp::net::cancellation_type::terminal);
    co_await Pause(*state.owner_io, 40ms);
    result.held_stats = co_await Snapshot(worker);
    result.still_joining_after_cancel = !state.unregister_done &&
        result.held_stats.resources &&
        result.held_stats.resources->udp_native_dispatches == 1;
    if (!result.still_joining_after_cancel)
        Fail("canceled unregister returned before the delayed outbound completed");

    state.cleanup_gate->cancel();
    co_await WaitTestPredicate(*state.owner_io,
        [&state] { return state.unregister_done; },
        3s, "unregister task did not complete after releasing outbound cleanup gate");
    result.stop_observed = state.stop_observed;
    if (!result.stop_observed)
        Fail("native Link did not observe RequestStop before cleanup gate release");
    result.cancel_committed_then_aborted = false;
    try {
        if (state.unregister_error) std::rethrow_exception(state.unregister_error);
    } catch (const acpp::IoSystemError& e) {
        result.cancel_committed_then_aborted =
            e.code() == acpp::net::error::operation_aborted;
    } catch (...) {}
    if (!result.cancel_committed_then_aborted) {
        if (!state.unregister_error)
            Fail("UnregisterListenerTask returned success despite owner cancellation");
        try { std::rethrow_exception(state.unregister_error); }
        catch (const std::system_error& e) {
            Fail(std::string("UnregisterListenerTask returned unexpected system error: ") +
                 e.code().message());
        } catch (const std::exception& e) {
            Fail(std::string("UnregisterListenerTask returned unexpected error: ") + e.what());
        } catch (...) {
            Fail("UnregisterListenerTask returned an unknown error");
        }
    }

    result.final_stats = co_await Snapshot(worker);
    if (!result.final_stats.resources ||
        result.final_stats.resources->udp_native_dispatches != 0 ||
        result.final_stats.resources->udp_listeners != 0 ||
        result.final_stats.resources->udp_receive_loops != 0 ||
        result.final_stats.resources->udp_associations != 0 ||
        result.final_stats.resources->udp_closed_associations != 0 ||
        result.final_stats.resources->udp_reply_senders != 0 ||
        state.created != state.destroyed)
        Fail("retirement completion left a native job, resource row, or response owner");
    result.response_created_after_join = state.created;
    result.response_destroyed_after_join = state.destroyed;

    // Both snapshot writers are public Worker tasks and now succeed in order.
    (void)co_await worker.RegisterInboundTask({},
        BuildFixtureRequest(std::string(kAfterDrainTag)),
        BuildFixtureReceiver(std::string(kAfterDrainTag), "native-test"));
    co_await worker.AddOutboundTask(MakeDelayedOutbound(state, "after-drain"));
    result.post_drain_mutations_succeeded = true;
    state.shutdown_signal->cancel();
    co_return result;
}

struct RetirementSnapshot {
    acpp::WorkerRuntimeStatsSnapshot stats;
    unsigned responses_created = 0;
    unsigned responses_destroyed = 0;
    bool wrong_destructor_thread = false;
};

acpp::net::awaitable<RetirementSnapshot> UnregisterAndSnapshot(
    acpp::Worker& worker) {
    co_await worker.UnregisterListenerTask(std::string(kTag));
    if (!g_state || !g_state->owner_io)
        Fail("Worker-local fixture state is unavailable during retirement");

    auto expired = std::make_shared<bool>(false);
    acpp::net::steady_timer deadline(*g_state->owner_io);
    deadline.expires_after(3s);
    deadline.async_wait([expired](const acpp::IoErrorCode& ec) {
        if (!ec) *expired = true;
    });
    RetirementSnapshot result;
    for (;;) {
        result.stats = co_await Snapshot(worker);
        const auto& resources = result.stats.resources;
        if (resources && resources->udp_native_dispatches == 0 &&
            resources->udp_listeners == 0 && resources->udp_receive_loops == 0 &&
            resources->udp_associations == 0 && resources->udp_closed_associations == 0 &&
            resources->udp_reply_senders == 0)
            break;
        if (*expired) Fail("Worker-owned UDP jobs/resources did not drain before test deadline");
        co_await Pause(*g_state->owner_io, 2ms);
    }
    acpp::IoErrorCode ignored;
    deadline.cancel(ignored);
    result.responses_created = g_state->created;
    result.responses_destroyed = g_state->destroyed;
    result.wrong_destructor_thread = g_state->wrong_destructor_thread;
    co_return result;
}

acpp::net::awaitable<void> StopOwnerJob(acpp::Worker&) {
    if (!g_state || !g_state->shutdown_signal)
        Fail("Worker-local shutdown signal is unavailable");
    g_state->shutdown_signal->cancel();
    co_return;
}

acpp::net::awaitable<void> AbortWorkerTask(acpp::Worker& worker) {
    if (!g_state) Fail("Worker-local fixture state is unavailable during abort cleanup");
    FixtureState& state = *g_state;
    std::exception_ptr failure;
    if (state.delayed_mode) {
        if (state.cleanup_gate) {
            acpp::IoErrorCode ignored;
            state.cleanup_gate->cancel(ignored);
        }
        if (state.unregister_started) {
            state.unregister_cancel.emit(acpp::net::cancellation_type::terminal);
            try {
                co_await WaitTestPredicate(*state.owner_io,
                    [&state] { return state.unregister_done; },
                    3s, "aborted delayed unregister failed to join its native job");
            } catch (...) { failure = std::current_exception(); }
        } else {
            try { co_await worker.UnregisterListenerTask(std::string(kTag)); }
            catch (...) { failure = std::current_exception(); }
        }
    } else {
        try { (void)co_await UnregisterAndSnapshot(worker); }
        catch (...) { failure = std::current_exception(); }
    }
    co_await StopOwnerJob(worker);
    if (failure) std::rethrow_exception(failure);
}

uint16_t BindUdp(acpp::net::io_context& io, acpp::udp::socket& socket) {
    acpp::IoErrorCode ec;
    socket.open(acpp::udp::v4(), ec);
    if (ec) Fail("opening loopback UDP socket failed");
    socket.bind({acpp::net::ip::address_v4::loopback(), 0}, ec);
    if (ec) Fail("binding loopback UDP socket failed");
    return socket.local_endpoint(ec).port();
}

acpp::net::awaitable<void> RunControl(
    acpp::net::io_context& control_io, acpp::app::dns::DNSWorker& dns,
    acpp::Worker& worker, acpp::udp::socket& dns_peer, DnsPacket& held_query,
    uint16_t inbound_port, acpp::udp::socket& echo_observer) {
    (void)dns;
    // Send one valid datagram through the real listener; its owned first Link
    // payload enters DefaultDispatcher and the frozen Freedom outbound.
    const std::array<uint8_t, 1> marker{kMarker};
    acpp::udp::socket client(control_io, acpp::udp::v4());
    acpp::IoErrorCode ec;
    client.send_to(asio::buffer(marker),
        {acpp::net::ip::address_v4::loopback(), inbound_port}, 0, ec);
    if (ec) Fail("sending native UDP datagram failed");
    held_query = co_await ReceiveQuery(dns_peer);

    // DNS query delivery itself is the synchronization point: now retirement
    // must cancel the real resolver wait, await its child task, then join RX.
    const auto retired = co_await worker.PostTask(UnregisterAndSnapshot(worker));
    const auto& final = retired.stats;
    if (!final.resources || final.resources->udp_native_dispatches != 0 ||
        final.resources->udp_listeners != 0 || final.resources->udp_receive_loops != 0 ||
        final.resources->udp_associations != 0 || final.resources->udp_closed_associations != 0)
        Fail("retirement returned before native dispatch/listener/association rows drained");
    if (retired.responses_created == 0 ||
        retired.responses_created != retired.responses_destroyed ||
        retired.wrong_destructor_thread)
        Fail("response ownership was not reclaimed on the live Worker before return");
    SendLateDnsReply(dns_peer, held_query);
    co_await Pause(control_io, 200ms);
    std::array<uint8_t, 32> received{};
    acpp::udp::endpoint sender;
    echo_observer.non_blocking(true, ec);
    if (ec) Fail("could not make the loopback echo observer nonblocking");
    const auto received_size = echo_observer.receive_from(asio::buffer(received), sender, 0, ec);
    if (!ec || received_size != 0)
        Fail("a late DNS response launched an outbound UDP request after cancellation");
    if (ec != acpp::net::error::would_block && ec != acpp::net::error::try_again)
        Fail("echo observer failed for a reason other than no late UDP request");
    co_await worker.PostTask(StopOwnerJob(worker));

}

struct SharedWorker {
    // The Worker remains constructed, used and destroyed on the data thread.
    // Cross-thread callers only use its public bounded mailbox entrypoints.
    acpp::Worker* worker = nullptr;
    std::promise<std::future<ProcessEntered>> entered_handoff;
    std::future<std::future<ProcessEntered>> entered_handoff_future =
        entered_handoff.get_future();
    std::promise<void> ready;
    std::future<void> ready_future = ready.get_future();
    std::promise<WorkerExit> done;
    std::future<WorkerExit> done_future = done.get_future();
};

} // namespace

int main(int argc, char** argv) {
    RuntimeMode mode = RuntimeMode::Dns;
    if (argc == 2 && std::string_view(argv[1]) == "--delayed-retirement") {
        mode = RuntimeMode::DelayedRetirement;
    } else if (argc != 1) {
        std::cerr << "usage: worker_udp_retirement_runtime_test [--delayed-retirement]\\n";
        return 64;
    }
    try {
        acpp::memory::ConfigureProcessAllocator();
        RegisterProtocol();
        acpp::net::io_context control_io;
        acpp::udp::socket dns_peer(control_io);
        const auto dns_port = BindUdp(control_io, dns_peer);
        acpp::app::dns::Config dns_config{
            .servers = {{acpp::net::ip::address_v4::loopback(), dns_port}},
            .timeout_sec = 15};
        acpp::app::dns::DNSWorker dns(control_io, dns_config, 8);

        acpp::udp::socket echo_observer(control_io);
        const auto echo_port = BindUdp(control_io, echo_observer);
        acpp::udp::socket reservation(control_io);
        const auto inbound_port = BindUdp(control_io, reservation);
        reservation.close();

        acpp::WorkerRuntimeConfig runtime;
        runtime.mailbox_capacity = 8;
        runtime.timeouts.idle = 0;
        runtime.timeouts.read = 0;
        SharedWorker shared;
        std::thread data_thread([&] {
            try {
                acpp::net::io_context data_io;
                acpp::StatsShard stats;
                FixtureState fixture;
                auto worker = std::make_unique<acpp::Worker>(1, data_io, runtime, stats, dns);
                shared.worker = worker.get();
                std::string runtime_error;
                acpp::net::co_spawn(data_io, WorkerJob(data_io, *worker, fixture,
                    inbound_port, echo_port, mode, shared.entered_handoff, shared.ready),
                    [&shared, &runtime_error](std::exception_ptr error) {
                        if (!error) return;
                        try { std::rethrow_exception(error); }
                        catch (const std::exception& e) { runtime_error = e.what(); }
                        catch (...) { runtime_error = "unknown Worker coroutine exception"; }
                        try { shared.ready.set_exception(error); } catch (...) {}
                    });
                data_io.run();
                // Keep Worker alive throughout the natural executor drain; its
                // owner-thread stack performs destruction only after run returns.
                worker.reset();
                data_io.restart();
                while (data_io.poll() != 0) {}
                WorkerExit result;
                result.clean = runtime_error.empty();
                result.error = std::move(runtime_error);
                result.responses_created = fixture.created;
                result.responses_destroyed = fixture.destroyed;
                result.wrong_destructor_thread = fixture.wrong_destructor_thread;
                shared.done.set_value(std::move(result));
            } catch (const std::exception& e) {
                auto failure = std::make_exception_ptr(std::runtime_error(e.what()));
                try { shared.ready.set_exception(failure); } catch (...) {}
                try { shared.done.set_value(WorkerExit{.error = e.what()}); } catch (...) {}
            } catch (...) {
                auto failure = std::current_exception();
                try { shared.ready.set_exception(failure); } catch (...) {}
                try { shared.done.set_value(WorkerExit{.error = "unknown data Worker thread failure"}); } catch (...) {}
            }
        });

        try {
            shared.ready_future.get();
        } catch (...) {
            if (data_thread.joinable()) data_thread.join();
            throw;
        }

        if (mode == RuntimeMode::DelayedRetirement) {
            std::exception_ptr failure;
            DelayedRetirementResult delayed;
            bool have_result = false;
            std::future<ProcessEntered> entered;
            try { entered = shared.entered_handoff_future.get(); }
            catch (...) { failure = std::current_exception(); }

            if (!failure) {
                acpp::udp::socket client(control_io, acpp::udp::v4());
                const std::array<uint8_t, 1> marker{kMarker};
                acpp::IoErrorCode ec;
                client.send_to(asio::buffer(marker),
                    {acpp::net::ip::address_v4::loopback(), inbound_port}, 0, ec);
                if (ec) failure = std::make_exception_ptr(
                    std::runtime_error("sending delayed native UDP request failed"));
            }
            if (!failure && entered.wait_for(7s) != std::future_status::ready)
                failure = std::make_exception_ptr(std::runtime_error(
                    "test outbound did not receive the real first Link payload before watchdog"));
            if (!failure) {
                try {
                    const auto process = entered.get();
                    auto retirement = shared.worker->PostForFuture(
                        RunDelayedRetirementOwner(*shared.worker));
                    if (retirement.wait_for(8s) != std::future_status::ready)
                        failure = std::make_exception_ptr(std::runtime_error(
                            "delayed retirement scenario exceeded test watchdog"));
                    else {
                        delayed = retirement.get();
                        if (delayed.process.first_payload_ok != process.first_payload_ok ||
                            delayed.process.outbound_tag != process.outbound_tag ||
                            delayed.process.outbound_handler_tag != process.outbound_handler_tag ||
                            delayed.process.user_id != process.user_id)
                            Fail("owner DTO differed from actual outbound entry metadata");
                        have_result = true;
                    }
                } catch (...) { failure = std::current_exception(); }
            }
            if (failure) {
                auto cleanup = shared.worker->PostForFuture(
                    AbortWorkerTask(*shared.worker));
                cleanup.wait();
                try { cleanup.get(); } catch (...) {}
            }
            auto worker_exit = shared.done_future.get();
            data_thread.join();
            if (failure) std::rethrow_exception(failure);
            if (!have_result || !worker_exit.clean ||
                !delayed.same_tag_mutation_busy || !delayed.other_tag_mutation_busy ||
                !delayed.still_joining_after_cancel || !delayed.stop_observed ||
                !delayed.cancel_committed_then_aborted ||
                !delayed.post_drain_mutations_succeeded ||
                delayed.response_created_before_release == 0 ||
                delayed.response_destroyed_before_release != 0 ||
                delayed.response_created_after_join == 0 ||
                delayed.response_created_after_join != delayed.response_destroyed_after_join ||
                worker_exit.wrong_destructor_thread ||
                worker_exit.responses_created != worker_exit.responses_destroyed)
                Fail("delayed retirement completion/gate/cancellation contract failed");
            control_io.restart();
            auto cache_future = asio::co_spawn(control_io, dns.GetCacheStats(), asio::use_future);
            while (cache_future.wait_for(0ms) != std::future_status::ready) {
                control_io.poll_one();
                std::this_thread::sleep_for(1ms);
            }
            if (cache_future.get().entries != 0)
                Fail("delayed test unexpectedly entered DNS cache");
            std::cout << "worker UDP retirement delayed completion passed\n";
            return 0;
        }

        // On main/control thread, drive DNSWorker and its real UDP peer while
        // polling the bounded worker mailbox task. Do not stop either executor.
        DnsPacket held;
        bool control_complete = false;
        std::exception_ptr control_error;
        acpp::net::co_spawn(control_io,
            RunControl(control_io, dns, *shared.worker, dns_peer, held,
                       inbound_port, echo_observer),
            [&control_complete, &control_error](std::exception_ptr error) {
                control_error = error;
                control_complete = true;
            });
        // The 15s DNS timeout is deliberately longer than this test watchdog;
        // a missing real query is reported, then owner-thread cleanup cancels it.
        for (unsigned i = 0; i != 10000 && !control_complete; ++i) {
            control_io.poll_one();
            std::this_thread::sleep_for(1ms);
        }
        if (!control_complete) {
            control_error = std::make_exception_ptr(
                std::runtime_error("control-side retirement orchestration timed out"));
            acpp::IoErrorCode ignored;
            dns_peer.cancel(ignored);
        }
        std::exception_ptr cleanup_error;
        if (control_error) {
            auto cleanup = shared.worker->PostForFuture(
                AbortWorkerTask(*shared.worker));
            while (cleanup.wait_for(0ms) != std::future_status::ready) {
                control_io.poll_one();
                std::this_thread::sleep_for(1ms);
            }
            try { cleanup.get(); }
            catch (...) { cleanup_error = std::current_exception(); }
        }
        auto worker_exit = shared.done_future.get();
        data_thread.join();
        if (control_error) std::rethrow_exception(control_error);
        if (cleanup_error) std::rethrow_exception(cleanup_error);
        if (!worker_exit.clean) Fail(worker_exit.error.empty() ? "data Worker failed" : worker_exit.error);
        if (worker_exit.wrong_destructor_thread ||
            worker_exit.responses_created == 0 ||
            worker_exit.responses_created != worker_exit.responses_destroyed)
            Fail("response ownership did not close on the data Worker thread");
        // DNS state observation is made only by its owning executor through
        // the public bounded API. No Worker/private state is inspected here.
        control_io.restart();
        auto cache_future = asio::co_spawn(control_io, dns.GetCacheStats(), asio::use_future);
        while (cache_future.wait_for(0ms) != std::future_status::ready) {
            control_io.poll_one();
            std::this_thread::sleep_for(1ms);
        }
        const auto cache = cache_future.get();
        if (cache.entries != 0) Fail("held, canceled DNS query unexpectedly entered cache");
        std::cout << "worker UDP retirement native DNS cancellation passed\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "worker UDP retirement runtime test: " << e.what() << '\n';
        return 1;
    }
}
