#include "acppnode/app/udp_channel.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>

#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
using namespace acpp;
using namespace std::chrono_literals;

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

TargetAddress Target(const udp::endpoint& endpoint) {
    return TargetAddress(endpoint.address(), endpoint.port());
}

buf::MultiBuffer Packet(const TargetAddress& target, size_t size = 32) {
    std::vector<uint8_t> bytes(size);
    for (size_t i = 0; i < size; ++i) bytes[i] = static_cast<uint8_t>(i * 37);
    buf::MultiBuffer payload;
    Check(buf::AppendSpanToMultiBuffer(bytes, payload), "packet allocation failed");
    for (auto* buffer : payload) buffer->SetUDP(target);
    return payload;
}

net::awaitable<void> Pause(net::io_context& io, std::chrono::milliseconds duration) {
    net::steady_timer timer(io, duration);
    co_await timer.async_wait(net::use_awaitable);
}

struct Fixture {
    net::io_context io;
    app::dns::DNS dns{io, app::dns::Config{.servers = {{net::ip::address_v4::loopback(), 53}}}};
    std::unique_ptr<UDPSessionManager> manager = std::make_unique<UDPSessionManager>(io, dns);
    std::shared_ptr<UDPSession> session;

    Fixture() {
        auto acquired = manager->AcquireSession("channel-test", net::ip::address_v4::loopback());
        Check(acquired.has_value(), "session creation failed");
        session = std::move(*acquired);
    }

    void Run(net::awaitable<void> task) {
        std::exception_ptr error;
        bool done = false;
        bool expired = false;
        net::steady_timer watchdog(io, 8s);
        watchdog.async_wait([&](const IoErrorCode& ec) {
            if (!ec) { expired = true; io.stop(); }
        });
        net::co_spawn(io, std::move(task), [&](std::exception_ptr failure) {
            error = failure;
            done = true;
            manager.reset();
            session.reset();
            watchdog.cancel();
        });
        io.run();
        Check(done && !expired, "channel operation or cancellation did not finish");
        if (error) std::rethrow_exception(error);
    }
};

net::awaitable<void> RoundTrip(Fixture& fixture, UDPChannel& channel, size_t size) {
    udp::socket peer(fixture.io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    const auto target = Target(peer.local_endpoint());
    co_await channel.WriteMultiBuffer(Packet(target, size));
    std::vector<uint8_t> received(65535);
    udp::endpoint source;
    const size_t count = co_await peer.async_receive_from(net::buffer(received), source, net::use_awaitable);
    Check(count == size, "one MultiBuffer must remain one complete UDP datagram");
    for (size_t i = 0; i < count; ++i) Check(received[i] == static_cast<uint8_t>(i * 37), "send bytes changed");
    co_await peer.async_send_to(net::buffer(received.data(), count), source, net::use_awaitable);
    auto reply = co_await channel.ReadMultiBuffer();
    const auto datagram = buf::InspectUdpDatagram(reply);
    Check(datagram.Valid() && datagram.payload_size == size, "UDP response was fragmented or lost");
    Check(datagram.target && datagram.target->port == peer.local_endpoint().port(), "response target was lost");
    size_t offset = 0;
    for (auto* buffer : reply) {
        for (auto byte : buffer->Bytes()) {
            Check(byte == static_cast<uint8_t>(offset++ * 37), "receive bytes changed");
        }
    }
}

net::awaitable<void> TestSharedSocket(Fixture& fixture) {
    UDPChannel cancelled(fixture.io, fixture.session);
    UDPChannel survivor(fixture.io, fixture.session);
    cancelled.Cancel();
    bool rejected = false;
    try { co_await cancelled.ReadMultiBuffer(); }
    catch (const transport::LinkError& error) { rejected = error.code() == ErrorCode::CANCELLED; }
    Check(rejected, "cancelled channel allowed another read");
    survivor.SetWriteTimeout(1s);
    co_await RoundTrip(fixture, survivor, 20000);
    co_await Pause(fixture.io, 1100ms);
    Check(!survivor.ConsumeWriteTimeout(), "completed write left a live request deadline");
    co_await RoundTrip(fixture, survivor, 11);
}

net::awaitable<void> TestDeadlines(Fixture& fixture, int kind) {
    UDPChannel channel(fixture.io, fixture.session);
    PhaseDeadlineHandle phase;
    if (kind == 0) channel.SetIdleTimeout(1s);
    if (kind == 1) channel.SetReadTimeout(1s);
    if (kind == 2) phase = channel.StartPhaseDeadline(1s);
    const auto started = std::chrono::steady_clock::now();
    bool cancelled = false;
    try { co_await channel.ReadMultiBuffer(); }
    catch (const transport::LinkError& error) { cancelled = error.code() == ErrorCode::CANCELLED; }
    const auto elapsed = std::chrono::steady_clock::now() - started;
    Check(cancelled && elapsed >= 800ms && elapsed < 3s, "pending read ignored its deadline");
    if (kind == 0) Check(channel.ConsumeIdleTimeout() && !channel.ConsumeIdleTimeout(), "idle signal was lost or duplicated");
    if (kind == 1) Check(channel.ConsumeReadTimeout() && !channel.ConsumeReadTimeout(), "read signal was lost or duplicated");
    if (kind == 2) {
        Check(phase.Expired(), "phase handle did not observe expiry");
        channel.ClearPhaseDeadline();
        Check(!phase.Expired() && !channel.ConsumePhaseDeadline(), "clear left a stale phase expiry on a closed channel");
        Check(!channel.StartPhaseDeadline(1s), "closed channel started a new phase");
    }
}

net::awaitable<void> TestIdleActivityAndClear(Fixture& fixture) {
    UDPChannel channel(fixture.io, fixture.session);
    channel.SetIdleTimeout(1s);
    const auto old_phase = channel.StartPhaseDeadline(1s);
    channel.ClearPhaseDeadline();
    Check(!old_phase.Expired(), "cleared phase handle remained active");
    for (int i = 0; i < 3; ++i) {
        co_await Pause(fixture.io, 450ms);
        co_await RoundTrip(fixture, channel, 32);
    }
    Check(!channel.ConsumeIdleTimeout(), "active datagrams did not refresh idle timeout");
    channel.SetIdleTimeout(0s);
    co_await Pause(fixture.io, 1100ms);
    co_await RoundTrip(fixture, channel, 32);
}

net::awaitable<void> TestParentCancellation(Fixture& fixture) {
    UDPChannel channel(fixture.io, fixture.session);
    net::cancellation_signal cancellation;
    struct Completion { bool finished = false; std::exception_ptr failure; };
    auto completion = std::make_shared<Completion>();
    net::co_spawn(fixture.io, channel.ReadMultiBuffer(),
        net::bind_cancellation_slot(cancellation.slot(),
            [completion](std::exception_ptr error, buf::MultiBuffer) {
                completion->failure = error; completion->finished = true;
            }));
    co_await Pause(fixture.io, 20ms);
    cancellation.emit(net::cancellation_type::all);
    co_await Pause(fixture.io, 20ms);
    Check(completion->finished && completion->failure, "parent cancellation left the logical reader waiting");
    UDPChannel survivor(fixture.io, fixture.session);
    co_await RoundTrip(fixture, survivor, 32);
}

net::awaitable<void> TestQueueLimit(Fixture& fixture) {
    UDPChannel channel(fixture.io, fixture.session);
    udp::socket peer(fixture.io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    co_await channel.WriteMultiBuffer(Packet(Target(peer.local_endpoint()), 1));
    std::array<uint8_t, 8> payload{};
    udp::endpoint source;
    co_await peer.async_receive_from(net::buffer(payload), source, net::use_awaitable);
    for (int i = 0; i < 800; ++i) {
        co_await peer.async_send_to(net::buffer(payload.data(), 1), source, net::use_awaitable);
        co_await net::post(fixture.io, net::use_awaitable);
    }
    co_await Pause(fixture.io, 50ms);
    bool rejected = false;
    try { co_await channel.ReadMultiBuffer(); }
    catch (const transport::LinkError& error) { rejected = error.code() == ErrorCode::RESOURCE_EXHAUSTED; }
    Check(rejected, "bounded queue overflow did not report resource exhaustion");
    UDPChannel survivor(fixture.io, fixture.session);
    co_await RoundTrip(fixture, survivor, 32);
}

net::awaitable<void> TestRetiredTimer(Fixture& fixture) {
    // Queue timer readiness while no handler can execute. Destroy the owner
    // before yielding to the event loop; queued callbacks must not borrow it.
    {
        UDPChannel old(fixture.io, fixture.session);
        old.StartPhaseDeadline(1s);
        std::this_thread::sleep_for(1050ms);
    }
    UDPChannel current(fixture.io, fixture.session);
    co_await RoundTrip(fixture, current, 32);
    current.StartPhaseDeadline(std::chrono::seconds::max());
    co_await Pause(fixture.io, 20ms);
    Check(!current.ConsumePhaseDeadline(), "large deadline overflowed into the present");
}

class OnePacketReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }

    explicit OnePacketReader(TargetAddress target) : target_(std::move(target)) {}
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (used_) co_return buf::MultiBuffer{};
        used_ = true;
        co_return Packet(target_, 2000);
    }
private:
    transport::CancellationSource cancellation_;

    TargetAddress target_;
    bool used_ = false;
};

class IgnoreWriter final : public transport::MultiBufferWriter {
public:
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer) override { co_return; }
};

net::awaitable<void> TestRelayRateAndAccounting(Fixture& fixture) {
    udp::socket peer(fixture.io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    UDPChannel target(fixture.io, fixture.session);
    OnePacketReader input(Target(peer.local_endpoint()));
    IgnoreWriter output;
    session::Context context;
    context.content.network = Network::UDP;
    StatsShard stats;
    const auto started = std::chrono::steady_clock::now();
    auto result = co_await DoRelayLink(fixture.io, input, output, target, context, stats,
                                      RelayConfig{.downlink_only = 1s, .speed_limit = 1000});
    const auto elapsed = std::chrono::steady_clock::now() - started;
    Check(result.error == ErrorCode::RELAY_TIMEOUT && result.bytes_up == 2000 && result.bytes_down == 0,
          "generic UDP relay traffic result changed");
    Check(stats.Snapshot().bytes_out == 2000 && context.traffic.bytes_up == 2000,
          "UDP relay accounting did not follow successful writes");
    Check(elapsed >= 1900ms && elapsed < 4s, "relay without client control ignored its rate limit or half-close budget");
}

net::awaitable<void> TestRelayErrorCode(Fixture& fixture) {
    UDPChannel target(fixture.io, fixture.session);
    // Empty DNS server responses cannot be needed for a malformed datagram:
    // the channel preserves its validation failure as an application error.
    OnePacketReader input(TargetAddress{});
    IgnoreWriter output;
    session::Context context;
    context.content.network = Network::UDP;
    StatsShard stats;
    auto result = co_await DoRelayLink(fixture.io, input, output, target, context, stats);
    Check(result.error == ErrorCode::INVALID_ARGUMENT && result.bytes_up == 0 &&
          stats.Snapshot().bytes_out == 0, "logical UDP failure or failed-send accounting was lost");
    Check(context.outbound.os_error_code == 0, "application failure fabricated an OS error code");
}

net::awaitable<void> TestRelayExternalCancellation(Fixture& fixture, bool deadline) {
    udp::socket peer(fixture.io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    UDPChannel target(fixture.io, fixture.session);
    OnePacketReader input(Target(peer.local_endpoint()));
    IgnoreWriter output;
    session::Context context;
    context.content.network = Network::UDP;
    StatsShard stats;
    TimeoutToken cancellation;
    if (deadline) target.StartPhaseDeadline(1s);
    else cancellation = TimeoutScheduler::ForIoContext(fixture.io).ScheduleAfter(50ms, [&] { target.Cancel(); });
    const auto start = std::chrono::steady_clock::now();
    const auto result = co_await DoRelayLink(fixture.io, input, output, target, context, stats,
        RelayConfig{.speed_limit = 100});
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto expected = deadline ? ErrorCode::RELAY_TIMEOUT : ErrorCode::CANCELLED;
    Check(result.error == expected && context.outbound.failure_detail_code == ErrorCodeToString(expected),
        "UDP external cancellation lost the terminal reason");
    Check(result.bytes_up == 0 && stats.Snapshot().bytes_out == 0 && elapsed < (deadline ? 1800ms : 500ms),
        "UDP cancellation failed to join the pending rate wait before sending");
}
}  // namespace

int main() {
    try {
        { Fixture fixture; fixture.Run(TestSharedSocket(fixture)); }
        for (int kind = 0; kind != 3; ++kind) {
            Fixture fixture; fixture.Run(TestDeadlines(fixture, kind));
        }
        { Fixture fixture; fixture.Run(TestIdleActivityAndClear(fixture)); }
        { Fixture fixture; fixture.Run(TestParentCancellation(fixture)); }
        { Fixture fixture; fixture.Run(TestQueueLimit(fixture)); }
        { Fixture fixture; fixture.Run(TestRetiredTimer(fixture)); }
        { Fixture fixture; fixture.Run(TestRelayRateAndAccounting(fixture)); }
        { Fixture fixture; fixture.Run(TestRelayErrorCode(fixture)); }
        for (bool deadline : {false, true}) {
            Fixture fixture; fixture.Run(TestRelayExternalCancellation(fixture, deadline));
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
