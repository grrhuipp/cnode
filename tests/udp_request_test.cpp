#include "proxy/freedom/outbound/udp_request.hpp"
#include "acppnode/app/dns/dns_worker.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
using namespace acpp;
using namespace std::chrono_literals;
using UdpRequest = proxy::freedom::outbound::UdpRequest;

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

class DnsPeer final {
public:
    struct Query {
        std::vector<uint8_t> packet;
        udp::endpoint sender;
    };

    explicit DnsPeer(net::io_context& io)
        : socket_(io, udp::endpoint(net::ip::address_v4::loopback(), 0)),
          query_ready_(io) {
        query_ready_.expires_at(std::chrono::steady_clock::time_point::max());
        Receive();
    }

    udp::endpoint Endpoint() const { return socket_.local_endpoint(); }

    net::awaitable<void> WaitForQuery() {
        while (queries_.empty()) {
            query_ready_.expires_at(std::chrono::steady_clock::time_point::max());
            IoErrorCode error;
            co_await query_ready_.async_wait(net::redirect_error(net::use_awaitable, error));
        }
    }

    void ReplyPendingAndEnable() {
        auto pending = queries_;
        auto_reply_ = true;
        for (const auto& query : pending) Reply(query);
    }

    size_t AReplies() const noexcept { return a_replies_; }

    void Stop() {
        stopped_ = true;
        IoErrorCode ignored;
        socket_.close(ignored);
        query_ready_.cancel(ignored);
    }

private:
    void Receive() {
        socket_.async_receive_from(net::buffer(buffer_), sender_,
            [this](const IoErrorCode& error, size_t size) {
                if (error || stopped_) return;
                Query query{{buffer_.begin(), buffer_.begin() + size}, sender_};
                queries_.push_back(query);
                IoErrorCode ignored;
                query_ready_.cancel(ignored);
                if (auto_reply_) Reply(query);
                Receive();
            });
    }

    void Reply(const Query& query) {
        if (query.packet.size() < 17) return;
        auto response = query.packet;
        size_t position = 12;
        while (position < response.size() && response[position] != 0) {
            const auto label_size = response[position++];
            if ((label_size & 0xc0) != 0 || position + label_size >= response.size()) return;
            position += label_size;
        }
        if (position + 5 > response.size()) return;
        ++position;
        const auto qtype = static_cast<uint16_t>((response[position] << 8) | response[position + 1]);
        response.resize(position + 4);
        response[2] = 0x81; // QR and RD
        response[3] = 0x80; // RA, NOERROR
        response[6] = 0;
        response[7] = qtype == 1 ? 1 : 0;
        response[8] = response[9] = response[10] = response[11] = 0;
        if (qtype == 1) {
            response.insert(response.end(), {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4,
                                             127, 0, 0, 1});
        }
        IoErrorCode ignored;
        socket_.send_to(net::buffer(response), query.sender, 0, ignored);
        if (!ignored && qtype == 1) ++a_replies_;
    }

    udp::socket socket_;
    udp::endpoint sender_;
    std::array<uint8_t, 512> buffer_{};
    net::steady_timer query_ready_;
    std::vector<Query> queries_;
    size_t a_replies_ = 0;
    bool auto_reply_ = false;
    bool stopped_ = false;
};

struct Fixture {
    net::io_context io;
    DnsPeer dns_peer{io};
    app::dns::DNSWorker dns_worker;
    app::dns::DNS dns;

    Fixture()
        : dns_worker(io, app::dns::Config{.servers = {dns_peer.Endpoint()}}, 8),
          dns(dns_worker) {}

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
            dns_peer.Stop();
            watchdog.cancel();
        });
        io.run();
        Check(done && !expired, "channel operation or cancellation did not finish");
        if (error) std::rethrow_exception(error);
    }
};

net::awaitable<void> RoundTrip(Fixture& fixture, UdpRequest& channel, size_t size) {
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

net::awaitable<void> TestCancellationIsolation(Fixture& fixture) {
    UdpRequest cancelled(fixture.io, fixture.dns, net::ip::address_v4::loopback());
    UdpRequest survivor(fixture.io, fixture.dns, net::ip::address_v4::loopback());
    struct Completion { bool finished = false; std::exception_ptr failure; };
    auto completion = std::make_shared<Completion>();
    net::co_spawn(fixture.io, cancelled.ReadMultiBuffer(),
        [completion](std::exception_ptr error, buf::MultiBuffer) {
            completion->failure = error;
            completion->finished = true;
        });
    co_await Pause(fixture.io, 20ms);
    cancelled.Cancel();
    co_await Pause(fixture.io, 20ms);
    Check(completion->finished && completion->failure,
          "request cancellation left the pending reader waiting");
    try {
        std::rethrow_exception(completion->failure);
    } catch (const transport::LinkError& error) {
        Check(error.code() == ErrorCode::CANCELLED, "request cancellation changed its error");
    }
    cancelled.Close();
    bool permanently_rejected = false;
    try { co_await cancelled.ReadMultiBuffer(); }
    catch (const transport::LinkError& error) {
        permanently_rejected = error.code() == ErrorCode::CANCELLED;
    }
    Check(permanently_rejected, "closed request accepted a new read");
    survivor.SetWriteTimeout(1s);
    co_await RoundTrip(fixture, survivor, 20000);
    co_await Pause(fixture.io, 1100ms);
    Check(!survivor.ConsumeWriteTimeout(), "completed write left a live request deadline");
    co_await RoundTrip(fixture, survivor, 11);
}

struct WriteCompletion {
    bool finished = false;
    std::exception_ptr failure;
};

enum class WriteAbort { RequestCancel, ParentCancellation, Deadline };

void RecordWriteCompletion(const std::shared_ptr<WriteCompletion>& completion,
                           std::exception_ptr error) {
    completion->failure = error;
    completion->finished = true;
}

ErrorCode WriteFailure(const std::exception_ptr& failure) {
    try {
        if (failure) std::rethrow_exception(failure);
    } catch (const transport::LinkError& error) {
        return error.code();
    }
    return ErrorCode::OK;
}

net::awaitable<void> WaitForWrite(Fixture& fixture, const WriteCompletion& completion) {
    for (int i = 0; i < 400 && !completion.finished; ++i)
        co_await Pause(fixture.io, 5ms);
    Check(completion.finished, "cancelled UDP write did not join promptly");
}

net::awaitable<void> TestDnsWriteCancellation(Fixture& fixture, WriteAbort abort) {
    UdpRequest request(fixture.io, fixture.dns, net::ip::address_v4::loopback());
    UdpRequest survivor(fixture.io, fixture.dns, net::ip::address_v4::loopback());
    udp::socket sink(fixture.io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    const auto port = sink.local_endpoint().port();
    const char* domain = abort == WriteAbort::RequestCancel ? "request-cancel.example" :
                         abort == WriteAbort::ParentCancellation ? "parent-cancel.example" :
                                                                  "write-timeout.example";
    request.SetWriteTimeout(1s);
    auto completion = std::make_shared<WriteCompletion>();
    net::cancellation_signal parent_cancellation;
    auto complete = [completion](std::exception_ptr error) {
        RecordWriteCompletion(completion, error);
    };
    auto write = request.WriteMultiBuffer(Packet(TargetAddress(domain, port), 32));
    if (abort == WriteAbort::ParentCancellation) {
        net::co_spawn(fixture.io, std::move(write),
            net::bind_cancellation_slot(parent_cancellation.slot(), complete));
    } else {
        net::co_spawn(fixture.io, std::move(write), complete);
    }

    // This proves the request reached DNSWorker's real UDP exchange before the
    // abort. The fake server then returns valid responses, including an A record
    // for the sink, so a late continuation would be observable as a UDP packet.
    co_await fixture.dns_peer.WaitForQuery();
    if (abort == WriteAbort::RequestCancel) request.Cancel();
    if (abort == WriteAbort::ParentCancellation)
        parent_cancellation.emit(net::cancellation_type::all);
    if (abort != WriteAbort::Deadline) fixture.dns_peer.ReplyPendingAndEnable();
    else co_await Pause(fixture.io, 1100ms);

    co_await WaitForWrite(fixture, *completion);
    if (abort == WriteAbort::Deadline) {
        Check(WriteFailure(completion->failure) == ErrorCode::CANCELLED &&
              request.ConsumeWriteTimeout(), "write timeout did not cancel DNS-backed write");
    } else {
        Check(WriteFailure(completion->failure) == ErrorCode::CANCELLED,
              "request/parent cancellation changed the DNS-backed write error");
    }

    if (abort == WriteAbort::Deadline) fixture.dns_peer.ReplyPendingAndEnable();
    co_await Pause(fixture.io, 40ms);
    Check(fixture.dns_peer.AReplies() != 0, "fake DNS peer did not return a valid A response");
    IoErrorCode available_error;
    Check(sink.available(available_error) == 0 && !available_error,
          "cancelled DNS write sent a datagram after a valid A response");

    // The timed-out/cancelled write deadline must be detached, and a separate
    // request must remain usable despite resolution completion arriving late.
    co_await RoundTrip(fixture, survivor, 32);
    if (abort != WriteAbort::Deadline) {
        co_await Pause(fixture.io, 1100ms);
        Check(!request.ConsumeWriteTimeout(), "cancelled write left a live deadline");
    } else {
        co_await Pause(fixture.io, 1100ms);
        Check(!request.ConsumeWriteTimeout(), "expired write deadline fired more than once");
    }
}

net::awaitable<void> TestDeadlines(Fixture& fixture, int kind) {
    UdpRequest channel(fixture.io, fixture.dns, net::ip::address_v4::loopback());
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
    UdpRequest channel(fixture.io, fixture.dns, net::ip::address_v4::loopback());
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
    UdpRequest channel(fixture.io, fixture.dns, net::ip::address_v4::loopback());
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
    UdpRequest survivor(fixture.io, fixture.dns, net::ip::address_v4::loopback());
    co_await RoundTrip(fixture, survivor, 32);
}

net::awaitable<void> TestRetiredTimer(Fixture& fixture) {
    // Queue timer readiness while no handler can execute. Destroy the owner
    // before yielding to the event loop; queued callbacks must not borrow it.
    {
        UdpRequest old(fixture.io, fixture.dns, net::ip::address_v4::loopback());
        old.StartPhaseDeadline(1s);
        std::this_thread::sleep_for(1050ms);
    }
    UdpRequest current(fixture.io, fixture.dns, net::ip::address_v4::loopback());
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
    UdpRequest target(fixture.io, fixture.dns, net::ip::address_v4::loopback());
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
    UdpRequest target(fixture.io, fixture.dns, net::ip::address_v4::loopback());
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
    UdpRequest target(fixture.io, fixture.dns, net::ip::address_v4::loopback());
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
        { Fixture fixture; fixture.Run(TestCancellationIsolation(fixture)); }
        { Fixture fixture; fixture.Run(TestDnsWriteCancellation(fixture, WriteAbort::RequestCancel)); }
        { Fixture fixture; fixture.Run(TestDnsWriteCancellation(fixture, WriteAbort::ParentCancellation)); }
        { Fixture fixture; fixture.Run(TestDnsWriteCancellation(fixture, WriteAbort::Deadline)); }
        for (int kind = 0; kind != 3; ++kind) {
            Fixture fixture; fixture.Run(TestDeadlines(fixture, kind));
        }
        { Fixture fixture; fixture.Run(TestIdleActivityAndClear(fixture)); }
        { Fixture fixture; fixture.Run(TestParentCancellation(fixture)); }
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
