#include "acppnode/app/relay.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/use_future.hpp>
#include <asio/write.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <array>
#include <stdexcept>
#include <vector>

namespace {
using namespace acpp;
using namespace std::chrono_literals;

buf::MultiBuffer Payload(size_t size, uint8_t byte = 0x42) {
    std::vector<uint8_t> bytes(size, byte);
    buf::MultiBuffer result;
    if (!buf::AppendSpanToMultiBuffer(bytes, result)) throw std::bad_alloc();
    return result;
}

struct Endpoint {
    buf::MultiBuffer input;
    net::io_context* io = nullptr;
    TimeoutToken phase_timer;
    bool phase_expired = false;
    ErrorCode read_error = ErrorCode::OK;
    ErrorCode write_error = ErrorCode::OK;
    bool allocation_failure = false;
    transport::EofAction eof_action = transport::EofAction::WaitForPeer;
    bool shutdown_closes_link = false;
    bool write_closed = false;
    int shutdown_failure = 0;
    int shutdowns = 0;
    bool write_timed_out = false;
    uint64_t written = 0;
    std::vector<uint8_t> output;
    bool cancelled = false;
    std::optional<net::steady_timer> pending_read;
    int active_reads = 0;
    transport::CancellationSource cancellation;
    std::chrono::steady_clock::time_point first_write{};
    std::chrono::steady_clock::time_point last_write{};

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() {
        if (read_error != ErrorCode::OK) throw transport::LinkError(read_error);
        if (cancelled) co_return buf::MultiBuffer{};
        if (pending_read) {
            struct ReadScope {
                int& active;
                explicit ReadScope(int& value) : active(value) { ++active; }
                ~ReadScope() { --active; }
            } scope(active_reads);
            co_await pending_read->async_wait(net::use_awaitable);
        }
        co_return std::move(input);
    }
    void RecordWrite(size_t size) {
        if (cancelled) throw transport::LinkError(ErrorCode::CANCELLED);
        if (write_closed) throw transport::WriteClosed();
        if (allocation_failure) throw std::bad_alloc();
        if (write_error == ErrorCode::CANCELLED) write_timed_out = true;
        if (write_error != ErrorCode::OK) throw transport::LinkError(write_error);
        if (written == 0) first_write = std::chrono::steady_clock::now();
        last_write = std::chrono::steady_clock::now();
        written += size;
    }
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) {
        RecordWrite(buf::TotalLen(payload));
        for (const auto* buffer : payload) {
            const auto bytes = buffer->Bytes();
            output.insert(output.end(), bytes.begin(), bytes.end());
        }
        co_return;
    }
    transport::EofAction ReadEofAction() const noexcept { return eof_action; }
    bool WriteShutdownClosesLink() const noexcept { return shutdown_closes_link; }
    net::awaitable<void> AsyncShutdownWrite() {
        ++shutdowns;
        if (shutdown_failure == 1) throw std::bad_alloc();
        if (shutdown_failure == 2) throw transport::LinkError(ErrorCode::BLOCKED);
        if (shutdown_failure == 3) throw std::runtime_error("shutdown failed");
        co_return;
    }
    void Cancel(ErrorCode reason = ErrorCode::CANCELLED) noexcept {
        cancelled = true;
        cancellation.Stop(reason);
        if (pending_read) {
            IoErrorCode ec;
            pending_read->cancel(ec);
        }
    }
    transport::CancellationSource& Cancellation() noexcept { return cancellation; }
    void Close() noexcept {}
    void SetAbortiveClose(bool) noexcept {}
    void SetIdleTimeout(std::chrono::seconds) noexcept {}
    void SetReadTimeout(std::chrono::seconds) noexcept {}
    void SetWriteTimeout(std::chrono::seconds) noexcept {}
    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        if (io) phase_timer = TimeoutScheduler::ForIoContext(*io).ScheduleAfter(timeout, [this] {
            phase_expired = true;
            Cancel();
        });
        return {};
    }
    void ClearPhaseDeadline() noexcept { phase_timer = {}; }
    bool ConsumeIdleTimeout() noexcept { return false; }
    bool ConsumeReadTimeout() noexcept { return false; }
    bool ConsumeWriteTimeout() noexcept { return std::exchange(write_timed_out, false); }
    bool ConsumePhaseDeadline() noexcept { return std::exchange(phase_expired, false); }
};

net::awaitable<bool> TestRateCancellation(net::io_context& io, int mode) {
    Endpoint client, target;
    client.io = &io;
    target.io = &io;
    if (mode == 1 || mode == 3) target.input = Payload(4000);
    else client.input = Payload(4000);
    if (mode >= 6) target.input = Payload(4000);
    if (mode == 2) target.read_error = ErrorCode::RELAY_READ_FAILED;
    TimeoutToken external_cancel;
    if (mode >= 14) client.Cancel(mode == 15 ? ErrorCode::RESOURCE_EXHAUSTED : ErrorCode::CANCELLED);
    if (mode >= 6 && mode < 14) external_cancel = TimeoutScheduler::ForIoContext(io).ScheduleAfter(50ms, [&client, &target, mode] {
        if (mode >= 12) {
            client.Cancel(mode == 13 ? ErrorCode::RESOURCE_EXHAUSTED : ErrorCode::CANCELLED);
            return;
        }
        target.phase_expired = mode == 8 || mode == 9;
        target.Cancel(mode >= 10 ? ErrorCode::RESOURCE_EXHAUSTED : ErrorCode::CANCELLED);
    });
    StatsShard stats;
    session::Context context;
    const RelayConfig config{.uplink_only = mode == 4 ? 0s : 1s,
                             .downlink_only = mode == 4 ? 0s : 1s, .speed_limit = 1000};
    const auto start = std::chrono::steady_clock::now();
    const auto result = mode == 1 || mode == 5 || mode == 7 || mode == 9 || mode == 11 || mode >= 12
        ? co_await DoRelayLink(io, client, client, target, context, stats, config,
            mode >= 14 ? Payload(4000) : buf::MultiBuffer{})
        : co_await DoRelayLink(io, client, client, client, target, context, stats, config);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto expected = mode == 12 || mode == 14 ? ErrorCode::CANCELLED :
        mode >= 10 ? ErrorCode::RESOURCE_EXHAUSTED : mode == 2 ? ErrorCode::RELAY_READ_FAILED :
        (mode == 6 || mode == 7 ? ErrorCode::CANCELLED : ErrorCode::RELAY_TIMEOUT);
    const bool passed = elapsed < (mode >= 6 ? 500ms : 1800ms) && result.bytes_up == 0 && result.bytes_down == 0 &&
        context.outbound.failure_detail_code == ErrorCodeToString(result.error) &&
        result.error == expected;
    std::printf("rate cancellation mode=%d elapsed=%lldms up=%llu down=%llu code=%s: %s\n",
                mode, static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
                static_cast<unsigned long long>(result.bytes_up), static_cast<unsigned long long>(result.bytes_down),
                ErrorCodeToString(result.error).data(), passed ? "PASS" : "FAIL");
    co_return passed;
}

net::awaitable<bool> TestPendingRead(net::io_context& io, bool controlled, int mode) {
    Endpoint client, target;
    client.io = &io;
    target.io = &io;
    auto block = [&](Endpoint& endpoint) {
        endpoint.pending_read.emplace(io);
        endpoint.pending_read->expires_at(std::chrono::steady_clock::time_point::max());
    };
    if (mode != 1) block(client);
    if (mode != 0 && mode != 4) block(target);
    StatsShard stats;
    session::Context context;
    net::cancellation_signal parent;
    TimeoutToken external;
    if (mode >= 2) external = TimeoutScheduler::ForIoContext(io).ScheduleAfter(50ms, [&] {
        if (mode == 3) parent.emit(net::cancellation_type::terminal);
        else target.Cancel();
    });
    const auto budget = mode == 4 ? std::chrono::seconds::max() : 1s;
    const RelayConfig config{.uplink_only = budget, .downlink_only = budget};
    const auto start = std::chrono::steady_clock::now();
    auto relay = controlled
        ? DoRelayLink(io, client, client, client, target, context, stats, config)
        : DoRelayLink(io, client, client, target, context, stats, config);
    const auto result = co_await net::co_spawn(io, std::move(relay),
        net::bind_cancellation_slot(parent.slot(), net::use_awaitable));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto expected = mode >= 2 ? ErrorCode::CANCELLED : ErrorCode::RELAY_TIMEOUT;
    const bool passed = result.error == expected && client.active_reads == 0 && target.active_reads == 0 &&
        result.bytes_up == 0 && result.bytes_down == 0 &&
        elapsed < (mode >= 2 ? 500ms : 1800ms) && (mode != 4 || elapsed >= 30ms) &&
        context.outbound.failure_detail_code == ErrorCodeToString(expected);
    std::printf("pending read controlled=%d mode=%d elapsed=%lldms code=%s joined=%d: %s\n",
        controlled, mode, static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
        ErrorCodeToString(result.error).data(), client.active_reads + target.active_reads == 0,
        passed ? "PASS" : "FAIL");
    co_return passed;
}

net::awaitable<bool> TestTcpCancellation(net::io_context& io, bool controlled, int mode) {
    tcp::acceptor listener(io, tcp::endpoint(net::ip::address_v4::loopback(), 0));
    tcp::socket peer(io);
    peer.connect(listener.local_endpoint());
    TcpStream target(listener.accept());
    Endpoint client;
    client.io = &io;
    client.input = Payload(4000);
    std::array<uint8_t, 4000> response{};
    if (mode != 4) net::write(peer, net::buffer(response));
    if (mode == 0) target.SetIdleTimeout(1s);
    if (mode == 1) (void)target.StartPhaseDeadline(1s);
    if (mode == 3) (void)target.StartPhaseDeadline(std::chrono::seconds::max());
    if (mode == 4) target.SetReadTimeout(1s);
    TimeoutToken external;
    if (mode == 2 || mode == 3)
        external = TimeoutScheduler::ForIoContext(io).ScheduleAfter(50ms, [&] { target.Cancel(); });
    StatsShard stats;
    session::Context context;
    const RelayConfig config{.speed_limit = 1000};
    const auto start = std::chrono::steady_clock::now();
    const auto result = controlled
        ? co_await DoRelayLink(io, client, client, client, target, context, stats, config)
        : co_await DoRelayLink(io, client, client, target, context, stats, config);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto expected = mode == 2 || mode == 3 ? ErrorCode::CANCELLED : ErrorCode::RELAY_TIMEOUT;
    const bool passed = result.error == expected && result.bytes_up == 0 && result.bytes_down == 0 &&
        stats.Snapshot().bytes_out == 0 && peer.available() == 0 &&
        elapsed < (expected == ErrorCode::CANCELLED ? 500ms : mode == 0 ? 2800ms : 1800ms) && elapsed >= 30ms &&
        context.outbound.failure_detail_code == ErrorCodeToString(expected);
    std::printf("TCP cancellation controlled=%d mode=%d elapsed=%lldms code=%s: %s\n",
        controlled, mode, static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
        ErrorCodeToString(result.error).data(), passed ? "PASS" : "FAIL");
    co_return passed;
}

net::awaitable<bool> TestTcpPending(net::io_context& io, bool controlled, bool parent_cancel, bool limited) {
    tcp::acceptor listener(io, tcp::endpoint(net::ip::address_v4::loopback(), 0));
    tcp::socket client_peer(io), target_peer(io);
    client_peer.connect(listener.local_endpoint());
    TcpStream client(listener.accept());
    target_peer.connect(listener.local_endpoint());
    TcpStream target(listener.accept());
    net::cancellation_signal parent;
    auto external = TimeoutScheduler::ForIoContext(io).ScheduleAfter(50ms, [&] {
        if (parent_cancel) parent.emit(net::cancellation_type::terminal);
        else target.Cancel();
    });
    session::Context context;
    StatsShard stats;
    const RelayConfig config{.uplink_only = 1s, .downlink_only = 1s,
        .speed_limit = limited ? 1000u : 0u};
    auto relay = controlled ? DoRelayLink(io, client, client, client, target, context, stats, config) :
        DoRelayLink(io, client, client, target, context, stats, config);
    const auto start = std::chrono::steady_clock::now();
    const auto result = co_await net::co_spawn(io, std::move(relay),
        net::bind_cancellation_slot(parent.slot(), net::use_awaitable));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const bool passed = result.error == ErrorCode::CANCELLED && elapsed < 500ms &&
        result.bytes_up == 0 && result.bytes_down == 0 &&
        context.outbound.failure_detail_code == ErrorCodeToString(ErrorCode::CANCELLED);
    std::printf("TCP pending controlled=%d parent=%d limited=%d elapsed=%lldms code=%s: %s\n",
        controlled, parent_cancel, limited,
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
        ErrorCodeToString(result.error).data(), passed ? "PASS" : "FAIL");
    co_return passed;
}

net::awaitable<bool> TestInitialPayload(net::io_context& io, bool controlled, int failure,
                                      size_t prefix_size, size_t later_size, bool limited) {
    Endpoint client, target;
    client.input = Payload(later_size, 0x73);
    if (failure == 1) target.write_error = ErrorCode::RESOURCE_EXHAUSTED;
    if (failure == 2) target.allocation_failure = true;
    if (failure == 3) target.write_error = ErrorCode::CANCELLED;
    auto prefix = Payload(prefix_size);
    const auto* first_buffer = *prefix.begin();
    StatsShard stats;
    session::Context context;
    const RelayConfig config{.uplink_only = 5s, .downlink_only = 5s,
                             .speed_limit = limited ? 1000u : 0u};
    RelayResult result;
    const auto start = std::chrono::steady_clock::now();
    if (controlled) {
        result = co_await DoRelayLink(io, client, client, client, target, context, stats,
                                    config, std::move(prefix));
    } else {
        result = co_await DoRelayLink(io, client, client, target, context, stats,
                                    config, std::move(prefix));
    }
    const auto stats_bytes = stats.Snapshot().bytes_out;
    const auto first_write_ms = target.written == 0 ? -1 :
        std::chrono::duration_cast<std::chrono::milliseconds>(target.first_write - start).count();
    const auto last_write_ms = target.written == 0 ? -1 :
        std::chrono::duration_cast<std::chrono::milliseconds>(target.last_write - start).count();
    bool passed = false;
    if (failure) {
        const ErrorCode expected = failure == 3 ? ErrorCode::RELAY_TIMEOUT : ErrorCode::RESOURCE_EXHAUSTED;
        // The failed writer must have released the owning first buffer before
        // relay returns. Client's later input is still owned independently.
        buf::BufferGuard recycled{buf::Buffer::New()};
        passed = result.error == expected && result.bytes_up == 0 && stats_bytes == 0 &&
            context.traffic.bytes_up == 0 && prefix.empty() && recycled.get() == first_buffer &&
            context.outbound.failure_detail_code == ErrorCodeToString(expected) &&
            context.outbound.os_error_code == 0 && (failure != 2 || !result.close_side_known);
    } else {
        std::vector<uint8_t> expected(prefix_size, 0x42);
        expected.insert(expected.end(), later_size, 0x73);
        passed = result.error == ErrorCode::OK && result.bytes_up == expected.size() &&
            stats_bytes == expected.size() && context.traffic.bytes_up == expected.size() &&
            target.output == expected && prefix.empty() &&
            (!limited || (prefix_size > 1000 ? first_write_ms >= 900 : last_write_ms >= 450));
    }
    std::printf("controlled=%d failure=%d prefix=%zu later=%zu limited=%d error=%s result=%llu context=%llu stats=%llu first_ms=%lld last_ms=%lld passed=%d\n",
        controlled, failure, prefix_size, later_size, limited, ErrorCodeToString(result.error).data(),
        static_cast<unsigned long long>(result.bytes_up), static_cast<unsigned long long>(context.traffic.bytes_up),
        static_cast<unsigned long long>(stats_bytes), static_cast<long long>(first_write_ms),
        static_cast<long long>(last_write_ms), passed);
    co_return passed;
}

net::awaitable<bool> TestFullClose(net::io_context& io, bool controlled, int mode) {
    Endpoint client, target;
    client.io = target.io = &io;
    auto block = [&](Endpoint& endpoint, std::chrono::milliseconds timeout) {
        endpoint.pending_read.emplace(io);
        endpoint.pending_read->expires_after(timeout);
    };
    uint64_t expected_down = 0;
    ErrorCode expected_error = ErrorCode::OK;
    if (mode == 0) {
        client.input = Payload(4000);
        target.eof_action = transport::EofAction::CloseLink;
        block(target, 50ms);
    } else if (mode == 1) {
        target.input = Payload(4000);
        target.shutdown_closes_link = true;
        block(client, 50ms);
    } else if (mode == 2) {
        client.input = Payload(17);
        target.input = Payload(4000);
        target.write_closed = true;
        target.eof_action = transport::EofAction::CloseLink;
        expected_down = 4000;
    } else {
        target.shutdown_closes_link = true;
        target.shutdown_failure = mode - 2;
        block(target, 1h);
        expected_error = mode == 3 ? ErrorCode::RESOURCE_EXHAUSTED :
            mode == 4 ? ErrorCode::BLOCKED : ErrorCode::RELAY_WRITE_FAILED;
    }
    StatsShard stats;
    session::Context context;
    const RelayConfig config{.uplink_only = 10s, .downlink_only = 10s, .speed_limit = 1000};
    const auto start = std::chrono::steady_clock::now();
    const auto result = controlled
        ? co_await DoRelayLink(io, client, client, client, target, context, stats, config)
        : co_await DoRelayLink(io, client, client, target, context, stats, config);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto snapshot = stats.Snapshot();
    const bool passed = result.error == expected_error && result.bytes_up == 0 &&
        result.bytes_down == expected_down && context.traffic.bytes_down == expected_down &&
        snapshot.bytes_in == expected_down && client.written == expected_down && target.written == 0 &&
        client.active_reads == 0 && target.active_reads == 0 && target.shutdowns == 1 &&
        (mode == 2 ? elapsed >= 2900ms && elapsed < 4s : elapsed < 500ms) &&
        (mode < 3 || context.outbound.failure_detail_code == ErrorCodeToString(expected_error));
    std::printf("full close controlled=%d mode=%d up=%llu down=%llu code=%s elapsed=%lldms joined=%d shutdowns=%d: %s\n",
        controlled, mode, static_cast<unsigned long long>(result.bytes_up),
        static_cast<unsigned long long>(result.bytes_down), ErrorCodeToString(result.error).data(),
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
        client.active_reads == 0 && target.active_reads == 0, target.shutdowns, passed ? "PASS" : "FAIL");
    co_return passed;
}

bool TestInitialPayloadAllocation() {
    static_assert(alignof(buf::Buffer) <= alignof(std::max_align_t));
    struct FreeBuffer { void operator()(buf::Buffer* value) const { buf::Buffer::Free(value); } };
    std::array<std::unique_ptr<buf::Buffer, FreeBuffer>, 64> pinned;
    for (auto& value : pinned) {
        value.reset(buf::Buffer::New());
        if (!value) throw std::bad_alloc();
    }
    std::array<uint8_t, 17> bytes{};
    bytes.fill(0x33);
    InitialPayload initial;
    initial.assign(bytes);
    const auto before = memory::rejected_pmr_allocations;
    bool failed = false;
    memory::reject_next_pmr_allocation = true;
    try { auto payload = initial.MoveToMultiBuffer(); }
    catch (const std::bad_alloc&) { failed = true; }
    memory::reject_next_pmr_allocation = false;
    const bool retained = initial.size() == bytes.size() &&
        std::equal(initial.span().begin(), initial.span().end(), bytes.begin(), bytes.end());
    auto recovered = initial.MoveToMultiBuffer();
    const bool passed = failed && retained && memory::rejected_pmr_allocations > before &&
        initial.empty() && buf::TotalLen(recovered) == bytes.size();
    std::printf("initial allocation: failed=%d retained=%d recovered=%zu passed=%d\n",
        failed, retained, buf::TotalLen(recovered), passed);
    return passed;
}
}  // namespace

int main(int argc, char** argv) {
    static_assert(!std::is_move_constructible_v<acpp::TcpStream>);
    static_assert(!std::is_move_assignable_v<acpp::TcpStream>);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc == 2 && std::string_view(argv[1]) == "--full-close") {
        bool passed = true;
        for (bool controlled : {false, true}) for (int mode = 0; mode < 6; ++mode) {
            net::io_context io;
            auto future = net::co_spawn(io, TestFullClose(io, controlled, mode), net::use_future);
            io.run();
            passed = future.get() && passed;
        }
        return passed ? 0 : 1;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--source-cancellation") {
        bool source_passed = true;
        for (int mode = 12; mode < 16; ++mode) {
            net::io_context io;
            auto future = net::co_spawn(io, TestRateCancellation(io, mode), net::use_future);
            io.run();
            source_passed = future.get() && source_passed;
        }
        return source_passed ? 0 : 1;
    }
    bool passed = TestInitialPayloadAllocation();
    for (int mode = 0; mode < 16; ++mode) {
        net::io_context io;
        auto future = net::co_spawn(io, TestRateCancellation(io, mode), net::use_future);
        io.run();
        passed = future.get() && passed;
    }
    for (bool controlled : {false, true}) {
        for (bool parent : {false, true}) for (bool limited : {false, true}) {
            net::io_context io;
            auto future = net::co_spawn(io, TestTcpPending(io, controlled, parent, limited), net::use_future);
            io.run();
            passed = future.get() && passed;
        }
        for (int mode = 0; mode < 5; ++mode) {
            net::io_context io;
            auto future = net::co_spawn(io, TestPendingRead(io, controlled, mode), net::use_future);
            io.run();
            passed = future.get() && passed;
        }
        for (int mode = 0; mode < 5; ++mode) {
            net::io_context io;
            auto future = net::co_spawn(io, TestTcpCancellation(io, controlled, mode), net::use_future);
            io.run();
            passed = future.get() && passed;
        }
        for (int failure = 0; failure != 4; ++failure) {
            net::io_context io;
            auto future = net::co_spawn(io, TestInitialPayload(io, controlled, failure, 7, 5, false), net::use_future);
            io.run();
            passed = future.get() && passed;
        }
        for (auto sizes : {std::pair<size_t, size_t>{2000, 0}, {750, 750}}) {
            net::io_context io;
            auto future = net::co_spawn(io, TestInitialPayload(io, controlled, 0, sizes.first, sizes.second, true), net::use_future);
            io.run();
            passed = future.get() && passed;
        }
    }
    return passed ? 0 : 1;
}
