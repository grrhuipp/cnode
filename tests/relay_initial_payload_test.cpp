#include <gtest/gtest.h>

#include "app/relay.hpp"
#include "common/initial_payload.hpp"
#include "transport/tcp_stream.hpp"
#include "transport/timeout_scheduler.hpp"
#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/use_future.hpp>
#include <asio/write.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <array>
#include <span>
#include <stdexcept>
#include <vector>

namespace {
using namespace std::chrono_literals;

template<class F>
struct TestEvent final : transport::TimeoutEvent {
    explicit TestEvent(F callback) : callback(std::move(callback)) {}
    void OnTimeout() override { callback(); }
    F callback;
};

common::MultiBuffer Payload(size_t size, uint8_t byte) {
    std::vector<uint8_t> bytes(size, byte);
    common::MultiBuffer result;
    if (!common::AppendSpanToMultiBuffer(bytes, result)) throw std::bad_alloc();
    return result;
}

common::MultiBuffer Payload(size_t size) {
    return Payload(size, 0x42);
}

struct Endpoint : transport::TimeoutEvent {
    common::MultiBuffer input;
    net::io_context* io = nullptr;
    bool phase_expired = false;
    uint8_t phase_flags = 0;
    uint32_t phase_generation = 0;
    common::ErrorCode read_error = common::ErrorCode::OK;
    common::ErrorCode write_error = common::ErrorCode::OK;
    bool allocation_failure = false;
    bool unknown_read_failure = false;
    bool unknown_write_failure = false;
    transport::EofAction eof_action = transport::EofAction::WaitForPeer;
    bool shutdown_closes_link = false;
    bool write_closed = false;
    int shutdown_failure = 0;
    int shutdowns = 0;
    bool write_timed_out = false;
    uint64_t written = 0;
    std::vector<uint8_t> output;
    std::vector<size_t> packet_sizes;
    std::vector<size_t> packet_fragments;
    std::vector<uint16_t> packet_ports;
    size_t read_calls = 0;
    size_t fail_after_writes = 0;
    common::ErrorCode later_write_error = common::ErrorCode::OK;
    bool cancelled = false;
    std::optional<net::steady_timer> pending_read;
    int active_reads = 0;
    std::optional<net::steady_timer> pending_write;
    int active_writes = 0;
    transport::CancellationSource cancellation;
    std::chrono::steady_clock::time_point first_write{};
    std::chrono::steady_clock::time_point last_write{};

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() {
        ++read_calls;
        if (unknown_read_failure) throw std::runtime_error("read failed");
        if (read_error != common::ErrorCode::OK) throw transport::LinkError(read_error);
        if (cancelled) co_return common::MultiBuffer{};
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
        if (cancelled) throw transport::LinkError(common::ErrorCode::CANCELLED);
        if (write_closed) throw transport::WriteClosed();
        if (allocation_failure) throw std::bad_alloc();
        if (unknown_write_failure) throw std::runtime_error("write failed");
        if (write_error == common::ErrorCode::CANCELLED) write_timed_out = true;
        if (write_error != common::ErrorCode::OK) throw transport::LinkError(write_error);
        if (written == 0) first_write = std::chrono::steady_clock::now();
        last_write = std::chrono::steady_clock::now();
        written += size;
    }
    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer payload) {
        if (pending_write) {
            struct WriteScope {
                int& active;
                explicit WriteScope(int& value) : active(value) { ++active; }
                ~WriteScope() { --active; }
            } scope(active_writes);
            co_await pending_write->async_wait(net::use_awaitable);
        }
        if (fail_after_writes && packet_sizes.size() == fail_after_writes)
            throw transport::LinkError(later_write_error);
        RecordWrite(payload.byte_size());
        packet_sizes.push_back(payload.byte_size());
        packet_fragments.push_back(payload.size());
        const auto* first = payload.empty() ? nullptr : *payload.begin();
        packet_ports.push_back(first && first->HasUDP() ? first->UDP().port : 0);
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
        if (shutdown_failure == 2) throw transport::LinkError(common::ErrorCode::BLOCKED);
        if (shutdown_failure == 3) throw std::runtime_error("shutdown failed");
        co_return;
    }
    void Cancel(common::ErrorCode reason = common::ErrorCode::CANCELLED) noexcept {
        cancelled = true;
        cancellation.Stop(reason);
        if (pending_read) {
            pending_read->cancel();
        }
        if (pending_write) pending_write->cancel();
    }
    transport::CancellationSource& Cancellation() noexcept { return cancellation; }
    void Close() noexcept {}
    void SetAbortiveClose(bool) noexcept {}
    void SetIdleTimeout(std::chrono::seconds) noexcept {}
    void SetReadTimeout(std::chrono::seconds) noexcept {}
    void SetWriteTimeout(std::chrono::seconds) noexcept {}
    transport::PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        if (!io) return {};
        ++phase_generation;
        phase_expired = false;
        phase_flags = 0;
        const auto maximum = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds::max());
        const auto delay = timeout >= maximum ? std::chrono::milliseconds::max()
            : std::chrono::duration_cast<std::chrono::milliseconds>(timeout);
        if (!transport::TimeoutScheduler::ForIoContext(*io).ScheduleAfter(delay, *this)) return {};
        return {&phase_flags, 1, &phase_generation, phase_generation};
    }
    void OnTimeout() override {
        phase_expired = true;
        phase_flags = 1;
        Cancel();
    }
    void ClearPhaseDeadline() noexcept {
        transport::TimeoutEvent::Cancel();
        ++phase_generation;
        phase_flags = 0;
        phase_expired = false;
    }
    bool ConsumeIdleTimeout() noexcept { return false; }
    bool ConsumeReadTimeout() noexcept { return false; }
    bool ConsumeWriteTimeout() noexcept { return std::exchange(write_timed_out, false); }
    bool ConsumePhaseDeadline() noexcept {
        phase_flags = 0;
        return std::exchange(phase_expired, false);
    }
};

// relay 的客户端侧只接受 transport 读写接口与 AsyncStream 控制面。该适配器把桩端点
// 接到这些具体接口上；客户端阶段截止期由内嵌的 StreamPhaseDeadline 承载，到期时取消桩端点。
class ClientStream final : public transport::AsyncStream {
public:
    ClientStream(net::io_context& io, Endpoint& endpoint) : endpoint_(endpoint), phase_(io, *this) {}

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override { return endpoint_.ReadMultiBuffer(); }
    transport::EofAction ReadEofAction() const noexcept override { return endpoint_.ReadEofAction(); }
    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer payload) override {
        return endpoint_.WriteMultiBuffer(std::move(payload));
    }
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return WriteBuffersAsMultiBuffer(buffers);
    }
    net::awaitable<void> AsyncShutdownWrite() override { return endpoint_.AsyncShutdownWrite(); }
    bool WriteShutdownClosesLink() const noexcept override { return endpoint_.WriteShutdownClosesLink(); }
    transport::CancellationSource& Cancellation() noexcept override { return endpoint_.Cancellation(); }
    void Cancel() noexcept override { endpoint_.Cancel(); }
    void Close() override { endpoint_.Close(); }
    bool ConsumeWriteTimeout() noexcept override { return endpoint_.ConsumeWriteTimeout(); }
    net::awaitable<std::size_t> AsyncRead(net::mutable_buffer) override {
        throw std::logic_error("relay reads MultiBuffer only");
    }
    net::awaitable<std::size_t> AsyncWrite(net::const_buffer) override {
        throw std::logic_error("relay writes MultiBuffer only");
    }
    void ShutdownWrite() override {}
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return true; }

protected:
    transport::StreamPhaseDeadline* LogicalPhaseDeadline() noexcept override { return &phase_; }

private:
    Endpoint& endpoint_;
    transport::StreamPhaseDeadline phase_;
};

net::awaitable<bool> TestRateCancellation(net::io_context& io, int mode) {
    Endpoint client, target;
    client.io = &io;
    target.io = &io;
    ClientStream link(io, client);
    if (mode == 1 || mode == 3) target.input = Payload(4000);
    else client.input = Payload(4000);
    if (mode >= 6) target.input = Payload(4000);
    if (mode == 2) target.read_error = common::ErrorCode::SOCKET_READ_FAILED;
    if (mode >= 14) client.Cancel(mode == 15 ? common::ErrorCode::RESOURCE_EXHAUSTED : common::ErrorCode::CANCELLED);
    TestEvent external_cancel([&client, &target, mode] {
        if (mode >= 12) {
            client.Cancel(mode == 13 ? common::ErrorCode::RESOURCE_EXHAUSTED : common::ErrorCode::CANCELLED);
            return;
        }
        target.phase_expired = mode == 8 || mode == 9;
        target.Cancel(mode >= 10 ? common::ErrorCode::RESOURCE_EXHAUSTED : common::ErrorCode::CANCELLED);
    });
    if (mode >= 6 && mode < 14)
        (void)transport::TimeoutScheduler::ForIoContext(io).ScheduleAfter(50ms, external_cancel);
    app::StatsShard stats;
    common::Context context;
    const app::RelayConfig config{.uplink_only = mode == 4 ? 0s : 1s,
                             .downlink_only = mode == 4 ? 0s : 1s, .speed_limit = 1000};
    const auto start = std::chrono::steady_clock::now();
    const bool controlled = !(mode == 1 || mode == 5 || mode == 7 || mode == 9 || mode == 11 || mode >= 12);
    const auto result = co_await app::DoRelayLink(io, link, link, controlled ? &link : nullptr,
        target, context, stats, config,
        common::MultiBufferBatch(mode >= 14 ? Payload(4000) : common::MultiBuffer{}));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto expected = mode == 12 || mode == 14 ? common::ErrorCode::CANCELLED :
        mode >= 10 ? common::ErrorCode::RESOURCE_EXHAUSTED : mode == 2 ? common::ErrorCode::SOCKET_READ_FAILED :
        (mode == 6 || mode == 7 ? common::ErrorCode::CANCELLED : common::ErrorCode::RELAY_TIMEOUT);
    const bool passed = elapsed < (mode >= 6 ? 500ms : 1800ms) && result.bytes_up == 0 && result.bytes_down == 0 &&
        result.error == expected;
    std::printf("rate cancellation mode=%d elapsed=%lldms up=%llu down=%llu code=%s: %s\n",
                mode, static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
                static_cast<unsigned long long>(result.bytes_up), static_cast<unsigned long long>(result.bytes_down),
                common::ErrorCodeToString(result.error).data(), passed ? "PASS" : "FAIL");
    co_return passed;
}

net::awaitable<bool> TestPendingRead(net::io_context& io, bool controlled, int mode) {
    Endpoint client, target;
    client.io = &io;
    target.io = &io;
    ClientStream link(io, client);
    auto block = [&](Endpoint& endpoint) {
        endpoint.pending_read.emplace(io);
        endpoint.pending_read->expires_at(std::chrono::steady_clock::time_point::max());
    };
    if (mode != 1) block(client);
    if (mode != 0 && mode != 4) block(target);
    app::StatsShard stats;
    common::Context context;
    net::cancellation_signal parent;
    TestEvent external([&] {
        if (mode == 3) parent.emit(net::cancellation_type::terminal);
        else target.Cancel();
    });
    if (mode >= 2) (void)transport::TimeoutScheduler::ForIoContext(io).ScheduleAfter(50ms, external);
    const auto budget = mode == 4 ? std::chrono::seconds::max() : 1s;
    const app::RelayConfig config{.uplink_only = budget, .downlink_only = budget};
    const auto start = std::chrono::steady_clock::now();
    auto relay = app::DoRelayLink(io, link, link, controlled ? &link : nullptr,
                            target, context, stats, config);
    const auto result = co_await net::co_spawn(io, std::move(relay),
        net::bind_cancellation_slot(parent.slot(), net::use_awaitable));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto expected = mode >= 2 ? common::ErrorCode::CANCELLED : common::ErrorCode::RELAY_TIMEOUT;
    const bool passed = result.error == expected && client.active_reads == 0 && target.active_reads == 0 &&
        result.bytes_up == 0 && result.bytes_down == 0 &&
        elapsed < (mode >= 2 ? 500ms : 1800ms) && (mode != 4 || elapsed >= 30ms);
    std::printf("pending read controlled=%d mode=%d elapsed=%lldms code=%s joined=%d: %s\n",
        controlled, mode, static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
        common::ErrorCodeToString(result.error).data(), client.active_reads + target.active_reads == 0,
        passed ? "PASS" : "FAIL");
    co_return passed;
}

net::awaitable<bool> TestTcpCancellation(net::io_context& io, bool controlled, int mode) {
    tcp::acceptor listener(io, tcp::endpoint(net::ip::address_v4::loopback(), 0));
    tcp::socket peer(io);
    peer.connect(listener.local_endpoint());
    transport::TcpStream target(listener.accept());
    Endpoint client;
    client.io = &io;
    ClientStream link(io, client);
    client.input = Payload(4000);
    std::array<uint8_t, 4000> response{};
    if (mode != 4) net::write(peer, net::buffer(response));
    if (mode == 0) target.SetIdleTimeout(1s);
    if (mode == 1) (void)target.StartPhaseDeadline(1s);
    if (mode == 3) (void)target.StartPhaseDeadline(std::chrono::seconds::max());
    if (mode == 4) target.SetReadTimeout(1s);
    TestEvent external([&] { target.Cancel(); });
    if (mode == 2 || mode == 3)
        (void)transport::TimeoutScheduler::ForIoContext(io).ScheduleAfter(50ms, external);
    app::StatsShard stats;
    common::Context context;
    const app::RelayConfig config{.speed_limit = 1000};
    const auto start = std::chrono::steady_clock::now();
    const auto result = co_await app::DoRelayLink(io, link, link, controlled ? &link : nullptr,
                                           target, context, stats, config);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto expected = mode == 2 || mode == 3 ? common::ErrorCode::CANCELLED : common::ErrorCode::RELAY_TIMEOUT;
    const bool passed = result.error == expected && result.bytes_up == 0 && result.bytes_down == 0 &&
        stats.Snapshot().bytes_out == 0 && peer.available() == 0 &&
        elapsed < (expected == common::ErrorCode::CANCELLED ? 500ms : mode == 0 ? 2800ms : 1800ms) && elapsed >= 30ms;
    std::printf("TCP cancellation controlled=%d mode=%d elapsed=%lldms code=%s: %s\n",
        controlled, mode, static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
        common::ErrorCodeToString(result.error).data(), passed ? "PASS" : "FAIL");
    co_return passed;
}

net::awaitable<bool> TestTcpPending(net::io_context& io, bool controlled, bool parent_cancel, bool limited) {
    tcp::acceptor listener(io, tcp::endpoint(net::ip::address_v4::loopback(), 0));
    tcp::socket client_peer(io), target_peer(io);
    client_peer.connect(listener.local_endpoint());
    transport::TcpStream client(listener.accept());
    target_peer.connect(listener.local_endpoint());
    transport::TcpStream target(listener.accept());
    net::cancellation_signal parent;
    TestEvent external([&] {
        if (parent_cancel) parent.emit(net::cancellation_type::terminal);
        else target.Cancel();
    });
    (void)transport::TimeoutScheduler::ForIoContext(io).ScheduleAfter(50ms, external);
    common::Context context;
    app::StatsShard stats;
    const app::RelayConfig config{.uplink_only = 1s, .downlink_only = 1s,
        .speed_limit = limited ? 1000u : 0u};
    auto relay = app::DoRelayLink(io, client, client, controlled ? &client : nullptr,
                            target, context, stats, config);
    const auto start = std::chrono::steady_clock::now();
    const auto result = co_await net::co_spawn(io, std::move(relay),
        net::bind_cancellation_slot(parent.slot(), net::use_awaitable));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const bool passed = result.error == common::ErrorCode::CANCELLED && elapsed < 500ms &&
        result.bytes_up == 0 && result.bytes_down == 0;
    std::printf("TCP pending controlled=%d parent=%d limited=%d elapsed=%lldms code=%s: %s\n",
        controlled, parent_cancel, limited,
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
        common::ErrorCodeToString(result.error).data(), passed ? "PASS" : "FAIL");
    co_return passed;
}

net::awaitable<bool> TestInitialPayload(net::io_context& io, bool controlled, int failure,
                                      size_t prefix_size, size_t later_size, bool limited) {
    Endpoint client, target;
    client.io = target.io = &io;
    ClientStream link(io, client);
    client.input = Payload(later_size, 0x73);
    if (failure == 1) target.write_error = common::ErrorCode::RESOURCE_EXHAUSTED;
    if (failure == 2) target.allocation_failure = true;
    if (failure == 3) target.write_error = common::ErrorCode::CANCELLED;
    auto prefix = Payload(prefix_size);
    app::StatsShard stats;
    common::Context context;
    const app::RelayConfig config{.uplink_only = 5s, .downlink_only = 5s,
                             .speed_limit = limited ? 1000u : 0u};
    app::RelayResult result;
    const auto start = std::chrono::steady_clock::now();
    result = co_await app::DoRelayLink(io, link, link, controlled ? &link : nullptr,
                                 target, context, stats, config, common::MultiBufferBatch(std::move(prefix)));
    const auto stats_bytes = stats.Snapshot().bytes_out;
    const auto first_write_ms = target.written == 0 ? -1 :
        std::chrono::duration_cast<std::chrono::milliseconds>(target.first_write - start).count();
    const auto last_write_ms = target.written == 0 ? -1 :
        std::chrono::duration_cast<std::chrono::milliseconds>(target.last_write - start).count();
    bool passed = false;
    if (failure) {
        const common::ErrorCode expected = failure == 3 ? common::ErrorCode::RELAY_TIMEOUT : common::ErrorCode::RESOURCE_EXHAUSTED;
        passed = result.error == expected && result.bytes_up == 0 && stats_bytes == 0 &&
            context.traffic.bytes_up == 0 && prefix.empty() &&
            (failure != 2 || !result.close_side_known);
    } else {
        std::vector<uint8_t> expected(prefix_size, 0x42);
        expected.insert(expected.end(), later_size, 0x73);
        passed = result.error == common::ErrorCode::OK && result.bytes_up == expected.size() &&
            stats_bytes == expected.size() && context.traffic.bytes_up == expected.size() &&
            target.output == expected && prefix.empty() &&
            (!limited || (prefix_size > 1000 ? first_write_ms >= 900 : last_write_ms >= 450));
    }
    std::printf("controlled=%d failure=%d prefix=%zu later=%zu limited=%d error=%s result=%llu context=%llu stats=%llu first_ms=%lld last_ms=%lld passed=%d\n",
        controlled, failure, prefix_size, later_size, limited, common::ErrorCodeToString(result.error).data(),
        static_cast<unsigned long long>(result.bytes_up), static_cast<unsigned long long>(context.traffic.bytes_up),
        static_cast<unsigned long long>(stats_bytes), static_cast<long long>(first_write_ms),
        static_cast<long long>(last_write_ms), passed);
    co_return passed;
}

bool TestBatchOwnership() {
    auto first = Payload(3);
    auto second = Payload(5);
    common::reject_next_process_allocation = true;
    common::MultiBufferBatch batch(std::move(first));
    bool passed = common::reject_next_process_allocation && batch.byte_size() == 3;
    bool failed = false;
    try { batch.Push(std::move(second)); }
    catch (const std::bad_alloc&) { failed = true; }
    common::reject_next_process_allocation = false;
    passed = passed && failed && batch.byte_size() == 3;
    batch.Push(Payload(7));
    batch.Push(Payload(11));
    common::MultiBufferBatch moved(std::move(batch));
    passed = passed && batch.empty() && batch.byte_size() == 0 &&
        moved.PopFront().byte_size() == 3 && moved.byte_size() == 18;
    common::MultiBufferBatch assigned(Payload(1));
    assigned = std::move(moved);
    passed = passed && moved.empty() && moved.byte_size() == 0 &&
        assigned.PopFront().byte_size() == 7 && assigned.PopFront().byte_size() == 11 &&
        assigned.empty() && assigned.byte_size() == 0 && assigned.PopFront().empty();
    first = Payload(13);
    second = Payload(17);
    common::reject_next_process_allocation = true;
    assigned.Push(std::move(first));
    passed = passed && common::reject_next_process_allocation;
    failed = false;
    try { assigned.Push(std::move(second)); }
    catch (const std::bad_alloc&) { failed = true; }
    common::reject_next_process_allocation = false;
    passed = passed && failed && assigned.byte_size() == 13;
    assigned.clear();
    passed = passed && assigned.empty() && assigned.byte_size() == 0;
    std::printf("batch ownership/allocation: %s\n", passed ? "PASS" : "FAIL");
    return passed;
}

net::awaitable<bool> TestDatagramBatch(net::io_context& io, bool controlled, int mode) {
    Endpoint client, target;
    client.io = target.io = &io;
    ClientStream link(io, client);
    auto packet = [](size_t size, uint8_t byte, uint16_t port) {
        auto result = Payload(size, byte);
        if (!common::SetUdpTarget(result, common::TargetAddress("127.0.0.1", port))) throw std::bad_alloc();
        return result;
    };
    common::MultiBufferBatch batch;
    batch.Push(packet(3, 0x11, 1001));
    batch.Push(packet(0, 0, 1005));
    batch.Push(packet(common::Buffer::kSize + 7, 0x22, 1002));
    batch.Push(packet(0, 0, 1006));
    batch.Push(packet(5, 0x33, 1003));
    const size_t queued_bytes = 3 + common::Buffer::kSize + 7 + 5;
    const bool queued_ok = batch.byte_size() == queued_bytes;
    client.input = packet(9, 0x44, 1004);
    if (mode == 1) client.read_error = common::ErrorCode::SOCKET_READ_FAILED;
    if (mode >= 2) {
        target.fail_after_writes = 1;
        target.later_write_error = mode == 2 ? common::ErrorCode::RESOURCE_EXHAUSTED : common::ErrorCode::CANCELLED;
    }
    app::StatsShard stats;
    common::Context context;
    context.content.network = common::Network::UDP;
    const app::RelayConfig config{.uplink_only = 5s, .downlink_only = 5s};
    const auto result = co_await app::DoRelayLink(io, link, link, controlled ? &link : nullptr,
                                           target, context, stats, config, std::move(batch));
    std::vector<size_t> sizes{3};
    std::vector<size_t> fragments{1};
    std::vector<uint16_t> ports{1001};
    std::vector<uint8_t> bytes(3, 0x11);
    if (mode < 2) {
        sizes.insert(sizes.end(), {0, common::Buffer::kSize + 7, 0, 5});
        fragments.insert(fragments.end(), {1, 1, 1, 1});
        ports.insert(ports.end(), {1005, 1002, 1006, 1003});
        bytes.insert(bytes.end(), common::Buffer::kSize + 7, 0x22);
        bytes.insert(bytes.end(), 5, 0x33);
        if (mode == 0) {
            sizes.push_back(9);
            fragments.push_back(1);
            ports.push_back(1004);
            bytes.insert(bytes.end(), 9, 0x44);
        }
    }
    const auto expected = mode == 0 ? common::ErrorCode::OK : mode == 1 ? common::ErrorCode::SOCKET_READ_FAILED :
        mode == 2 ? common::ErrorCode::RESOURCE_EXHAUSTED : common::ErrorCode::CANCELLED;
    const bool passed = queued_ok && batch.empty() && batch.byte_size() == 0 &&
        target.packet_sizes == sizes && target.packet_fragments == fragments &&
        target.packet_ports == ports && target.output == bytes &&
        result.error == expected && result.bytes_up == bytes.size() &&
        context.traffic.bytes_up == bytes.size() && stats.Snapshot().bytes_out == bytes.size() &&
        client.read_calls == (mode == 0 ? 2u : mode == 1 ? 1u : 0u);
    std::printf("datagram batch controlled=%d mode=%d: %s\n",
        controlled, mode, passed ? "PASS" : "FAIL");
    co_return passed;
}

net::awaitable<bool> TestFullClose(net::io_context& io, bool controlled, int mode) {
    Endpoint client, target;
    client.io = target.io = &io;
    ClientStream link(io, client);
    auto block = [&](Endpoint& endpoint, std::chrono::milliseconds timeout) {
        endpoint.pending_read.emplace(io);
        endpoint.pending_read->expires_after(timeout);
    };
    uint64_t expected_down = 0;
    common::ErrorCode expected_error = common::ErrorCode::OK;
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
        expected_error = mode == 3 ? common::ErrorCode::RESOURCE_EXHAUSTED :
            mode == 4 ? common::ErrorCode::BLOCKED : common::ErrorCode::RELAY_WRITE_FAILED;
    }
    app::StatsShard stats;
    common::Context context;
    const app::RelayConfig config{.uplink_only = 10s, .downlink_only = 10s, .speed_limit = 1000};
    const auto start = std::chrono::steady_clock::now();
    const auto result = co_await app::DoRelayLink(io, link, link, controlled ? &link : nullptr,
                                           target, context, stats, config);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto snapshot = stats.Snapshot();
    const bool passed = result.error == expected_error && result.bytes_up == 0 &&
        result.bytes_down == expected_down && context.traffic.bytes_down == expected_down &&
        snapshot.bytes_in == expected_down && client.written == expected_down && target.written == 0 &&
        client.active_reads == 0 && target.active_reads == 0 && target.shutdowns == 1 &&
        (mode == 2 ? elapsed >= 2900ms && elapsed < 4s : elapsed < 500ms);
    std::printf("full close controlled=%d mode=%d up=%llu down=%llu code=%s elapsed=%lldms joined=%d shutdowns=%d: %s\n",
        controlled, mode, static_cast<unsigned long long>(result.bytes_up),
        static_cast<unsigned long long>(result.bytes_down), common::ErrorCodeToString(result.error).data(),
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()),
        client.active_reads == 0 && target.active_reads == 0, target.shutdowns, passed ? "PASS" : "FAIL");
    co_return passed;
}
net::awaitable<bool> TestExceptionClassification(net::io_context& io, bool controlled, int mode) {
    Endpoint client, target;
    client.io = target.io = &io;
    ClientStream link(io, client);
    if (mode == 0) client.unknown_read_failure = true;
    else if (mode == 1) {
        client.input = Payload(3);
        target.unknown_write_failure = true;
    } else {
        // Both children throw: their original causes must survive the join,
        // including bad_alloc and LinkError, not become multiple_exceptions.
        client.shutdown_failure = target.shutdown_failure = mode - 1;
        target.shutdown_closes_link = true;
    }
    const auto expected = mode == 0 ? common::ErrorCode::INTERNAL :
        mode == 2 ? common::ErrorCode::RESOURCE_EXHAUSTED :
        mode == 3 ? common::ErrorCode::BLOCKED : common::ErrorCode::RELAY_WRITE_FAILED;
    app::StatsShard stats;
    common::Context context;
    const auto result = co_await app::DoRelayLink(io, link, link, controlled ? &link : nullptr,
                                           target, context, stats);
    const bool passed = result.error == expected &&
        client.active_reads == 0 && target.active_reads == 0 &&
        client.active_writes == 0 && target.active_writes == 0 &&
        (mode < 2 || (client.shutdowns == 1 && target.shutdowns == 1));
    std::printf("exception classification controlled=%d mode=%d code=%s: %s\n",
        controlled, mode, common::ErrorCodeToString(result.error).data(), passed ? "PASS" : "FAIL");
    co_return passed;
}


net::awaitable<bool> TestTcpHalfClose(net::io_context& io, bool controlled, bool upload_first) {
    using namespace net::experimental::awaitable_operators;
    tcp::acceptor listener(io, tcp::endpoint(net::ip::address_v4::loopback(), 0));
    tcp::socket client_peer(io), target_peer(io);
    client_peer.connect(listener.local_endpoint());
    transport::TcpStream client(listener.accept());
    target_peer.connect(listener.local_endpoint());
    transport::TcpStream target(listener.accept());
    common::Context context;
    app::StatsShard stats;
    auto peers = [&]() -> net::awaitable<bool> {
        auto& first = upload_first ? client_peer : target_peer;
        auto& reverse = upload_first ? target_peer : client_peer;
        const std::array<uint8_t, 3> request{1, 2, 3};
        const std::array<uint8_t, 5> response{4, 5, 6, 7, 8};
        co_await net::async_write(first, net::buffer(request), net::use_awaitable);
        first.shutdown(tcp::socket::shutdown_send);
        std::array<uint8_t, 16> received{};
        size_t count = 0;
        for (;;) {
            auto [error, size] = co_await reverse.async_read_some(
                net::buffer(received.data() + count, received.size() - count),
                net::as_tuple(net::use_awaitable));
            count += size;
            if (error == net::error::eof) break;
            if (error || count >= received.size()) co_return false;
        }
        if (count != request.size() || !std::equal(request.begin(), request.end(), received.begin())) co_return false;
        // Only send the reverse payload AFTER observing directional FIN.
        co_await net::async_write(reverse, net::buffer(response), net::use_awaitable);
        reverse.shutdown(tcp::socket::shutdown_send);
        count = 0;
        for (;;) {
            auto [error, size] = co_await first.async_read_some(
                net::buffer(received.data() + count, received.size() - count),
                net::as_tuple(net::use_awaitable));
            count += size;
            if (error == net::error::eof) break;
            if (error || count >= received.size()) co_return false;
        }
        co_return count == response.size() && std::equal(response.begin(), response.end(), received.begin());
    };
    auto [result, received] = co_await (
        app::DoRelayLink(io, client, client, controlled ? &client : nullptr, target, context, stats,
                    app::RelayConfig{.uplink_only = 2s, .downlink_only = 2s}) && peers());
    const auto snapshot = stats.Snapshot();
    const bool passed = received && result.error == common::ErrorCode::OK &&
        result.bytes_up == (upload_first ? 3u : 5u) && result.bytes_down == (upload_first ? 5u : 3u) &&
        snapshot.bytes_out == result.bytes_up && snapshot.bytes_in == result.bytes_down &&
        result.close_side_known && result.client_closed_first == upload_first;
    std::printf("TCP half-close controlled=%d upload_first=%d: %s\n", controlled, upload_first, passed ? "PASS" : "FAIL");
    co_return passed;
}

net::awaitable<bool> TestBackpressuredWrite(net::io_context& io, bool controlled, bool upload, int mode) {
    Endpoint client, target;
    client.io = target.io = &io;
    ClientStream link(io, client);
    auto& reader = upload ? client : target;
    auto& writer = upload ? target : client;
    reader.input = Payload(17);
    writer.pending_read.emplace(io);
    writer.pending_read->expires_at(std::chrono::steady_clock::time_point::max());
    writer.pending_write.emplace(io);
    writer.pending_write->expires_at(std::chrono::steady_clock::time_point::max());
    net::cancellation_signal parent;
    TestEvent stop([&] {
        if (mode == 1) parent.emit(net::cancellation_type::terminal);
        else target.Cancel(common::ErrorCode::RESOURCE_EXHAUSTED);
    });
    if (mode == 2) (void)target.StartPhaseDeadline(1s);
    else (void)transport::TimeoutScheduler::ForIoContext(io).ScheduleAfter(50ms, stop);
    common::Context context;
    app::StatsShard stats;
    const auto start = std::chrono::steady_clock::now();
    const auto result = co_await net::co_spawn(io,
        app::DoRelayLink(io, link, link, controlled ? &link : nullptr, target, context, stats),
        net::bind_cancellation_slot(parent.slot(), net::use_awaitable));
    const auto expected = mode == 2 ? common::ErrorCode::RELAY_TIMEOUT :
        mode == 1 ? common::ErrorCode::CANCELLED : common::ErrorCode::RESOURCE_EXHAUSTED;
    const bool passed = result.error == expected && result.bytes_up == 0 && result.bytes_down == 0 &&
        client.active_reads == 0 && target.active_reads == 0 &&
        client.active_writes == 0 && target.active_writes == 0 &&
        stats.Snapshot().bytes_out == 0 && stats.Snapshot().bytes_in == 0 &&
        std::chrono::steady_clock::now() - start < (mode == 2 ? 1800ms : 500ms);
    std::printf("backpressured write controlled=%d upload=%d mode=%d: %s\n",
                controlled, upload, mode, passed ? "PASS" : "FAIL");
    co_return passed;
}

template <class Scenario>
bool RunScenario(Scenario scenario) {
    net::io_context io;
    auto future = net::co_spawn(io, scenario(io), net::use_future);
    io.run();
    return future.get();
}

}  // namespace

class RelayInitialPayload : public ::testing::Test {
protected:
    void SetUp() override { std::setvbuf(stdout, nullptr, _IONBF, 0); }
};

TEST_F(RelayInitialPayload, FullCloseAndExceptionClassification) {
    bool passed = true;
    for (bool controlled : {false, true}) for (int mode = 0; mode < 6; ++mode) {
        passed = RunScenario([&](net::io_context& io) { return TestFullClose(io, controlled, mode); }) && passed;
    }
    for (bool controlled : {false, true}) for (int mode = 0; mode < 5; ++mode) {
        passed = RunScenario([&](net::io_context& io) {
            return TestExceptionClassification(io, controlled, mode);
        }) && passed;
    }
    EXPECT_TRUE(passed);
}

TEST_F(RelayInitialPayload, SourceCancellation) {
    bool passed = true;
    for (int mode = 12; mode < 16; ++mode) {
        passed = RunScenario([&](net::io_context& io) { return TestRateCancellation(io, mode); }) && passed;
    }
    EXPECT_TRUE(passed);
}

TEST_F(RelayInitialPayload, HalfCloseBackpressure) {
    bool passed = true;
    for (bool controlled : {false, true}) {
        for (bool upload_first : {false, true}) {
            passed = RunScenario([&](net::io_context& io) {
                return TestTcpHalfClose(io, controlled, upload_first);
            }) && passed;
        }
        for (bool upload : {false, true}) for (int mode = 0; mode < 3; ++mode) {
            passed = RunScenario([&](net::io_context& io) {
                return TestBackpressuredWrite(io, controlled, upload, mode);
            }) && passed;
        }
    }
    EXPECT_TRUE(passed);
}

TEST_F(RelayInitialPayload, Lifecycle) {
    bool passed = TestBatchOwnership();
    for (int mode = 0; mode < 16; ++mode) {
        passed = RunScenario([&](net::io_context& io) { return TestRateCancellation(io, mode); }) && passed;
    }
    for (bool controlled : {false, true}) {
        for (int mode = 0; mode < 4; ++mode) {
            passed = RunScenario([&](net::io_context& io) { return TestDatagramBatch(io, controlled, mode); }) && passed;
        }
        for (bool parent : {false, true}) for (bool limited : {false, true}) {
            passed = RunScenario([&](net::io_context& io) {
                return TestTcpPending(io, controlled, parent, limited);
            }) && passed;
        }
        for (int mode = 0; mode < 5; ++mode) {
            passed = RunScenario([&](net::io_context& io) { return TestPendingRead(io, controlled, mode); }) && passed;
        }
        for (int mode = 0; mode < 5; ++mode) {
            passed = RunScenario([&](net::io_context& io) { return TestTcpCancellation(io, controlled, mode); }) && passed;
        }
        for (int failure = 0; failure != 4; ++failure) {
            passed = RunScenario([&](net::io_context& io) {
                return TestInitialPayload(io, controlled, failure, 7, 5, false);
            }) && passed;
        }
        for (auto sizes : {std::pair<size_t, size_t>{2000, 0}, {750, 750}}) {
            passed = RunScenario([&](net::io_context& io) {
                return TestInitialPayload(io, controlled, 0, sizes.first, sizes.second, true);
            }) && passed;
        }
    }
    EXPECT_TRUE(passed);
}
