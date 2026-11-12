#include <gtest/gtest.h>

#include "allocation_hook.hpp"
#include "proxy/anytls/anytls_codec.hpp"
#include "app/relay.hpp"
#include "app/dns/dns.hpp"
#include "app/stats.hpp"
#include "app/session_group_executor.hpp"
#include "common/session.hpp"
#include "infra/config_types.hpp"
#include "transport/internet/tls_stream.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/internet/timeout_scheduler.hpp"
#include "common/awaitable_task_group.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/this_coro.hpp>
#include <array>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace {
// Armed together with memory::reject_next_process_allocation; whichever
// allocation (coroutine frame via operator new, or process-layer string/Buffer)
// comes first consumes the single injected failure.
thread_local bool fail_next_allocation = false;
thread_local size_t operator_new_failures = 0;
thread_local size_t armed_process_rejections = 0;

void ArmNextAllocationFailure() {
    fail_next_allocation = true;
    memory::reject_next_process_allocation = true;
    armed_process_rejections = memory::rejected_process_allocations;
}

void DisarmAllocationFailure() {
    fail_next_allocation = false;
    memory::reject_next_process_allocation = false;
}

size_t AllocationFailures() {
    return operator_new_failures + memory::rejected_process_allocations;
}
static_assert(alignof(::buf::Buffer) <= alignof(std::max_align_t));

void FailArmedAllocation(std::size_t size) {
    if (fail_next_allocation && memory::rejected_process_allocations != armed_process_rejections) {
        fail_next_allocation = false;
    }
    if (fail_next_allocation) {
        DisarmAllocationFailure();
        ++operator_new_failures;
        throw std::bad_alloc();
    }
}
}
constinit allocation_hook::Hooks allocation_hook::hooks{.before_new = FailArmedAllocation};

namespace {
using namespace std::chrono_literals;

size_t BufferCount() noexcept { return memory::detail::test_buffers_live; }
size_t BufferPeak() noexcept { return memory::detail::test_buffers_peak; }

struct QueueScenario {
    int mode = 0;
    std::vector<size_t> fragments;
    std::vector<uint8_t> expected;
    std::vector<uint8_t> wire_payload;
    std::vector<uint8_t> received;
    std::vector<size_t> datagram_sizes;
    size_t queued_blocks = 0;
    bool snapshot = false;
    std::unique_ptr<net::steady_timer> consumer_gate;
    bool consumer_started = false;
    bool consumer_released = false;
    bool consumer_cleaned = false;
    int pending_consumer = 0;
};
QueueScenario* queue_scenario = nullptr;

struct OpenOrderScenario {
    int mode = 0;
    bool before_write_completion = false;
    bool target_sent = false;
    bool delivered = false;
    bool write_held = false;
    bool write_released = false;
    size_t fin_replies = 0;
    size_t payload_after_close = 0;
};
OpenOrderScenario* open_order_scenario = nullptr;

bool client_padding_probe = false;
constexpr std::string_view kPaddingA = "stop=8\n0=45-45\n1=256-256\n2=64-64\n";
constexpr std::string_view kPaddingB = "stop=8\n0=91-91\n1=320-320\n2=80-80\n";

struct Wire {
    explicit Wire(net::io_context& io) : wake(io), open_gate(io) {}
    net::steady_timer wake;
    net::steady_timer open_gate;
    std::vector<uint8_t> input;
    size_t offset = 0;
    size_t writes = 0;
    int active_reads = 0;
    int active_writes = 0;
    size_t writes_after_close = 0;
    bool closed = false;
    bool destroyed = false;
    bool read_eof = false;
    bool responded = false;
    bool fail_settings = false;
    bool fail_on_header = false;
    bool respond_on_auth = false;
    bool cleanup_completed = false;
    int io_fault_mode = 0;
    int io_fault_kind = 0;
    int io_faults = 0;
    size_t partial_write = 0;
    QueueScenario* queue = nullptr;
    size_t heart_responses = 0;
    OpenOrderScenario* open_order = nullptr;
    std::vector<uint8_t> outgoing;
    size_t parsed_outgoing = 0;
    std::array<bool, 4> target_seen{};
    bool padding_probe = false;
    size_t padding_index = 0;
    uint16_t auth_padding = 0;
    bool auth_update_seen = false;
    std::string client_settings;
    std::vector<size_t> padding_lengths;

    void ObservePaddingWrites(const uint8_t* bytes, size_t size) {
        outgoing.insert(outgoing.end(), bytes, bytes + size);
        while (outgoing.size() - parsed_outgoing >= 7) {
            const auto* header = outgoing.data() + parsed_outgoing;
            const size_t length = (size_t(header[5]) << 8) | header[6];
            if (outgoing.size() - parsed_outgoing < 7 + length) break;
            const uint8_t command = header[0];
            const uint32_t sid = (uint32_t(header[1]) << 24) | (uint32_t(header[2]) << 16) |
                (uint32_t(header[3]) << 8) | header[4];
            parsed_outgoing += 7 + length;
            if (command == proxy::anytls::kCmdSettings)
                client_settings.assign(reinterpret_cast<const char*>(header + 7), length);
            if (command == proxy::anytls::kCmdWaste) padding_lengths.push_back(length);
            if (command == proxy::anytls::kCmdHeartResponse) ++heart_responses;
            if (command != proxy::anytls::kCmdPSH || responded) continue;
            responded = true;
            Frame(proxy::anytls::kCmdServerSettings, 0, "v=2");
            if (padding_index == 0) Frame(proxy::anytls::kCmdUpdatePaddingScheme, 0, kPaddingA);
            Frame(proxy::anytls::kCmdSYNACK, sid);
            Frame(proxy::anytls::kCmdPSH, sid, "reply");
            // The first request stays busy while another physical session opens.
            if (padding_index != 0) Frame(proxy::anytls::kCmdFIN, sid);
            wake.cancel();
        }
    }

    void DeliverOpenResult() {
        if (!open_order || open_order->delivered) return;
        open_order->delivered = true;
        const int mode = open_order->mode;
        if (mode == 0 || mode == 5) Frame(proxy::anytls::kCmdSYNACK, 2);
        if (mode == 0 || mode == 2) Frame(proxy::anytls::kCmdPSH, 2, "reply");
        if (mode <= 2) Frame(proxy::anytls::kCmdFIN, 2);
        if (mode == 3) Frame(proxy::anytls::kCmdSYNACK, 2, "rejected");
        if (mode == 4 || mode == 5) Frame(proxy::anytls::kCmdAlert, 0, "closed");
        if (mode == 8) {
            Frame(proxy::anytls::kCmdSYNACK, 2, "rejected");
            input.resize(input.size() - 5);
            read_eof = true;
        }
        wake.cancel();
    }

    void ObserveOpenWrites(const uint8_t* bytes, size_t size) {
        outgoing.insert(outgoing.end(), bytes, bytes + size);
        while (outgoing.size() - parsed_outgoing >= 7) {
            const auto* header = outgoing.data() + parsed_outgoing;
            const size_t length = (size_t(header[5]) << 8) | header[6];
            if (outgoing.size() - parsed_outgoing < 7 + length) break;
            const uint8_t command = header[0];
            const uint32_t sid = (uint32_t(header[1]) << 24) | (uint32_t(header[2]) << 16) |
                (uint32_t(header[3]) << 8) | header[4];
            parsed_outgoing += 7 + length;
            if (command == proxy::anytls::kCmdFIN && sid == 2) ++open_order->fin_replies;
            if (command != proxy::anytls::kCmdPSH || sid >= target_seen.size()) continue;
            if (target_seen[sid]) {
                if (sid == 2 && open_order->delivered) ++open_order->payload_after_close;
                continue;
            }
            target_seen[sid] = true;
            if (sid == 2) {
                open_order->target_sent = true;
                if (open_order->before_write_completion) DeliverOpenResult();
            } else {
                if (sid == 1) {
                    Frame(proxy::anytls::kCmdServerSettings, 0, "v=2");
                    Frame(proxy::anytls::kCmdUpdatePaddingScheme, 0, "stop=1\n");
                }
                Frame(proxy::anytls::kCmdSYNACK, sid);
                Frame(proxy::anytls::kCmdPSH, sid, "reply");
                Frame(proxy::anytls::kCmdFIN, sid);
                wake.cancel();
            }
        }
    }

    [[noreturn]] void RaiseIoFault() {
        ++io_faults;
        if (io_fault_kind == 1) throw std::bad_alloc();
        if (io_fault_kind == 2) throw transport::LinkError(common::ErrorCode::BLOCKED);
        throw std::runtime_error("original physical I/O exception");
    }

    void Frame(uint8_t command, uint32_t sid, std::string_view payload = {}) {
        input.insert(input.end(), {command, uint8_t(sid >> 24), uint8_t(sid >> 16),
            uint8_t(sid >> 8), uint8_t(sid), uint8_t(payload.size() >> 8), uint8_t(payload.size())});
        input.insert(input.end(), payload.begin(), payload.end());
    }
    void Fault() {
        Frame(proxy::anytls::kCmdUpdatePaddingScheme, 0, std::string(1024, 'x'));
        fail_on_header = true;
        wake.cancel();
    }
    void Reply() {
        if (queue) {
            Frame(proxy::anytls::kCmdServerSettings, 0, "v=2");
            Frame(proxy::anytls::kCmdSYNACK, 1);
            size_t payload_offset = 0;
            for (size_t bytes : queue->fragments) {
                Frame(proxy::anytls::kCmdPSH, 1, std::string_view(
                    reinterpret_cast<const char*>(queue->wire_payload.data() + payload_offset), bytes));
                payload_offset += bytes;
                if (queue->mode >= 13 && payload_offset == 3 * 65535) Frame(proxy::anytls::kCmdHeartRequest, 0);
            }
            if (queue->mode != 6 && queue->mode != 9) Frame(proxy::anytls::kCmdFIN, 1);
            if (queue->mode == 12) Frame(proxy::anytls::kCmdAlert, 0);
        } else if (fail_settings) {
            Frame(proxy::anytls::kCmdServerSettings, 0, std::string(1024, 'x'));
            fail_on_header = true;
        } else {
            Frame(proxy::anytls::kCmdServerSettings, 0, "v=2");
            if (io_fault_mode >= 3) Frame(proxy::anytls::kCmdUpdatePaddingScheme, 0, "stop=2\n1=64-65\n");
            Frame(proxy::anytls::kCmdSYNACK, 1);
            if (io_fault_mode < 2) {
                Frame(proxy::anytls::kCmdPSH, 1, "reply");
                Frame(proxy::anytls::kCmdFIN, 1);
            }
        }
        wake.cancel();
    }
};

std::vector<std::shared_ptr<Wire>> dialed;
bool fail_first_session = false;
bool respond_on_auth = false;
int io_fault_mode = 0;
int io_fault_kind = 0;

// The migration regression uses actual TCP sockets and the production native
class Stream final : public transport::AsyncStream {
public:
    explicit Stream(std::shared_ptr<Wire> wire) : wire_(std::move(wire)) {}
    ~Stream() override {
        if (wire_->active_reads != 0) std::terminate();
        wire_->destroyed = true;
    }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer output) override {
        while (wire_->offset == wire_->input.size() && !wire_->closed && !wire_->read_eof) {
            if (wire_->queue && wire_->responded && !wire_->queue->snapshot) {
                wire_->queue->queued_blocks = BufferCount();
                wire_->queue->snapshot = true;
            }
            wire_->wake.expires_at(net::steady_timer::time_point::max());
            ++wire_->active_reads;
            const auto [error] = co_await wire_->wake.async_wait(net::as_tuple(net::use_awaitable));
            if (wire_->closed) {
                co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
                net::steady_timer cleanup(co_await net::this_coro::executor, 20ms);
                co_await cleanup.async_wait(net::use_awaitable);
                wire_->cleanup_completed = true;
            }
            --wire_->active_reads;
            if (error && wire_->offset == wire_->input.size() && !wire_->closed) throw IoSystemError(error);
        }
        if (wire_->closed || (wire_->read_eof && wire_->offset == wire_->input.size())) co_return 0;
        if (wire_->io_fault_mode == 1 && wire_->responded) {
            co_await net::post(net::use_awaitable);
            wire_->RaiseIoFault();
        }
        const auto count = std::min(output.size(), wire_->input.size() - wire_->offset);
        std::memcpy(output.data(), wire_->input.data() + wire_->offset, count);
        wire_->offset += count;
        if (wire_->fail_on_header && count == 7) {
            wire_->fail_on_header = false;
            // Fail the production codec's next coroutine/string allocation,
            // after ReadFrameHeader has successfully returned this header.
            ArmNextAllocationFailure();
        }
        co_return count;
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer data) override {
        struct PendingWrite {
            int& count;
            explicit PendingWrite(int& count) : count(count) { ++count; }
            ~PendingWrite() { --count; }
        } pending(wire_->active_writes);
        if (wire_->closed) ++wire_->writes_after_close;
        ++wire_->writes;
        const auto* bytes = static_cast<const uint8_t*>(data.data());
        if (wire_->padding_probe) {
            if (wire_->writes == 1) {
                if (data.size() < 34) throw std::runtime_error("incomplete authentication");
                wire_->auth_padding = uint16_t((uint16_t(bytes[32]) << 8) | bytes[33]);
                if (data.size() != 34u + wire_->auth_padding)
                    throw std::runtime_error("authentication padding length mismatch");
                if (wire_->padding_index == 1) {
                    // Authentication bytes already belong to A. Publish B on
                    // the older live session before this write completes.
                    dialed[0]->Frame(proxy::anytls::kCmdUpdatePaddingScheme, 0, kPaddingB);
                    dialed[0]->Frame(proxy::anytls::kCmdHeartRequest, 0);
                    dialed[0]->wake.cancel();
                    size_t turns = 0;
                    while (dialed[0]->heart_responses == 0 && !dialed[0]->closed) {
                        if (++turns > 10000) throw std::runtime_error("padding update did not reach its barrier");
                        co_await net::post(net::use_awaitable);
                    }
                    wire_->auth_update_seen = dialed[0]->heart_responses == 1;
                }
            } else wire_->ObservePaddingWrites(bytes, data.size());
            co_return data.size();
        }
        if (wire_->open_order) {
            // The first write is authentication; all subsequent bytes are frames.
            if (wire_->writes > 1) wire_->ObserveOpenWrites(bytes, data.size());
            if (wire_->open_order->before_write_completion && wire_->target_seen[2] &&
                !wire_->open_order->write_released) {
                wire_->open_order->write_held = true;
                // A new pending read proves the frame loop has processed the
                // terminal frame, rather than only copying its final byte.
                while (!wire_->closed && !(wire_->offset == wire_->input.size() && wire_->active_reads == 1))
                    co_await net::post(net::use_awaitable);
                wire_->open_order->write_released = true;
            }
            co_return data.size();
        }
        if (data.size() == 7 && bytes[0] == proxy::anytls::kCmdHeartResponse) ++wire_->heart_responses;
        if ((wire_->io_fault_mode == 2 && wire_->writes == 2) ||
            (wire_->io_fault_mode >= 3 && data.size() == 7 &&
             bytes[0] == (wire_->io_fault_mode == 5 ? proxy::anytls::kCmdFIN : proxy::anytls::kCmdPSH))) {
            wire_->partial_write += 3;
            co_await net::post(net::use_awaitable);
            wire_->RaiseIoFault();
        }
        if (wire_->writes >= (wire_->respond_on_auth ? 1u : 2u) && !wire_->responded) {
            wire_->responded = true;
            wire_->Reply();
            // Deliver the peer's padding update before the first request can
            // write payload; first-session streams do not wait for SYNACK.
            if (wire_->io_fault_mode >= 3 || (wire_->queue && wire_->queue->mode < 13)) {
                while (wire_->offset < wire_->input.size() && !wire_->closed) {
                    if (wire_->queue && wire_->queue->mode == 5 && wire_->input.size() - wire_->offset == 7) {
                        // Eight queued blocks plus the one-byte pending frame.
                        wire_->queue->queued_blocks = BufferCount() ? BufferCount() - 1 : 0;
                        wire_->queue->snapshot = true;
                        break;
                    }
                    co_await net::post(net::use_awaitable);
                }
            }
            if (wire_->queue && wire_->queue->mode == 6) {
                wire_->open_gate.expires_at(net::steady_timer::time_point::max());
                co_await wire_->open_gate.async_wait(net::use_awaitable);
            }
        }
        co_return data.size();
    }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override { co_return buf::MultiBuffer{}; }
    void ShutdownWrite() override {}
    void Cancel() noexcept override { NotifyCancellation(); wire_->wake.cancel(); }
    void Close() override { wire_->closed = true; NotifyClosed(); wire_->wake.cancel(); }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return !wire_->closed; }
private:
    std::shared_ptr<Wire> wire_;
};

class Client final : public transport::MultiBufferReader, public transport::MultiBufferWriter {
public:
    transport::CancellationSource source;
    size_t received = 0;
    int active_reads = 0;
    bool eof = false;
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        struct PendingRead {
            int& count;
            explicit PendingRead(int& count) : count(count) { ++count; }
            ~PendingRead() { --count; }
        } pending(active_reads);
        if (!eof) {
            net::steady_timer pending(co_await net::this_coro::executor);
            pending.expires_at(net::steady_timer::time_point::max());
            co_await pending.async_wait(net::use_awaitable);
        }
        co_return buf::MultiBuffer{};
    }
    transport::CancellationSource& Cancellation() noexcept override { return source; }
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        co_return co_await WriteBuffersAsMultiBuffer(buffers);
    }
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer bytes) override {
        if (queue_scenario && queue_scenario->mode >= 13 && !queue_scenario->consumer_started) {
            auto& queue = *queue_scenario;
            queue.consumer_started = true;
            ++queue.pending_consumer;
            queue.consumer_gate->expires_at(net::steady_timer::time_point::max());
            const auto [error] = co_await queue.consumer_gate->async_wait(net::as_tuple(net::use_awaitable));
            if (error && !queue.consumer_released) {
                co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
                net::steady_timer cleanup(co_await net::this_coro::executor, 20ms);
                co_await cleanup.async_wait(net::use_awaitable);
                queue.consumer_cleaned = true;
                --queue.pending_consumer;
                throw IoSystemError(error);
            }
            --queue.pending_consumer;
        }
        received += bytes.byte_size();
        if (queue_scenario) {
            if (queue_scenario->mode == 10 || queue_scenario->mode == 11) {
                queue_scenario->datagram_sizes.push_back(bytes.byte_size());
            }
            for (const auto* block : bytes) {
                queue_scenario->received.insert(queue_scenario->received.end(), block->Bytes().begin(), block->Bytes().end());
            }
            if (queue_scenario->mode == 9 && queue_scenario->received.size() == 65535) {
                auto& wire = *dialed[0];
                wire.Frame(proxy::anytls::kCmdPSH, 1, std::string_view(
                    reinterpret_cast<const char*>(queue_scenario->expected.data() + 65535), 65535));
                wire.Frame(proxy::anytls::kCmdFIN, 1);
                wire.wake.cancel();
            }
        }
        co_return;
    }
};
}

// Only the external dial boundary is replaced. The production target builder,
// Handler, codec, session pool, logical endpoint and relay execute unchanged.

net::awaitable<transport::DialResult> transport::internet::DialOutboundTransport(net::io_context& io, session::Context&,
                                                const transport::internet::OutboundTransportTarget&) {
    auto wire = std::make_shared<Wire>(io);
    wire->fail_settings = fail_first_session && dialed.empty();
    wire->respond_on_auth = respond_on_auth;
    wire->queue = queue_scenario;
    wire->open_order = open_order_scenario;
    wire->padding_probe = client_padding_probe;
    wire->padding_index = dialed.size();
    if (dialed.empty()) { wire->io_fault_mode = io_fault_mode; wire->io_fault_kind = io_fault_kind; }
    dialed.push_back(wire);
    transport::DialResult result;
    result.stream = std::make_unique<Stream>(wire);
    co_return result;
}

namespace {
template <typename Cleanup>
class CleanupGuard {
public:
    explicit CleanupGuard(Cleanup cleanup) : cleanup_(std::move(cleanup)) {}
    ~CleanupGuard() { cleanup_(); }
private:
    Cleanup cleanup_;
};

class AnyTlsLifecycleTest : public testing::Test {
protected:
    void SetUp() override {
        peak_ = memory::detail::test_buffers_peak;
        ResetHooks();
    }
    void TearDown() override {
        ResetHooks();
        memory::detail::test_buffers_peak = peak_;
    }
private:
    static void ResetHooks() {
        DisarmAllocationFailure();
        queue_scenario = nullptr;
        open_order_scenario = nullptr;
        client_padding_probe = false;
        fail_first_session = respond_on_auth = false;
        io_fault_mode = io_fault_kind = 0;
        dialed.clear();
    }
    size_t peak_ = 0;
};

// The Worker joins resident physical tasks after its request owners finish.
// Do not abandon completion callbacks borrowing the caller's stack.
bool JoinResidentTasks(net::io_context& io, common::ResidentTaskGroup& tasks) {
    bool done = false;
    std::exception_ptr failure;
    net::co_spawn(io, tasks.AsyncJoin(), [&](std::exception_ptr error) {
        failure = error;
        done = true;
    });
    io.restart();
    io.run();
    return done && !failure;
}

// The Handler's production dialer over the default raw TCP sender settings;
// only DialOutboundTransport above is replaced.
struct TestDialer {
    TestDialer(net::io_context& io, app::dns::DNS& dns) : dialer(io, dns, sender, 1s) {}
    transport::internet::OutboundSenderSettings sender;
    transport::internet::OutboundDialer dialer;
};

transport::internet::OutboundServer LoopbackServer() {
    return transport::internet::OutboundServer{
        .address = "127.0.0.1",
        .literal_address = net::ip::address_v4::loopback(),
        .port = 443,
    };
}

void RunClientPadding() {
    net::io_context io;
    app::dns::Config dns_config;
    dns_config.servers = {{net::ip::address_v4::loopback(), 1}};
    app::dns::DNSWorker dns_worker(io, dns_config, 8);
    app::dns::DNS dns(dns_worker);
    TestDialer outbound(io, dns);
    common::ResidentTaskGroup tasks(io.get_executor());
    infra::AnyTlsSettings settings;
    settings.server = LoopbackServer();
    settings.idle_session_check_interval = 60s;
    settings.idle_session_timeout = 60s;
    settings.min_idle_sessions = 1;
    auto make_handler = [&] {
        return std::make_unique<proxy::anytls::outbound::Handler>(
            "same-client-tag", io,
            std::make_shared<const infra::AnyTlsSettings>(settings),
            tasks.Tasks());
    };
    auto handler = make_handler();
    dialed.clear();
    fail_first_session = respond_on_auth = false;
    io_fault_mode = io_fault_kind = 0;
    client_padding_probe = true;
    std::array<Client, 4> clients;
    std::array<session::Context, 4> contexts;
    std::array<net::cancellation_signal, 4> cancellations;
    std::array<bool, 4> done{};
    std::array<bool, 4> failed{};
    std::array<common::ErrorCode, 4> errors{};
    auto request = [&](proxy::anytls::outbound::Handler& active, size_t index) -> net::awaitable<proxy::OutboundProcessResult> {
        auto& ctx = contexts[index];
        ctx.outbound.target = common::TargetAddress("192.0.2.1", 443);
        app::StatsShard stats;
        infra::TimeoutsConfig timeouts;
        app::RelayConfig config;
        config.idle_timeout = config.write_timeout = 10s;
        config.uplink_only = config.downlink_only = 5s;
        co_return co_await active.Process(ctx,
            {&clients[index], &clients[index], nullptr}, outbound.dialer, timeouts,
            stats, config, {});
    };
    auto start = [&](proxy::anytls::outbound::Handler& active, size_t index) {
        net::co_spawn(io, request(active, index), net::bind_cancellation_slot(cancellations[index].slot(),
            [&, index](std::exception_ptr exception, proxy::OutboundProcessResult result) {
                failed[index] = bool(exception);
                errors[index] = result ? result->error : result.error();
                done[index] = true;
            }));
        io.restart();
        io.poll();
    };
    std::unique_ptr<proxy::anytls::outbound::Handler> replacement;
    CleanupGuard cleanup([&] {
        DisarmAllocationFailure();
        for (auto& cancellation : cancellations) cancellation.emit(net::cancellation_type::all);
        replacement.reset();
        handler.reset();
        for (const auto& wire : dialed) {
            wire->closed = true;
            wire->wake.cancel();
            wire->open_gate.cancel();
        }
        (void)JoinResidentTasks(io, tasks);
        io.restart();
        io.run();
    });
    start(*handler, 0);
    EXPECT_EQ(dialed.size(), 1);
    EXPECT_FALSE(done[0]);
    EXPECT_EQ(clients[0].received, 5);
    start(*handler, 1);
    EXPECT_EQ(dialed.size(), 2);
    EXPECT_TRUE(done[1]);
    EXPECT_FALSE(failed[1]);
    EXPECT_EQ(errors[1], common::ErrorCode::OK);
    if (dialed.size() == 2) {
        {
            EXPECT_TRUE(dialed[1]->auth_update_seen);
            EXPECT_EQ(dialed[1]->auth_padding, 45);
        }
        EXPECT_EQ(dialed[1]->padding_lengths, (std::vector<size_t>{160}));
        dialed[1]->Frame(proxy::anytls::kCmdAlert, 0, "fresh session required");
        dialed[1]->wake.cancel();
        io.restart();
        io.run_for(40ms);
    }
    start(*handler, 2);
    EXPECT_EQ(dialed.size(), 3);
    EXPECT_TRUE(done[2]);
    EXPECT_FALSE(failed[2]);
    EXPECT_EQ(errors[2], common::ErrorCode::OK);
    if (dialed.size() == 3) {
        {
            EXPECT_EQ(dialed[2]->auth_padding, 91);
        }
        EXPECT_EQ(dialed[2]->padding_lengths, (std::vector<size_t>{224}));
    }
    cancellations[0].emit(net::cancellation_type::all);
    io.restart();
    io.poll();
    EXPECT_TRUE(done[0]);
    EXPECT_FALSE(failed[0]);
    EXPECT_EQ(errors[0], common::ErrorCode::CANCELLED);
    handler.reset();
    const bool retired_during_cleanup = std::any_of(dialed.begin(), dialed.end(),
        [](const auto& wire) { return wire->closed && !wire->destroyed; });
    replacement = make_handler();
    start(*replacement, 3);
    EXPECT_EQ(dialed.size(), 4);
    EXPECT_TRUE(done[3]);
    EXPECT_FALSE(failed[3]);
    EXPECT_EQ(errors[3], common::ErrorCode::OK);
    if (dialed.size() == 4)
        {
            EXPECT_EQ(dialed[3]->auth_padding, dialed[0]->auth_padding);
        }
    replacement.reset();
    const bool join_completed = JoinResidentTasks(io, tasks);
    const bool joined = join_completed && std::all_of(dialed.begin(), dialed.end(),
        [](const auto& wire) { return wire->closed && wire->destroyed && wire->active_reads == 0; });
    EXPECT_TRUE(retired_during_cleanup);
    EXPECT_TRUE(joined);
    EXPECT_TRUE(std::all_of(done.begin(), done.end(), [](bool value) { return value; }));
    dialed.clear();
    client_padding_probe = false;
}

void RunOpenOrder(int mode, bool before) {
    net::io_context io;
    app::dns::Config dns_config;
    dns_config.servers = {{net::ip::address_v4::loopback(), 1}};
    app::dns::DNSWorker dns_worker(io, dns_config, 8);
    app::dns::DNS dns(dns_worker);
    TestDialer outbound(io, dns);
    common::ResidentTaskGroup tasks(io.get_executor());
    infra::AnyTlsSettings settings;
    settings.server = LoopbackServer();
    settings.idle_session_check_interval = 60s;
    settings.idle_session_timeout = 60s;
    settings.min_idle_sessions = 1;
    OpenOrderScenario scenario{.mode = mode, .before_write_completion = before};
    open_order_scenario = &scenario;
    dialed.clear();
    auto handler = std::make_unique<proxy::anytls::outbound::Handler>("open-order", io,
        std::make_shared<const infra::AnyTlsSettings>(settings),
        tasks.Tasks());
    auto request = [&](Client& client, session::Context& ctx) -> net::awaitable<proxy::OutboundProcessResult> {
        ctx.outbound.target = common::TargetAddress("192.0.2.1", 443);
        ctx.content.network = common::Network::TCP;
        app::StatsShard stats;
        infra::TimeoutsConfig timeouts;
        app::RelayConfig config;
        config.idle_timeout = config.write_timeout = 10s;
        config.uplink_only = config.downlink_only = 5s;
        co_return co_await handler->Process(ctx,
            {&client, &client, nullptr}, outbound.dialer, timeouts, stats, config, {});
    };
    Client warm, tested, recovery;
    session::Context warm_ctx, tested_ctx, recovery_ctx;
    bool warm_done = false, done = false, recovery_done = false;
    common::ErrorCode observed = common::ErrorCode::OK;
    std::exception_ptr failure;
    net::cancellation_signal cancel;
    CleanupGuard cleanup([&] {
        DisarmAllocationFailure();
        cancel.emit(net::cancellation_type::all);
        handler.reset();
        for (const auto& wire : dialed) {
            wire->closed = true;
            wire->wake.cancel();
            wire->open_gate.cancel();
        }
        (void)JoinResidentTasks(io, tasks);
        io.restart();
        io.run();
    });
    net::co_spawn(io, request(warm, warm_ctx), [&](std::exception_ptr error, proxy::OutboundProcessResult result) {
        EXPECT_FALSE(error);
        EXPECT_TRUE(result);
        if (result) EXPECT_EQ(result->error, common::ErrorCode::OK);
        EXPECT_EQ(warm.received, 5);
        warm_done = true;
    });
    io.run_for(100ms);
    ASSERT_TRUE(warm_done);
    ASSERT_EQ(dialed.size(), 1);
    net::co_spawn(io, request(tested, tested_ctx), net::bind_cancellation_slot(cancel.slot(),
        [&](std::exception_ptr error, proxy::OutboundProcessResult result) {
            done = true; failure = error;
            observed = result ? result->error : result.error();
        }));
    io.restart();
    io.run_for(80ms);
    EXPECT_TRUE(scenario.target_sent);
    if (before) EXPECT_TRUE(scenario.write_released);
    const bool waited_without_signal = !done;
    if (!before) {
        if (mode == 7) cancel.emit(net::cancellation_type::terminal);
        else if (mode != 6) dialed.front()->DeliverOpenResult();
        io.restart();
        io.run_for(mode == 6 ? 3200ms : 80ms);
    }
    const bool timely = done;
    const auto expected = mode <= 2 ? common::ErrorCode::OK : mode == 6 ? common::ErrorCode::TIMEOUT :
        mode == 7 ? common::ErrorCode::CANCELLED : common::ErrorCode::PROTOCOL_DECODE_FAILED;
    EXPECT_TRUE(timely);
    EXPECT_FALSE(failure);
    EXPECT_EQ(observed, expected);
    EXPECT_EQ(tested.received, (mode == 0 || mode == 2 ? 5u : 0u));
    EXPECT_TRUE((before || waited_without_signal));
    EXPECT_EQ(scenario.fin_replies, 0);
    EXPECT_EQ(scenario.payload_after_close, 0);
    if (!done) {
        // Record the actual incorrect deadline result before cleaning up.
        io.restart();
        io.run_for(3200ms);
    }
    if (!done) {
        cancel.emit(net::cancellation_type::terminal);
        io.restart(); io.run_for(200ms);
    }
    net::co_spawn(io, request(recovery, recovery_ctx), [&](std::exception_ptr error, proxy::OutboundProcessResult result) {
        EXPECT_FALSE(error);
        EXPECT_TRUE(result);
        if (result) EXPECT_EQ(result->error, common::ErrorCode::OK);
        EXPECT_EQ(recovery.received, 5);
        recovery_done = true;
    });
    io.restart(); io.run_for(100ms);
    const size_t expected_connections = mode <= 2 ? 1 : 2;
    EXPECT_TRUE(done);
    EXPECT_TRUE(recovery_done);
    EXPECT_EQ(dialed.size(), expected_connections);
    handler.reset();
    io.restart(); io.run_for(200ms);
    EXPECT_TRUE(JoinResidentTasks(io, tasks));
    for (const auto& wire : dialed) {
        EXPECT_TRUE(wire->closed);
        EXPECT_TRUE(wire->destroyed);
        EXPECT_EQ(wire->active_reads, 0);
    }
    dialed.clear(); open_order_scenario = nullptr;
}

void RunQueue(int mode, unsigned seed = 1) {
    net::io_context io;
    QueueScenario queue;
    queue.mode = mode;
    if (mode >= 13) queue.consumer_gate = std::make_unique<net::steady_timer>(io);
    if (mode == 0) queue.fragments.assign(2048, 1);
    else if (mode == 1 || mode == 5 || mode == 6 || mode == 9 || mode == 12) queue.fragments = {65535};
    else if (mode == 10) queue.fragments = {29003};
    else if (mode == 11) queue.fragments.assign(29003, 1);
    else if (mode >= 13) queue.fragments.assign(4, 65535);
    else if (mode == 4) queue.fragments.assign(65535, 1);
    else {
        size_t remaining = 65535;
        unsigned random = seed;
        constexpr std::array<size_t, 6> edges{4095, 1, 4096, 8191, 8192, 4097};
        for (size_t i = 0; remaining; ++i) {
            random = random * 1664525u + 1013904223u;
            const size_t fragment = mode == 2 ? (i % 2 == 0 ? 1 : 8192)
                : mode == 3 ? edges[i % edges.size()] : 1 + random % 8192;
            queue.fragments.push_back(std::min(fragment, remaining));
            remaining -= queue.fragments.back();
        }
    }
    if (mode == 5) queue.fragments.push_back(1);
    size_t bytes = 0;
    for (size_t fragment : queue.fragments) bytes += fragment;
    queue.expected.resize(mode == 9 ? bytes * 2 : mode == 10 || mode == 11 ? 28999 : bytes);
    for (size_t i = 0; i < queue.expected.size(); ++i) queue.expected[i] = uint8_t(i % 251);
    if (mode == 10 || mode == 11) {
        size_t payload_offset = 0;
        for (size_t length : {size_t(9000), size_t(19999)}) {
            queue.wire_payload.push_back(uint8_t(length >> 8));
            queue.wire_payload.push_back(uint8_t(length));
            queue.wire_payload.insert(queue.wire_payload.end(), queue.expected.begin() + payload_offset,
                queue.expected.begin() + payload_offset + length);
            payload_offset += length;
        }
    } else queue.wire_payload.assign(queue.expected.begin(), queue.expected.begin() + bytes);
    app::dns::Config dns_config;
    dns_config.servers = {{net::ip::make_address("127.0.0.1"), 53}};
    app::dns::DNSWorker dns_worker(io, dns_config, 8);
    app::dns::DNS dns(dns_worker);
    TestDialer outbound(io, dns);
    common::ResidentTaskGroup tasks(io.get_executor());
    infra::AnyTlsSettings settings;
    settings.server = LoopbackServer();
    settings.idle_session_check_interval = 1s;
    settings.idle_session_timeout = 60s;
    settings.min_idle_sessions = 1;
    auto handler = std::make_unique<proxy::anytls::outbound::Handler>("queue", io,
        std::make_shared<const infra::AnyTlsSettings>(settings),
        tasks.Tasks());
    queue_scenario = &queue;
    dialed.clear();
    fail_first_session = respond_on_auth = false;
    io_fault_mode = io_fault_kind = 0;
    memory::detail::test_buffers_peak = BufferCount();
    Client client;
    auto control_wire = std::make_shared<Wire>(io);
    Stream control(control_wire);
    const bool use_control = mode == 0 || mode == 10 || mode == 11;
    struct RequestTimeout final : transport::internet::TimeoutEvent {
        explicit RequestTimeout(Client& client) : client(client) {}
        void OnTimeout() override { client.source.Stop(common::ErrorCode::RELAY_TIMEOUT); }
        Client& client;
    } request_timeout(client);
    if (mode == 15) (void)transport::internet::TimeoutScheduler::ForIoContext(io).ScheduleAfter(1s, request_timeout);
    session::Context ctx;
    ctx.outbound.target = common::TargetAddress("192.0.2.1", 443);
    ctx.content.network = mode == 10 || mode == 11 ? common::Network::UDP : common::Network::TCP;
    app::StatsShard stats;
    infra::TimeoutsConfig timeouts;
    app::RelayConfig config;
    config.idle_timeout = config.write_timeout = 10s;
    config.uplink_only = config.downlink_only = 5s;
    bool done = false;
    const auto started = std::chrono::steady_clock::now();
    int64_t completed_ms = 0;
    common::ErrorCode observed = common::ErrorCode::OK;
    std::exception_ptr exception;
    net::cancellation_signal cancellation;
    CleanupGuard cleanup([&] {
        DisarmAllocationFailure();
        cancellation.emit(net::cancellation_type::all);
        handler.reset();
        for (const auto& wire : dialed) {
            wire->closed = true;
            wire->wake.cancel();
            wire->open_gate.cancel();
        }
        if (queue.consumer_gate) queue.consumer_gate->cancel();
        (void)JoinResidentTasks(io, tasks);
        io.restart();
        io.run();
    });
    net::co_spawn(io, handler->Process(ctx,
        {&client, &client, use_control ? &control : nullptr}, outbound.dialer, timeouts,
        stats, config, {}),
        net::bind_cancellation_slot(cancellation.slot(), [&](std::exception_ptr failure, proxy::OutboundProcessResult result) {
            done = true; exception = failure;
            completed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started).count();
            observed = result ? result->error : result.error();
        }));
    io.poll();
    ASSERT_FALSE(dialed.empty());
    EXPECT_FALSE(exception);
    EXPECT_TRUE((mode == 6 || mode >= 13 ? !done : done));
    if (mode >= 13) {
        {
            EXPECT_TRUE(queue.consumer_started);
            EXPECT_EQ(queue.pending_consumer, 1);
        }
        // Eight consumer blocks, eight queued blocks, eight in the waiting frame.
        queue.queued_blocks = BufferCount() >= 16 ? BufferCount() - 16 : 0;
        queue.snapshot = true;
        if (mode == 13) {
            queue.consumer_released = true;
            queue.consumer_gate->cancel();
        } else if (mode == 14) cancellation.emit(net::cancellation_type::terminal);
    }
    if (mode == 6) {
        {
            EXPECT_TRUE(queue.snapshot);
            EXPECT_FALSE(dialed[0]->closed);
            EXPECT_EQ(dialed[0]->active_reads, 1);
        }
        cancellation.emit(net::cancellation_type::terminal);
    }
    io.restart();
    io.run_for(mode == 15 ? 1300ms : 80ms);
    const common::ErrorCode expected = mode == 6 || mode == 14 ? common::ErrorCode::CANCELLED : mode == 15 ? common::ErrorCode::RELAY_TIMEOUT
        : mode == 12 ? common::ErrorCode::PROTOCOL_DECODE_FAILED : common::ErrorCode::OK;
    EXPECT_TRUE(done);
    EXPECT_FALSE(exception);
    EXPECT_EQ(observed, expected);
    if (mode != 6 && mode != 12 && mode != 14 && mode != 15) {
        EXPECT_EQ(queue.received, queue.expected);
    }
    else {
        EXPECT_TRUE(queue.received.empty());
    }
    if (mode == 14 || mode == 15) {
        EXPECT_TRUE(queue.consumer_cleaned);
        EXPECT_EQ(queue.pending_consumer, 0);
    }
    if (mode == 15) {
        EXPECT_GE(completed_ms, 900);
        EXPECT_LT(completed_ms, 1500);
    }
    if (mode == 13) {
        EXPECT_EQ(dialed[0]->heart_responses, 1);
    }
    if (mode == 10 || mode == 11) {
        EXPECT_EQ(queue.datagram_sizes, (std::vector<size_t>{9000, 19999}));
    }

    if (mode != 12) {
        EXPECT_TRUE(queue.snapshot);
    }
    EXPECT_LE(queue.queued_blocks, 16);
    EXPECT_LE(BufferPeak(), 24);
    handler.reset();
    io.restart();
    io.run_for(100ms);
    EXPECT_TRUE(JoinResidentTasks(io, tasks));
    for (const auto& wire : dialed) {
        EXPECT_TRUE(wire->closed);
        EXPECT_TRUE(wire->destroyed);
        EXPECT_EQ(wire->active_reads, 0);
    }
    EXPECT_EQ(BufferCount(), 0);
    dialed.clear();
    queue_scenario = nullptr;
}

void RunIoFault(int mode, int kind) {
    net::io_context io;
    app::dns::Config dns_config;
    dns_config.servers = {{net::ip::make_address("127.0.0.1"), 53}};
    app::dns::DNSWorker dns_worker(io, dns_config, 8);
    app::dns::DNS dns(dns_worker);
    TestDialer outbound(io, dns);
    common::ResidentTaskGroup tasks(io.get_executor());
    infra::AnyTlsSettings settings;
    settings.server = LoopbackServer();
    settings.idle_session_check_interval = 1s;
    settings.idle_session_timeout = 60s;
    settings.min_idle_sessions = 1;
    auto handler = std::make_unique<proxy::anytls::outbound::Handler>("io-fault", io,
        std::make_shared<const infra::AnyTlsSettings>(settings),
        tasks.Tasks());
    dialed.clear();
    fail_first_session = false;
    respond_on_auth = false;
    io_fault_mode = mode;
    io_fault_kind = kind;
    auto control_wire = std::make_shared<Wire>(io);
    Stream control(control_wire);
    auto request = [&](Client& client, session::Context& ctx, bool first) -> net::awaitable<proxy::OutboundProcessResult> {
        ctx.outbound.target = common::TargetAddress("192.0.2.1", 443);
        ctx.content.network = first && mode == 4 ? common::Network::UDP : common::Network::TCP;
        app::StatsShard stats;
        infra::TimeoutsConfig timeouts;
        app::RelayConfig config;
        config.idle_timeout = config.write_timeout = 10s;
        config.uplink_only = config.downlink_only = 5s;
        buf::MultiBuffer payload;
        if (first && (mode == 3 || mode == 4)) {
            buf::BufferGuard block{buf::Buffer::New()};
            if (!block) throw std::bad_alloc();
            std::memcpy(block->Tail().data(), "abc", 3);
            block->Produce(3);
            if (mode == 4) block->SetUDP(ctx.outbound.target);
            payload.push_back(std::move(block));
        }
        co_return co_await handler->Process(ctx,
            {&client, &client, first && mode == 4 ? &control : nullptr}, outbound.dialer,
            timeouts, stats, config, buf::MultiBufferBatch(std::move(payload)));
    };
    // Relay payload and FIN failures retain the write-phase category. An open
    // exception escapes Process unchanged; unknown physical reads are INTERNAL.
    const common::ErrorCode expected = kind == 1 ? common::ErrorCode::RESOURCE_EXHAUSTED : kind == 2 ? common::ErrorCode::BLOCKED :
        mode >= 3 ? common::ErrorCode::RELAY_WRITE_FAILED : common::ErrorCode::INTERNAL;
    Client first, second;
    first.eof = mode == 5;
    session::Context first_ctx, second_ctx;
    bool first_done = false, second_done = false;
    bool request_joined = false;
    common::ErrorCode observed = common::ErrorCode::OK;
    net::cancellation_signal cancel;
    CleanupGuard cleanup([&] {
        DisarmAllocationFailure();
        cancel.emit(net::cancellation_type::all);
        handler.reset();
        for (const auto& wire : dialed) {
            wire->closed = true;
            wire->wake.cancel();
            wire->open_gate.cancel();
        }
        (void)JoinResidentTasks(io, tasks);
        io.restart();
        io.run();
    });
    net::co_spawn(io, request(first, first_ctx, true), net::bind_cancellation_slot(cancel.slot(),
        [&](std::exception_ptr failure, proxy::OutboundProcessResult result) {
            first_done = true;
            // The pool owns the independent physical reader's cleanup. No
            // request reader or physical write may still borrow this request.
            request_joined = first.active_reads == 0 && dialed.size() == 1 &&
                dialed[0]->active_writes == 0 && dialed[0]->closed;
            observed = result ? result->error : result.error();
            if (!failure) return;
            try { std::rethrow_exception(failure); }
            catch (const std::bad_alloc&) { observed = common::ErrorCode::RESOURCE_EXHAUSTED; }
            catch (const transport::LinkError& error) { observed = error.code(); }
            catch (...) { observed = common::ErrorCode::INTERNAL; }
        }));
    io.run_for(180ms);
    ASSERT_FALSE(dialed.empty());
    EXPECT_TRUE(first_done);
    EXPECT_TRUE(request_joined);
    EXPECT_EQ(observed, expected);
    EXPECT_EQ(dialed.size(), 1);
    EXPECT_EQ(dialed[0]->io_faults, 1);
    EXPECT_TRUE(dialed[0]->closed);
    EXPECT_TRUE(dialed[0]->destroyed);
    EXPECT_EQ(dialed[0]->writes_after_close, 0);
    EXPECT_TRUE((mode == 1 || dialed[0]->partial_write == 3));
    if (!first_done) {
        cancel.emit(net::cancellation_type::terminal);
        io.restart();
        io.run_for(200ms);
    }
    net::co_spawn(io, request(second, second_ctx, false), [&](std::exception_ptr failure, proxy::OutboundProcessResult result) {
        EXPECT_FALSE(failure);
        EXPECT_TRUE(result);
        if (result) EXPECT_EQ(result->error, common::ErrorCode::OK);
        EXPECT_EQ(second.received, 5);
        second_done = true;
    });
    io.restart();
    io.run_for(180ms);
    EXPECT_TRUE(second_done);
    EXPECT_EQ(dialed.size(), 2);
    handler.reset();
    io.restart();
    io.run_for(200ms);
    EXPECT_TRUE(JoinResidentTasks(io, tasks));
    for (const auto& wire : dialed) {
        EXPECT_TRUE(wire->closed);
        EXPECT_TRUE(wire->destroyed);
        EXPECT_EQ(wire->active_reads, 0);
    }
    dialed.clear();
    io_fault_mode = io_fault_kind = 0;
}

void RunSessionRetirement(int mode) {
    net::io_context io;
    app::dns::Config dns_config;
    dns_config.servers = {{net::ip::make_address("127.0.0.1"), 53}};
    app::dns::DNSWorker dns_worker(io, dns_config, 8);
    app::dns::DNS dns(dns_worker);
    TestDialer outbound(io, dns);
    common::ResidentTaskGroup tasks(io.get_executor());
    infra::AnyTlsSettings settings;
    settings.server = LoopbackServer();
    settings.idle_session_check_interval = 1s;
    settings.idle_session_timeout = 60s;
    settings.min_idle_sessions = 1;
    auto handler = std::make_unique<proxy::anytls::outbound::Handler>(
        "test", io,
        std::make_shared<const infra::AnyTlsSettings>(settings),
        tasks.Tasks());
    dialed.clear();
    fail_first_session = mode == 0 || mode == 3;
    respond_on_auth = mode == 3;
    const auto failures_before = AllocationFailures();
    auto request = [&](Client& client, session::Context& ctx) -> net::awaitable<proxy::OutboundProcessResult> {
        ctx.outbound.target = common::TargetAddress("192.0.2.1", 443);
        ctx.content.network = common::Network::TCP;
        app::StatsShard stats;
        infra::TimeoutsConfig timeouts;
        app::RelayConfig config;
        config.idle_timeout = config.write_timeout = 10s;
        config.uplink_only = config.downlink_only = 5s;
        co_return co_await handler->Process(ctx,
            {&client, &client, nullptr}, outbound.dialer, timeouts, stats, config, {});
    };
    Client first, second;
    session::Context ctx_first, ctx_second;
    bool first_done = false, second_done = false;
    proxy::OutboundProcessResult first_result, second_result;
    std::exception_ptr failure;
    net::cancellation_signal cancel;
    CleanupGuard cleanup([&] {
        DisarmAllocationFailure();
        cancel.emit(net::cancellation_type::all);
        handler.reset();
        for (const auto& wire : dialed) {
            wire->closed = true;
            wire->wake.cancel();
            wire->open_gate.cancel();
        }
        (void)JoinResidentTasks(io, tasks);
        io.restart();
        io.run();
    });
    net::co_spawn(io, request(first, ctx_first), net::bind_cancellation_slot(cancel.slot(),
        [&](std::exception_ptr error, proxy::OutboundProcessResult result) {
            failure = error; first_result = result; first_done = true;
        }));
    io.run_for(180ms);
    ASSERT_FALSE(dialed.empty());
    const bool timely = first_done;
    EXPECT_TRUE(timely);
    EXPECT_FALSE(failure);
    EXPECT_FALSE(dialed.empty());
    if (mode == 0) {
        ASSERT_TRUE(first_result);
        EXPECT_EQ(first_result->error, common::ErrorCode::RESOURCE_EXHAUSTED);
        EXPECT_TRUE(dialed[0]->closed);
    }
    // The reply is already buffered when Adopt starts the physical loop, which
    // fails and closes the session inline: the request's open reports the
    // session's terminal cause before any relay begins.
    else if (mode == 3) {
        ASSERT_FALSE(first_result);
        EXPECT_EQ(first_result.error(), common::ErrorCode::RESOURCE_EXHAUSTED);
        EXPECT_TRUE(dialed[0]->closed);
    }
    else {
        ASSERT_TRUE(first_result);
        EXPECT_EQ(first_result->error, common::ErrorCode::OK);
        EXPECT_EQ(first.received, 5);
    }
    bool retired_while_cleaning = false;
    if (mode == 1 && first_done) {
        dialed[0]->Fault();
        io.restart();
        io.run_for(60ms);
        EXPECT_TRUE(dialed[0]->closed);
        EXPECT_TRUE(dialed[0]->destroyed);
        net::co_spawn(io, request(second, ctx_second), net::bind_cancellation_slot(cancel.slot(),
            [&](std::exception_ptr error, proxy::OutboundProcessResult result) {
                failure = error; second_result = result; second_done = true;
            }));
        io.restart();
        io.run_for(180ms);
        EXPECT_TRUE(second_done);
        EXPECT_FALSE(failure);
        ASSERT_TRUE(second_result);
        EXPECT_EQ(second_result->error, common::ErrorCode::OK);
        EXPECT_EQ(second.received, 5);
        EXPECT_EQ(dialed.size(), 2);
    }
    if (!first_done || (mode == 1 && !second_done)) {
        cancel.emit(net::cancellation_type::terminal);
        io.restart();
        io.run_for(200ms);
    }
    handler.reset();
    if (mode == 2) retired_while_cleaning = dialed[0]->closed && !dialed[0]->destroyed;
    // The join itself must wait for the retired session's asynchronous cleanup.
    EXPECT_TRUE(JoinResidentTasks(io, tasks));
    if (mode == 2) {
        EXPECT_TRUE(dialed[0]->cleanup_completed);
        EXPECT_TRUE(dialed[0]->destroyed);
    }
    io.restart();
    io.run_for(200ms);
    EXPECT_TRUE(first_done);
    EXPECT_TRUE((mode != 1 || second_done));
    for (const auto& wire : dialed) {
        EXPECT_TRUE(wire->closed);
        EXPECT_TRUE(wire->destroyed);
        EXPECT_EQ(wire->active_reads, 0);
    }
    EXPECT_EQ(AllocationFailures() - failures_before, (mode == 2 ? 0 : 1));
    if (mode == 2) {
        EXPECT_TRUE(retired_while_cleaning);
        EXPECT_TRUE(dialed[0]->cleanup_completed);
    }
    dialed.clear();
}

// Pool policy and ownership through the public Handler contract. Two busy
// requests own two physical sessions; idle expiry keeps minIdleSession of
// them. Handler retirement only cancels the physical loops and the Worker join
// waits for their cleanup; a Worker join with a live Handler cancels its idle
// loops and later admissions fail instead of starting unowned work.
void RunPoolLifecycle(bool join_before_retirement) {
    net::io_context io;
    app::dns::Config dns_config;
    dns_config.servers = {{net::ip::make_address("127.0.0.1"), 53}};
    app::dns::DNSWorker dns_worker(io, dns_config, 8);
    app::dns::DNS dns(dns_worker);
    TestDialer outbound(io, dns);
    common::ResidentTaskGroup tasks(io.get_executor());
    infra::AnyTlsSettings settings;
    settings.server = LoopbackServer();
    settings.idle_session_check_interval = 1s;
    settings.idle_session_timeout = 1s;
    settings.min_idle_sessions = 1;
    auto handler = std::make_unique<proxy::anytls::outbound::Handler>("pool", io,
        std::make_shared<const infra::AnyTlsSettings>(settings),
        tasks.Tasks());
    dialed.clear();
    fail_first_session = respond_on_auth = false;
    io_fault_mode = io_fault_kind = 0;
    auto request = [&](Client& client, session::Context& ctx) -> net::awaitable<proxy::OutboundProcessResult> {
        ctx.outbound.target = common::TargetAddress("192.0.2.1", 443);
        ctx.content.network = common::Network::TCP;
        app::StatsShard stats;
        infra::TimeoutsConfig timeouts;
        app::RelayConfig config;
        config.idle_timeout = config.write_timeout = 10s;
        config.uplink_only = config.downlink_only = 5s;
        co_return co_await handler->Process(ctx,
            {&client, &client, nullptr}, outbound.dialer, timeouts, stats, config, {});
    };
    std::array<Client, 3> clients;
    std::array<session::Context, 3> contexts;
    std::array<bool, 3> succeeded{};
    std::array<bool, 3> threw{};
    auto start = [&](size_t index) {
        net::co_spawn(io, request(clients[index], contexts[index]),
            [&, index](std::exception_ptr error, proxy::OutboundProcessResult result) {
                threw[index] = bool(error);
                if (index < 2) {
                    EXPECT_FALSE(error);
                    EXPECT_TRUE(result);
                    if (result) EXPECT_EQ(result->error, common::ErrorCode::OK);
                    EXPECT_EQ(clients[index].received, 5);
                }
                succeeded[index] = !error && result && result->error == common::ErrorCode::OK &&
                    clients[index].received == 5;
            });
    };
    CleanupGuard cleanup([&] {
        DisarmAllocationFailure();
        handler.reset();
        for (const auto& wire : dialed) {
            wire->closed = true;
            wire->wake.cancel();
            wire->open_gate.cancel();
        }
        (void)JoinResidentTasks(io, tasks);
        io.restart();
        io.run();
    });
    start(0);
    start(1);
    io.run_for(180ms);
    ASSERT_GE(dialed.size(), 2);
    EXPECT_TRUE(succeeded[0]);
    EXPECT_TRUE(succeeded[1]);
    EXPECT_EQ(dialed.size(), 2);
    EXPECT_FALSE(dialed[0]->closed);
    EXPECT_FALSE(dialed[1]->closed);

    size_t expired = 0;
    bool retired_during_cleanup = false;
    bool rejected_after_join = false;
    bool joined = false;
    if (!join_before_retirement) {
        io.restart();
        io.run_for(2300ms);
        for (size_t i = 0; i < 2 && i < dialed.size(); ++i)
            expired += dialed[i]->closed && dialed[i]->destroyed;
        EXPECT_EQ(expired, 1);
        handler.reset();
        retired_during_cleanup = std::any_of(dialed.begin(), dialed.end(),
            [](const auto& wire) { return wire->closed && !wire->destroyed; });
        // The join resumes only after the retired loop finished its cleanup.
        joined = JoinResidentTasks(io, tasks) && std::all_of(dialed.begin(), dialed.end(),
            [](const auto& wire) { return wire->destroyed && wire->cleanup_completed; });
        EXPECT_TRUE(retired_during_cleanup);
    } else {
        // A Worker join cancels idle loops even while their Handler is alive.
        joined = JoinResidentTasks(io, tasks) && std::all_of(dialed.begin(), dialed.end(),
            [](const auto& wire) { return wire->closed && wire->destroyed; });
        start(2);
        io.restart();
        io.run_for(180ms);
        rejected_after_join = threw[2] && dialed.size() == 3 && dialed[2]->closed;
        EXPECT_TRUE(rejected_after_join);
        handler.reset();
    }
    io.restart();
    io.run_for(100ms);
    EXPECT_TRUE(joined);
    for (const auto& wire : dialed) {
        {
            EXPECT_TRUE(wire->closed);
            EXPECT_TRUE(wire->destroyed);
            EXPECT_EQ(wire->active_reads, 0);
        }
    }
    dialed.clear();
}

void RunDomainPoolIsolation() {
    net::io_context io;
    auto coordinator = std::make_shared<app::GroupCoordinator>(io, 2);
    coordinator->RegisterWorker(io);
    app::dns::Config dns_config;
    dns_config.servers = {{net::ip::address_v4::loopback(), 1}};
    app::dns::DNSWorker dns_worker(io, dns_config, 8);
    app::dns::DNS dns(dns_worker);
    TestDialer outbound(io, dns);
    auto tasks = std::make_unique<common::ResidentTaskGroup>(io.get_executor());
    infra::AnyTlsSettings settings;
    settings.server = LoopbackServer();
    settings.idle_session_check_interval = 60s;
    settings.idle_session_timeout = 60s;
    auto handler = std::make_unique<proxy::anytls::outbound::Handler>("isolation", io,
        std::make_shared<const infra::AnyTlsSettings>(settings), tasks->Tasks());
    OpenOrderScenario scenario{.mode = 0, .before_write_completion = false};
    open_order_scenario = &scenario;
    fail_first_session = respond_on_auth = client_padding_probe = false;
    io_fault_mode = io_fault_kind = 0;
    dialed.clear();
    std::array<Client, 4> clients;
    std::array<session::Context, 4> contexts;
    std::array<bool, 4> done{};
    auto request = [&](size_t index) -> net::awaitable<proxy::OutboundProcessResult> {
        contexts[index].outbound.target = common::TargetAddress("192.0.2.1", 443);
        contexts[index].content.network = common::Network::TCP;
        app::StatsShard stats;
        infra::TimeoutsConfig timeouts;
        app::RelayConfig relay;
        relay.idle_timeout = relay.write_timeout = 10s;
        relay.uplink_only = relay.downlink_only = 5s;
        co_return co_await handler->Process(contexts[index],
            {&clients[index], &clients[index], nullptr}, outbound.dialer,
            timeouts, stats, relay, {});
    };
    auto start = [&](size_t index) {
        net::co_spawn(io, request(index),
            [&, index](std::exception_ptr error, proxy::OutboundProcessResult result) {
                EXPECT_FALSE(error);
                EXPECT_TRUE(result);
                if (result) EXPECT_EQ(result->error, common::ErrorCode::OK);
                EXPECT_EQ(clients[index].received, 5);
                done[index] = true;
            });
        io.restart();
        io.run_for(100ms);
    };
    bool joined = false;
    bool finalized = false;
    CleanupGuard cleanup([&] {
        DisarmAllocationFailure();
        handler.reset();
        for (const auto& wire : dialed) {
            wire->closed = true;
            wire->wake.cancel();
            wire->open_gate.cancel();
        }
        if (tasks) (void)JoinResidentTasks(io, *tasks);
        io.restart();
        io.run();
        tasks.reset();
        if (!finalized) {
            coordinator->CloseAdmission();
            net::co_spawn(io, [&]() -> net::awaitable<void> {
                co_await coordinator->AsyncJoin();
                coordinator->ReleaseServices();
                co_await coordinator->Finalize();
            }, [&](std::exception_ptr error) { finalized = !error; });
            io.restart();
            io.run();
        }
    });
    start(0);
    ASSERT_TRUE(done[0]);
    ASSERT_EQ(dialed.size(), 1);
    EXPECT_TRUE(done[0]);
    EXPECT_EQ(dialed.size(), 1);
    start(1);
    EXPECT_FALSE(done[1]);
    EXPECT_EQ(dialed.size(), 1);
    start(2);
    EXPECT_TRUE(done[2]);
    EXPECT_EQ(dialed.size(), 2);
    if (!dialed.empty()) {
        dialed.front()->DeliverOpenResult();
    }
    io.restart();
    io.run_for(100ms);
    EXPECT_TRUE(done[1]);
    start(3);
    EXPECT_TRUE(done[3]);
    EXPECT_EQ(dialed.size(), 2);
    net::co_spawn(io, [&]() -> net::awaitable<void> {
        handler.reset();
        co_await tasks->AsyncJoin();
    }, [&](std::exception_ptr error) { joined = !error; });
    io.restart();
    io.run_for(250ms);
    EXPECT_TRUE(joined);
    for (const auto& wire : dialed)
        {
            EXPECT_TRUE(wire->closed);
            EXPECT_TRUE(wire->destroyed);
            EXPECT_EQ(wire->active_reads, 0);
        }
    dialed.clear();
    open_order_scenario = nullptr;
    tasks.reset();
    coordinator->CloseAdmission();
    net::co_spawn(io, [&]() -> net::awaitable<void> {
        co_await coordinator->AsyncJoin();
        coordinator->ReleaseServices();
        co_await coordinator->Finalize();
    }, [&](std::exception_ptr error) { finalized = !error; });
    io.restart();
    io.run_for(250ms);
    EXPECT_TRUE(finalized);
}

}

namespace {
TEST_F(AnyTlsLifecycleTest, PaddingUpdatesStayWithClientAndAuthenticationSnapshot) { RunClientPadding(); }
TEST_F(AnyTlsLifecycleTest, IndependentRequestsDoNotShareAnOpeningPoolLease) { RunDomainPoolIsolation(); }
class AnyTlsOpenOrder : public AnyTlsLifecycleTest,
    public testing::WithParamInterface<std::tuple<int, bool>> {};
TEST_P(AnyTlsOpenOrder, PreservesTerminalResultAndRecoversAfterOpening) {
    const auto [mode, before] = GetParam();
    RunOpenOrder(mode, before);
}
INSTANTIATE_TEST_SUITE_P(FrameAndWriteOrdering, AnyTlsOpenOrder, testing::Values(
    std::tuple{0, false}, std::tuple{0, true}, std::tuple{1, false}, std::tuple{1, true},
    std::tuple{2, false}, std::tuple{2, true}, std::tuple{3, false}, std::tuple{3, true},
    std::tuple{4, false}, std::tuple{4, true}, std::tuple{5, false}, std::tuple{5, true},
    std::tuple{6, false}, std::tuple{7, false}, std::tuple{8, false}, std::tuple{8, true}),
    ([](const auto& info) {
        constexpr std::array names{"SynackPayloadFin", "FinOnly", "PayloadFin", "RejectedSynack",
            "Alert", "SynackThenAlert", "Timeout", "Cancellation", "TruncatedPhysicalFrame"};
        return std::string(names[std::get<0>(info.param)]) +
            (std::get<1>(info.param) ? "BeforeWriteCompletion" : "AfterWriteCompletion");
    }));
class AnyTlsSessionRetirement : public AnyTlsLifecycleTest, public testing::WithParamInterface<int> {};
TEST_P(AnyTlsSessionRetirement, PreservesFailureAndJoinsPhysicalCleanup) { RunSessionRetirement(GetParam()); }
INSTANTIATE_TEST_SUITE_P(Behaviors, AnyTlsSessionRetirement, testing::Range(0, 4),
    ([](const auto& info) {
        constexpr std::array names{"SettingsAllocationFailure", "IdleFailureEvictionAndRecovery",
            "RetiredReaderCleanup", "InlineOpenAllocationFailure"};
        return names[info.param];
    }));
class AnyTlsPoolRetirement : public AnyTlsLifecycleTest, public testing::WithParamInterface<bool> {};
TEST_P(AnyTlsPoolRetirement, JoinsIdleLoopsAndRejectsUnownedAdmissions) { RunPoolLifecycle(GetParam()); }
INSTANTIATE_TEST_SUITE_P(OwnerOrdering, AnyTlsPoolRetirement, testing::Bool(),
    [](const auto& info) { return info.param ? "JoinBeforeHandlerRetirement" : "IdleExpiryBeforeRetirement"; });
class AnyTlsPhysicalIoFailure : public AnyTlsLifecycleTest,
    public testing::WithParamInterface<std::tuple<int, int>> {};
TEST_P(AnyTlsPhysicalIoFailure, PreservesErrorCategoryAndEvictsFailedSessionBeforeReuse) {
    const auto [mode, kind] = GetParam();
    RunIoFault(mode, kind);
}
INSTANTIATE_TEST_SUITE_P(PhaseAndFault, AnyTlsPhysicalIoFailure,
    testing::Combine(testing::Range(1, 6), testing::Range(1, 4)),
    ([](const auto& info) {
        constexpr std::array phases{"", "Read", "OpenWrite", "TcpPayloadWrite", "UdpPayloadWrite", "FinWrite"};
        constexpr std::array faults{"", "AllocationFailure", "LinkFailure", "UnexpectedException"};
        return std::string(phases[std::get<0>(info.param)]) + faults[std::get<1>(info.param)];
    }));
class AnyTlsOutboundQueue : public AnyTlsLifecycleTest, public testing::WithParamInterface<int> {};
TEST_P(AnyTlsOutboundQueue, PreservesBoundariesAndReclaimsBoundedStorageOnCompletionOrStop) { RunQueue(GetParam()); }
INSTANTIATE_TEST_SUITE_P(Behaviors, AnyTlsOutboundQueue,
    testing::Values(0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15),
    ([](const auto& info) {
        constexpr std::array names{"TinyFragments", "WholeFrame", "SparseFragments", "BoundaryFragments",
            "MaximumTinyFragments", "FullQueueBackpressure", "CancelFullQueue", "Unused", "RandomFragments",
            "RefillAfterDrain", "CoalescedUdpDatagrams", "FragmentedUdpDatagrams", "AlertDiscardsQueue",
            "SlowConsumerAndHeartResponse", "CancelSlowConsumer", "TimeoutSlowConsumer"};
        return names[info.param];
    }));
class AnyTlsOutboundQueueFragments : public AnyTlsLifecycleTest, public testing::WithParamInterface<unsigned> {};
TEST_P(AnyTlsOutboundQueueFragments, PreservesPayloadAcrossRandomFrameBoundaries) { RunQueue(8, GetParam()); }
INSTANTIATE_TEST_SUITE_P(Seeds, AnyTlsOutboundQueueFragments, testing::Range(1u, 17u));
}  // namespace
