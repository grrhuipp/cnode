#include "anytls_outbound.hpp"
#include "../anytls_codec.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/infra/runtime_config_types.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/transport/link_error.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace {
thread_local bool fail_next_allocation = false;
thread_local bool fail_next_pmr_allocation = false;
thread_local size_t allocation_failures = 0;
thread_local size_t failed_allocation_size = 0;
thread_local size_t fail_allocation_bytes = 0;
static_assert(alignof(acpp::buf::Buffer) <= alignof(std::max_align_t));
}
void* operator new(std::size_t size) {
    if (fail_next_allocation) {
        fail_next_allocation = false;
        ++allocation_failures; failed_allocation_size = size; throw std::bad_alloc();
    }
    if (auto* result = std::malloc(size ? size : 1)) return result;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { ::operator delete(value); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void operator delete(void* value, const std::nothrow_t&) noexcept { ::operator delete(value); }

namespace {
using namespace acpp;
using namespace std::chrono_literals;

class FailingPmrResource final : public std::pmr::memory_resource {
public:
    explicit FailingPmrResource(std::pmr::memory_resource* upstream) : upstream_(upstream) {}

private:
    void* do_allocate(size_t size, size_t alignment) override {
        if (fail_next_pmr_allocation && size == fail_allocation_bytes) {
            fail_next_pmr_allocation = false;
            fail_allocation_bytes = 0;
            ++allocation_failures;
            failed_allocation_size = size;
            throw std::bad_alloc();
        }
        return upstream_->allocate(size, alignment);
    }
    void do_deallocate(void* pointer, size_t size, size_t alignment) override {
        upstream_->deallocate(pointer, size, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
    std::pmr::memory_resource* upstream_;
};

size_t BufferCount() noexcept { return memory::detail::test_buffers_live; }
size_t BufferPeak() noexcept { return memory::detail::test_buffers_peak; }

struct QueueScenario {
    int mode = 0;
    std::vector<size_t> fragments;
    std::vector<uint8_t> expected;
    std::vector<uint8_t> wire_payload;
    std::vector<uint8_t> received;
    std::vector<size_t> datagram_sizes;
    std::vector<const void*> read_addresses;
    std::vector<const void*> delivered_addresses;
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
            if (command == anytls::kCmdSettings)
                client_settings.assign(reinterpret_cast<const char*>(header + 7), length);
            if (command == anytls::kCmdWaste) padding_lengths.push_back(length);
            if (command == anytls::kCmdHeartResponse) ++heart_responses;
            if (command != anytls::kCmdPSH || responded) continue;
            responded = true;
            Frame(anytls::kCmdServerSettings, 0, "v=2");
            if (padding_index == 0) Frame(anytls::kCmdUpdatePaddingScheme, 0, kPaddingA);
            Frame(anytls::kCmdSYNACK, sid);
            Frame(anytls::kCmdPSH, sid, "reply");
            // The first request stays busy while another physical session opens.
            if (padding_index != 0) Frame(anytls::kCmdFIN, sid);
            wake.cancel();
        }
    }

    void DeliverOpenResult() {
        if (!open_order || open_order->delivered) return;
        open_order->delivered = true;
        const int mode = open_order->mode;
        if (mode == 0 || mode == 5) Frame(anytls::kCmdSYNACK, 2);
        if (mode == 0 || mode == 2) Frame(anytls::kCmdPSH, 2, "reply");
        if (mode <= 2) Frame(anytls::kCmdFIN, 2);
        if (mode == 3) Frame(anytls::kCmdSYNACK, 2, "rejected");
        if (mode == 4 || mode == 5) Frame(anytls::kCmdAlert, 0, "closed");
        if (mode == 8) {
            Frame(anytls::kCmdSYNACK, 2, "rejected");
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
            if (command == anytls::kCmdFIN && sid == 2) ++open_order->fin_replies;
            if (command != anytls::kCmdPSH || sid >= target_seen.size()) continue;
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
                    Frame(anytls::kCmdServerSettings, 0, "v=2");
                    Frame(anytls::kCmdUpdatePaddingScheme, 0, "stop=1\n");
                }
                Frame(anytls::kCmdSYNACK, sid);
                Frame(anytls::kCmdPSH, sid, "reply");
                Frame(anytls::kCmdFIN, sid);
                wake.cancel();
            }
        }
    }

    [[noreturn]] void RaiseIoFault() {
        ++io_faults;
        if (io_fault_kind == 1) throw std::bad_alloc();
        if (io_fault_kind == 2) throw transport::LinkError(ErrorCode::BLOCKED);
        throw std::runtime_error("original physical I/O exception");
    }

    void Frame(uint8_t command, uint32_t sid, std::string_view payload = {}) {
        input.insert(input.end(), {command, uint8_t(sid >> 24), uint8_t(sid >> 16),
            uint8_t(sid >> 8), uint8_t(sid), uint8_t(payload.size() >> 8), uint8_t(payload.size())});
        input.insert(input.end(), payload.begin(), payload.end());
    }
    void Fault() {
        Frame(anytls::kCmdUpdatePaddingScheme, 0, std::string(1024, 'x'));
        fail_on_header = true;
        wake.cancel();
    }
    void Reply() {
        if (queue) {
            Frame(anytls::kCmdServerSettings, 0, "v=2");
            Frame(anytls::kCmdSYNACK, 1);
            size_t payload_offset = 0;
            for (size_t bytes : queue->fragments) {
                Frame(anytls::kCmdPSH, 1, std::string_view(
                    reinterpret_cast<const char*>(queue->wire_payload.data() + payload_offset), bytes));
                payload_offset += bytes;
                if (queue->mode >= 13 && payload_offset == 3 * 65535) Frame(anytls::kCmdHeartRequest, 0);
            }
            if (queue->mode != 6 && queue->mode != 7 && queue->mode != 9) Frame(anytls::kCmdFIN, 1);
            if (queue->mode == 12) Frame(anytls::kCmdAlert, 0);
        } else if (fail_settings) {
            Frame(anytls::kCmdServerSettings, 0, std::string(1024, 'x'));
            fail_on_header = true;
        } else {
            Frame(anytls::kCmdServerSettings, 0, "v=2");
            if (io_fault_mode >= 3) Frame(anytls::kCmdUpdatePaddingScheme, 0, "stop=2\n1=64-65\n");
            Frame(anytls::kCmdSYNACK, 1);
            if (io_fault_mode < 2) {
                Frame(anytls::kCmdPSH, 1, "reply");
                Frame(anytls::kCmdFIN, 1);
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

class Stream final : public AsyncStream {
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
        if (wire_->queue && wire_->queue->mode == 1 && count >= 4096) {
            wire_->queue->read_addresses.push_back(output.data());
        }
        std::memcpy(output.data(), wire_->input.data() + wire_->offset, count);
        wire_->offset += count;
        if (wire_->queue && wire_->queue->mode == 7 && count == 4096) {
            fail_allocation_bytes = 128;
            fail_next_pmr_allocation = true;
        }
        if (wire_->fail_on_header && count == 7) {
            wire_->fail_on_header = false;
            // Fail the production codec's next coroutine/string allocation,
            // after ReadFrameHeader has successfully returned this header.
            fail_next_allocation = true;
        }
        co_return count;
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer data) override {
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
                    dialed[0]->Frame(anytls::kCmdUpdatePaddingScheme, 0, kPaddingB);
                    dialed[0]->Frame(anytls::kCmdHeartRequest, 0);
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
        if (data.size() == 7 && bytes[0] == anytls::kCmdHeartResponse) ++wire_->heart_responses;
        if ((wire_->io_fault_mode == 2 && wire_->writes == 2) ||
            (wire_->io_fault_mode >= 3 && data.size() == 7 &&
             bytes[0] == (wire_->io_fault_mode == 5 ? anytls::kCmdFIN : anytls::kCmdPSH))) {
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
    bool eof = false;
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!eof) {
            net::steady_timer pending(co_await net::this_coro::executor);
            pending.expires_at(net::steady_timer::time_point::max());
            co_await pending.async_wait(net::use_awaitable);
        }
        co_return buf::MultiBuffer{};
    }
    transport::CancellationSource& Cancellation() noexcept override { return source; }
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
        received += buf::TotalLen(bytes);
        if (queue_scenario) {
            if (queue_scenario->mode == 10 || queue_scenario->mode == 11) {
                queue_scenario->datagram_sizes.push_back(bytes.byte_size());
            }
            for (const auto* block : bytes) {
                queue_scenario->received.insert(queue_scenario->received.end(), block->Bytes().begin(), block->Bytes().end());
                queue_scenario->delivered_addresses.push_back(block->Bytes().data());
            }
            if (queue_scenario->mode == 9 && queue_scenario->received.size() == 65535) {
                auto& wire = *dialed[0];
                wire.Frame(anytls::kCmdPSH, 1, std::string_view(
                    reinterpret_cast<const char*>(queue_scenario->expected.data() + 65535), 65535));
                wire.Frame(anytls::kCmdFIN, 1);
                wire.wake.cancel();
            }
        }
        co_return;
    }
};
}

// Only the external dial boundary is replaced. The production target builder,
// Handler, codec, session pool, logical endpoint and relay execute unchanged.
namespace acpp {
net::awaitable<DialResult> DialOutboundTransport(net::io_context& io, session::Context&,
                                                const OutboundTransportTarget&) {
    auto wire = std::make_shared<Wire>(io);
    wire->fail_settings = fail_first_session && dialed.empty();
    wire->respond_on_auth = respond_on_auth;
    wire->queue = queue_scenario;
    wire->open_order = open_order_scenario;
    wire->padding_probe = client_padding_probe;
    wire->padding_index = dialed.size();
    if (dialed.empty()) { wire->io_fault_mode = io_fault_mode; wire->io_fault_kind = io_fault_kind; }
    dialed.push_back(wire);
    DialResult result;
    result.stream = std::make_unique<Stream>(wire);
    co_return result;
}
}

namespace {
bool RunClientPadding() {
    net::io_context io;
    app::dns::Config dns_config;
    dns_config.servers = {{net::ip::address_v4::loopback(), 1}};
    app::dns::DNS dns(io, dns_config);
    proxy::anytls::outbound::Settings settings;
    settings.address = "127.0.0.1";
    settings.literal_address = net::ip::address_v4::loopback();
    settings.port = 443;
    settings.idle_session_check_interval = 60s;
    settings.idle_session_timeout = 60s;
    settings.min_idle_sessions = 1;
    auto make_handler = [&] {
        return std::make_unique<proxy::anytls::outbound::Handler>(
            "same-client-tag", io, settings, StreamSettings{}, 1s, dns);
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
    std::array<ErrorCode, 4> errors{};
    auto request = [&](proxy::anytls::outbound::Handler& active, size_t index) -> net::awaitable<OutboundProcessResult> {
        auto& ctx = contexts[index];
        ctx.outbound.target = TargetAddress("192.0.2.1", 443);
        StatsShard stats;
        TimeoutsConfig timeouts;
        RelayConfig config;
        config.uplink_only = config.downlink_only = 5s;
        co_return co_await active.Process(io, nullptr, ctx, timeouts,
            {&clients[index], &clients[index], nullptr}, stats, config, {}, 10s, 10s);
    };
    auto start = [&](proxy::anytls::outbound::Handler& active, size_t index) {
        net::co_spawn(io, request(active, index), net::bind_cancellation_slot(cancellations[index].slot(),
            [&, index](std::exception_ptr exception, OutboundProcessResult result) {
                failed[index] = bool(exception);
                errors[index] = result ? result->error : result.error();
                done[index] = true;
            }));
        io.restart();
        io.poll();
    };
    start(*handler, 0);
    bool passed = dialed.size() == 1 && !done[0] && clients[0].received == 5;
    start(*handler, 1);
    passed &= dialed.size() == 2 && done[1] && !failed[1] && errors[1] == ErrorCode::OK;
    const auto matches = [](const Wire& wire, uint16_t auth, std::string_view digest) {
        return wire.auth_padding == auth && wire.client_settings ==
            "v=2\nclient=cnode\npadding-md5=" + std::string(digest);
    };
    if (dialed.size() == 2) {
        passed &= matches(*dialed[0], 30, "75cff2ad89aadf5e257059ee571ebe11");
        passed &= dialed[1]->auth_update_seen && matches(*dialed[1], 45, "52a2071298e4ff6f3bad08249a70a53c");
        passed &= dialed[1]->padding_lengths == std::vector<size_t>{160};
        dialed[1]->Frame(anytls::kCmdAlert, 0, "fresh session required");
        dialed[1]->wake.cancel();
        io.restart();
        io.run_for(40ms);
    }
    start(*handler, 2);
    passed &= dialed.size() == 3 && done[2] && !failed[2] && errors[2] == ErrorCode::OK;
    if (dialed.size() == 3) {
        passed &= matches(*dialed[2], 91, "75051a2e7a47cba8affd2d07cbe8d0c8");
        passed &= dialed[2]->padding_lengths == std::vector<size_t>{224};
    }
    cancellations[0].emit(net::cancellation_type::all);
    io.restart();
    io.poll();
    passed &= done[0] && !failed[0] && errors[0] == ErrorCode::CANCELLED;
    handler.reset();
    const bool retired_during_cleanup = std::any_of(dialed.begin(), dialed.end(),
        [](const auto& wire) { return wire->closed && !wire->destroyed; });
    auto replacement = make_handler();
    start(*replacement, 3);
    passed &= dialed.size() == 4 && done[3] && !failed[3] && errors[3] == ErrorCode::OK;
    if (dialed.size() == 4)
        passed &= matches(*dialed[3], 30, "75cff2ad89aadf5e257059ee571ebe11");
    replacement.reset();
    io.restart();
    io.run_for(100ms);
    const bool joined = std::all_of(dialed.begin(), dialed.end(),
        [](const auto& wire) { return wire->closed && wire->destroyed && wire->active_reads == 0; });
    passed &= retired_during_cleanup && joined && std::all_of(done.begin(), done.end(), [](bool value) { return value; });
    std::printf("client-padding connections=%zu during-auth=%d retired-cleanup=%d joined=%d auth=",
        dialed.size(), dialed.size() > 1 && dialed[1]->auth_update_seen, retired_during_cleanup, joined);
    for (const auto& wire : dialed) std::printf("%u,", unsigned(wire->auth_padding));
    std::printf(" %s\n", passed ? "PASS" : "FAIL");
    dialed.clear();
    client_padding_probe = false;
    return passed;
}

bool RunOpenOrder(int mode, bool before) {
    net::io_context io;
    app::dns::Config dns_config;
    dns_config.servers = {{net::ip::address_v4::loopback(), 1}};
    app::dns::DNS dns(io, dns_config);
    proxy::anytls::outbound::Settings settings;
    settings.address = "127.0.0.1";
    settings.literal_address = net::ip::address_v4::loopback();
    settings.port = 443;
    settings.idle_session_check_interval = 60s;
    settings.idle_session_timeout = 60s;
    settings.min_idle_sessions = 1;
    OpenOrderScenario scenario{.mode = mode, .before_write_completion = before};
    open_order_scenario = &scenario;
    dialed.clear();
    auto handler = std::make_unique<proxy::anytls::outbound::Handler>("open-order", io, settings, StreamSettings{}, 1s, dns);
    auto request = [&](Client& client, session::Context& ctx) -> net::awaitable<OutboundProcessResult> {
        ctx.outbound.target = TargetAddress("192.0.2.1", 443);
        ctx.content.network = Network::TCP;
        StatsShard stats;
        TimeoutsConfig timeouts;
        RelayConfig config;
        config.uplink_only = config.downlink_only = 5s;
        co_return co_await handler->Process(io, nullptr, ctx, timeouts,
            {&client, &client, nullptr}, stats, config, {}, 10s, 10s);
    };
    Client warm, tested, recovery;
    session::Context warm_ctx, tested_ctx, recovery_ctx;
    bool warm_done = false, done = false, recovery_done = false;
    ErrorCode observed = ErrorCode::OK;
    std::exception_ptr failure;
    net::cancellation_signal cancel;
    net::co_spawn(io, request(warm, warm_ctx), [&](std::exception_ptr error, OutboundProcessResult result) {
        warm_done = !error && result && result->error == ErrorCode::OK && warm.received == 5;
    });
    io.run_for(100ms);
    if (!warm_done || dialed.size() != 1) throw std::runtime_error("open-order warmup did not establish one reusable v2 session");
    net::co_spawn(io, request(tested, tested_ctx), net::bind_cancellation_slot(cancel.slot(),
        [&](std::exception_ptr error, OutboundProcessResult result) {
            done = true; failure = error;
            observed = result ? result->error : result.error();
        }));
    io.restart();
    io.run_for(80ms);
    if (!scenario.target_sent || (before && !scenario.write_released))
        throw std::runtime_error("open-order fixture did not establish the requested write/read ordering");
    const bool waited_without_signal = !done;
    if (!before) {
        if (mode == 7) cancel.emit(net::cancellation_type::terminal);
        else if (mode != 6) dialed.front()->DeliverOpenResult();
        io.restart();
        io.run_for(mode == 6 ? 3200ms : 80ms);
    }
    const bool timely = done;
    const auto expected = mode <= 2 ? ErrorCode::OK : mode == 6 ? ErrorCode::TIMEOUT :
        mode == 7 ? ErrorCode::CANCELLED : mode == 8 ? ErrorCode::CONNECTION_CLOSED : ErrorCode::PROTOCOL_DECODE_FAILED;
    bool passed = timely && !failure && observed == expected &&
        tested.received == (mode == 0 || mode == 2 ? 5u : 0u) &&
        (before || waited_without_signal) && scenario.fin_replies == 0 && scenario.payload_after_close == 0;
    if (!done) {
        // Record the actual incorrect deadline result before cleaning up.
        io.restart();
        io.run_for(3200ms);
    }
    if (!done) {
        cancel.emit(net::cancellation_type::terminal);
        io.restart(); io.run_for(200ms);
    }
    net::co_spawn(io, request(recovery, recovery_ctx), [&](std::exception_ptr error, OutboundProcessResult result) {
        recovery_done = !error && result && result->error == ErrorCode::OK && recovery.received == 5;
    });
    io.restart(); io.run_for(100ms);
    const size_t expected_connections = mode <= 2 ? 1 : 2;
    passed &= done && recovery_done && dialed.size() == expected_connections;
    handler.reset();
    io.restart(); io.run_for(200ms);
    bool joined = true;
    for (const auto& wire : dialed) joined &= wire->closed && wire->destroyed && wire->active_reads == 0;
    passed &= joined;
    std::printf("open-order mode=%d before=%d held=%d released=%d timely=%d code=%s bytes=%zu connections=%zu recovered=%d joined=%d: %s\n",
        mode, before, scenario.write_held, scenario.write_released, timely,
        ErrorCodeToString(observed).data(), tested.received, dialed.size(), recovery_done, joined, passed ? "PASS" : "FAIL");
    dialed.clear(); open_order_scenario = nullptr;
    return passed;
}

bool RunQueue(int mode, unsigned seed = 1, bool baseline = false) {
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
    else if (mode == 7) { queue.fragments.assign(7, 4097); queue.fragments.push_back(4096); }
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
    app::dns::DNS dns(io, dns_config);
    proxy::anytls::outbound::Settings settings;
    settings.address = "127.0.0.1";
    settings.literal_address = net::ip::make_address("127.0.0.1");
    settings.port = 443;
    settings.idle_session_check_interval = 1s;
    settings.idle_session_timeout = 60s;
    settings.min_idle_sessions = 1;
    auto handler = std::make_unique<proxy::anytls::outbound::Handler>("queue", io, settings, StreamSettings{}, 1s, dns);
    queue_scenario = &queue;
    dialed.clear();
    fail_first_session = respond_on_auth = false;
    io_fault_mode = io_fault_kind = 0;
    memory::detail::test_buffers_peak = BufferCount();
    failed_allocation_size = 0;
    fail_allocation_bytes = 0;
    const auto failures_before = allocation_failures;
    Client client;
    TimeoutToken request_timeout;
    if (mode == 15) request_timeout = TimeoutScheduler::ForIoContext(io).ScheduleAfter(1s, [&client] {
        client.source.Stop(ErrorCode::RELAY_TIMEOUT);
    });
    session::Context ctx;
    ctx.outbound.target = TargetAddress("192.0.2.1", 443);
    ctx.content.network = mode == 10 || mode == 11 ? Network::UDP : Network::TCP;
    StatsShard stats;
    TimeoutsConfig timeouts;
    RelayConfig config;
    config.uplink_only = config.downlink_only = 5s;
    bool done = false;
    const auto started = std::chrono::steady_clock::now();
    int64_t completed_ms = 0;
    ErrorCode observed = ErrorCode::OK;
    std::exception_ptr exception;
    net::cancellation_signal cancellation;
    net::co_spawn(io, handler->Process(io, nullptr, ctx, timeouts,
        {&client, &client, nullptr}, stats, config, {}, 10s, 10s),
        net::bind_cancellation_slot(cancellation.slot(), [&](std::exception_ptr failure, OutboundProcessResult result) {
            done = true; exception = failure;
            completed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - started).count();
            observed = result ? result->error : result.error();
        }));
    io.poll();
    bool passed = !exception && (mode == 6 || mode >= 13 ? !done : done);
    if (mode >= 13) {
        passed &= queue.consumer_started && queue.pending_consumer == 1 && BufferCount() == 24;
        // Eight consumer blocks, eight queued blocks, eight in the waiting frame.
        queue.queued_blocks = BufferCount() >= 16 ? BufferCount() - 16 : 0;
        queue.snapshot = true;
        if (mode == 13) {
            queue.consumer_released = true;
            queue.consumer_gate->cancel();
        } else if (mode == 14) cancellation.emit(net::cancellation_type::terminal);
    }
    if (mode == 6) {
        passed &= queue.snapshot && !dialed[0]->closed && dialed[0]->active_reads == 1;
        cancellation.emit(net::cancellation_type::terminal);
    }
    io.restart();
    io.run_for(mode == 15 ? 1300ms : 80ms);
    const ErrorCode expected = mode == 7 ? ErrorCode::RESOURCE_EXHAUSTED
        : mode == 6 || mode == 14 ? ErrorCode::CANCELLED : mode == 15 ? ErrorCode::RELAY_TIMEOUT
        : mode == 12 ? ErrorCode::PROTOCOL_DECODE_FAILED : ErrorCode::OK;
    passed &= done && !exception && observed == expected;
    if (mode != 6 && mode != 7 && mode != 12 && mode != 14 && mode != 15) passed &= queue.received == queue.expected;
    else passed &= queue.received.empty();
    if (mode == 1) passed &= queue.read_addresses.size() == 8 && queue.delivered_addresses == queue.read_addresses;
    if (mode == 7) passed &= allocation_failures - failures_before == 1 && failed_allocation_size == 128;
    if (mode == 14 || mode == 15) passed &= queue.consumer_cleaned && queue.pending_consumer == 0;
    if (mode == 15) passed &= completed_ms >= 900 && completed_ms < 1500;
    if (mode == 13) passed &= dialed[0]->heart_responses == 1;
    if (mode == 10 || mode == 11) passed &= queue.datagram_sizes == std::vector<size_t>{9000, 19999};
    const bool bounded = queue.queued_blocks <= 16 && BufferPeak() <= 24;
    if (mode != 7 && mode != 12) passed &= queue.snapshot;
    if (mode == 0) passed &= baseline || queue.queued_blocks == 1;
    if (!baseline) passed &= bounded;
    handler.reset();
    io.restart();
    io.run_for(100ms);
    for (const auto& wire : dialed) passed &= wire->closed && wire->destroyed && wire->active_reads == 0;
    passed &= BufferCount() == 0;
    std::printf("outbound-queue mode=%d seed=%u fragments=%zu bytes=%zu queued-blocks=%zu capacity-bytes=%zu peak-blocks=%zu bounded=%d received=%zu datagrams=%zu code=%s allocation-size=%zu completed-ms=%lld heart-responses=%zu pending-consumer=%d released=%d: %s\n",
        mode, seed, queue.fragments.size(), bytes, queue.queued_blocks, queue.queued_blocks * buf::Buffer::kSize,
        BufferPeak(), bounded, queue.received.size(), queue.datagram_sizes.size(), ErrorCodeToString(observed).data(), failed_allocation_size,
        static_cast<long long>(completed_ms), dialed[0]->heart_responses, queue.pending_consumer,
        BufferCount() == 0, passed ? "PASS" : "FAIL");
    dialed.clear();
    queue_scenario = nullptr;
    return passed;
}

bool RunIoFault(int mode, int kind) {
    net::io_context io;
    app::dns::Config dns_config;
    dns_config.servers = {{net::ip::make_address("127.0.0.1"), 53}};
    app::dns::DNS dns(io, dns_config);
    proxy::anytls::outbound::Settings settings;
    settings.address = "127.0.0.1";
    settings.literal_address = net::ip::make_address("127.0.0.1");
    settings.port = 443;
    settings.idle_session_check_interval = 1s;
    settings.idle_session_timeout = 60s;
    settings.min_idle_sessions = 1;
    auto handler = std::make_unique<proxy::anytls::outbound::Handler>("io-fault", io, settings, StreamSettings{}, 1s, dns);
    dialed.clear();
    fail_first_session = false;
    respond_on_auth = false;
    io_fault_mode = mode;
    io_fault_kind = kind;
    auto request = [&](Client& client, session::Context& ctx, bool first) -> net::awaitable<OutboundProcessResult> {
        ctx.outbound.target = TargetAddress("192.0.2.1", 443);
        ctx.content.network = first && mode == 4 ? Network::UDP : Network::TCP;
        StatsShard stats;
        TimeoutsConfig timeouts;
        RelayConfig config;
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
        co_return co_await handler->Process(io, nullptr, ctx, timeouts,
            {&client, &client, nullptr}, stats, config, std::move(payload), 10s, 10s);
    };
    // Relay owns payload failures and retains its generic write-phase category
    // for unknown exceptions; the codec must not invent a socket error.
    const ErrorCode expected = kind == 1 ? ErrorCode::RESOURCE_EXHAUSTED : kind == 2 ? ErrorCode::BLOCKED :
        (mode == 3 || mode == 4) ? ErrorCode::RELAY_WRITE_FAILED : ErrorCode::INTERNAL;
    Client first, second;
    first.eof = mode == 5;
    session::Context first_ctx, second_ctx;
    bool first_done = false, second_done = false;
    ErrorCode observed = ErrorCode::OK;
    net::cancellation_signal cancel;
    net::co_spawn(io, request(first, first_ctx, true), net::bind_cancellation_slot(cancel.slot(),
        [&](std::exception_ptr failure, OutboundProcessResult result) {
            first_done = true;
            observed = result ? result->error : result.error();
            if (!failure) return;
            try { std::rethrow_exception(failure); }
            catch (const std::bad_alloc&) { observed = ErrorCode::RESOURCE_EXHAUSTED; }
            catch (const transport::LinkError& error) { observed = error.code(); }
            catch (...) { observed = ErrorCode::INTERNAL; }
        }));
    io.run_for(180ms);
    bool passed = first_done && observed == expected && dialed.size() == 1 &&
        dialed[0]->io_faults == 1 && dialed[0]->closed && dialed[0]->destroyed &&
        first_ctx.outbound.os_error_code == 0 &&
        (mode == 1 || dialed[0]->partial_write == 3);
    if (!first_done) {
        cancel.emit(net::cancellation_type::terminal);
        io.restart();
        io.run_for(200ms);
    }
    net::co_spawn(io, request(second, second_ctx, false), [&](std::exception_ptr failure, OutboundProcessResult result) {
        second_done = !failure && result && result->error == ErrorCode::OK && second.received == 5;
    });
    io.restart();
    io.run_for(180ms);
    passed &= second_done && dialed.size() == 2;
    handler.reset();
    io.restart();
    io.run_for(200ms);
    for (const auto& wire : dialed) passed &= wire->closed && wire->destroyed && wire->active_reads == 0;
    std::printf("outbound-io mode=%d kind=%d observed=%s expected=%s faults=%d partial=%zu recovered=%d joined=%d: %s\n",
        mode, kind, ErrorCodeToString(observed).data(), ErrorCodeToString(expected).data(),
        dialed[0]->io_faults, dialed[0]->partial_write, second_done, dialed[0]->destroyed, passed ? "PASS" : "FAIL");
    dialed.clear();
    io_fault_mode = io_fault_kind = 0;
    return passed;
}

bool Run(int mode) {
    net::io_context io;
    app::dns::Config dns_config;
    dns_config.servers = {{net::ip::make_address("127.0.0.1"), 53}};
    app::dns::DNS dns(io, dns_config);
    proxy::anytls::outbound::Settings settings;
    settings.address = "127.0.0.1";
    settings.literal_address = net::ip::make_address("127.0.0.1");
    settings.port = 443;
    settings.idle_session_check_interval = 1s;
    settings.idle_session_timeout = 60s;
    settings.min_idle_sessions = 1;
    auto handler = std::make_unique<proxy::anytls::outbound::Handler>(
        "test", io, settings, StreamSettings{}, 1s, dns);
    dialed.clear();
    fail_first_session = mode == 0 || mode == 3;
    respond_on_auth = mode == 3;
    const auto failures_before = allocation_failures;
    auto request = [&](Client& client, session::Context& ctx) -> net::awaitable<OutboundProcessResult> {
        ctx.outbound.target = TargetAddress("192.0.2.1", 443);
        ctx.content.network = Network::TCP;
        StatsShard stats;
        TimeoutsConfig timeouts;
        RelayConfig config;
        config.uplink_only = config.downlink_only = 5s;
        co_return co_await handler->Process(io, nullptr, ctx, timeouts,
            {&client, &client, nullptr}, stats, config, {}, 10s, 10s);
    };
    Client first, second;
    session::Context ctx_first, ctx_second;
    bool first_done = false, second_done = false;
    OutboundProcessResult first_result, second_result;
    std::exception_ptr failure;
    net::cancellation_signal cancel;
    net::co_spawn(io, request(first, ctx_first), net::bind_cancellation_slot(cancel.slot(),
        [&](std::exception_ptr error, OutboundProcessResult result) {
            failure = error; first_result = result; first_done = true;
        }));
    io.run_for(180ms);
    const bool timely = first_done;
    bool passed = timely && !failure && !dialed.empty();
    if (mode == 0 || mode == 3) passed &= first_result && first_result->error == ErrorCode::RESOURCE_EXHAUSTED && dialed[0]->closed;
    else passed &= first_result && first_result->error == ErrorCode::OK && first.received == 5;
    bool retired_while_cleaning = false;
    if (mode == 1 && first_done) {
        dialed[0]->Fault();
        io.restart();
        io.run_for(60ms);
        passed &= dialed[0]->closed && dialed[0]->destroyed;
        net::co_spawn(io, request(second, ctx_second), net::bind_cancellation_slot(cancel.slot(),
            [&](std::exception_ptr error, OutboundProcessResult result) {
                failure = error; second_result = result; second_done = true;
            }));
        io.restart();
        io.run_for(180ms);
        passed &= second_done && !failure && second_result && second_result->error == ErrorCode::OK &&
            second.received == 5 && dialed.size() == 2;
    }
    if (!first_done || (mode == 1 && !second_done)) {
        cancel.emit(net::cancellation_type::terminal);
        io.restart();
        io.run_for(200ms);
    }
    handler.reset();
    if (mode == 2) retired_while_cleaning = dialed[0]->closed && !dialed[0]->destroyed;
    io.restart();
    io.run_for(200ms);
    passed &= first_done && (mode != 1 || second_done);
    for (const auto& wire : dialed) passed &= wire->closed && wire->destroyed && wire->active_reads == 0;
    passed &= allocation_failures - failures_before == (mode == 2 ? 0 : 1);
    if (mode == 2) passed &= retired_while_cleaning && dialed[0]->cleanup_completed;
    std::printf("mode=%d timely=%d allocations=%zu connections=%zu first=%s second-done=%d closed=%d destroyed=%d cleanup=%d: %s\n",
        mode, timely, allocation_failures - failures_before, dialed.size(),
        ErrorCodeToString(first_result ? first_result->error : first_result.error()).data(), second_done,
        dialed[0]->closed, dialed[0]->destroyed, dialed[0]->cleanup_completed, passed ? "PASS" : "FAIL");
    dialed.clear();
    return passed;
}
}

int main(int argc, char** argv) {
    FailingPmrResource resource(std::pmr::get_default_resource());
    auto* original = std::pmr::set_default_resource(&resource);
    struct RestoreResource {
        std::pmr::memory_resource* original;
        ~RestoreResource() { std::pmr::set_default_resource(original); }
    } restore{original};
    try {
        if (argc == 2 && std::string_view(argv[1]) == "--client-padding")
            return RunClientPadding() ? 0 : 1;
        if (argc == 2 && std::string_view(argv[1]) == "--queue-baseline") {
            bool passed = RunQueue(0, 1, true);
            passed &= RunQueue(1, 1, true);
            return passed ? 0 : 1;
        }
        if (argc == 2 && std::string_view(argv[1]) == "--open-order") {
            bool passed = true;
            for (int mode = 0; mode < 9; ++mode)
                for (bool before : {false, true})
                    if (!before || (mode != 6 && mode != 7)) passed &= RunOpenOrder(mode, before);
            return passed ? 0 : 1;
        }
        bool passed = RunClientPadding();
        for (int mode = 0; mode < 9; ++mode)
            for (bool before : {false, true})
                if (!before || (mode != 6 && mode != 7)) passed &= RunOpenOrder(mode, before);
        for (int mode = 0; mode < 4; ++mode) passed &= Run(mode);
        for (int mode = 1; mode <= 5; ++mode)
            for (int kind = 1; kind <= 3; ++kind) passed &= RunIoFault(mode, kind);
        for (int mode = 0; mode <= 7; ++mode) passed &= RunQueue(mode);
        for (unsigned seed = 1; seed <= 16; ++seed) passed &= RunQueue(8, seed);
        for (int mode = 9; mode <= 12; ++mode) passed &= RunQueue(mode);
        for (int mode = 13; mode <= 15; ++mode) passed &= RunQueue(mode);
        return passed ? 0 : 1;
    } catch (const std::exception& error) {
        fail_next_allocation = false;
        fail_next_pmr_allocation = false;
        std::fprintf(stderr, "fixture failure: %s\n", error.what());
        return 1;
    }
}
