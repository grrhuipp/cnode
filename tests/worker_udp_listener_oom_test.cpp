#include "async_allocation_fault.hpp"
#include "worker/udp_receive_loop.hpp"

#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/runtime_config_types.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/proxy/inbound_datagram.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "worker/udp_ingress.hpp"
#include "worker/udp_association_reclaimer.hpp"

#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <memory_resource>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#  include <mstcpip.h>
#endif

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

struct TestState {
    bool large_packet_processed = false;
    bool after_processor_oom_processed = false;
    bool after_peer_error_processed = false;
    bool dispatcher_completed = false;
    bool dispatcher_payload_valid = false;
};

class TargetedPmrResource final : public std::pmr::memory_resource {
public:
    bool fail_next_large = false;
    size_t failed_large = 0;
    size_t large_allocations = 0;
    size_t large_deallocations = 0;
    bool arm_async_receive_after_large_prepare = false;

private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (bytes > acpp::buf::Buffer::kSize) {
            ++large_allocations;
            if (std::exchange(fail_next_large, false)) {
                acpp::memory::reject_next_pmr_allocation = true;
                void* ptr = acpp::memory::AllocatePmr(bytes, alignment);
                if (!ptr) {
                    ++failed_large;
                    throw std::bad_alloc();
                }
                return ptr;
            }
            if (void* ptr = acpp::memory::AllocatePmr(bytes, alignment)) {
                if (std::exchange(arm_async_receive_after_large_prepare, false)) {
                    async_allocation_test::fail_after = 0;
                }
                return ptr;
            }
            throw std::bad_alloc();
        }
        if (void* ptr = acpp::memory::AllocatePmr(bytes, alignment)) return ptr;
        throw std::bad_alloc();
    }

    void do_deallocate(void* ptr, size_t bytes, size_t alignment) override {
        if (bytes > acpp::buf::Buffer::kSize) ++large_deallocations;
        acpp::memory::DeallocatePmr(ptr, bytes, alignment);
    }

    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};

class TestResponse final : public acpp::InboundDatagramResponse {
public:
    acpp::buf::MultiBuffer Encode(acpp::UDPPacketView) override { return {}; }
};

class TestInbound final : public acpp::Inbound {
public:
    explicit TestInbound(TestState& state) : state_(state) {}

    acpp::net::awaitable<acpp::RelayResult> Process(
        std::unique_ptr<acpp::AsyncStream>, acpp::routing::Dispatcher&,
        const acpp::proxyman::inbound::ReceiverSettings&,
        acpp::net::io_context&, acpp::session::Context&,
        const acpp::TimeoutsConfig&, uint32_t) override {
        co_return acpp::RelayResult{};
    }

    std::expected<acpp::InboundDatagramResult, acpp::ErrorCode> Process(
        const acpp::InboundDatagramRequest& request) override {
        if (request.payload.size() == 1 && request.payload[0] == 0x42) {
            acpp::InboundDatagramResult result;
            SetAuthenticatedResult(result);
            auto payload = acpp::buf::BufferGuard{acpp::buf::Buffer::New()};
            if (!payload) throw std::bad_alloc();
            payload->data[0] = 0x5a;
            payload->Produce(1);
            result.payload.push_back(std::move(payload));
            return result;
        }
        if (request.payload.size() > acpp::buf::Buffer::kSize &&
            request.payload[0] == 0x43) {
            return std::unexpected(acpp::ErrorCode::PROTOCOL_AUTH_FAILED);
        }
        if (request.payload.size() == 1 && request.payload[0] == 0x44) {
            acpp::InboundDatagramResult result;
            SetAuthenticatedResult(result);
            acpp::memory::reject_next_pmr_allocation = true;
            return result;
        }
        if (request.payload.size() == 1 && request.payload[0] == 0x45) {
            state_.after_processor_oom_processed = true;
        }
        if (request.payload.size() == 1 && request.payload[0] == 0x46) {
            state_.after_peer_error_processed = true;
        }
        return std::unexpected(acpp::ErrorCode::PROTOCOL_AUTH_FAILED);
    }

private:
    static void SetAuthenticatedResult(acpp::InboundDatagramResult& result) {
        const std::array<uint8_t, 1> owner{0x01};
        if (!result.session_owner.Assign(owner)) throw std::bad_alloc();
        result.response = std::make_shared<TestResponse>();
        result.target = acpp::TargetAddress(
            acpp::net::ip::address_v4::loopback(), 53);
    }

    TestState& state_;
};

class TestDispatcher final : public acpp::routing::Dispatcher {
public:
    explicit TestDispatcher(TestState& state) : state_(state) {}

    acpp::net::awaitable<acpp::RelayResult> Dispatch(
        acpp::net::io_context&, const acpp::routing::DispatchPolicy&,
        std::unique_ptr<acpp::AsyncStream>, acpp::transport::Link link,
        acpp::InitialPayload, acpp::session::Context&, acpp::StatsShard&,
        const acpp::TimeoutsConfig&) override {
        auto payload = co_await link.reader->ReadMultiBuffer();
        state_.dispatcher_payload_valid = payload.byte_size() == 1;
        for (const auto* buffer : payload) {
            state_.dispatcher_payload_valid =
                state_.dispatcher_payload_valid && buffer && buffer->Len() == 1 &&
                buffer->Bytes()[0] == 0x5a;
        }
        state_.dispatcher_completed = true;
        co_return acpp::RelayResult{};
    }

private:
    TestState& state_;
};

class TestReplySink final : public acpp::worker_detail::UdpReplySink {
public:
    bool EnqueueUdpReply(const std::string&, acpp::udp::socket*,
                         acpp::udp::endpoint, acpp::buf::MultiBuffer,
                         uint32_t) override {
        return false;
    }
};

bool EnableUdpConnectionResetNotifications(acpp::udp::socket& socket) noexcept {
#ifdef _WIN32
    BOOL enabled = TRUE;
    DWORD returned = 0;
    return ::WSAIoctl(
        socket.native_handle(), SIO_UDP_CONNRESET,
        &enabled, sizeof(enabled), nullptr, 0, &returned, nullptr, nullptr) == 0;
#else
    (void)socket;
    return true;
#endif
}

acpp::udp::endpoint LoopbackEndpoint() {
    return {acpp::net::ip::address_v4::loopback(), 0};
}

void Send(acpp::udp::socket& sender, const acpp::udp::endpoint& target,
          std::span<const uint8_t> payload) {
    acpp::IoErrorCode ec;
    sender.send_to(acpp::net::buffer(payload), target, 0, ec);
    if (ec) Fail("loopback UDP send failed");
}

struct Fixture {
    explicit Fixture(TargetedPmrResource& resource)
        : pmr(resource), reclaimer(acpp::TimeoutScheduler::ForIoContext(io)),
          receiver(std::make_shared<acpp::udp::socket>(io)),
          sender(io, acpp::udp::v4()), dispatcher(state) {
        acpp::IoErrorCode ec;
        receiver->open(acpp::udp::v4(), ec);
        if (ec) Fail("failed to open loopback receiver");
        receiver->bind(LoopbackEndpoint(), ec);
        if (ec) Fail("failed to bind loopback receiver");
        receiver->non_blocking(true, ec);
        if (ec) Fail("failed to enable socket non_blocking mode");
        target = receiver->local_endpoint(ec);
        if (ec) Fail("failed to query receiver endpoint");
        ingress = std::make_unique<acpp::worker_detail::UdpIngress>(
            "udp-test", std::unique_ptr<acpp::Inbound>(new TestInbound(state)), reclaimer,
            io);
        if (!ingress->AttachSocket(socket_key, receiver))
            Fail("failed to register loopback receiver with its real ingress owner");
        rejected_before = acpp::memory::rejected_pmr_allocations;
    }

    void StartReceive() {
        published_socket = receiver;
        acpp::net::co_spawn(
            io,
            acpp::worker_detail::RunUdpReceiveLoop(
                receiver,
                [this](const std::shared_ptr<acpp::udp::socket>& current) noexcept {
                    if (++ownership_checks == 2 && arm_small_buffer_fault) {
                        arm_small_buffer_fault = false;
                        acpp::memory::reject_next_pmr_allocation = true;
                    }
                    return current == published_socket;
                },
                [this](const acpp::udp::endpoint& peer,
                       std::span<const uint8_t> bytes) {
                    if (bytes.size() == kSuccessfulLargeBytes &&
                        std::all_of(bytes.begin(), bytes.end(),
                                    [](uint8_t byte) { return byte == 0x43; })) {
                        state.large_packet_processed = true;
                    }
                    ingress->ProcessDatagram(acpp::worker_detail::UdpDatagramContext{
                        .socket_key = socket_key,
                        .sock = receiver.get(),
                        .client_endpoint = peer,
                        .payload = bytes,
                        .receiver = &receiver_settings,
                        .io_context = io,
                        .dispatcher = dispatcher,
                        .stats = stats,
                        .timeouts = timeouts,
                        .worker_id = 0,
                        .reply_sink = reply_sink,
                    });
                },
                resource_drops),
            [this](std::exception_ptr error) {
                receive_error = error;
                receive_completed = true;
            });
    }

    static constexpr size_t kSuccessfulLargeBytes = acpp::buf::Buffer::kSize + 513;

    TargetedPmrResource& pmr;
    acpp::net::io_context io;
    acpp::worker_detail::UdpAssociationReclaimer reclaimer;
    std::shared_ptr<acpp::udp::socket> receiver;
    acpp::udp::socket sender;
    acpp::udp::endpoint target;
    TestState state;
    TestDispatcher dispatcher;
    TestReplySink reply_sink;
    acpp::proxyman::inbound::ReceiverSettings receiver_settings{
        .dispatch_policy = {.outbound = acpp::routing::ForceOutbound{"loopback"}}};
    acpp::StatsShard stats;
    acpp::TimeoutsConfig timeouts;
    std::unique_ptr<acpp::worker_detail::UdpIngress> ingress;
    const std::string socket_key = "loopback";
    std::shared_ptr<acpp::udp::socket> published_socket;
    uint64_t resource_drops = 0;
    size_t ownership_checks = 0;
    size_t rejected_before = 0;
    bool arm_small_buffer_fault = true;
    bool peer_icmp_observed = false;
    acpp::udp::endpoint closed_peer_endpoint;
    bool receive_completed = false;
    std::exception_ptr receive_error;
};

struct AsyncFaultCase {
    std::shared_ptr<acpp::udp::socket> socket;
    std::shared_ptr<acpp::udp::socket> published;
    size_t ownership_checks = 0;
    uint64_t resource_drops = 0;
    int injected_before = 0;
    int injected_at_completion = 0;
    bool fail_receive_initiation = false;
    bool armed = false;
    bool completed = false;
    std::exception_ptr error;
};

void StartAsyncFaultCase(Fixture& fixture, AsyncFaultCase& test,
                         bool fail_receive_initiation) {
    test.fail_receive_initiation = fail_receive_initiation;
    test.injected_before = async_allocation_test::injected;
    test.socket = std::make_shared<acpp::udp::socket>(fixture.io);
    acpp::IoErrorCode ec;
    test.socket->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open async-initiation fault socket");
    test.socket->bind(LoopbackEndpoint(), ec);
    if (ec) Fail("failed to bind async-initiation fault socket");
    test.socket->non_blocking(true, ec);
    if (ec) Fail("failed to set async-initiation fault socket nonblocking");
    test.published = test.socket;

    if (fail_receive_initiation) {
        const std::vector<uint8_t> payload(acpp::buf::Buffer::kSize + 128, 0x71);
        const auto endpoint = test.socket->local_endpoint(ec);
        if (ec) Fail("failed to query async-receive fault endpoint");
        Send(fixture.sender, endpoint, payload);
    }

    acpp::net::co_spawn(
        fixture.io,
        acpp::worker_detail::RunUdpReceiveLoop(
            test.socket,
            [&fixture, &test](
                const std::shared_ptr<acpp::udp::socket>& current) noexcept {
                ++test.ownership_checks;
                const size_t arm_check = test.fail_receive_initiation ? 2 : 1;
                if (test.ownership_checks == arm_check) {
                    test.armed = true;
                    if (test.fail_receive_initiation) {
                        fixture.pmr.arm_async_receive_after_large_prepare = true;
                    } else {
                        async_allocation_test::fail_after = 0;
                    }
                }
                return current == test.published;
            },
            [](const acpp::udp::endpoint&, std::span<const uint8_t>) {},
            test.resource_drops),
        [&test](std::exception_ptr error) {
            async_allocation_test::fail_after = -1;
            test.error = error;
            test.injected_at_completion = async_allocation_test::injected;
            test.completed = true;
        });
}

acpp::udp::endpoint MakeClosedPeer(Fixture& fixture) {
    acpp::udp::socket peer(fixture.io, acpp::udp::v4());
    acpp::IoErrorCode ec;
    peer.bind(LoopbackEndpoint(), ec);
    if (ec) Fail("failed to bind temporary closed UDP peer");
    const auto endpoint = peer.local_endpoint(ec);
    if (ec) Fail("failed to query temporary UDP peer endpoint");
    peer.close(ec);
    if (ec) Fail("failed to close temporary UDP peer");
    return endpoint;
}

bool ObserveClosedPeerIcmp(Fixture& fixture,
                           const acpp::udp::endpoint& peer) {
    if (!EnableUdpConnectionResetNotifications(*fixture.receiver)) return false;
    const std::array<uint8_t, 1> probe{0x7f};
    Send(*fixture.receiver, peer, probe);
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(500);
    std::array<uint8_t, 1> received{};
    while (std::chrono::steady_clock::now() < deadline) {
        acpp::udp::endpoint source;
        acpp::IoErrorCode ec;
        (void)fixture.receiver->receive_from(
            acpp::net::buffer(received), source, 0, ec);
        if (ec == acpp::io_error::connection_refused ||
            ec == acpp::io_error::connection_reset) {
            return true;
        }
        if (ec && ec != acpp::io_error::would_block &&
            ec != acpp::io_error::try_again && ec != acpp::io_error::interrupted) {
            Fail("unexpected error while probing UDP peer ICMP behavior");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}

template <class Predicate>
acpp::net::awaitable<void> WaitUntil(Fixture& fixture, Predicate predicate,
                                     std::string_view failure) {
    acpp::net::steady_timer timer(fixture.io);
    for (size_t attempt = 0; attempt < 500; ++attempt) {
        if (predicate()) co_return;
        timer.expires_after(std::chrono::milliseconds(10));
        co_await timer.async_wait(acpp::net::use_awaitable);
    }
    Fail(failure);
}

acpp::net::awaitable<void> VerifyAsyncInitiationFaults(Fixture& fixture) {
    for (bool fail_receive : std::array<bool, 2>{false, true}) {
        AsyncFaultCase test;
        StartAsyncFaultCase(fixture, test, fail_receive);
        co_await WaitUntil(fixture, [&test] { return test.completed; },
                           "injected Asio initiation fault did not complete the loop");
        bool caught_bad_alloc = false;
        try {
            if (test.error) std::rethrow_exception(test.error);
        } catch (const std::bad_alloc&) {
            caught_bad_alloc = true;
        }
        if (!test.armed || !caught_bad_alloc || test.resource_drops != 0 ||
            test.injected_at_completion != test.injected_before + 1 ||
            async_allocation_test::fail_after != -1 ||
            (fail_receive && test.ownership_checks < 2)) {
            Fail(fail_receive
                ? "async_receive_from initiation OOM was swallowed or misinjected"
                : "async_wait initiation OOM was swallowed or misinjected");
        }
        test.socket.reset();
        test.published.reset();
    }
    co_return;
}

acpp::net::awaitable<void> VerifyOwnedCancellation(Fixture& fixture) {
    auto socket = std::make_shared<acpp::udp::socket>(fixture.io);
    acpp::IoErrorCode ec;
    socket->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open owned-cancellation socket");
    socket->bind(LoopbackEndpoint(), ec);
    if (ec) Fail("failed to bind owned-cancellation socket");
    socket->non_blocking(true, ec);
    if (ec) Fail("failed to set owned-cancellation socket nonblocking");
    auto published = socket;
    size_t checks = 0;
    bool completed = false;
    std::exception_ptr completion_error;
    uint64_t drops = 0;
    acpp::net::co_spawn(
        fixture.io,
        acpp::worker_detail::RunUdpReceiveLoop(
            socket,
            [&published, &checks](
                const std::shared_ptr<acpp::udp::socket>& current) noexcept {
                ++checks;
                return current == published;
            },
            [](const acpp::udp::endpoint&, std::span<const uint8_t>) {},
            drops),
        [&completed, &completion_error](std::exception_ptr error) {
            completion_error = error;
            completed = true;
        });
    co_await WaitUntil(fixture, [&checks] { return checks >= 1; },
                       "owned-cancellation loop did not start");
    acpp::net::steady_timer settle(fixture.io);
    settle.expires_after(std::chrono::milliseconds(10));
    co_await settle.async_wait(acpp::net::use_awaitable);
    socket->cancel(ec);
    if (ec) Fail("failed to cancel owned socket");
    co_await WaitUntil(fixture, [&completed] { return completed; },
                       "owned cancellation did not complete");
    bool operation_aborted = false;
    try {
        if (completion_error) std::rethrow_exception(completion_error);
    } catch (const acpp::IoSystemError& error) {
        operation_aborted = error.code() == acpp::io_error::operation_aborted;
    }
    if (!operation_aborted) Fail("owned cancellation was not propagated");
    socket.reset();
    co_return;
}

acpp::net::awaitable<void> RunRegression(Fixture& fixture) {
    const std::vector<uint8_t> small_oom{0x41};
    const std::vector<uint8_t> oversized(acpp::buf::Buffer::kSize + 1024, 0x41);
    const std::vector<uint8_t> small_b{0x42};
    const std::vector<uint8_t> large_good(
        Fixture::kSuccessfulLargeBytes, 0x43);
    const std::vector<uint8_t> processor_oom{0x44};
    const std::vector<uint8_t> after_processor_oom{0x45};

    fixture.closed_peer_endpoint = MakeClosedPeer(fixture);
    fixture.peer_icmp_observed =
        ObserveClosedPeerIcmp(fixture, fixture.closed_peer_endpoint);

    fixture.StartReceive();
    Send(fixture.sender, fixture.target, small_oom);
    co_await WaitUntil(fixture, [&fixture] {
        return fixture.resource_drops == 1;
    }, "small Buffer::New OOM did not consume/drop one datagram");
    if (acpp::memory::rejected_pmr_allocations != fixture.rejected_before + 1) {
        Fail("small Buffer::New did not consume the targeted AllocatePmr fault");
    }

    fixture.pmr.fail_next_large = true;
    Send(fixture.sender, fixture.target, oversized);
    co_await WaitUntil(fixture, [&fixture] {
        return fixture.resource_drops == 2;
    }, "large PMR OOM did not consume/drop one datagram");
    if (fixture.pmr.failed_large != 1 ||
        acpp::memory::rejected_pmr_allocations != fixture.rejected_before + 2) {
        Fail("targeted large PMR allocation fault was not consumed");
    }

    Send(fixture.sender, fixture.target, small_b);
    co_await WaitUntil(fixture, [&fixture] {
        return fixture.state.dispatcher_completed;
    }, "successful datagram did not reach the real dispatcher path");
    if (!fixture.state.dispatcher_payload_valid) {
        Fail("dispatcher did not read the exact decoded datagram payload");
    }

    const auto large_frees_before = fixture.pmr.large_deallocations;
    Send(fixture.sender, fixture.target, large_good);
    co_await WaitUntil(fixture, [&fixture] {
        return fixture.state.large_packet_processed;
    }, "large datagram was truncated or not processed");
    // No subsequent packet may cause Prepare() to release this backing: the
    // production loop itself must free it before its next idle readiness wait.
    co_await WaitUntil(fixture, [&fixture, large_frees_before] {
        return fixture.pmr.large_deallocations > large_frees_before;
    }, "successful large receive backing was retained while idle");

    Send(fixture.sender, fixture.target, processor_oom);
    co_await WaitUntil(fixture, [&fixture] {
        return fixture.resource_drops == 3;
    }, "post-decode UdpIngress allocation failure was not contained");
    if (acpp::memory::reject_next_pmr_allocation ||
        acpp::memory::rejected_pmr_allocations != fixture.rejected_before + 3) {
        Fail("post-decode UdpIngress PMR fault did not hit the allocation hook");
    }

    Send(fixture.sender, fixture.target, after_processor_oom);
    co_await WaitUntil(fixture, [&fixture] {
        return fixture.state.after_processor_oom_processed;
    }, "receive loop did not continue after processor bad_alloc");

    acpp::net::steady_timer peer_settle(fixture.io);
    peer_settle.expires_after(std::chrono::milliseconds(25));
    co_await peer_settle.async_wait(acpp::net::use_awaitable);
    const std::array<uint8_t, 1> reply_to_closed_peer{0x7e};
    acpp::IoErrorCode peer_send_error;
    fixture.receiver->send_to(
        acpp::net::buffer(reply_to_closed_peer),
        fixture.closed_peer_endpoint, 0, peer_send_error);
    if (peer_send_error == acpp::io_error::connection_refused ||
        peer_send_error == acpp::io_error::connection_reset) {
        fixture.peer_icmp_observed = true;
    } else if (peer_send_error) {
        Fail("failed to send UDP datagram to closed peer");
    }
    peer_settle.expires_after(std::chrono::milliseconds(25));
    co_await peer_settle.async_wait(acpp::net::use_awaitable);
    const std::array<uint8_t, 1> after_peer_error{0x46};
    Send(fixture.sender, fixture.target, after_peer_error);
    co_await WaitUntil(fixture, [&fixture] {
        return fixture.state.after_peer_error_processed || fixture.receive_completed;
    }, "closed-peer follow-up datagram did not resolve");
    if (!fixture.state.after_peer_error_processed || fixture.receive_completed) {
        Fail("closed-peer UDP error retired the still-owned receive loop");
    }

    // Replace identity and retire the outstanding readiness wait on the owning thread.
    fixture.published_socket = std::make_shared<acpp::udp::socket>(fixture.io);
    acpp::IoErrorCode ec;
    fixture.receiver->cancel(ec);
    if (ec) Fail("failed to cancel retired socket");
    co_await WaitUntil(fixture, [&fixture] {
        return fixture.receive_completed;
    }, "retired receive loop did not complete");
    if (fixture.receive_error) {
        Fail("identity-replaced receive loop did not retire normally");
    }

    co_await VerifyAsyncInitiationFaults(fixture);
    co_await VerifyOwnedCancellation(fixture);
    fixture.ingress->RequestStop();
    co_return;
}

}  // namespace

int main() {
#ifndef CNODE_TEST_ALLOCATOR_FAULT
    Fail("CNODE_TEST_ALLOCATOR_FAULT must be enabled for this regression");
#else
    TargetedPmrResource pmr;
    auto* previous = std::pmr::set_default_resource(&pmr);
    {
        Fixture fixture(pmr);
        auto completed = acpp::net::co_spawn(
            fixture.io, RunRegression(fixture), acpp::net::use_future);
        fixture.io.run();
        completed.get();
        if (!fixture.peer_icmp_observed) {
            std::cout << "worker_udp_listener_oom_test: closed-peer ICMP was not observable on this platform; "
                         "the transient ICMP error branch remains unproven\n";
        }
    }
    std::pmr::set_default_resource(previous);
    return 0;
#endif
}
