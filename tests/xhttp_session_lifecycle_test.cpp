#include "transport_coordinator_fixture.hpp"
#include <gtest/gtest.h>

#include "transport/xhttp_session.hpp"
#include "transport/tcp_stream.hpp"
#include "app/group_coordinator.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/post.hpp>
#include <asio/write.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/read.hpp>
#include <asio/use_future.hpp>
#include <thread>
#include <array>
#include <chrono>
#include <cstdio>
#include <exception>
#include <memory>
#include <future>
#include <list>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
namespace net = ::net;
using namespace ::transport;
using namespace std::chrono_literals;


template<class Predicate>
bool RunUntil(net::io_context& io, Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!predicate() && std::chrono::steady_clock::now() < deadline) {
        io.restart();
        io.run_for(5ms);
    }
    return predicate();
}

template<class Scenario>
void RunTableScenario(Scenario scenario) {
    net::io_context io;
    bool done = false;
    std::exception_ptr failure;
    net::cancellation_signal cancel;
    TransportCoordinatorFixture transport_coordinator{io};
    net::co_spawn(io, scenario(transport_coordinator.Coordinator(), io), net::bind_cancellation_slot(cancel.slot(),
        [&](std::exception_ptr error) {
            failure = error;
            done = true;
        }));
    const bool completed_before_cleanup = RunUntil(io, [&] { return done; });
    if (!done) cancel.emit(net::cancellation_type::terminal);
    io.restart();
    io.run();
    EXPECT_TRUE(completed_before_cleanup);
    EXPECT_TRUE(done);
    if (failure) std::rethrow_exception(failure);
}

// Single-Worker table checks: every resolution here is local.
net::awaitable<std::shared_ptr<XHttpPacketUpSession>> GetXHttpPacketSession(
    app::GroupCoordinator& coordinator, net::io_context& io,
    std::string_view session_namespace, std::string_view session_id,
    XHttpSessionAccess access) {
    co_return (co_await ResolveXHttpSession(
        coordinator, io, session_namespace, session_id, access)).session;
}

net::awaitable<void> NamespaceAndRetirement(app::GroupCoordinator& coordinator, net::io_context& io) {
    auto first = co_await GetXHttpPacketSession(coordinator, io, "inbound-a:g1", "same-id", XHttpSessionAccess::Open);
    auto other = co_await GetXHttpPacketSession(coordinator, io, "inbound-b:g1", "same-id", XHttpSessionAccess::Open);
    auto replacement = co_await GetXHttpPacketSession(coordinator, io, "inbound-a:g2", "same-id", XHttpSessionAccess::Open);
    EXPECT_TRUE(first);
    EXPECT_TRUE(other);
    EXPECT_TRUE(replacement);
    EXPECT_NE(first, other);
    EXPECT_NE(first, replacement);
    if (!first || !other || !replacement) co_return;
    EXPECT_EQ((co_await GetXHttpPacketSession(coordinator, io, "inbound-a:g1", "same-id", XHttpSessionAccess::Join)), first) << "same namespace failed to join";
    first->Close(); // still held by this test: retirement must not wait for weak expiration.
    EXPECT_FALSE((co_await GetXHttpPacketSession(coordinator, io, "inbound-a:g1", "same-id", XHttpSessionAccess::Upload))) << "ended session accepted a replay";
    auto reopened = co_await GetXHttpPacketSession(coordinator, io, "inbound-a:g1", "same-id", XHttpSessionAccess::Open);
    EXPECT_TRUE(reopened);
    EXPECT_NE(reopened, first);
    first.reset(); // must not retire the replacement generation.
    EXPECT_EQ((co_await GetXHttpPacketSession(coordinator, io, "inbound-a:g1", "same-id", XHttpSessionAccess::Join)), reopened) << "old generation destructor retired new session";
    other->CloseInput();
    EXPECT_FALSE((co_await GetXHttpPacketSession(coordinator, io, "inbound-b:g1", "same-id", XHttpSessionAccess::Join))) << "input EOF was not retired";
}

net::awaitable<void> FullTableReclaimsOnEvents(app::GroupCoordinator& coordinator, net::io_context& io) {
    std::vector<std::shared_ptr<XHttpPacketUpSession>> active;
    active.reserve(1024);
    for (int n = 0; n != 1024; ++n) {
        auto session = co_await GetXHttpPacketSession(coordinator, io, "capacity", std::to_string(n), XHttpSessionAccess::Open);
        EXPECT_TRUE(bool(session)) << "table exhausted before active limit";
        if (!session) co_return;
        active.push_back(std::move(session));
    }
    for (int n = 0; n != 64; ++n)
        EXPECT_FALSE((co_await GetXHttpPacketSession(coordinator, io, "capacity", "overflow", XHttpSessionAccess::Open))) << "full table admitted an extra live session";
    active.front()->Close();
    auto next = co_await GetXHttpPacketSession(coordinator, io, "capacity", "replacement", XHttpSessionAccess::Open);
    EXPECT_TRUE(bool(next)) << "close did not free active capacity while session remained referenced";
    EXPECT_FALSE((co_await GetXHttpPacketSession(coordinator, io, "capacity", "0", XHttpSessionAccess::Upload))) << "capacity pressure discarded a recent tombstone";
    active.back().reset();
    auto after_destroy = co_await GetXHttpPacketSession(coordinator, io, "capacity", "after-destroy", XHttpSessionAccess::Upload);
    EXPECT_TRUE(bool(after_destroy)) << "destruction did not free active capacity";
    active[1]->CloseInput();
    auto after_eof = co_await GetXHttpPacketSession(coordinator, io, "capacity", "after-eof", XHttpSessionAccess::Open);
    EXPECT_TRUE(bool(after_eof)) << "input EOF did not free active capacity";
}

net::awaitable<void> BoundedReplayWindow(app::GroupCoordinator& coordinator, net::io_context& io) {
    for (int n = 0; n != 1025; ++n) {
        auto session = co_await GetXHttpPacketSession(coordinator, io, "replay", std::to_string(n), XHttpSessionAccess::Open);
        EXPECT_TRUE(bool(session)) << "tombstones consumed live capacity";
        if (!session) co_return;
        session->Close();
    }
    EXPECT_FALSE((co_await GetXHttpPacketSession(coordinator, io, "replay", "1", XHttpSessionAccess::Upload))) << "recent tombstone was evicted too early";
    EXPECT_FALSE((co_await GetXHttpPacketSession(coordinator, io, "replay", "1024", XHttpSessionAccess::Upload))) << "newest tombstone was evicted";
    auto oldest = co_await GetXHttpPacketSession(coordinator, io, "replay", "0", XHttpSessionAccess::Upload);
    EXPECT_TRUE(bool(oldest)) << "oldest tombstone was not bounded by FIFO eviction";
}

net::awaitable<void> DomainsJoinBySession(app::GroupCoordinator& coordinator, net::io_context& io) {
    auto scenario = [&]() -> net::awaitable<void> {
        auto first = co_await GetXHttpPacketSession(coordinator, 
            io, "group", "session-a", XHttpSessionAccess::Open);
        auto other = co_await GetXHttpPacketSession(coordinator, 
            io, "group", "session-b", XHttpSessionAccess::Open);
        EXPECT_TRUE(first);
        EXPECT_TRUE(other);
        EXPECT_NE(first, other);
        if (!first || !other) co_return;
        auto upload = co_await GetXHttpPacketSession(coordinator, 
            io, "group", "session-a", XHttpSessionAccess::Upload);
        EXPECT_EQ(upload, first) << "upload did not resolve to the existing logical session";
        first->Close();
        auto replay = co_await GetXHttpPacketSession(coordinator, 
            io, "group", "session-a", XHttpSessionAccess::Upload);
        EXPECT_FALSE(replay) << "retired upload recreated a session inside the replay window";
        auto reopened = co_await GetXHttpPacketSession(coordinator, 
            io, "group", "session-a", XHttpSessionAccess::Open);
        EXPECT_TRUE(reopened);
        EXPECT_NE(reopened, first);
        upload.reset();
        first.reset();
        auto joined = co_await GetXHttpPacketSession(coordinator, 
            io, "group", "session-a", XHttpSessionAccess::Join);
        EXPECT_EQ(joined, reopened) << "old session destruction retired the replacement generation";
        joined.reset();
        reopened.reset();
        other.reset();
        co_await BoundedReplayWindow(coordinator, io);
    };
    std::exception_ptr failure;
    try {
        co_await scenario();
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    co_await net::this_coro::throw_if_cancelled(false);
    co_await net::post(io, net::use_awaitable);
    if (failure) std::rethrow_exception(failure);
}

std::string Receive(::tcp::socket& socket) {
    std::string bytes;
    std::array<char, 8192> buffer;
    for (;;) {
        ::IoErrorCode ec;
        const auto n = socket.read_some(net::buffer(buffer), ec);
        if (ec) break;
        bytes.append(buffer.data(), n);
    }
    return bytes;
}

// Exercise the actual H1 client and TCP transport, including no response yet,
// forced close despite a configured keep-alive, response padding beyond the
// peer send buffer, and cancellation of a reader still waiting for padding.
TEST(XhttpSessionLifecycle, UploadResponseDrainPreservesWritesAndJoinsReaderOnClose) {
    net::io_context io;
    ::tcp::acceptor listener(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket client(io), peer(io);
    client.connect(listener.local_endpoint());
    listener.accept(peer);
    peer.non_blocking(true);
    peer.set_option(net::socket_base::send_buffer_size(4096));
    ::transport::HttpConfig config;
    config.path = "/fixture/id";
    config.method = "POST";
    config.headers.emplace("Connection", "keep-alive");
    std::unique_ptr<::transport::AsyncStream> upload;
    std::exception_ptr failure;
    bool built = false;
    const std::string initial = "first";
    const std::array<net::const_buffer, 1> payload{net::buffer(initial)};
    net::co_spawn(io, DoXHttp1ClientRequest(std::make_unique<::transport::TcpStream>(std::move(client)),
        ::transport::HttpClientRequestView::FromConfig(config), "localhost", ::transport::XHttpClientRequestKind::StreamUp, payload, 0),
        [&](std::exception_ptr error, ::transport::TransportBuildResult result) {
            failure = error;
            if (!error && result) upload = std::move(*result);
            built = true;
        });
    bool drained = false;
    bool wrote = false;
    const std::string later = "second";
    auto scenario = [&] {
        ASSERT_TRUE(RunUntil(io, [&] { return built; }));
        if (failure) std::rethrow_exception(failure);
        ASSERT_TRUE(upload);
        const auto request = Receive(peer);
        EXPECT_NE(request.find("Connection: close\r\n"), std::string::npos);
        EXPECT_EQ(request.find("keep-alive"), std::string::npos);
        EXPECT_TRUE(request.ends_with("5\r\nfirst\r\n"));

        net::co_spawn(io, [&]() -> net::awaitable<void> {
            const std::string head = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
            co_await net::async_write(peer, net::buffer(head), net::use_awaitable);
            const std::string padding(4096, 'X');
            for (int n = 0; n != 512; ++n)
                co_await net::async_write(peer, net::buffer(padding), net::use_awaitable);
        }, [&](std::exception_ptr error) { failure = error; drained = true; });
        ASSERT_TRUE(RunUntil(io, [&] { return drained; }));
        if (failure) std::rethrow_exception(failure);
        EXPECT_TRUE(upload->IsOpen());
        net::co_spawn(io, upload->AsyncWrite(net::buffer(later)),
            [&](std::exception_ptr error, size_t n) {
                failure = error;
                wrote = n == later.size();
            });
        ASSERT_TRUE(RunUntil(io, [&] { return wrote || failure; }));
        if (failure) std::rethrow_exception(failure);
        EXPECT_EQ(Receive(peer), "6\r\nsecond\r\n");
    };
    std::exception_ptr scenario_failure;
    try {
        scenario();
    } catch (...) {
        scenario_failure = std::current_exception();
    }
    upload.reset();
    peer.close();
    bool joined = false;
    net::co_spawn(io, JoinXHttpClientTasks(io), [&](std::exception_ptr error) {
        failure = error;
        joined = true;
    });
    io.restart();
    io.run();
    EXPECT_TRUE(joined);
    if (scenario_failure) std::rethrow_exception(scenario_failure);
    if (failure) std::rethrow_exception(failure);
}

// A session's requests arrive on connections accepted by different Workers.
// The connection that reaches a non-owner moves whole to the owner, which
// serves it with a handler adopted there; sinks never cross threads.
TEST(XhttpSessionLifecycle, CrossWorkerRequestMovesConnectionToSessionOwner) {
    net::io_context control;
    auto worker0 = std::make_unique<net::io_context>();
    auto worker1 = std::make_unique<net::io_context>();
    auto work_c = net::make_work_guard(control);
    auto work_0 = std::make_optional(net::make_work_guard(*worker0));
    auto work_1 = std::make_optional(net::make_work_guard(*worker1));
    auto coordinator = std::make_shared<::app::GroupCoordinator>(control);
    coordinator->RegisterWorker();
    coordinator->RegisterWorker();

    std::promise<std::thread::id> started_0, started_1;
    std::thread thread_c([&] { control.run(); });
    std::thread thread_0([&] {
        started_0.set_value(std::this_thread::get_id());
        worker0->run();
        worker0.reset();
    });
    std::thread thread_1([&] {
        started_1.set_value(std::this_thread::get_id());
        worker1->run();
        worker1.reset();
    });
    std::map<net::io_context*, std::thread::id> threads{
        {worker0.get(), started_0.get_future().get()},
        {worker1.get(), started_1.get_future().get()},
    };

    struct Delivery {
        std::thread::id thread;
        std::string bytes;
    };
    struct MovingSink final : ::transport::InboundTransportStreamHandler {
        MovingSink(std::thread::id thread,
                   const std::map<net::io_context*, std::thread::id>& threads,
                   std::promise<Delivery>& delivery)
            : thread(thread), threads(threads), delivery(delivery) {}
        ~MovingSink() noexcept override {
            EXPECT_EQ(std::this_thread::get_id(), thread);
        }
        net::awaitable<void> OnInboundTransportStream(
            std::unique_ptr<::transport::AsyncStream> stream,
            ::transport::InboundTransportMetadata) override {
            std::array<char, 5> buffer{};
            const size_t n = co_await stream->AsyncRead(net::buffer(buffer));
            stream->Close();
            delivery.set_value({std::this_thread::get_id(), std::string(buffer.data(), n)});
        }
        std::shared_ptr<::transport::InboundTransportStreamHandler> AdoptOn(
            net::io_context& owner) const override {
            EXPECT_EQ(std::this_thread::get_id(), threads.at(&owner));
            return std::make_shared<MovingSink>(threads.at(&owner), threads, delivery);
        }
        std::thread::id thread;
        const std::map<net::io_context*, std::thread::id>& threads;
        std::promise<Delivery>& delivery;
    };

    ::transport::StreamSettings settings;
    settings.network_mode = ::transport::NetworkMode::XHttp;
    settings.xhttp.path = "/fixture";
    settings.xhttp.mode = ::transport::XHttpMode::PacketUp;
    settings = ::transport::NormalizeStreamSettings(settings);
    settings.xhttp.session_namespace = "cross-worker-move";

    ::tcp::acceptor acceptor(control, {net::ip::address_v4::loopback(), 0});
    const auto endpoint = acceptor.local_endpoint();
    const auto serve = [&](net::io_context& io, ::tcp::socket socket,
                           std::promise<Delivery>& delivery) {
        return net::co_spawn(io,
            [&, socket = std::move(socket)]() mutable -> net::awaitable<int> {
                auto sink = std::make_shared<MovingSink>(threads.at(&io), threads, delivery);
                auto built = co_await ::transport::BuildInboundTransport(*coordinator, io,
                    std::make_unique<::transport::TcpStream>(std::move(socket)),
                    settings, nullptr, 0, std::move(sink));
                if (!built) co_return static_cast<int>(built.error());
                co_return *built ? -1 : 0;
            }, net::use_future);
    };
    const auto wait_owner = [&](const std::string& session_id) {
        for (int attempt = 0; attempt != 300; ++attempt) {
            auto owner = net::co_spawn(control, ::transport::FindXHttpSessionOwner(
                *coordinator, settings.xhttp.session_namespace, session_id),
                net::use_future).get();
            if (owner) return owner;
            std::this_thread::sleep_for(10ms);
        }
        return static_cast<net::io_context*>(nullptr);
    };

    // Sinks may outlive a failed round; their promises outlive the scenario.
    std::list<std::promise<Delivery>> deliveries;
    std::exception_ptr scenario_failure;
    try {
    for (int round = 0; round < 8; ++round) {
        const std::string session_id = "s-" + std::to_string(round);
        // Even rounds: the upload on Worker 1 owns the session and the
        // downlink moves there. Odd rounds: the reverse.
        const bool upload_first = round % 2 == 0;
        auto& upload_io = *worker1;
        auto& downlink_io = *worker0;
        auto& delivery = deliveries.emplace_back();
        auto delivered = delivery.get_future();

        ::tcp::socket client_up(control), server_up(upload_io);
        client_up.connect(endpoint);
        acceptor.accept(server_up);
        ::tcp::socket client_down(control), server_down(downlink_io);
        client_down.connect(endpoint);
        acceptor.accept(server_down);
        auto up_built = serve(upload_io, std::move(server_up), delivery);
        auto down_built = serve(downlink_io, std::move(server_down), delivery);

        const std::string post =
            "POST /fixture/" + session_id + "/0 HTTP/1.1\r\n"
            "Host: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
        const std::string get =
            "GET /fixture/" + session_id + " HTTP/1.1\r\nHost: localhost\r\n\r\n";
        net::write(upload_first ? client_up : client_down,
                   net::buffer(upload_first ? post : get));
        auto* owner = wait_owner(session_id);
        EXPECT_EQ(owner, upload_first ? &upload_io : &downlink_io);
        net::write(upload_first ? client_down : client_up,
                   net::buffer(upload_first ? get : post));

        if (delivered.wait_for(5s) != std::future_status::ready) {
            ADD_FAILURE() << "no logical stream reached the session owner in round " << round;
            break;
        }
        const auto received = delivered.get();
        EXPECT_EQ(received.bytes, "hello");
        EXPECT_EQ(received.thread, threads.at(owner));
        const auto response = Receive(client_up);
        EXPECT_TRUE(response.starts_with("HTTP/1.1 200"))
            << "round " << round << " upload response: " << response;
        EXPECT_EQ(up_built.get(), 0) << "round " << round;
        EXPECT_EQ(down_built.get(), 0) << "round " << round;
    }
    } catch (...) {
        scenario_failure = std::current_exception();
    }

    auto stop_future = net::co_spawn(control, [&]() -> net::awaitable<void> {
        coordinator->CloseAdmission();
        co_await coordinator->AsyncJoin();
        coordinator->ReleaseServices();
        co_await coordinator->Finalize();
    }, net::use_future);
    stop_future.get();
    coordinator.reset();
    work_0.reset();
    work_1.reset();
    work_c.reset();
    thread_0.join();
    thread_1.join();
    thread_c.join();
    if (scenario_failure) std::rethrow_exception(scenario_failure);
}
} // namespace

TEST(XhttpSessionLifecycle, NamespaceIsolationAndRetirementProtectReplacementGeneration) {
    RunTableScenario(NamespaceAndRetirement);
}

TEST(XhttpSessionLifecycle, CloseDestructionAndEofReturnFullTableCapacity) {
    RunTableScenario(FullTableReclaimsOnEvents);
}

TEST(XhttpSessionLifecycle, ReplayTombstonesHaveBoundedFifoLifetime) {
    RunTableScenario(BoundedReplayWindow);
}

TEST(XhttpSessionLifecycle, CoordinatorJoinsBySessionAndRetiresOnlyCurrentGeneration) {
    RunTableScenario(DomainsJoinBySession);
}
