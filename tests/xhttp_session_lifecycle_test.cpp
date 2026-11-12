#include "transport_coordinator_fixture.hpp"
#include <gtest/gtest.h>

#include "transport/internet/xhttp_session.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "app/session_group_executor.hpp"

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
#include <stdexcept>
#include <string>
#include <vector>

namespace {
namespace net = ::net;
using namespace ::transport::internet;
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
    ::transport::internet::HttpConfig config;
    config.path = "/fixture/id";
    config.method = "POST";
    config.headers.emplace("Connection", "keep-alive");
    std::unique_ptr<::transport::AsyncStream> upload;
    std::exception_ptr failure;
    bool built = false;
    const std::string initial = "first";
    const std::array<net::const_buffer, 1> payload{net::buffer(initial)};
    net::co_spawn(io, DoXHttp1ClientRequest(std::make_unique<::transport::internet::TcpStream>(std::move(client)),
        config, "localhost", ::transport::internet::XHttpClientRequestKind::StreamUp, payload, 0),
        [&](std::exception_ptr error, ::transport::internet::TransportBuildResult result) {
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

TEST(XhttpSessionLifecycle, CrossWorkerUploadHandoffKeepsSinkOnOriginUntilRetirement) {
    net::io_context control;
    auto worker0 = std::make_unique<net::io_context>();
    auto worker1 = std::make_unique<net::io_context>();
    auto work_c = net::make_work_guard(control);
    auto work_0 = std::make_optional(net::make_work_guard(*worker0));
    auto work_1 = std::make_optional(net::make_work_guard(*worker1));
    auto coordinator = std::make_shared<::app::GroupCoordinator>(control);
    coordinator->RegisterWorker(*worker0);
    coordinator->RegisterWorker(*worker1);

    std::thread thread_c([&] { control.run(); });
    std::thread thread_0([&] {
        worker0->run();
        worker0.reset();
    });
    std::thread thread_1([&] {
        worker1->run();
        worker1.reset();
    });

    struct OriginBoundSink final : ::transport::internet::InboundTransportStreamHandler {
        explicit OriginBoundSink(std::thread::id owner)
            : owner_thread(owner), local_tag(128, 'x', ::memory::process_resource()) {}
        ~OriginBoundSink() noexcept override {
            EXPECT_EQ(std::this_thread::get_id(), owner_thread);
        }
        net::awaitable<void> OnInboundTransportStream(
            std::unique_ptr<::transport::AsyncStream> s, ::transport::internet::InboundTransportMetadata) override {
            logical = std::move(s);
            co_return;
        }
        std::chrono::seconds TransportHandshakeTimeout() const noexcept override { return 5s; }
        std::chrono::seconds TransportIdleTimeout() const noexcept override { return 10s; }
        std::thread::id owner_thread;
        std::pmr::string local_tag;
        std::unique_ptr<::transport::AsyncStream> logical;
    };

    ::transport::internet::HttpConfig http_cfg;
    http_cfg.path = "/fixture";
    ::transport::internet::XHttpConfig xhttp_cfg;
    xhttp_cfg.path = "/fixture";
    xhttp_cfg.normalized_path = "/fixture/";
    xhttp_cfg.mode = ::transport::internet::XHttpMode::PacketUp;
    xhttp_cfg.session_namespace = "cross-worker-handoff";

    ::tcp::acceptor acceptor(control, {net::ip::address_v4::loopback(), 0});
    const auto endpoint = acceptor.local_endpoint();

    std::exception_ptr scenario_failure;
    try {
    for (int round = 0; round < 16; ++round) {
        const std::string session_id = "s-" + std::to_string(round);
        ::tcp::socket client_up(control), server_up(*worker1);
        client_up.connect(endpoint);
        acceptor.accept(server_up);

        ::tcp::socket client_down(control), server_down(*worker0);
        client_down.connect(endpoint);
        acceptor.accept(server_down);

        // Start PacketUp on worker1 before PacketDown arrives on worker0 on even rounds.
        auto up_future = net::co_spawn(*worker1,
            [&, sock = std::move(server_up)]() mutable -> net::awaitable<void> {
                auto sink = std::make_shared<OriginBoundSink>(std::this_thread::get_id());
                auto res = co_await DoXHttp1ServerHandshake(
                    *coordinator,                     *worker1, std::make_unique<::transport::internet::TcpStream>(std::move(sock)),
                    http_cfg, xhttp_cfg, 1, nullptr, {}, sink);
                EXPECT_TRUE(res.has_value() && !*res) << "packet-up handoff failed";
            }, net::use_future);

        const std::string post_req =
            "POST /fixture/" + session_id + "/0 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Length: 5\r\n"
            "Connection: close\r\n\r\n"
            "hello";
        net::write(client_up, net::buffer(post_req));

        auto down_future = net::co_spawn(*worker0,
            [&, sock = std::move(server_down)]() mutable -> net::awaitable<std::string> {
                auto sink = std::make_shared<OriginBoundSink>(std::this_thread::get_id());
                auto res = co_await DoXHttp1ServerHandshake(
                    *coordinator,                     *worker0, std::make_unique<::transport::internet::TcpStream>(std::move(sock)),
                    http_cfg, xhttp_cfg, 2, nullptr, {}, sink);
                EXPECT_TRUE(res.has_value() && !*res && sink->logical != nullptr) << "packet-down did not produce logical stream";
                if (!sink->logical) co_return std::string{};
                std::array<char, 5> buf{};
                const size_t n = co_await sink->logical->AsyncRead(net::buffer(buf));
                EXPECT_EQ(n, 5) << "short read on logical stream";
                sink->logical->Close();
                co_return std::string(buf.data(), n);
            }, net::use_future);

        const std::string get_req =
            "GET /fixture/" + session_id + " HTTP/1.1\r\n"
            "Host: localhost\r\n\r\n";
        net::write(client_down, net::buffer(get_req));

        std::exception_ptr up_error, down_error;
        std::string received;
        try { up_future.get(); } catch (...) { up_error = std::current_exception(); }
        try { received = down_future.get(); } catch (...) { down_error = std::current_exception(); }
        EXPECT_FALSE(up_error);
        EXPECT_FALSE(down_error);
        EXPECT_EQ(received, "hello");
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
