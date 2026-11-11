#include <gtest/gtest.h>

#include "xhttp_session.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "app/session_group_executor.hpp"

#include <asio/co_spawn.hpp>
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

void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

template<class Predicate>
void RunUntil(net::io_context& io, Predicate predicate, const char* message) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!predicate() && std::chrono::steady_clock::now() < deadline) {
        io.restart();
        io.run_for(5ms);
    }
    Require(predicate(), message);
}

template<class Scenario>
void RunTableScenario(Scenario scenario) {
    ::memory::worker_memory pool;
    net::io_context io;
    bool done = false;
    std::exception_ptr failure;
    net::co_spawn(io, scenario(io, pool), [&](std::exception_ptr error) {
        failure = error;
        done = true;
    });
    RunUntil(io, [&] { return done; }, "session table scenario did not finish");
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> NamespaceAndRetirement(net::io_context& io, ::memory::worker_memory& pool) {
    auto first = co_await GetXHttpPacketSession(io, "inbound-a:g1", "same-id", XHttpSessionAccess::Open, pool);
    auto other = co_await GetXHttpPacketSession(io, "inbound-b:g1", "same-id", XHttpSessionAccess::Open, pool);
    auto replacement = co_await GetXHttpPacketSession(io, "inbound-a:g2", "same-id", XHttpSessionAccess::Open, pool);
    Require(first && other && replacement && first != other && first != replacement,
            "configuration namespaces shared a session");
    Require((co_await GetXHttpPacketSession(io, "inbound-a:g1", "same-id", XHttpSessionAccess::Join, pool)) == first,
            "same namespace failed to join");
    first->Close(); // still held by this test: retirement must not wait for weak expiration.
    Require(!(co_await GetXHttpPacketSession(io, "inbound-a:g1", "same-id", XHttpSessionAccess::Upload, pool)),
            "ended session accepted a replay");
    auto reopened = co_await GetXHttpPacketSession(io, "inbound-a:g1", "same-id", XHttpSessionAccess::Open, pool);
    Require(reopened && reopened != first, "explicit reopen did not replace tombstone");
    first.reset(); // must not retire the replacement generation.
    Require((co_await GetXHttpPacketSession(io, "inbound-a:g1", "same-id", XHttpSessionAccess::Join, pool)) == reopened,
            "old generation destructor retired new session");
    other->CloseInput();
    Require(!(co_await GetXHttpPacketSession(io, "inbound-b:g1", "same-id", XHttpSessionAccess::Join, pool)),
            "input EOF was not retired");
}

net::awaitable<void> StandaloneContextsDoNotShare(net::io_context& io, ::memory::worker_memory& pool) {
    net::io_context second_io;
    auto first = co_await GetXHttpPacketSession(io, "standalone", "same-id", XHttpSessionAccess::Open, pool);
    auto second = co_await GetXHttpPacketSession(
        second_io, "standalone", "same-id", XHttpSessionAccess::Open, pool);
    Require(first && second && first != second, "standalone io_context services shared a table");
    first->Close();
    Require((co_await GetXHttpPacketSession(
                second_io, "standalone", "same-id", XHttpSessionAccess::Upload, pool)) == second,
            "one standalone context retired another context's session");
}

net::awaitable<void> FullTableReclaimsOnEvents(net::io_context& io, ::memory::worker_memory& pool) {
    std::vector<std::shared_ptr<XHttpPacketUpSession>> active;
    active.reserve(1024);
    for (int n = 0; n != 1024; ++n) {
        auto session = co_await GetXHttpPacketSession(io, "capacity", std::to_string(n), XHttpSessionAccess::Open, pool);
        Require(bool(session), "table exhausted before active limit");
        active.push_back(std::move(session));
    }
    for (int n = 0; n != 64; ++n)
        Require(!(co_await GetXHttpPacketSession(io, "capacity", "overflow", XHttpSessionAccess::Open, pool)),
                "full table admitted an extra live session");
    active.front()->Close();
    auto next = co_await GetXHttpPacketSession(io, "capacity", "replacement", XHttpSessionAccess::Open, pool);
    Require(bool(next), "close did not free active capacity while session remained referenced");
    Require(!(co_await GetXHttpPacketSession(io, "capacity", "0", XHttpSessionAccess::Upload, pool)),
            "capacity pressure discarded a recent tombstone");
    active.back().reset();
    auto after_destroy = co_await GetXHttpPacketSession(io, "capacity", "after-destroy", XHttpSessionAccess::Upload, pool);
    Require(bool(after_destroy), "destruction did not free active capacity");
    active[1]->CloseInput();
    auto after_eof = co_await GetXHttpPacketSession(io, "capacity", "after-eof", XHttpSessionAccess::Open, pool);
    Require(bool(after_eof), "input EOF did not free active capacity");
}

net::awaitable<void> BoundedReplayWindow(net::io_context& io, ::memory::worker_memory& pool) {
    for (int n = 0; n != 1025; ++n) {
        auto session = co_await GetXHttpPacketSession(io, "replay", std::to_string(n), XHttpSessionAccess::Open, pool);
        Require(bool(session), "tombstones consumed live capacity");
        session->Close();
    }
    Require(!(co_await GetXHttpPacketSession(io, "replay", "1", XHttpSessionAccess::Upload, pool)),
            "recent tombstone was evicted too early");
    Require(!(co_await GetXHttpPacketSession(io, "replay", "1024", XHttpSessionAccess::Upload, pool)),
            "newest tombstone was evicted");
    auto oldest = co_await GetXHttpPacketSession(io, "replay", "0", XHttpSessionAccess::Upload, pool);
    Require(bool(oldest), "oldest tombstone was not bounded by FIFO eviction");
}

net::awaitable<void> DomainsJoinBySession(net::io_context& io, ::memory::worker_memory& pool) {
    auto coordinator = std::make_shared<::GroupCoordinator>(io);
    coordinator->RegisterWorker(1, io);
    auto scenario = [&]() -> net::awaitable<void> {
        auto first = co_await GetXHttpPacketSession(
            io, "group", "session-a", XHttpSessionAccess::Open, pool);
        auto other = co_await GetXHttpPacketSession(
            io, "group", "session-b", XHttpSessionAccess::Open, pool);
        Require(first && other && first != other,
                "unrelated sessions of one inbound were not independent");
        auto upload = co_await GetXHttpPacketSession(
            io, "group", "session-a", XHttpSessionAccess::Upload, pool);
        Require(upload == first,
                "upload did not resolve to the existing logical session");
        first->Close();
        auto replay = co_await GetXHttpPacketSession(
            io, "group", "session-a", XHttpSessionAccess::Upload, pool);
        Require(!replay,
                "retired upload recreated a session inside the replay window");
        auto reopened = co_await GetXHttpPacketSession(
            io, "group", "session-a", XHttpSessionAccess::Open, pool);
        Require(reopened && reopened != first,
                "explicit reopen did not claim a new session generation");
        upload.reset();
        first.reset();
        auto joined = co_await GetXHttpPacketSession(
            io, "group", "session-a", XHttpSessionAccess::Join, pool);
        Require(joined == reopened,
                "old session destruction retired the replacement generation");
        joined.reset();
        reopened.reset();
        other.reset();
        co_await BoundedReplayWindow(io, pool);
    };
    std::exception_ptr failure;
    try {
        co_await scenario();
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::post(io, net::use_awaitable);
    coordinator->CloseAdmission();
    co_await coordinator->AsyncJoin();
    coordinator->ReleaseServices();
    co_await coordinator->Finalize();
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
void UploadResponseIsDrained() {
    ::memory::worker_memory pool;
    net::io_context io;
    ::tcp::acceptor listener(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket client(io), peer(io);
    client.connect(listener.local_endpoint());
    listener.accept(peer);
    peer.non_blocking(true);
    peer.set_option(net::socket_base::send_buffer_size(4096));
    ::HttpConfig config;
    config.path = "/fixture/id";
    config.method = "POST";
    config.headers.emplace("Connection", "keep-alive");
    std::unique_ptr<::AsyncStream> upload;
    std::exception_ptr failure;
    bool built = false;
    const std::string initial = "first";
    const std::array<net::const_buffer, 1> payload{net::buffer(initial)};
    net::co_spawn(io, DoXHttp1ClientRequest(::memory::MakeUnique<::TcpStream>(pool, pool, std::move(client)),
        config, "localhost", ::XHttpClientRequestKind::StreamUp, payload, 0),
        [&](std::exception_ptr error, ::TransportBuildResult result) {
            failure = error;
            if (!error && result) upload = std::move(*result);
            built = true;
        });
    RunUntil(io, [&] { return built; }, "upload waited for response before becoming writable");
    if (failure) std::rethrow_exception(failure);
    Require(bool(upload), "upload handshake failed");
    const auto request = Receive(peer);
    Require(request.find("Connection: close\r\n") != std::string::npos &&
            request.find("keep-alive") == std::string::npos,
            "H1 stream-up did not force Xray-compatible Connection: close");
    Require(request.ends_with("5\r\nfirst\r\n"), "initial upload chunk missing");

    bool drained = false;
    net::co_spawn(io, [&]() -> net::awaitable<void> {
        const std::string head = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
        co_await net::async_write(peer, net::buffer(head), net::use_awaitable);
        const std::string padding(4096, 'X');
        for (int n = 0; n != 512; ++n)
            co_await net::async_write(peer, net::buffer(padding), net::use_awaitable);
    }, [&](std::exception_ptr error) { failure = error; drained = true; });
    RunUntil(io, [&] { return drained; }, "upload response padding blocked on unread receive window");
    if (failure) std::rethrow_exception(failure);
    Require(upload->IsOpen(), "padding closed upload prematurely");
    bool wrote = false;
    const std::string later = "second";
    net::co_spawn(io, upload->AsyncWrite(net::buffer(later)),
        [&](std::exception_ptr error, size_t n) {
            failure = error;
            wrote = n == later.size();
        });
    RunUntil(io, [&] { return wrote || failure; }, "upload stalled after draining response padding");
    if (failure) std::rethrow_exception(failure);
    Require(Receive(peer) == "6\r\nsecond\r\n", "later upload chunk was damaged");
    upload.reset();
    bool joined = false;
    net::co_spawn(io, JoinXHttpClientTasks(io), [&](std::exception_ptr error) {
        failure = error;
        joined = true;
    });
    RunUntil(io, [&] { return joined; }, "upload response reader was not joined at teardown");
    if (failure) std::rethrow_exception(failure);
}

void CrossWorkerUploadHandoffDoesNotEscapeOriginSink() {
    net::io_context control;
    auto worker0 = std::make_unique<net::io_context>();
    auto worker1 = std::make_unique<net::io_context>();
    auto work_c = net::make_work_guard(control);
    auto work_0 = std::make_optional(net::make_work_guard(*worker0));
    auto work_1 = std::make_optional(net::make_work_guard(*worker1));
    auto coordinator = std::make_shared<::GroupCoordinator>(control);
    coordinator->RegisterWorker(0, *worker0);
    coordinator->RegisterWorker(1, *worker1);

    std::thread thread_c([&] { control.run(); });
    ::memory::worker_memory* pool0 = nullptr;
    ::memory::worker_memory* pool1 = nullptr;
    std::thread thread_0([&] {
        ::memory::worker_memory pool;
        pool0 = &pool;
        worker0->run();
        worker0.reset();
    });
    std::thread thread_1([&] {
        ::memory::worker_memory pool;
        pool1 = &pool;
        worker1->run();
        worker1.reset();
    });

    struct OriginBoundSink final
        : ::memory::WorkerAllocated
        , ::InboundTransportStreamHandler {
        explicit OriginBoundSink(std::thread::id owner)
            : owner_thread(owner), local_tag(128, 'x') {}
        ~OriginBoundSink() noexcept override {
            if (std::this_thread::get_id() != owner_thread) std::terminate();
        }
        net::awaitable<void> OnInboundTransportStream(
            std::unique_ptr<::AsyncStream> s, ::InboundTransportMetadata) override {
            logical = std::move(s);
            co_return;
        }
        std::chrono::seconds TransportHandshakeTimeout() const noexcept override { return 5s; }
        std::chrono::seconds TransportIdleTimeout() const noexcept override { return 10s; }
        std::thread::id owner_thread;
        ::memory::String local_tag;
        std::unique_ptr<::AsyncStream> logical;
    };

    ::HttpConfig http_cfg;
    http_cfg.path = "/fixture";
    ::XHttpConfig xhttp_cfg;
    xhttp_cfg.path = "/fixture";
    xhttp_cfg.normalized_path = "/fixture/";
    xhttp_cfg.mode = ::XHttpMode::PacketUp;
    xhttp_cfg.session_namespace = "cross-worker-handoff";

    ::tcp::acceptor acceptor(control, {net::ip::address_v4::loopback(), 0});
    const auto endpoint = acceptor.local_endpoint();

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
                auto sink = ::memory::AllocateShared<OriginBoundSink>(pool1, std::this_thread::get_id());
                auto res = co_await DoXHttp1ServerHandshake(
                    *worker1, ::memory::MakeUnique<::TcpStream>(*pool1, *pool1, std::move(sock)),
                    http_cfg, xhttp_cfg, 1, nullptr, {}, sink);
                Require(res.has_value() && !*res, "packet-up handoff failed");
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
                auto sink = ::memory::AllocateShared<OriginBoundSink>(pool0, std::this_thread::get_id());
                auto res = co_await DoXHttp1ServerHandshake(
                    *worker0, ::memory::MakeUnique<::TcpStream>(*pool0, *pool0, std::move(sock)),
                    http_cfg, xhttp_cfg, 2, nullptr, {}, sink);
                Require(res.has_value() && !*res && sink->logical != nullptr,
                        "packet-down did not produce logical stream");
                std::array<char, 5> buf{};
                const size_t n = co_await sink->logical->AsyncRead(net::buffer(buf));
                Require(n == 5, "short read on logical stream");
                sink->logical->Close();
                co_return std::string(buf.data(), n);
            }, net::use_future);

        const std::string get_req =
            "GET /fixture/" + session_id + " HTTP/1.1\r\n"
            "Host: localhost\r\n\r\n";
        net::write(client_down, net::buffer(get_req));

        up_future.get();
        Require(down_future.get() == "hello", "mismatched payload after cross-worker handoff");
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
}
} // namespace

TEST(XhttpSessionLifecycle, Contract) {
    try {
        RunTableScenario(NamespaceAndRetirement);
        RunTableScenario(StandaloneContextsDoNotShare);
        RunTableScenario(FullTableReclaimsOnEvents);
        RunTableScenario(BoundedReplayWindow);
        RunTableScenario(DomainsJoinBySession);
        UploadResponseIsDrained();
        CrossWorkerUploadHandoffDoesNotEscapeOriginSink();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        FAIL() << error.what();
    }
}
