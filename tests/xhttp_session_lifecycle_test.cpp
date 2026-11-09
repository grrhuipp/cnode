#include <gtest/gtest.h>

#include "xhttp_session.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "app/session_group_executor.hpp"

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/write.hpp>
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
    net::io_context io;
    bool done = false;
    std::exception_ptr failure;
    net::co_spawn(io, scenario(io), [&](std::exception_ptr error) {
        failure = error;
        done = true;
    });
    RunUntil(io, [&] { return done; }, "session table scenario did not finish");
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> NamespaceAndRetirement(net::io_context& io) {
    auto first = co_await GetXHttpPacketSession(io, "inbound-a:g1", "same-id", XHttpSessionAccess::Open);
    auto other = co_await GetXHttpPacketSession(io, "inbound-b:g1", "same-id", XHttpSessionAccess::Open);
    auto replacement = co_await GetXHttpPacketSession(io, "inbound-a:g2", "same-id", XHttpSessionAccess::Open);
    Require(first && other && replacement && first != other && first != replacement,
            "configuration namespaces shared a session");
    Require((co_await GetXHttpPacketSession(io, "inbound-a:g1", "same-id", XHttpSessionAccess::Join)) == first,
            "same namespace failed to join");
    first->Close(); // still held by this test: retirement must not wait for weak expiration.
    Require(!(co_await GetXHttpPacketSession(io, "inbound-a:g1", "same-id", XHttpSessionAccess::Upload)),
            "ended session accepted a replay");
    auto reopened = co_await GetXHttpPacketSession(io, "inbound-a:g1", "same-id", XHttpSessionAccess::Open);
    Require(reopened && reopened != first, "explicit reopen did not replace tombstone");
    first.reset(); // must not retire the replacement generation.
    Require((co_await GetXHttpPacketSession(io, "inbound-a:g1", "same-id", XHttpSessionAccess::Join)) == reopened,
            "old generation destructor retired new session");
    other->CloseInput();
    Require(!(co_await GetXHttpPacketSession(io, "inbound-b:g1", "same-id", XHttpSessionAccess::Join)),
            "input EOF was not retired");
}

net::awaitable<void> StandaloneContextsDoNotShare(net::io_context& io) {
    net::io_context second_io;
    auto first = co_await GetXHttpPacketSession(io, "standalone", "same-id", XHttpSessionAccess::Open);
    auto second = co_await GetXHttpPacketSession(
        second_io, "standalone", "same-id", XHttpSessionAccess::Open);
    Require(first && second && first != second, "standalone io_context services shared a table");
    first->Close();
    Require((co_await GetXHttpPacketSession(
                second_io, "standalone", "same-id", XHttpSessionAccess::Upload)) == second,
            "one standalone context retired another context's session");
}

net::awaitable<void> FullTableReclaimsOnEvents(net::io_context& io) {
    std::vector<std::shared_ptr<XHttpPacketUpSession>> active;
    active.reserve(1024);
    for (int n = 0; n != 1024; ++n) {
        auto session = co_await GetXHttpPacketSession(io, "capacity", std::to_string(n), XHttpSessionAccess::Open);
        Require(bool(session), "table exhausted before active limit");
        active.push_back(std::move(session));
    }
    for (int n = 0; n != 64; ++n)
        Require(!(co_await GetXHttpPacketSession(io, "capacity", "overflow", XHttpSessionAccess::Open)),
                "full table admitted an extra live session");
    active.front()->Close();
    auto next = co_await GetXHttpPacketSession(io, "capacity", "replacement", XHttpSessionAccess::Open);
    Require(bool(next), "close did not free active capacity while session remained referenced");
    Require(!(co_await GetXHttpPacketSession(io, "capacity", "0", XHttpSessionAccess::Upload)),
            "capacity pressure discarded a recent tombstone");
    active.back().reset();
    auto after_destroy = co_await GetXHttpPacketSession(io, "capacity", "after-destroy", XHttpSessionAccess::Upload);
    Require(bool(after_destroy), "destruction did not free active capacity");
    active[1]->CloseInput();
    auto after_eof = co_await GetXHttpPacketSession(io, "capacity", "after-eof", XHttpSessionAccess::Open);
    Require(bool(after_eof), "input EOF did not free active capacity");
}

net::awaitable<void> BoundedReplayWindow(net::io_context& io) {
    for (int n = 0; n != 1025; ++n) {
        auto session = co_await GetXHttpPacketSession(io, "replay", std::to_string(n), XHttpSessionAccess::Open);
        Require(bool(session), "tombstones consumed live capacity");
        session->Close();
    }
    Require(!(co_await GetXHttpPacketSession(io, "replay", "1", XHttpSessionAccess::Upload)),
            "recent tombstone was evicted too early");
    Require(!(co_await GetXHttpPacketSession(io, "replay", "1024", XHttpSessionAccess::Upload)),
            "newest tombstone was evicted");
    auto oldest = co_await GetXHttpPacketSession(io, "replay", "0", XHttpSessionAccess::Upload);
    Require(bool(oldest), "oldest tombstone was not bounded by FIFO eviction");
}

net::awaitable<void> DomainsJoinBySession(net::io_context& io) {
    auto coordinator = std::make_shared<::GroupCoordinator>(io);
    coordinator->RegisterWorker(1, io, io.get_executor());
    auto scenario = [&]() -> net::awaitable<void> {
        auto first = co_await GetXHttpPacketSession(
            io, "group", "session-a", XHttpSessionAccess::Open);
        auto other = co_await GetXHttpPacketSession(
            io, "group", "session-b", XHttpSessionAccess::Open);
        Require(first && other && first != other,
                "unrelated sessions of one inbound were not independent");
        auto upload = co_await GetXHttpPacketSession(
            io, "group", "session-a", XHttpSessionAccess::Upload);
        Require(upload == first,
                "upload did not resolve to the existing logical session");
        first->Close();
        auto replay = co_await GetXHttpPacketSession(
            io, "group", "session-a", XHttpSessionAccess::Upload);
        Require(!replay,
                "retired upload recreated a session inside the replay window");
        auto reopened = co_await GetXHttpPacketSession(
            io, "group", "session-a", XHttpSessionAccess::Open);
        Require(reopened && reopened != first,
                "explicit reopen did not claim a new session generation");
        upload.reset();
        first.reset();
        auto joined = co_await GetXHttpPacketSession(
            io, "group", "session-a", XHttpSessionAccess::Join);
        Require(joined == reopened,
                "old session destruction retired the replacement generation");
        joined.reset();
        reopened.reset();
        other.reset();
        co_await BoundedReplayWindow(io);
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
    net::co_spawn(io, DoXHttp1ClientRequest(std::make_unique<::TcpStream>(std::move(client)),
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
} // namespace

TEST(XhttpSessionLifecycle, Contract) {
    try {
        RunTableScenario(NamespaceAndRetirement);
        RunTableScenario(StandaloneContextsDoNotShare);
        RunTableScenario(FullTableReclaimsOnEvents);
        RunTableScenario(BoundedReplayWindow);
        RunTableScenario(DomainsJoinBySession);
        UploadResponseIsDrained();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "%s\n", error.what());
        FAIL() << error.what();
    }
}
