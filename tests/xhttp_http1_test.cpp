#include <gtest/gtest.h>

#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/transport_stack.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/write.hpp>
#include <array>
#include <chrono>
#include <cstdio>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
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

void Settle(net::io_context& io) {
    io.restart();
    io.run_for(50ms);
}

::StreamSettings XHttpSettings(::XHttpMode mode) {
    ::StreamSettings settings;
    settings.network = "xhttp";
    settings.xhttp.path = "/fixture";
    settings.xhttp.mode = mode;
    return ::NormalizeStreamSettings(settings);
}

size_t Count(std::string_view haystack, std::string_view needle) {
    size_t count = 0;
    for (size_t at = haystack.find(needle); at != std::string_view::npos;
         at = haystack.find(needle, at + needle.size())) {
        ++count;
    }
    return count;
}

// A client socket plus the server-side transport build running on its peer.
struct Connection {
    Connection(net::io_context& io, ::tcp::acceptor& acceptor,
               const ::StreamSettings& settings,
               std::shared_ptr<::InboundTransportStreamHandler> sink)
        : client(io), accepted(io) {
        client.connect(acceptor.local_endpoint());
        acceptor.accept(accepted);
        client.non_blocking(true);
        auto raw = std::make_unique<::TcpStream>(std::move(accepted));
        auto build = [this, &io, raw = std::move(raw), &settings,
                      sink = std::move(sink)]() mutable -> net::awaitable<void> {
            auto result = co_await ::BuildInboundTransport(
                io, std::move(raw), settings, nullptr, 0, std::move(sink));
            build_ok = result.has_value() && !*result;
        };
        net::co_spawn(io, std::move(build), [this](std::exception_ptr error) {
            failure = error;
            returned = true;
        });
    }

    void Write(std::string_view bytes) { net::write(client, net::buffer(bytes)); }

    const std::string& Received() {
        std::array<char, 4096> chunk{};
        while (true) {
            ::IoErrorCode error;
            const size_t n = client.read_some(net::buffer(chunk), error);
            if (error) break;
            received.append(chunk.data(), n);
        }
        return received;
    }

    ::tcp::socket client;
    ::tcp::socket accepted;
    std::string received;
    std::exception_ptr failure;
    bool returned = false;
    bool build_ok = false;
};

// Reads the uplink until `expected` arrives, answers on the downlink, then
// holds the logical stream until released.
class EchoSink final : public ::InboundTransportStreamHandler {
public:
    EchoSink(net::io_context& io, std::string expected, std::string reply)
        : release(io, 1), expected(std::move(expected)), reply(std::move(reply)) {}

    net::awaitable<void> OnInboundTransportStream(
        std::unique_ptr<::AsyncStream> stream,
        ::InboundTransportMetadata) override {
        ++started;
        try {
            std::array<char, 256> chunk{};
            while (uplink.size() < expected.size()) {
                const size_t n = co_await stream->AsyncRead(net::buffer(chunk));
                if (n == 0) break;
                uplink.append(chunk.data(), n);
            }
            (void)co_await stream->AsyncWrite(net::buffer(reply));
        } catch (const ::IoSystemError&) {
        }
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        (void)co_await release.async_receive(net::as_tuple(net::use_awaitable));
        stream->CloseAbortive();
        stream.reset();
        ++finished;
    }

    net::experimental::channel<void(::IoErrorCode)> release;
    std::string expected;
    std::string reply;
    std::string uplink;
    int started = 0;
    int finished = 0;
};

std::string PacketUp(std::string_view session, int seq, std::string_view body,
                     bool close = false) {
    return "POST /fixture/" + std::string(session) + "/" + std::to_string(seq) +
        " HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(body.size()) +
        "\r\n" + (close ? "Connection: close\r\n" : "") + "\r\n" + std::string(body);
}

// RFC 9112 9.3: packet-up uploads share one persistent, pipelined connection,
// and an upload may precede its downlink GET on another connection. A late
// upload for an ended session is answered without closing the connection.
void PacketUpPersistsAndPrecedesDownlink() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    const auto settings = XHttpSettings(::XHttpMode::PacketUp);
    auto sink = std::make_shared<EchoSink>(io, "hello world", "pong");

    Connection upload(io, acceptor, settings, sink);
    upload.Write(PacketUp("s1", 0, "hello ") + PacketUp("s1", 1, "world"));
    Settle(io);
    Require(!upload.returned && upload.Received().empty(),
            "upload before its downlink was not held for the downlink");

    Connection downlink(io, acceptor, settings, sink);
    downlink.Write("GET /fixture/s1 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    RunUntil(io, [&] {
        return Count(upload.Received(), "HTTP/1.1 200 OK\r\n") == 2 &&
               downlink.Received().find("4\r\npong\r\n") != std::string::npos;
    }, "pipelined uploads or downlink reply missing");
    Require(sink->uplink == "hello world", "uploads reached the session out of order");
    Require(upload.Received().find("Connection: close") == std::string::npos && !upload.returned,
            "persistent upload connection was closed");

    Require(sink->release.try_send(::IoErrorCode{}), "sink release failed");
    RunUntil(io, [&] { return sink->finished == 1; }, "logical stream did not finish");
    upload.Write(PacketUp("s1", 2, "late"));
    RunUntil(io, [&] { return upload.Received().find("404 Not Found") != std::string::npos; },
             "late upload for an ended session was not rejected");
    Require(!upload.returned, "late upload closed the shared connection");
    upload.Write(PacketUp("s1", 3, "bye", true));
    RunUntil(io, [&] { return upload.returned; }, "Connection: close was not honoured");
    Require(Count(upload.Received(), "Connection: close") == 1, "close response not announced");
    if (upload.failure) std::rethrow_exception(upload.failure);
    Require(upload.build_ok, "upload connection ended with an error");

    ::IoErrorCode ignored;
    downlink.client.close(ignored);
    RunUntil(io, [&] { return downlink.returned; }, "downlink connection did not finish");
}

// Uploads on separate connections may all reach a session before its downlink
// GET; that GET releases every one of them, not just one.
void ConcurrentUploadsPrecedeDownlink() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    const auto settings = XHttpSettings(::XHttpMode::PacketUp);
    auto sink = std::make_shared<EchoSink>(io, "abc", "ok");

    Connection first(io, acceptor, settings, sink);
    Connection second(io, acceptor, settings, sink);
    Connection third(io, acceptor, settings, sink);
    first.Write(PacketUp("s2", 0, "a"));
    second.Write(PacketUp("s2", 1, "b"));
    third.Write(PacketUp("s2", 2, "c"));
    Settle(io);
    Require(first.Received().empty() && second.Received().empty() && third.Received().empty(),
            "uploads were answered before their downlink");

    Connection downlink(io, acceptor, settings, sink);
    downlink.Write("GET /fixture/s2 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    RunUntil(io, [&] {
        return first.Received().starts_with("HTTP/1.1 200 OK\r\n") &&
               second.Received().starts_with("HTTP/1.1 200 OK\r\n") &&
               third.Received().starts_with("HTTP/1.1 200 OK\r\n") &&
               downlink.Received().find("2\r\nok\r\n") != std::string::npos;
    }, "an upload waiting for the downlink was not released");
    Require(sink->uplink == "abc", "uploads reached the session out of order");

    Require(sink->release.try_send(::IoErrorCode{}), "sink release failed");
    RunUntil(io, [&] { return sink->finished == 1; }, "logical stream did not finish");
    ::IoErrorCode ignored;
    for (Connection* connection : {&first, &second, &third, &downlink}) {
        connection->client.close(ignored);
    }
    RunUntil(io, [&] {
        return first.returned && second.returned && third.returned && downlink.returned;
    }, "connections did not finish");
    for (Connection* connection : {&first, &second, &third}) {
        if (connection->failure) std::rethrow_exception(connection->failure);
        Require(connection->build_ok, "upload connection ended with an error");
    }
}

// RFC 9112 9.6: "close" in any Connection field line ends the connection
// after the response; a request pipelined behind it is not processed.
void LaterConnectionCloseFieldEndsConnection() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    const auto settings = XHttpSettings(::XHttpMode::PacketUp);
    auto sink = std::make_shared<EchoSink>(io, "a", "ok");

    Connection downlink(io, acceptor, settings, sink);
    downlink.Write("GET /fixture/s3 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    RunUntil(io, [&] { return sink->started == 1; }, "downlink did not start");

    Connection upload(io, acceptor, settings, sink);
    upload.Write("POST /fixture/s3/0 HTTP/1.1\r\nHost: localhost\r\n"
                 "Connection: keep-alive\r\nContent-Length: 1\r\nConnection: close\r\n\r\na" +
                 PacketUp("s3", 1, "b"));
    RunUntil(io, [&] { return upload.returned; }, "Connection: close in a later field line ignored");
    Require(Count(upload.Received(), "HTTP/1.1 ") == 1 &&
                upload.Received().find("Connection: close\r\n") != std::string::npos,
            "request pipelined behind Connection: close was processed");
    if (upload.failure) std::rethrow_exception(upload.failure);
    Require(upload.build_ok, "upload connection ended with an error");

    Require(sink->release.try_send(::IoErrorCode{}), "sink release failed");
    RunUntil(io, [&] { return sink->finished == 1; }, "logical stream did not finish");
    ::IoErrorCode ignored;
    downlink.client.close(ignored);
    RunUntil(io, [&] { return downlink.returned; }, "downlink connection did not finish");
}

// Without a session id one POST carries both directions: the chunked request
// body is the uplink and the chunked response body the downlink.
void StreamOneOverHttp1() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    const auto settings = XHttpSettings(::XHttpMode::StreamOne);
    auto sink = std::make_shared<EchoSink>(io, "hello", "world");
    Connection connection(io, acceptor, settings, sink);
    connection.Write("POST /fixture/ HTTP/1.1\r\nHost: localhost\r\n"
                     "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n");
    RunUntil(io, [&] {
        const auto& wire = connection.Received();
        return wire.starts_with("HTTP/1.1 200 OK\r\n") &&
               wire.find("Transfer-Encoding: chunked\r\n") != std::string::npos &&
               wire.find("\r\n\r\n5\r\nworld\r\n") != std::string::npos;
    }, "stream-one response missing");
    Require(sink->uplink == "hello", "stream-one request body lost");
    Require(sink->release.try_send(::IoErrorCode{}), "sink release failed");
    RunUntil(io, [&] { return connection.returned; }, "stream-one connection did not finish");
    if (connection.failure) std::rethrow_exception(connection.failure);
}

// RFC 9112 6.3: a stream-one Content-Length body ends after its declared
// octets, so a request pipelined behind it never reaches the uplink. 6.1-6.3:
// conflicting, repeated, unsupported or missing framing is refused.
void StreamOneHonoursBodyFraming() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    const auto settings = XHttpSettings(::XHttpMode::StreamOne);
    // Asks for more than the body holds: only body EOF ends the read.
    auto sink = std::make_shared<EchoSink>(io, "hello!", "world");
    Connection connection(io, acceptor, settings, sink);
    connection.Write("POST /fixture/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello"
                     "POST /fixture/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nbye");
    RunUntil(io, [&] {
        return connection.Received().find("\r\n\r\n5\r\nworld\r\n") != std::string::npos;
    }, "stream-one response missing");
    Require(sink->uplink == "hello", "bytes past Content-Length reached the uplink");
    Require(sink->release.try_send(::IoErrorCode{}), "sink release failed");
    RunUntil(io, [&] { return connection.returned; }, "stream-one connection did not finish");
    if (connection.failure) std::rethrow_exception(connection.failure);

    constexpr std::array<std::string_view, 4> kRejected{
        "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n",
        "Transfer-Encoding: gzip, chunked\r\n",
        "Content-Length: 5\r\nContent-Length: 5\r\n",
        "",
    };
    for (const std::string_view framing : kRejected) {
        auto rejecting = std::make_shared<EchoSink>(io, "hello", "world");
        Connection rejected(io, acceptor, settings, rejecting);
        rejected.Write("POST /fixture/ HTTP/1.1\r\nHost: localhost\r\n" + std::string(framing) +
                       "\r\n5\r\nhello\r\n0\r\n\r\n");
        RunUntil(io, [&] { return rejected.returned; }, "invalid stream-one framing was not refused");
        if (rejected.failure) std::rethrow_exception(rejected.failure);
        Require(!rejected.build_ok && rejecting->started == 0,
                "stream-one request with invalid framing was accepted");
    }
}

}  // namespace

TEST(XhttpHttp1, Contract) {
    try {
        PacketUpPersistsAndPrecedesDownlink();
        ConcurrentUploadsPrecedeDownlink();
        LaterConnectionCloseFieldEndsConnection();
        StreamOneOverHttp1();
        StreamOneHonoursBodyFraming();
        std::puts("XHTTP HTTP/1: persistent packet-up and stream-one completed");
        return;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "XHTTP HTTP/1: %s\n", error.what());
        FAIL() << error.what();
    }
}
