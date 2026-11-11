#include "transport_coordinator_fixture.hpp"
#include <gtest/gtest.h>

#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/transport_stack.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/write.hpp>
#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <string_view>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;


template<class Predicate>
bool PumpUntil(net::io_context& io, Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!predicate() && std::chrono::steady_clock::now() < deadline) {
        io.restart();
        io.run_for(5ms);
    }
    return predicate();
}

void Settle(net::io_context& io) {
    io.restart();
    io.run_for(50ms);
}

::StreamSettings XHttpSettings(::XHttpMode mode) {
    ::StreamSettings settings;
    settings.network_mode = ::NetworkMode::XHttp;
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
// A client socket plus the server-side transport build running on its peer.
struct Connection {
    Connection(GroupCoordinator& coordinator, net::io_context& io, ::tcp::acceptor& acceptor,
               const ::StreamSettings& settings,
               std::shared_ptr<EchoSink> sink)
        : io(io), sink(sink), client(io), accepted(io) {
        client.connect(acceptor.local_endpoint());
        acceptor.accept(accepted);
        client.non_blocking(true);
        auto raw = std::make_unique<::TcpStream>(std::move(accepted));
        auto build = [state = state, &io, &coordinator, raw = std::move(raw), settings,
                      sink = std::move(sink)]() mutable -> net::awaitable<void> {
            auto result = co_await ::BuildInboundTransport(coordinator, io, std::move(raw), settings, nullptr, 0, std::move(sink));
            state->build_ok = result.has_value() && !*result;
        };
        net::co_spawn(io, std::move(build),
            net::bind_cancellation_slot(cancellation.slot(),
                [state = state](std::exception_ptr error) {
                    state->failure = error;
                    state->returned = true;
                }));
    }

    ~Connection() {
        (void)sink->release.try_send(::IoErrorCode{});
        ::IoErrorCode ignored;
        client.close(ignored);
        cancellation.emit(net::cancellation_type::terminal);
        EXPECT_TRUE(PumpUntil(io, [&] {
            return returned && sink->finished == sink->started;
        })) << "transport tasks did not drain during fixture teardown";
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

    struct BuildState {
        std::exception_ptr failure;
        bool returned = false;
        bool build_ok = false;
    };
    std::shared_ptr<BuildState> state = std::make_shared<BuildState>();
    net::io_context& io;
    std::shared_ptr<EchoSink> sink;
    net::cancellation_signal cancellation;
    ::tcp::socket client;
    ::tcp::socket accepted;
    std::string received;
    std::exception_ptr& failure = state->failure;
    bool& returned = state->returned;
    bool& build_ok = state->build_ok;
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
TEST(XhttpHttp1, PacketUpPersistsAndPrecedesDownlink) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    const auto settings = XHttpSettings(::XHttpMode::PacketUp);
    auto sink = std::make_shared<EchoSink>(io, "hello world", "pong");

    Connection upload(transport_coordinator.Coordinator(), io, acceptor, settings, sink);
    upload.Write(PacketUp("s1", 0, "hello ") + PacketUp("s1", 1, "world"));
    Settle(io);
    EXPECT_TRUE((!upload.returned && upload.Received().empty())) << "upload before its downlink was not held for the downlink";

    Connection downlink(transport_coordinator.Coordinator(), io, acceptor, settings, sink);
    downlink.Write("GET /fixture/s1 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    ASSERT_TRUE(PumpUntil(io, [&] {
        return Count(upload.Received(), "HTTP/1.1 200 OK\r\n") == 2 &&
               downlink.Received().find("4\r\npong\r\n") != std::string::npos;
    })) << "pipelined uploads or downlink reply missing";
    EXPECT_EQ(sink->uplink, "hello world") << "uploads reached the session out of order";
    EXPECT_TRUE((upload.Received().find("Connection: close") == std::string::npos && !upload.returned)) << "persistent upload connection was closed";

    EXPECT_TRUE((sink->release.try_send(::IoErrorCode{}))) << "sink release failed";
    ASSERT_TRUE(PumpUntil(io, [&] { return sink->finished == 1; })) << "logical stream did not finish";
    upload.Write(PacketUp("s1", 2, "late"));
    ASSERT_TRUE(PumpUntil(io, [&] { return upload.Received().find("404 Not Found") != std::string::npos; })) << "late upload for an ended session was not rejected";
    EXPECT_FALSE(upload.returned) << "late upload closed the shared connection";
    upload.Write(PacketUp("s1", 3, "bye", true));
    ASSERT_TRUE(PumpUntil(io, [&] { return upload.returned; })) << "Connection: close was not honoured";
    EXPECT_EQ(Count(upload.Received(), "Connection: close"), 1) << "close response not announced";
    EXPECT_EQ(Count(upload.Received(), "HTTP/1.1 404 Not Found\r\n"), 2)
        << "every upload for the retired session must be rejected";
    EXPECT_EQ(sink->started, 1) << "a late upload recreated the logical stream";
    EXPECT_EQ(sink->finished, 1);
    if (upload.failure) std::rethrow_exception(upload.failure);
    EXPECT_TRUE((upload.build_ok)) << "upload connection ended with an error";

    ::IoErrorCode ignored;
    downlink.client.close(ignored);
    ASSERT_TRUE(PumpUntil(io, [&] { return downlink.returned; })) << "downlink connection did not finish";
    if (downlink.failure) std::rethrow_exception(downlink.failure);
    EXPECT_TRUE(downlink.build_ok) << "downlink connection ended with an error";
}

// Uploads on separate connections may all reach a session before its downlink
// GET; that GET releases every one of them, not just one.
TEST(XhttpHttp1, ConcurrentUploadsPrecedeDownlink) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    const auto settings = XHttpSettings(::XHttpMode::PacketUp);
    auto sink = std::make_shared<EchoSink>(io, "abc", "ok");

    Connection first(transport_coordinator.Coordinator(), io, acceptor, settings, sink);
    Connection second(transport_coordinator.Coordinator(), io, acceptor, settings, sink);
    Connection third(transport_coordinator.Coordinator(), io, acceptor, settings, sink);
    first.Write(PacketUp("s2", 0, "a"));
    second.Write(PacketUp("s2", 1, "b"));
    third.Write(PacketUp("s2", 2, "c"));
    Settle(io);
    EXPECT_TRUE((first.Received().empty() && second.Received().empty() && third.Received().empty())) << "uploads were answered before their downlink";

    Connection downlink(transport_coordinator.Coordinator(), io, acceptor, settings, sink);
    downlink.Write("GET /fixture/s2 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    ASSERT_TRUE(PumpUntil(io, [&] {
        return first.Received().starts_with("HTTP/1.1 200 OK\r\n") &&
               second.Received().starts_with("HTTP/1.1 200 OK\r\n") &&
               third.Received().starts_with("HTTP/1.1 200 OK\r\n") &&
               downlink.Received().find("2\r\nok\r\n") != std::string::npos;
    })) << "an upload waiting for the downlink was not released";
    EXPECT_EQ(sink->uplink, "abc") << "uploads reached the session out of order";

    EXPECT_TRUE((sink->release.try_send(::IoErrorCode{}))) << "sink release failed";
    ASSERT_TRUE(PumpUntil(io, [&] { return sink->finished == 1; })) << "logical stream did not finish";
    ::IoErrorCode ignored;
    for (Connection* connection : {&first, &second, &third, &downlink}) {
        connection->client.close(ignored);
    }
    ASSERT_TRUE(PumpUntil(io, [&] {
        return first.returned && second.returned && third.returned && downlink.returned;
    })) << "connections did not finish";
    for (Connection* connection : {&first, &second, &third}) {
        if (connection->failure) std::rethrow_exception(connection->failure);
        EXPECT_TRUE((connection->build_ok)) << "upload connection ended with an error";
    }
}

// RFC 9112 9.6: "close" in any Connection field line ends the connection
// after the response; a request pipelined behind it is not processed.
TEST(XhttpHttp1, LaterConnectionCloseFieldEndsConnection) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    const auto settings = XHttpSettings(::XHttpMode::PacketUp);
    auto sink = std::make_shared<EchoSink>(io, "a", "ok");

    Connection downlink(transport_coordinator.Coordinator(), io, acceptor, settings, sink);
    downlink.Write("GET /fixture/s3 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    ASSERT_TRUE(PumpUntil(io, [&] { return sink->started == 1; })) << "downlink did not start";

    Connection upload(transport_coordinator.Coordinator(), io, acceptor, settings, sink);
    upload.Write("POST /fixture/s3/0 HTTP/1.1\r\nHost: localhost\r\n"
                 "Connection: keep-alive\r\nContent-Length: 1\r\nConnection: close\r\n\r\na" +
                 PacketUp("s3", 1, "b"));
    ASSERT_TRUE(PumpUntil(io, [&] { return upload.returned; })) << "Connection: close in a later field line ignored";
    EXPECT_TRUE((Count(upload.Received(), "HTTP/1.1 ") == 1 &&
                upload.Received().find("Connection: close\r\n") != std::string::npos)) << "request pipelined behind Connection: close was processed";
    if (upload.failure) std::rethrow_exception(upload.failure);
    EXPECT_TRUE((upload.build_ok)) << "upload connection ended with an error";

    EXPECT_TRUE((sink->release.try_send(::IoErrorCode{}))) << "sink release failed";
    ASSERT_TRUE(PumpUntil(io, [&] { return sink->finished == 1; })) << "logical stream did not finish";
    ::IoErrorCode ignored;
    downlink.client.close(ignored);
    ASSERT_TRUE(PumpUntil(io, [&] { return downlink.returned; })) << "downlink connection did not finish";
}

// Without a session id one POST carries both directions: the chunked request
// body is the uplink and the chunked response body the downlink.
TEST(XhttpHttp1, StreamOneSupportsChunkedDuplexBody) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    const auto settings = XHttpSettings(::XHttpMode::StreamOne);
    auto sink = std::make_shared<EchoSink>(io, "hello", "world");
    Connection connection(transport_coordinator.Coordinator(), io, acceptor, settings, sink);
    connection.Write("POST /fixture/ HTTP/1.1\r\nHost: localhost\r\n"
                     "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n");
    ASSERT_TRUE(PumpUntil(io, [&] {
        const auto& wire = connection.Received();
        return wire.starts_with("HTTP/1.1 200 OK\r\n") &&
               wire.find("Transfer-Encoding: chunked\r\n") != std::string::npos &&
               wire.find("\r\n\r\n5\r\nworld\r\n") != std::string::npos;
    })) << "stream-one response missing";
    EXPECT_EQ(sink->uplink, "hello") << "stream-one request body lost";
    EXPECT_TRUE((sink->release.try_send(::IoErrorCode{}))) << "sink release failed";
    ASSERT_TRUE(PumpUntil(io, [&] { return connection.returned; })) << "stream-one connection did not finish";
    if (connection.failure) std::rethrow_exception(connection.failure);
}

// RFC 9112 6.3: a stream-one Content-Length body ends after its declared
// octets, so a request pipelined behind it never reaches the uplink. 6.1-6.3:
// conflicting, repeated, unsupported or missing framing is refused.
TEST(XhttpHttp1, ContentLengthExcludesPipelinedRequestFromStreamOneUplink) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    const auto settings = XHttpSettings(::XHttpMode::StreamOne);
    // Asks for more than the body holds: only body EOF ends the read.
    auto sink = std::make_shared<EchoSink>(io, "hello!", "world");
    Connection connection(transport_coordinator.Coordinator(), io, acceptor, settings, sink);
    connection.Write("POST /fixture/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello"
                     "POST /fixture/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\nbye");
    ASSERT_TRUE(PumpUntil(io, [&] {
        return connection.Received().find("\r\n\r\n5\r\nworld\r\n") != std::string::npos;
    })) << "stream-one response missing";
    EXPECT_EQ(sink->uplink, "hello") << "bytes past Content-Length reached the uplink";
    EXPECT_TRUE((sink->release.try_send(::IoErrorCode{}))) << "sink release failed";
    ASSERT_TRUE(PumpUntil(io, [&] { return connection.returned; })) << "stream-one connection did not finish";
    if (connection.failure) std::rethrow_exception(connection.failure);

}

class InvalidStreamOneFraming : public testing::TestWithParam<std::string_view> {};
TEST_P(InvalidStreamOneFraming, RefusesAmbiguousUnsupportedOrMissingFraming) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    const auto settings = XHttpSettings(::XHttpMode::StreamOne);
    const auto framing = GetParam();
        auto rejecting = std::make_shared<EchoSink>(io, "hello", "world");
        Connection rejected(transport_coordinator.Coordinator(), io, acceptor, settings, rejecting);
        rejected.Write("POST /fixture/ HTTP/1.1\r\nHost: localhost\r\n" + std::string(framing) +
                       "\r\n5\r\nhello\r\n0\r\n\r\n");
        ASSERT_TRUE(PumpUntil(io, [&] { return rejected.returned; })) << "invalid stream-one framing was not refused";
        if (rejected.failure) std::rethrow_exception(rejected.failure);
        EXPECT_TRUE((!rejected.build_ok && rejecting->started == 0)) << "stream-one request with invalid framing was accepted";
}
INSTANTIATE_TEST_SUITE_P(Headers, InvalidStreamOneFraming, testing::Values(
    std::string_view("Transfer-Encoding: chunked\r\nContent-Length: 5\r\n"),
    std::string_view("Transfer-Encoding: gzip, chunked\r\n"),
    std::string_view("Content-Length: 5\r\nContent-Length: 5\r\n"),
    std::string_view("")));

}  // namespace

