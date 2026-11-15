#include "transport_coordinator_fixture.hpp"
#include <gtest/gtest.h>

#include "transport/tcp_stream.hpp"
#include "transport/xhttp_session.hpp"
#include "transport/transport_stack.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/write.hpp>
#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
using namespace std::chrono_literals;


std::string Frame(uint8_t type, uint8_t flags, uint32_t stream, std::string_view payload = {}) {
    std::string result;
    const auto size = payload.size();
    result.push_back(static_cast<char>(size >> 16));
    result.push_back(static_cast<char>(size >> 8));
    result.push_back(static_cast<char>(size));
    result.push_back(static_cast<char>(type));
    result.push_back(static_cast<char>(flags));
    for (int shift = 24; shift >= 0; shift -= 8)
        result.push_back(static_cast<char>(stream >> shift));
    result.append(payload);
    return result;
}

// HPACK literal field without indexing, new name (RFC 7541 6.2.2).
std::string HeaderField(std::string_view name, std::string_view value) {
    std::string field;
    field.push_back('\0');
    field.push_back(static_cast<char>(name.size()));
    field.append(name);
    field.push_back(static_cast<char>(value.size()));
    field.append(value);
    return field;
}

std::string Headers(std::string_view network, std::string_view method = "POST",
                    std::string_view path = {}) {
    if (path.empty()) {
        path = network == "grpc" ? "/fixture/Tun" : network == "xhttp" ? "/fixture/" : "/fixture";
    }
    std::string block = HeaderField(":method", method) +
        HeaderField(":scheme", "http") +
        HeaderField(":authority", "localhost") +
        HeaderField(":path", path);
    if (network == "grpc") {
        block += HeaderField("content-type", "application/grpc");
        block += HeaderField("te", "trailers");
    }
    return block;
}

class CleanupSink final : public ::transport::InboundTransportStreamHandler {
public:
    explicit CleanupSink(net::io_context& io) : release_cleanup(io, 1) {}

    net::awaitable<void> OnInboundTransportStream(
        std::unique_ptr<::transport::AsyncStream> stream,
        ::transport::InboundTransportMetadata) override {
        ++started;
        std::array<uint8_t, 1> byte{};
        try {
            (void)co_await stream->AsyncRead(net::buffer(byte));
        } catch (const ::IoSystemError&) {
            // Physical EOF/error and task cancellation may race. Both must
            // unwind through the same owned request-cleanup barrier.
        }
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        ++cleanup_started;
        co_await release_cleanup.async_receive(net::use_awaitable);
        stream->CloseAbortive();
        stream.reset();
        ++cleanup_finished;
    }

    net::experimental::channel<void(::IoErrorCode)> release_cleanup;
    int started = 0;
    int cleanup_started = 0;
    int cleanup_finished = 0;
};

struct SessionJoin {
    net::io_context& io;
    ::tcp::socket& peer;
    CleanupSink& sink;
    ~SessionJoin() {
        ::IoErrorCode ignored;
        peer.close(ignored);
        sink.release_cleanup.close();
        io.restart();
        io.run();
    }
};

template<class Predicate>
void RunUntil(net::io_context& io, Predicate predicate, const char* message) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!predicate() && std::chrono::steady_clock::now() < deadline) {
        io.restart();
        io.run_for(10ms);
    }
    EXPECT_TRUE(predicate()) << message;
}

::transport::StreamSettings FixtureSettings(
    std::string_view network,
    ::transport::XHttpMode xhttp_mode = ::transport::XHttpMode::StreamOne) {
    ::transport::StreamSettings settings;
    settings.network_mode = transport::ParseNetworkMode(network);
    settings.http.force_http2 = common::EqualsAsciiCI(network, "h2");
    settings.grpc.service_name = "fixture";
    settings.http.path = "/fixture";
    settings.http.method = "POST";
    settings.xhttp.path = "/fixture";
    settings.xhttp.mode = xhttp_mode;
    return ::transport::NormalizeStreamSettings(settings);
}

void ParentWaitsForCleanup(std::string_view network, bool protocol_error) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket client(io), accepted(io);
    client.connect(acceptor.local_endpoint());
    acceptor.accept(accepted);
    auto raw = std::make_unique<::transport::TcpStream>(std::move(accepted));
    auto sink = std::make_shared<CleanupSink>(io);
    const auto settings = FixtureSettings(network);
    bool returned = false;
    std::exception_ptr failure;
    auto build = [&]() -> net::awaitable<void> {
        const auto result = co_await ::transport::BuildInboundTransport(transport_coordinator.Coordinator(), io, std::move(raw), settings, nullptr, 0, sink);
        EXPECT_TRUE(result.has_value() && !*result);
        EXPECT_EQ(sink->cleanup_finished, 1);
    };
    net::co_spawn(io, build(), [&](std::exception_ptr error) {
        failure = error;
        returned = true;
    });
    SessionJoin join{io, client, *sink};
    const auto opening = std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") +
        Frame(4, 0, 0) + Frame(1, 4, 1, Headers(network));
    net::write(client, net::buffer(opening));
    RunUntil(io, [&] { return sink->started == 1 || returned; }, "logical request did not start");
    EXPECT_EQ(sink->started, 1);
    EXPECT_FALSE(returned);
    if (protocol_error) {
        // RFC 9113 section 6.7: PING on a nonzero stream is a connection error.
        const auto invalid = Frame(6, 0, 1, "bad-ping");
        net::write(client, net::buffer(invalid));
    } else {
        ::IoErrorCode ignored;
        client.close(ignored);
    }
    RunUntil(io, [&] { return sink->cleanup_started == 1 || returned; },
             "physical termination did not cancel the request");
    io.restart();
    io.run_for(20ms);
    EXPECT_EQ(sink->cleanup_started, 1);
    EXPECT_EQ(sink->cleanup_finished, 0);
    EXPECT_FALSE(returned);
    EXPECT_TRUE(sink->release_cleanup.try_send(::IoErrorCode{}));
    RunUntil(io, [&] { return returned; }, "parent failed to join released request cleanup");
    if (failure) std::rethrow_exception(failure);
    EXPECT_EQ(sink->cleanup_finished, 1);
}

// Calls `visit(type, flags, stream, payload)` for each complete frame of `wire`.
template<class Visit>
void ForEachFrame(std::string_view wire, Visit visit) {
    size_t offset = 0;
    while (wire.size() - offset >= 9) {
        const auto* header = reinterpret_cast<const uint8_t*>(wire.data() + offset);
        const size_t length = (size_t{header[0]} << 16) | (size_t{header[1]} << 8) | header[2];
        if (wire.size() - offset - 9 < length) break;
        const uint32_t id = ((uint32_t{header[5]} & 0x7f) << 24) | (uint32_t{header[6]} << 16) |
            (uint32_t{header[7]} << 8) | header[8];
        visit(header[3], header[4], id, wire.substr(offset + 9, length));
        offset += 9 + length;
    }
}

// Returns true once `wire` holds a complete RST_STREAM(stream, PROTOCOL_ERROR).
bool HasProtocolReset(std::string_view wire, uint32_t stream) {
    bool found = false;
    ForEachFrame(wire, [&](uint8_t type, uint8_t, uint32_t id, std::string_view payload) {
        found = found || (type == 3 && id == stream && payload == std::string_view("\0\0\0\1", 4));
    });
    return found;
}

// RFC 9113 8.1.1: a repeated pseudo-header or a Host that disagrees with
// :authority makes the request malformed. It is a stream error: the request
// never reaches the sink, and a later request on the same connection does.
void ResetsMalformedRequest(std::string_view network, std::string_view extra_field) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket client(io), accepted(io);
    client.connect(acceptor.local_endpoint());
    acceptor.accept(accepted);
    auto raw = std::make_unique<::transport::TcpStream>(std::move(accepted));
    auto sink = std::make_shared<CleanupSink>(io);
    const auto settings = FixtureSettings(network);
    bool returned = false;
    std::exception_ptr failure;
    auto build = [&]() -> net::awaitable<void> {
        const auto result = co_await ::transport::BuildInboundTransport(transport_coordinator.Coordinator(), io, std::move(raw), settings, nullptr, 0, sink);
        EXPECT_TRUE(result.has_value() && !*result);
    };
    net::co_spawn(io, build(), [&](std::exception_ptr error) {
        failure = error;
        returned = true;
    });
    SessionJoin join{io, client, *sink};
    const auto opening = std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") +
        Frame(4, 0, 0) + Frame(1, 4, 1, Headers(network) + std::string(extra_field)) +
        Frame(1, 4, 3, Headers(network));
    net::write(client, net::buffer(opening));
    client.non_blocking(true);
    std::string received;
    const auto reset_seen = [&] {
        std::array<char, 4096> chunk{};
        ::IoErrorCode error;
        const size_t n = client.read_some(net::buffer(chunk), error);
        if (!error) received.append(chunk.data(), n);
        return HasProtocolReset(received, 1);
    };
    RunUntil(io, [&] { return (reset_seen() && sink->started == 1) || returned; },
             "malformed request was not reset while its sibling started");
    EXPECT_FALSE(returned);
    EXPECT_EQ(sink->started, 1);
    ::IoErrorCode ignored;
    client.close(ignored);
    RunUntil(io, [&] { return sink->cleanup_started == 1; }, "sibling request was not cancelled");
    EXPECT_TRUE(sink->release_cleanup.try_send(::IoErrorCode{}));
    RunUntil(io, [&] { return returned; }, "parent failed to join released request cleanup");
    if (failure) std::rethrow_exception(failure);
    EXPECT_EQ(sink->started, 1);
    EXPECT_EQ(sink->cleanup_finished, 1);
}
}  // namespace

class Http2ServerErrors : public testing::TestWithParam<const char*> {};
TEST_P(Http2ServerErrors, DisconnectWaitsForRequestCleanup) {
    ParentWaitsForCleanup(GetParam(), false);
}
TEST_P(Http2ServerErrors, ProtocolErrorWaitsForRequestCleanup) {
    ParentWaitsForCleanup(GetParam(), true);
}
TEST_P(Http2ServerErrors, DuplicatePathResetsOnlyMalformedRequest) {
    ResetsMalformedRequest(GetParam(), HeaderField(":path", "/fixture"));
}
TEST_P(Http2ServerErrors, ConflictingHostResetsOnlyMalformedRequest) {
    ResetsMalformedRequest(GetParam(), HeaderField("host", "other.example"));
}
INSTANTIATE_TEST_SUITE_P(Transports, Http2ServerErrors,
    testing::Values("grpc", "h2", "xhttp"));

// RST_STREAM returns the reset upload's slot in its XHTTP session at once. The
// reader meets the upload that follows the reset in the same read before the
// reset upload's coroutine resumes to unwind, and must still admit it.
TEST(Http2ServerXHttpUploads, ResetReturnsUploadSlotBeforeNextRequest) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket client(io), accepted(io);
    client.connect(acceptor.local_endpoint());
    acceptor.accept(accepted);
    auto raw = std::make_unique<::transport::TcpStream>(std::move(accepted));
    auto sink = std::make_shared<CleanupSink>(io);
    const auto settings = FixtureSettings("xhttp", ::transport::XHttpMode::PacketUp);
    bool returned = false;
    std::exception_ptr failure;
    auto build = [&]() -> net::awaitable<void> {
        const auto result = co_await ::transport::BuildInboundTransport(transport_coordinator.Coordinator(), io, std::move(raw), settings, nullptr, 0, sink);
        EXPECT_TRUE(result.has_value() && !*result);
    };
    net::co_spawn(io, build(), [&](std::exception_ptr error) {
        failure = error;
        returned = true;
    });
    SessionJoin join{io, client, *sink};
    const auto upload = [](uint32_t stream, size_t sequence, bool end_stream) {
        return Frame(1, end_stream ? 5 : 4, stream,
                     Headers("xhttp", "POST", "/fixture/slots/" + std::to_string(sequence)));
    };
    // Every slot of the session holds an upload still waiting for its body.
    constexpr uint32_t slots = ::transport::XHttpPacketQueue::kMaxUploads;
    const uint32_t first = 3, refused = first + 2 * slots, admitted = refused + 2;
    auto opening = std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") +
        Frame(4, 0, 0) + Frame(1, 5, 1, Headers("xhttp", "GET", "/fixture/slots"));
    for (uint32_t n = 0; n != slots; ++n) opening += upload(first + 2 * n, n + 1, false);
    opening += upload(refused, slots + 1, false);
    net::write(client, net::buffer(opening));
    client.non_blocking(true);
    std::string received;
    bool ended = false, reset = false;
    const auto observe = [&](uint32_t stream) {
        std::array<char, 4096> chunk{};
        ::IoErrorCode error;
        const size_t n = client.read_some(net::buffer(chunk), error);
        if (!error) received.append(chunk.data(), n);
        ended = reset = false;
        ForEachFrame(received, [&](uint8_t type, uint8_t flags, uint32_t id, std::string_view) {
            if (id != stream) return;
            ended = ended || (type <= 1 && (flags & 1) != 0);
            reset = reset || type == 3;
        });
        return ended || reset;
    };
    RunUntil(io, [&] { return observe(refused) || returned; },
             "upload beyond the session's slots was not answered");
    EXPECT_TRUE(reset);
    EXPECT_FALSE(returned);
    // One write: both frames are buffered before the reader takes the reset.
    const auto retry = Frame(3, 0, first, std::string_view("\0\0\0\x08", 4)) +
        upload(admitted, slots + 2, true);
    net::write(client, net::buffer(retry));
    RunUntil(io, [&] { return observe(admitted) || returned; },
             "upload following the reset was not answered");
    EXPECT_TRUE(ended);
    EXPECT_FALSE(reset);
    EXPECT_FALSE(returned);
    EXPECT_EQ(sink->started, 1);
    ::IoErrorCode ignored;
    client.close(ignored);
    RunUntil(io, [&] { return sink->cleanup_started == 1; }, "downlink request was not cancelled");
    EXPECT_TRUE(sink->release_cleanup.try_send(::IoErrorCode{}));
    RunUntil(io, [&] { return returned; }, "parent failed to join released request cleanup");
    if (failure) std::rethrow_exception(failure);
    EXPECT_EQ(sink->cleanup_finished, 1);
}
