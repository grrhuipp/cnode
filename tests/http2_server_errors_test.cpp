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

std::string Headers(std::string_view network) {
    std::string block = HeaderField(":method", "POST") +
        HeaderField(":scheme", "http") +
        HeaderField(":authority", "localhost") +
        HeaderField(":path", network == "grpc" ? "/fixture/Tun" :
                             network == "xhttp" ? "/fixture/" : "/fixture");
    if (network == "grpc") {
        block += HeaderField("content-type", "application/grpc");
        block += HeaderField("te", "trailers");
    }
    return block;
}

class CleanupSink final : public ::InboundTransportStreamHandler {
public:
    explicit CleanupSink(net::io_context& io) : release_cleanup(io, 1) {}

    net::awaitable<void> OnInboundTransportStream(
        std::unique_ptr<::AsyncStream> stream,
        ::InboundTransportMetadata) override {
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

template<class Predicate>
void RunUntil(net::io_context& io, Predicate predicate, const char* message) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!predicate() && std::chrono::steady_clock::now() < deadline) {
        io.restart();
        io.run_for(10ms);
    }
    Require(predicate(), message);
}

::StreamSettings FixtureSettings(std::string_view network) {
    ::StreamSettings settings;
    settings.network = network;
    settings.grpc.service_name = "fixture";
    settings.http.path = "/fixture";
    settings.http.method = "POST";
    settings.xhttp.path = "/fixture";
    settings.xhttp.mode = ::XHttpMode::StreamOne;
    return ::NormalizeStreamSettings(settings);
}

void ParentWaitsForCleanup(std::string_view network, bool protocol_error) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket client(io), accepted(io);
    client.connect(acceptor.local_endpoint());
    acceptor.accept(accepted);
    auto raw = std::make_unique<::TcpStream>(std::move(accepted));
    auto sink = std::make_shared<CleanupSink>(io);
    const auto settings = FixtureSettings(network);
    bool returned = false;
    std::exception_ptr failure;
    auto build = [&]() -> net::awaitable<void> {
        const auto result = co_await ::BuildInboundTransport(io, std::move(raw), settings, nullptr, 0, sink);
        Require(result.has_value() && !*result, "demux builder returned a request stream");
        Require(sink->cleanup_finished == 1, "builder returned before child cleanup finished");
    };
    net::co_spawn(io, build(), [&](std::exception_ptr error) {
        failure = error;
        returned = true;
    });
    const auto opening = std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") +
        Frame(4, 0, 0) + Frame(1, 4, 1, Headers(network));
    net::write(client, net::buffer(opening));
    RunUntil(io, [&] { return sink->started == 1 || returned; }, "logical request did not start");
    Require(sink->started == 1 && !returned, "builder detached the active request");
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
    Require(sink->cleanup_started == 1 && sink->cleanup_finished == 0 && !returned,
            "parent completed while request cleanup was suspended");
    Require(sink->release_cleanup.try_send(::IoErrorCode{}), "cleanup gate was not released");
    RunUntil(io, [&] { return returned; }, "parent failed to join released request cleanup");
    if (failure) std::rethrow_exception(failure);
    Require(sink->cleanup_finished == 1, "request cleanup was skipped or repeated");
}

// Returns true once `wire` holds a complete RST_STREAM(stream, PROTOCOL_ERROR).
bool HasProtocolReset(std::string_view wire, uint32_t stream) {
    size_t offset = 0;
    while (wire.size() - offset >= 9) {
        const auto* header = reinterpret_cast<const uint8_t*>(wire.data() + offset);
        const size_t length = (size_t{header[0]} << 16) | (size_t{header[1]} << 8) | header[2];
        if (wire.size() - offset - 9 < length) break;
        const uint32_t id = ((uint32_t{header[5]} & 0x7f) << 24) | (uint32_t{header[6]} << 16) |
            (uint32_t{header[7]} << 8) | header[8];
        if (header[3] == 3 && id == stream && length == 4 &&
            wire.substr(offset + 9, 4) == std::string_view("\0\0\0\1", 4)) {
            return true;
        }
        offset += 9 + length;
    }
    return false;
}

// RFC 9113 8.1.1: a repeated pseudo-header or a Host that disagrees with
// :authority makes the request malformed. It is a stream error: the request
// never reaches the sink, and a later request on the same connection does.
void ResetsMalformedRequest(std::string_view network, std::string_view extra_field) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket client(io), accepted(io);
    client.connect(acceptor.local_endpoint());
    acceptor.accept(accepted);
    auto raw = std::make_unique<::TcpStream>(std::move(accepted));
    auto sink = std::make_shared<CleanupSink>(io);
    const auto settings = FixtureSettings(network);
    bool returned = false;
    std::exception_ptr failure;
    auto build = [&]() -> net::awaitable<void> {
        const auto result = co_await ::BuildInboundTransport(io, std::move(raw), settings, nullptr, 0, sink);
        Require(result.has_value() && !*result, "demux builder returned a request stream");
    };
    net::co_spawn(io, build(), [&](std::exception_ptr error) {
        failure = error;
        returned = true;
    });
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
    Require(!returned, "malformed request ended the connection");
    Require(sink->started == 1, "malformed request was delivered");
    ::IoErrorCode ignored;
    client.close(ignored);
    RunUntil(io, [&] { return sink->cleanup_started == 1; }, "sibling request was not cancelled");
    Require(sink->release_cleanup.try_send(::IoErrorCode{}), "cleanup gate was not released");
    RunUntil(io, [&] { return returned; }, "parent failed to join released request cleanup");
    if (failure) std::rethrow_exception(failure);
    Require(sink->started == 1 && sink->cleanup_finished == 1, "malformed request was delivered");
}
}  // namespace

TEST(Http2ServerErrors, Contract) {
    try {
        for (const auto network : {"grpc", "h2", "xhttp"}) {
            ParentWaitsForCleanup(network, false);
            ParentWaitsForCleanup(network, true);
            ResetsMalformedRequest(network, HeaderField(":path", "/fixture"));
            ResetsMalformedRequest(network, HeaderField("host", "other.example"));
        }
        std::puts("HTTP/2 parent cleanup: all network cases completed");
        return;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "HTTP/2 parent cleanup: %s\n", error.what());
        FAIL() << error.what();
    }
}
