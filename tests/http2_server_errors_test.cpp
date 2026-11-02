#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"

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
namespace net = acpp::net;
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

std::string Headers(std::string_view network) {
    std::string block;
    const auto append = [&](std::string_view name, std::string_view value) {
        block.push_back('\0');
        block.push_back(static_cast<char>(name.size()));
        block.append(name);
        block.push_back(static_cast<char>(value.size()));
        block.append(value);
    };
    append(":method", "POST");
    append(":scheme", "http");
    append(":authority", "localhost");
    append(":path", network == "grpc" ? "/fixture/Tun" :
                    network == "xhttp" ? "/fixture/" : "/fixture");
    if (network == "grpc") {
        append("content-type", "application/grpc");
        append("te", "trailers");
    }
    return block;
}

class CleanupSink final : public acpp::InboundTransportStreamHandler {
public:
    explicit CleanupSink(net::io_context& io) : release_cleanup(io, 1) {}

    net::awaitable<void> OnInboundTransportStream(
        std::unique_ptr<acpp::AsyncStream> stream,
        acpp::InboundTransportMetadata) override {
        ++started;
        std::array<uint8_t, 1> byte{};
        try {
            (void)co_await stream->AsyncRead(net::buffer(byte));
        } catch (const acpp::IoSystemError&) {
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

    net::experimental::channel<void(acpp::IoErrorCode)> release_cleanup;
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

void ParentWaitsForCleanup(std::string_view network, bool protocol_error) {
    net::io_context io;
    acpp::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    acpp::tcp::socket client(io), accepted(io);
    client.connect(acceptor.local_endpoint());
    acceptor.accept(accepted);
    auto raw = std::make_unique<acpp::TcpStream>(std::move(accepted));
    auto sink = std::make_shared<CleanupSink>(io);
    acpp::StreamSettings settings;
    settings.network = network;
    settings.grpc.service_name = "fixture";
    settings.http.path = "/fixture";
    settings.http.method = "POST";
    settings.xhttp.path = "/fixture";
    settings.xhttp.mode = "stream-one";
    settings = acpp::NormalizeStreamSettings(settings);
    bool returned = false;
    std::exception_ptr failure;
    auto build = [&]() -> net::awaitable<void> {
        const auto result = co_await acpp::BuildInboundTransport(io, std::move(raw), settings, 0, sink);
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
        acpp::IoErrorCode ignored;
        client.close(ignored);
    }
    RunUntil(io, [&] { return sink->cleanup_started == 1 || returned; },
             "physical termination did not cancel the request");
    io.restart();
    io.run_for(20ms);
    Require(sink->cleanup_started == 1 && sink->cleanup_finished == 0 && !returned,
            "parent completed while request cleanup was suspended");
    Require(sink->release_cleanup.try_send(acpp::IoErrorCode{}), "cleanup gate was not released");
    RunUntil(io, [&] { return returned; }, "parent failed to join released request cleanup");
    if (failure) std::rethrow_exception(failure);
    Require(sink->cleanup_finished == 1, "request cleanup was skipped or repeated");
}
}  // namespace

int main() {
    try {
        for (const auto network : {"grpc", "h2", "xhttp"}) {
            ParentWaitsForCleanup(network, false);
            ParentWaitsForCleanup(network, true);
        }
        std::puts("HTTP/2 parent cleanup: all network cases completed");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "HTTP/2 parent cleanup: %s\n", error.what());
        return 1;
    }
}
