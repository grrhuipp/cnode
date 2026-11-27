#include "transport_coordinator_fixture.hpp"
#include <gtest/gtest.h>

#include "transport/tcp_stream.hpp"
#include "transport/xhttp_session.hpp"
#include "transport/transport_stack.hpp"

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

std::string Request(std::string_view method, std::string_view path) {
    return HeaderField(":method", method) + HeaderField(":scheme", "http") +
        HeaderField(":authority", "localhost") + HeaderField(":path", path);
}

// The split stream of the downlink: reads its session only when released.
class DeferredReadSink final : public ::transport::InboundTransportStreamHandler {
public:
    explicit DeferredReadSink(net::io_context& io) : release_read(io, 1) {}

    net::awaitable<void> OnInboundTransportStream(
        std::unique_ptr<::transport::AsyncStream> stream,
        ::transport::InboundTransportMetadata) override {
        try {
            co_await release_read.async_receive(net::use_awaitable);
            while (read_bytes < expected_bytes) {
                auto received = co_await stream->ReadMultiBuffer();
                if (received.empty()) break;
                read_bytes += received.byte_size();
                received.clear();
            }
            std::array<uint8_t, 1> byte{};
            (void)co_await stream->AsyncRead(net::buffer(byte));
        } catch (const ::IoSystemError&) {
        }
        stream->CloseAbortive();
        finished = true;
    }

    net::experimental::channel<void(::IoErrorCode)> release_read;
    size_t expected_bytes = 0;
    size_t read_bytes = 0;
    bool finished = false;
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

bool HasResponseHeaders(std::string_view wire, uint32_t stream) {
    size_t offset = 0;
    while (wire.size() - offset >= 9) {
        const auto* header = reinterpret_cast<const uint8_t*>(wire.data() + offset);
        const size_t length = (size_t{header[0]} << 16) | (size_t{header[1]} << 8) | header[2];
        if (wire.size() - offset - 9 < length) break;
        const uint32_t id = ((uint32_t{header[5]} & 0x7f) << 24) | (uint32_t{header[6]} << 16) |
            (uint32_t{header[7]} << 8) | header[8];
        if (header[3] == 1 && id == stream) return true;
        offset += 9 + length;
    }
    return false;
}
}  // namespace

// DATA queued on a stream-up upload before its session is known is charged to
// the session payload budget like the DATA after it: draining the upload
// returns exactly what it took, whatever the receive Buffers' capacities.
TEST(Http2UploadBudget, DataQueuedBeforeSessionLookupIsChargedExactly) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket client(io), accepted(io);
    client.connect(acceptor.local_endpoint());
    acceptor.accept(accepted);
    auto raw = std::make_unique<::transport::TcpStream>(std::move(accepted));
    auto sink = std::make_shared<DeferredReadSink>(io);
    ::transport::StreamSettings raw_settings;
    raw_settings.network_mode = ::transport::ParseNetworkMode("xhttp");
    raw_settings.xhttp.path = "/fixture";
    raw_settings.xhttp.mode = ::transport::XHttpMode::StreamUp;
    const auto settings = ::transport::NormalizeStreamSettings(raw_settings);
    bool returned = false;
    std::exception_ptr failure;
    auto build = [&]() -> net::awaitable<void> {
        const auto result = co_await ::transport::BuildInboundTransport(
            transport_coordinator.Coordinator(), io, std::move(raw), settings, nullptr, 0, sink);
        EXPECT_TRUE(result.has_value() && !*result);
    };
    net::co_spawn(io, build(), [&](std::exception_ptr error) {
        failure = error;
        returned = true;
    });

    // The upload's first DATA arrives with its HEADERS, before the server
    // has looked its session up on the coordinator.
    const std::string early(100, 'a');
    const std::string late(16384, 'b');
    sink->expected_bytes = early.size() + late.size();
    const auto opening = std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") + Frame(4, 0, 0) +
        Frame(1, 5, 1, Request("GET", "/fixture/budget")) +
        Frame(1, 4, 3, Request("POST", "/fixture/budget")) + Frame(0, 0, 3, early);
    net::write(client, net::buffer(opening));
    client.non_blocking(true);
    std::string received;
    RunUntil(io, [&] {
        std::array<char, 4096> chunk{};
        ::IoErrorCode error;
        const size_t n = client.read_some(net::buffer(chunk), error);
        if (!error) received.append(chunk.data(), n);
        return HasResponseHeaders(received, 3) || returned;
    }, "stream-up upload was not answered");
    io.restart();
    io.run_for(20ms);
    // A larger DATA frame lands in a larger receive Buffer once the session is attached.
    client.non_blocking(false);
    net::write(client, net::buffer(Frame(0, 0, 3, late)));
    io.restart();
    io.run_for(50ms);
    EXPECT_TRUE(sink->release_read.try_send(::IoErrorCode{}));
    RunUntil(io, [&] { return sink->read_bytes == sink->expected_bytes || returned; },
             "session did not read the whole upload");

    const auto target = ::transport::FindLocalXHttpUploadTarget(
        io, settings.xhttp.session_namespace, "budget", ::transport::XHttpSessionAccess::Upload);
    ASSERT_TRUE(target.session);
    // Everything was consumed: the whole budget, and no more, is free.
    EXPECT_TRUE(target.session->Reserve(::transport::XHttpPacketQueue::kMaxQueuedBytes));
    target.session->Release(::transport::XHttpPacketQueue::kMaxQueuedBytes);
    const bool overcommitted =
        target.session->Reserve(::transport::XHttpPacketQueue::kMaxQueuedBytes + 1);
    EXPECT_FALSE(overcommitted) << "upload released more session budget than it reserved";
    if (overcommitted) target.session->Release(::transport::XHttpPacketQueue::kMaxQueuedBytes + 1);

    ::IoErrorCode ignored;
    client.close(ignored);
    RunUntil(io, [&] { return returned; }, "session did not end with its peer");
    if (failure) std::rethrow_exception(failure);
    EXPECT_TRUE(sink->finished);
}
