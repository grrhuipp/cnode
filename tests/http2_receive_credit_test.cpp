#include "transport_coordinator_fixture.hpp"
#include <gtest/gtest.h>

#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/transport_stack.hpp"

#include <asio/co_spawn.hpp>
#include <asio/write.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;
constexpr size_t kStreamWindow = 4 * 1024 * 1024;
constexpr size_t kConnectionWindow = 8 * 1024 * 1024;


std::string U32(uint32_t value) {
    std::string bytes;
    for (int shift = 24; shift >= 0; shift -= 8) bytes.push_back(static_cast<char>(value >> shift));
    return bytes;
}

uint32_t Load32(std::string_view bytes) {
    const auto* p = reinterpret_cast<const uint8_t*>(bytes.data());
    return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | p[3];
}

std::string Frame(uint8_t type, uint8_t flags, uint32_t id, std::string_view payload = {}) {
    const size_t size = payload.size();
    std::string out;
    out.push_back(static_cast<char>(size >> 16));
    out.push_back(static_cast<char>(size >> 8));
    out.push_back(static_cast<char>(size));
    out.push_back(static_cast<char>(type));
    out.push_back(static_cast<char>(flags));
    out += U32(id);
    out.append(payload);
    return out;
}

std::string Field(std::string_view name, std::string_view value) {
    return std::string(1, '\0') + static_cast<char>(name.size()) + std::string(name) +
        static_cast<char>(value.size()) + std::string(value);
}

std::string Headers(std::string_view network, std::string_view path = {},
                    std::string_view method = "POST") {
    if (path.empty()) path = network == "grpc" ? "/fixture/Tun" :
                            network == "xhttp" ? "/fixture/" : "/fixture";
    auto out = Field(":method", method) + Field(":scheme", "http") +
        Field(":authority", "localhost") + Field(":path", path);
    if (network == "grpc") out += Field("content-type", "application/grpc") + Field("te", "trailers");
    return out;
}

std::string GrpcMessage(std::string_view body) {
    std::string size;
    for (size_t value = body.size(); ; value >>= 7) {
        size.push_back(static_cast<char>((value & 127) | (value >= 128 ? 128 : 0)));
        if (value < 128) break;
    }
    const auto length = static_cast<uint32_t>(1 + size.size() + body.size());
    return std::string(1, '\0') + U32(length) + '\x0a' + size + std::string(body);
}

struct WireFrame {
    uint8_t type;
    uint8_t flags;
    uint32_t id;
    std::string payload;
};

// The sink deliberately retains request ownership without starting a reader.
// Tests can consume, reject, half-close, or destroy exactly one logical stream.
class HoldingSink final : public ::InboundTransportStreamHandler {
public:
    net::awaitable<void> OnInboundTransportStream(
        std::unique_ptr<::AsyncStream> stream,
        ::InboundTransportMetadata) override {
        if (reject) throw std::runtime_error("fixture rejects callback");
        streams.push_back(std::move(stream));
        co_return;
    }
    bool reject = false;
    std::vector<std::unique_ptr<::AsyncStream>> streams;
};

class Fixture {
public:
    explicit Fixture(std::string_view network = "http", uint32_t initial_window = kStreamWindow,
                     ::XHttpMode mode = ::XHttpMode::StreamOne)
        : acceptor(io, {net::ip::address_v4::loopback(), 0}), peer(io), sink(std::make_shared<HoldingSink>()) {
        settings.network_mode = ParseNetworkMode(network);
        settings.http.force_http2 = EqualsAsciiCI(network, "h2");
        settings.http.path = "/fixture";
        settings.http.method = "POST";
        settings.http.initial_window_size = initial_window;
        settings.grpc.service_name = "fixture";
        settings.grpc.initial_window_size = initial_window;
        settings.xhttp.path = "/fixture";
        settings.xhttp.mode = mode;
        settings = ::NormalizeStreamSettings(settings);
        peer.connect(acceptor.local_endpoint());
        ::tcp::socket accepted(io);
        acceptor.accept(accepted);
        raw = std::make_unique<::TcpStream>(std::move(accepted));
        net::co_spawn(io, Serve(), [this](std::exception_ptr error) {
            failure = error;
            returned = true;
        });
        try {
            Send(std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") + Frame(4, 0, 0));
            Until([&] { return Credit(0) == kConnectionWindow - 65535; }, "connection receive grant missing");
            initial_credit = Credit(0);
            Send(Frame(4, 1, 0));
            Barrier();
        } catch (...) {
            Stop();
            throw;
        }
    }

    ~Fixture() {
        Stop();
    }

    net::awaitable<void> Serve() {
        const auto result = co_await ::BuildInboundTransport(transport_coordinator.Coordinator(), io, std::move(raw), settings, nullptr, 0, sink);
        EXPECT_TRUE(result.has_value() && !*result) << "HTTP/2 server build failed";
    }

    void Poll() {
        peer.non_blocking(true);
        std::array<char, 32768> bytes{};
        for (;;) {
            ::IoErrorCode error;
            const auto n = peer.read_some(net::buffer(bytes), error);
            if (error) break;
            wire.append(bytes.data(), n);
        }
        while (wire.size() >= 9) {
            const auto* h = reinterpret_cast<const uint8_t*>(wire.data());
            const size_t size = (size_t{h[0]} << 16) | (size_t{h[1]} << 8) | h[2];
            if (wire.size() < 9 + size) break;
            frames.push_back({h[3], h[4], Load32(std::string_view(wire).substr(5, 4)) & 0x7fffffff,
                              wire.substr(9, size)});
            wire.erase(0, 9 + size);
        }
    }

    template<class Predicate>
    void Until(Predicate predicate, const char* message) {
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        do {
            io.restart();
            io.run_for(2ms);
            Poll();
            if (predicate()) return;
        } while (std::chrono::steady_clock::now() < deadline);
        if (failure) std::rethrow_exception(failure);
        throw std::runtime_error(message);
    }

    void Send(std::string_view bytes) {
        peer.non_blocking(false);
        net::write(peer, net::buffer(bytes));
        io.restart();
        io.run_for(1ms);
        Poll();
    }

    void Barrier() {
        ++ping;
        const auto token = U32(ping) + U32(ping);
        Send(Frame(6, 0, 0, token));
        Until([&] {
            return std::any_of(frames.begin(), frames.end(), [&](const auto& f) {
                return f.type == 6 && f.flags == 1 && f.payload == token;
            });
        }, "frame pump stalled behind a logical consumer");
        io.restart();
        io.run_for(10ms);
        Poll();
    }

    void Open(uint32_t id, std::string_view path = {}, std::string_view method = "POST",
              bool end = false) {
        Send(Frame(1, static_cast<uint8_t>(4 | (end ? 1 : 0)), id,
                   Headers(settings.NetworkName(), path, method)));
        Until([&] {
            return std::any_of(frames.begin(), frames.end(), [&](const auto& f) {
                return f.id == id && f.type == 1;
            });
        }, "request response headers missing");
    }

    size_t Credit(uint32_t id) const {
        size_t total = 0;
        for (const auto& f : frames) if (f.type == 8 && f.id == id && f.payload.size() == 4)
            total += Load32(f.payload) & 0x7fffffff;
        return total;
    }

    std::optional<uint32_t> Reset(uint32_t id) const {
        for (const auto& f : frames) if (f.type == 3 && f.id == id && f.payload.size() == 4)
            return Load32(f.payload);
        return std::nullopt;
    }

    std::optional<uint32_t> GoAway() const {
        for (const auto& f : frames) if (f.type == 7 && f.payload.size() >= 8)
            return Load32(std::string_view(f.payload).substr(4, 4));
        return std::nullopt;
    }

    std::string Read(size_t index, size_t size) {
        std::string bytes(size, '\0');
        size_t count = 0;
        bool done = false;
        std::exception_ptr error;
        auto consume = [&]() -> net::awaitable<void> {
            while (count < size) {
                const auto n = co_await sink->streams.at(index)->AsyncRead(
                    net::buffer(bytes.data() + count, size - count));
                if (n == 0) throw std::runtime_error("unexpected logical EOF");
                count += n;
            }
        };
        net::co_spawn(io, consume(), [&](std::exception_ptr ex) { error = ex; done = true; });
        struct JoinRead {
            Fixture& fixture;
            bool& done;
            ~JoinRead() { if (!done) fixture.Stop(); }
        } join{*this, done};
        Until([&] { return done; }, "logical read did not complete");
        if (error) std::rethrow_exception(error);
        Barrier();
        return bytes;
    }

    void Stop() {
        for (auto& stream : sink->streams) if (stream) stream->CloseAbortive();
        ::IoErrorCode ignored;
        peer.close(ignored);
        // Poll uses the socket; completion after close is driven separately.
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (!returned && std::chrono::steady_clock::now() < deadline) {
            io.restart();
            io.run_for(2ms);
        }
        io.restart();
        io.run();
        sink->streams.clear();
        EXPECT_TRUE(returned) << "server owner did not join on close";
        if (failure) {
            try { std::rethrow_exception(failure); }
            catch (const std::exception& error) { ADD_FAILURE() << error.what(); }
            failure = nullptr;
        }
    }

    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor;
    ::tcp::socket peer;
    std::shared_ptr<HoldingSink> sink;
    ::StreamSettings settings;
    std::unique_ptr<::AsyncStream> raw;
    std::vector<WireFrame> frames;
    std::string wire;
    size_t initial_credit = 0;
    uint32_t ping = 0;
    bool returned = false;
    std::exception_ptr failure;
};

void ConsumptionPaddingAndDiscard(std::string_view network) {
    Fixture f(network);
    f.Open(1);
    f.Send(Frame(0, 8, 1, std::string("\x03" "abcdefXYZ", 10)));
    f.Barrier();
    EXPECT_EQ(f.Credit(0) - f.initial_credit, 4u);
    EXPECT_EQ(f.Credit(1), 4u);
    EXPECT_EQ(f.Read(0, 2), "ab");
    EXPECT_EQ(f.Credit(0) - f.initial_credit, 6u);
    EXPECT_EQ(f.Credit(1), 6u);
    f.Send(Frame(3, 0, 1, U32(8)));
    f.Barrier();
    EXPECT_EQ(f.Credit(0) - f.initial_credit, 10u);
    EXPECT_EQ(f.Credit(1), 6u);
    f.Send(Frame(0, 0, 1, "late"));
    f.Barrier();
    EXPECT_EQ(f.Credit(0) - f.initial_credit, 14u);
    EXPECT_EQ(f.Credit(1), 6u);
    f.Open(3);
    f.Send(Frame(0, 1, 3, "ended"));
    f.Barrier();
    EXPECT_EQ(f.Credit(3), 0u);
    EXPECT_EQ(f.Read(1, 5), "ended");
    EXPECT_EQ(f.Credit(0) - f.initial_credit, 19u);
    EXPECT_EQ(f.Credit(3), 0u);
    f.Stop();
}

TEST(Http2ReceiveCredit, LocalCloseAndRejectedCallback) {
    Fixture f;
    f.Open(1);
    f.Send(Frame(0, 0, 1, "unread"));
    f.Barrier();
    f.sink->streams[0]->ShutdownRead();
    f.Barrier();
    EXPECT_EQ(f.Credit(0) - f.initial_credit, 6u);
    EXPECT_EQ(f.Credit(1), 0u);
    f.sink->streams[0]->Close();
    f.Barrier();
    EXPECT_EQ(f.Credit(0) - f.initial_credit, 6u);
    f.sink->reject = true;
    f.Open(3);
    f.Send(Frame(0, 0, 3, "rejected"));
    f.Barrier();
    EXPECT_EQ(f.Credit(0) - f.initial_credit, 14u);
    EXPECT_EQ(f.Credit(3), 0u);
    f.sink->reject = false;
    f.Open(5);
    f.Send(Frame(0, 0, 5, "live"));
    EXPECT_EQ(f.Read(1, 4), "live");
    f.Stop();
}

TEST(Http2ReceiveCredit, StreamWindowViolationAndPaddingOnly) {
    Fixture f("http", 32);
    f.Open(1);
    f.Send(Frame(0, 8, 1, std::string("\x03" "xyz", 4)));
    f.Barrier();
    EXPECT_EQ(f.Credit(1), 4u);
    f.Send(Frame(0, 0, 1, std::string(33, 'x')));
    f.Until([&] { return f.Reset(1).has_value(); }, "stream window violation not reset");
    EXPECT_EQ(f.Reset(1), 3u);
    EXPECT_FALSE(f.GoAway());
    f.Open(3);
    f.Send(Frame(0, 0, 3, "ok"));
    EXPECT_EQ(f.Read(1, 2), "ok");
    f.Stop();
}

TEST(Http2ReceiveCredit, SlowStreamDoesNotBlockSibling) {
    Fixture f;
    f.Open(1);
    const std::string chunk(16384, 's');
    for (size_t sent = 0; sent < kStreamWindow; sent += chunk.size()) f.Send(Frame(0, 0, 1, chunk));
    f.Barrier();
    EXPECT_EQ(f.Credit(1), 0u);
    EXPECT_EQ(f.Credit(0), f.initial_credit);
    f.Open(3);
    f.Send(Frame(0, 0, 3, "fast"));
    EXPECT_EQ(f.Read(1, 4), "fast");
    f.Send(Frame(3, 0, 1, U32(8)));
    f.Barrier();
    EXPECT_EQ(f.Credit(0) - f.initial_credit, kStreamWindow + 4);
    f.Stop();
}

TEST(Http2ReceiveCredit, ConnectionWindowViolation) {
    Fixture f;
    f.Open(1);
    f.Open(3);
    f.Open(5);
    const std::string chunk(16384, 'c');
    for (uint32_t id : {1u, 3u}) {
        for (size_t sent = 0; sent < kStreamWindow; sent += chunk.size()) f.Send(Frame(0, 0, id, chunk));
    }
    f.Barrier();
    EXPECT_EQ(f.Credit(0), f.initial_credit);
    f.Send(Frame(0, 0, 5, "x"));
    f.Until([&] { return f.GoAway().has_value(); }, "connection window overrun not rejected");
    EXPECT_EQ(f.GoAway(), 3u);
    f.Stop();
}

TEST(Http2ReceiveCredit, FragmentedWindowRetainsOnlyBoundedSlack) {
    Fixture f;
    f.Open(1);
    f.Send(Frame(0, 0, 1, std::string(16384, 'h')));
    EXPECT_EQ(f.Read(0, 1), "h");
    std::string expected(16383, 'h');
    bool tiny = true;
    while (expected.size() < kStreamWindow) {
        const size_t n = std::min(kStreamWindow - expected.size(),
                                  tiny ? size_t{9} : size_t{16384});
        const std::string bytes(n, tiny ? 't' : 'b');
        f.Send(Frame(0, 0, 1, bytes));
        expected += bytes;
        tiny = !tiny;
    }
    f.Barrier();
    EXPECT_FALSE(f.Reset(1));
    EXPECT_FALSE(f.GoAway());
    EXPECT_EQ(f.Credit(1), 1u);
    EXPECT_EQ(f.Credit(0) - f.initial_credit, 1u);
    EXPECT_EQ(f.Read(0, expected.size()), expected);
    EXPECT_EQ(f.Credit(1), kStreamWindow + 1);
    EXPECT_EQ(f.Credit(0) - f.initial_credit, kStreamWindow + 1);
    f.Stop();
}

TEST(Http2ReceiveCredit, PaddedWindowPackingAndDiscard) {
    Fixture f;
    f.Open(1);
    const auto chunk = std::string(1, static_cast<char>(255)) + std::string(16128, 'p') + std::string(255, 'x');
    size_t body_bytes = 0;
    size_t padding_bytes = 0;
    // Packing reuses retained padding capacity. It must therefore admit a
    // complete unread byte window, not reset at an incidental frame count.
    // Respect the full flow-controlled size, including padding, on each send.
    while (kStreamWindow - body_bytes >= chunk.size()) {
        f.Send(Frame(0, 8, 1, chunk));
        body_bytes += 16128;
        padding_bytes += 256;
        f.Until([&] { return f.Credit(1) == padding_bytes || f.Reset(1); },
                "consumed padding did not replenish the stream window");
        EXPECT_FALSE(f.Reset(1));
        EXPECT_FALSE(f.GoAway());
    }
    f.Send(Frame(0, 0, 1, std::string(kStreamWindow - body_bytes, 'p')));
    f.Barrier();
    EXPECT_FALSE(f.Reset(1));
    EXPECT_FALSE(f.GoAway());
    EXPECT_EQ(f.Credit(1), padding_bytes);
    EXPECT_EQ(f.Credit(0) - f.initial_credit, padding_bytes);
    EXPECT_EQ(f.Read(0, 17), std::string(17, 'p'));
    EXPECT_EQ(f.Credit(1), padding_bytes + 17);
    EXPECT_EQ(f.Credit(0) - f.initial_credit, padding_bytes + 17);
    f.Open(3);
    f.Send(Frame(0, 0, 3, "ok"));
    EXPECT_EQ(f.Read(1, 2), "ok");
    f.Send(Frame(3, 0, 1, U32(8)));
    f.Barrier();
    EXPECT_EQ(f.Credit(0) - f.initial_credit, padding_bytes + kStreamWindow + 2);
    EXPECT_EQ(f.Credit(1), padding_bytes + 17);
    f.Stop();
}

void GrpcFragmentedMessageAdvancesWindow(uint32_t window, size_t body_size) {
    Fixture f("grpc", window);
    f.Open(1);
    const std::string body(body_size, 'g');
    const auto encoded = GrpcMessage(body);
    // Fill the entire advertised window before starting a consumer. A maximum
    // legal protobuf message needs five more wire bytes than the 4 MiB window.
    const size_t initial = std::min<size_t>(window, encoded.size());
    for (size_t offset = 0; offset < initial; ) {
        const size_t n = std::min<size_t>(16384, initial - offset);
        f.Send(Frame(0, 0, 1, std::string_view(encoded).substr(offset, n)));
        offset += n;
    }
    f.Barrier();
    EXPECT_EQ(f.Credit(1), 0u);
    bool done = false;
    std::exception_ptr error;
    std::string result(body.size(), '\0');
    auto read = [&]() -> net::awaitable<void> {
        size_t offset = 0;
        while (offset < result.size()) {
            const size_t n = co_await f.sink->streams[0]->AsyncRead(
                net::buffer(result.data() + offset, result.size() - offset));
            if (n == 0) throw std::runtime_error("gRPC ended before the message completed");
            offset += n;
        }
    };
    net::co_spawn(f.io, read(), [&](std::exception_ptr ex) { error = ex; done = true; });
    struct JoinRead {
        Fixture& fixture;
        bool& done;
        ~JoinRead() { if (!done) fixture.Stop(); }
    } join{f, done};
    size_t sent = initial;
    while (sent < encoded.size()) {
        f.Until([&] { return window + f.Credit(1) > sent || done; }, "fragmented gRPC parser deadlocked on credit");
        if (error) std::rethrow_exception(error);
        if (done) throw std::runtime_error("gRPC exposed payload before validating the complete message");
        const size_t n = std::min({encoded.size() - sent, window + f.Credit(1) - sent, size_t{16384}});
        f.Send(Frame(0, 0, 1, std::string_view(encoded).substr(sent, n)));
        sent += n;
    }
    f.Until([&] { return done; }, "gRPC read never completed");
    if (error) std::rethrow_exception(error);
    f.Barrier();
    EXPECT_EQ(result, body);
    EXPECT_EQ(f.Credit(1), encoded.size());
    f.Stop();
}

void XHttpSplitCredit(::XHttpMode mode) {
    Fixture f("xhttp", kStreamWindow, mode);
    const std::string session = mode == ::XHttpMode::StreamUp ? "/fixture/receive-stream" : "/fixture/receive-packet";
    f.Open(1, session, "GET", true);
    const bool packet = mode == ::XHttpMode::PacketUp;
    f.Open(3, packet ? session + "/0" : session);
    f.Send(Frame(0, packet ? 1 : 0, 3, "upload"));
    f.Barrier();
    if (!packet) EXPECT_EQ(f.Credit(3), 0u);
    EXPECT_EQ(f.Read(0, 6), "upload");
    EXPECT_EQ(f.Credit(0) - f.initial_credit, 6u);
    EXPECT_EQ(f.Credit(3), packet ? 0u : 6u);
    f.Stop();
}

TEST(Http2ReceiveCredit, GrpcAssemblySharesConnectionMemoryBudget) {
    Fixture f("grpc");
    size_t completed_reads = 0;
    size_t sent = 0;
    struct JoinAssembly {
        Fixture& fixture;
        ~JoinAssembly() { fixture.Stop(); }
    } join{f};
    auto hold_incomplete = [](::AsyncStream* stream) -> net::awaitable<void> {
        std::array<char, 1> byte{};
        try {
            (void)co_await stream->AsyncRead(net::buffer(byte));
        } catch (const ::IoSystemError&) {
        }
    };
    const std::string chunk(16384, 'g');
    const auto prefix = std::string(1, '\0') + U32(kStreamWindow);
    auto start = [&](uint32_t id) {
        f.Open(id);
        net::co_spawn(f.io, hold_incomplete(f.sink->streams.back().get()),
                      [&](std::exception_ptr error) {
                          if (error) f.failure = error;
                          ++completed_reads;
                      });
    };
    auto fill = [&](uint32_t id) {
        f.Send(Frame(0, 0, id, prefix));
        sent += prefix.size();
        for (size_t bytes = 0; bytes < 3 * 1024 * 1024 && !f.Reset(id); bytes += chunk.size()) {
            f.Send(Frame(0, 0, id, chunk));
            sent += chunk.size();
        }
        f.Barrier();
    };
    start(1);
    fill(1);
    start(3);
    fill(3);
    EXPECT_FALSE(f.Reset(1));
    EXPECT_FALSE(f.Reset(3));
    start(5);
    fill(5);
    f.Until([&] { return f.Reset(5).has_value(); }, "partial gRPC messages bypassed connection memory cap");
    EXPECT_EQ(f.Reset(5), 11u);
    EXPECT_FALSE(f.GoAway());
    f.Send(Frame(3, 0, 1, U32(8)) + Frame(3, 0, 3, U32(8)));
    f.Until([&] { return completed_reads == 3; }, "reset did not wake gRPC assembly readers");
    f.Barrier();
    EXPECT_EQ(f.Credit(0) - f.initial_credit, sent);
    // Reset frees assembly reservations, not just the raw DATA queue.
    start(7);
    fill(7);
    EXPECT_FALSE(f.Reset(7));
    f.Send(Frame(3, 0, 7, U32(8)));
    f.Until([&] { return completed_reads == 4; }, "last assembly reader did not finish");
    f.Barrier();
    EXPECT_EQ(f.Credit(0) - f.initial_credit, sent);
    f.Stop();
}

TEST(Http2ReceiveCredit, InvalidPaddingFailsConnection) {
    Fixture f;
    f.Open(1);
    // Pad Length includes neither itself nor any DATA; 4 padding octets cannot
    // fit after a one-octet payload (RFC 9113 6.1).
    f.Send(Frame(0, 8, 1, std::string(1, '\x04')));
    f.Until([&] { return f.GoAway().has_value(); }, "invalid padding was accepted");
    EXPECT_EQ(f.GoAway(), 1u);
    f.Stop();
}

}  // namespace

class Http2ReceiveCreditTransport : public testing::TestWithParam<const char*> {};
TEST_P(Http2ReceiveCreditTransport, ConsumptionPaddingAndDiscard) {
    ConsumptionPaddingAndDiscard(GetParam());
}
INSTANTIATE_TEST_SUITE_P(Transports, Http2ReceiveCreditTransport, testing::Values("http", "xhttp"));
class GrpcReceiveWindow : public testing::TestWithParam<std::pair<uint32_t, size_t>> {};
TEST_P(GrpcReceiveWindow, FragmentedMessageAdvancesWindow) {
    GrpcFragmentedMessageAdvancesWindow(GetParam().first, GetParam().second);
}
INSTANTIATE_TEST_SUITE_P(Windows, GrpcReceiveWindow, testing::Values(
    std::pair<uint32_t, size_t>{32, 4096},
    std::pair<uint32_t, size_t>{65535, kStreamWindow - 5},
    std::pair<uint32_t, size_t>{kStreamWindow, kStreamWindow - 5}));
class XHttpReceiveCredit : public testing::TestWithParam<::XHttpMode> {};
TEST_P(XHttpReceiveCredit, SplitUploadReclaimsExactCredit) { XHttpSplitCredit(GetParam()); }
INSTANTIATE_TEST_SUITE_P(Modes, XHttpReceiveCredit,
    testing::Values(::XHttpMode::StreamUp, ::XHttpMode::PacketUp));
