#include <gtest/gtest.h>

#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/transport_stack.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/write.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;

constexpr uint32_t kDefaultWindow = 65535;
constexpr size_t kMaxFramePayload = 16384;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::string U32(uint32_t value) {
    std::string out;
    for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<char>(value >> shift));
    return out;
}

std::string Frame(uint8_t type, uint8_t flags, uint32_t stream, std::string_view payload = {}) {
    const auto size = payload.size();
    std::string result;
    result.push_back(static_cast<char>(size >> 16));
    result.push_back(static_cast<char>(size >> 8));
    result.push_back(static_cast<char>(size));
    result.push_back(static_cast<char>(type));
    result.push_back(static_cast<char>(flags));
    result += U32(stream);
    result.append(payload);
    return result;
}

std::string InitialWindowSetting(uint32_t value) {
    return std::string("\0\x04", 2) + U32(value);
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

std::string GrpcRequestHeaders() {
    return HeaderField(":method", "POST") + HeaderField(":scheme", "http") +
        HeaderField(":authority", "localhost") + HeaderField(":path", "/fixture/Tun") +
        HeaderField("content-type", "application/grpc") + HeaderField("te", "trailers");
}

// One gRPC message whose Hunk carries `data` (fewer than 16384 octets).
std::string GrpcMessage(std::string_view data) {
    std::string varint;
    for (size_t value = data.size(); ; value >>= 7) {
        varint.push_back(static_cast<char>((value & 0x7f) | (value >= 0x80 ? 0x80 : 0)));
        if (value < 0x80) break;
    }
    const auto hunk_size = static_cast<uint32_t>(1 + varint.size() + data.size());
    return std::string(1, '\0') + U32(hunk_size) + "\x0a" + varint + std::string(data);
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

::StreamSettings GrpcSettings() {
    ::StreamSettings settings;
    settings.network = "grpc";
    settings.grpc.service_name = "fixture";
    return ::NormalizeStreamSettings(settings);
}

struct WireFrame {
    uint8_t type = 0;
    uint8_t flags = 0;
    uint32_t stream = 0;
    std::string payload;
};

// Raw HTTP/2 peer on a non-blocking socket; Poll() collects complete frames.
class RawPeer {
public:
    RawPeer(::tcp::socket& socket, size_t preface) : socket_(socket), skip_(preface) {
        socket_.non_blocking(true);
    }

    void Write(std::string_view bytes) { net::write(socket_, net::buffer(bytes)); }

    void Poll() {
        std::array<char, 16384> chunk{};
        while (true) {
            ::IoErrorCode error;
            const size_t n = socket_.read_some(net::buffer(chunk), error);
            if (error) break;
            buffer_.append(chunk.data(), n);
        }
        const size_t skip = std::min(skip_, buffer_.size());
        buffer_.erase(0, skip);
        skip_ -= skip;
        while (buffer_.size() >= 9) {
            const auto* h = reinterpret_cast<const uint8_t*>(buffer_.data());
            const size_t length = (size_t{h[0]} << 16) | (size_t{h[1]} << 8) | h[2];
            if (buffer_.size() - 9 < length) break;
            frames.push_back(WireFrame{
                .type = h[3],
                .flags = h[4],
                .stream = ((uint32_t{h[5]} & 0x7f) << 24) | (uint32_t{h[6]} << 16) |
                          (uint32_t{h[7]} << 8) | h[8],
                .payload = buffer_.substr(9, length),
            });
            buffer_.erase(0, 9 + length);
        }
    }

    [[nodiscard]] size_t DataBytes(uint32_t stream) const {
        size_t total = 0;
        for (const auto& frame : frames) {
            if (frame.type == 0 && frame.stream == stream) total += frame.payload.size();
        }
        return total;
    }

    [[nodiscard]] size_t LargestData() const {
        size_t largest = 0;
        for (const auto& frame : frames) {
            if (frame.type == 0) largest = std::max(largest, frame.payload.size());
        }
        return largest;
    }

    [[nodiscard]] size_t SettingsAcks() const {
        return static_cast<size_t>(std::count_if(frames.begin(), frames.end(),
            [](const WireFrame& frame) { return frame.type == 4 && (frame.flags & 1) != 0; }));
    }

    [[nodiscard]] bool HasHeaders(uint32_t stream) const {
        return std::any_of(frames.begin(), frames.end(),
            [&](const WireFrame& frame) { return frame.type == 1 && frame.stream == stream; });
    }

    // Sum of WINDOW_UPDATE increments the client sent for `stream`.
    [[nodiscard]] size_t WindowCredit(uint32_t stream) const {
        size_t total = 0;
        for (const auto& frame : frames) {
            if (frame.type != 8 || frame.stream != stream || frame.payload.size() != 4) continue;
            const auto* p = reinterpret_cast<const uint8_t*>(frame.payload.data());
            total += ((uint32_t{p[0]} & 0x7f) << 24) | (uint32_t{p[1]} << 16) |
                     (uint32_t{p[2]} << 8) | p[3];
        }
        return total;
    }

    // Error code of the first GOAWAY, if any.
    [[nodiscard]] std::optional<uint32_t> GoAwayError() const {
        for (const auto& frame : frames) {
            if (frame.type != 7 || frame.payload.size() < 8) continue;
            const auto* p = reinterpret_cast<const uint8_t*>(frame.payload.data()) + 4;
            return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | p[3];
        }
        return std::nullopt;
    }

    std::vector<WireFrame> frames;

private:
    ::tcp::socket& socket_;
    std::string buffer_;
    size_t skip_ = 0;
};

// RFC 9113 6.9.1: the client never sends more DATA than the connection and
// stream windows allow; 6.9.2: SETTINGS_INITIAL_WINDOW_SIZE credits the open
// stream by the difference while the connection window stays independent.
void ClientWaitsForPeerWindows() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket dialed(io), server(io);
    dialed.connect(acceptor.local_endpoint());
    acceptor.accept(server);
    auto raw = std::make_unique<::TcpStream>(std::move(dialed));
    const auto settings = GrpcSettings();
    const std::string payload(200000, 'x');
    std::unique_ptr<::AsyncStream> stream;
    bool written = false;
    bool finished = false;
    std::exception_ptr failure;
    auto client = [&]() -> net::awaitable<void> {
        auto result = co_await ::BuildOutboundTransport(std::move(raw), settings, nullptr);
        Require(result.has_value() && *result, "gRPC client handshake failed");
        stream = std::move(*result);
        (void)co_await stream->AsyncWrite(net::buffer(payload));
        written = true;
    };
    net::co_spawn(io, client(), [&](std::exception_ptr error) {
        failure = error;
        finished = true;
    });

    RawPeer peer(server, 24);
    RunUntil(io, [&] { peer.Poll(); return peer.HasHeaders(1) || finished; },
             "client request headers missing");
    // Empty SETTINGS keeps the 65535-octet defaults; 0x88 is :status 200.
    peer.Write(Frame(4, 0, 0) + Frame(1, 4, 1, "\x88"));
    RunUntil(io, [&] { peer.Poll(); return peer.DataBytes(1) >= kDefaultWindow || finished; },
             "client did not use its initial send window");
    Settle(io);
    peer.Poll();
    if (failure) std::rethrow_exception(failure);
    Require(!written && peer.DataBytes(1) == kDefaultWindow,
            "client sent DATA beyond the peer's flow-control window");
    Require(peer.SettingsAcks() == 1, "client did not acknowledge SETTINGS");

    peer.Write(Frame(4, 0, 0, InitialWindowSetting(1u << 20)));
    Settle(io);
    peer.Poll();
    Require(peer.SettingsAcks() == 2, "client did not acknowledge the window SETTINGS");
    Require(!written && peer.DataBytes(1) == kDefaultWindow,
            "stream credit alone let the client exceed the connection window");

    peer.Write(Frame(8, 0, 0, U32(1u << 20)));
    // One Hunk message: 5-octet gRPC prefix, field key and 3-octet length.
    const size_t expected = payload.size() + 9;
    RunUntil(io, [&] { peer.Poll(); return (written && peer.DataBytes(1) == expected) || finished; },
             "client did not resume after WINDOW_UPDATE");
    if (failure) std::rethrow_exception(failure);
    Require(peer.LargestData() <= kMaxFramePayload, "client exceeded SETTINGS_MAX_FRAME_SIZE");
    stream->CloseAbortive();
    RunUntil(io, [&] { return finished; }, "client task did not finish");
}

// gRPC client whose writer stays parked on send credit, so its frame pump is
// what consumes the peer's frames while no reader runs.
struct ParkedWriterClient {
    explicit ParkedWriterClient(net::io_context& io)
        : acceptor(io, {net::ip::address_v4::loopback(), 0}), dialed(io), server(io) {
        dialed.connect(acceptor.local_endpoint());
        acceptor.accept(server);
        auto client = [this, raw = std::make_unique<::TcpStream>(std::move(dialed))]()
            mutable -> net::awaitable<void> {
            auto result = co_await ::BuildOutboundTransport(std::move(raw), settings, nullptr);
            Require(result.has_value() && *result, "gRPC client handshake failed");
            stream = std::move(*result);
            (void)co_await stream->AsyncWrite(net::buffer(payload));
        };
        net::co_spawn(io, std::move(client), [this](std::exception_ptr error) {
            writer_failure = error;
            writer_finished = true;
        });
    }

    // Opens the response and waits until the writer used its send window.
    void OpenResponse(net::io_context& io, RawPeer& peer) {
        RunUntil(io, [&] { peer.Poll(); return peer.HasHeaders(1) || writer_finished; },
                 "client request headers missing");
        // Empty SETTINGS, the ACK of the client's SETTINGS, then :status 200.
        peer.Write(Frame(4, 0, 0) + Frame(4, 1, 0) + Frame(1, 4, 1, "\x88"));
        RunUntil(io, [&] { peer.Poll(); return peer.DataBytes(1) >= kDefaultWindow || writer_finished; },
                 "client did not use its send window");
        Settle(io);
        peer.Poll();
        Require(!writer_finished, "client writer stopped waiting for send credit");
    }

    ::tcp::acceptor acceptor;
    ::tcp::socket dialed;
    ::tcp::socket server;
    ::StreamSettings settings = GrpcSettings();
    std::string payload = std::string(200000, 'x');
    std::unique_ptr<::AsyncStream> stream;
    std::exception_ptr writer_failure;
    bool writer_finished = false;
};

// RFC 9113 6.9.1: DATA, padding included, is charged against the windows the
// client advertised even while only a writer short of send credit pumps
// frames; DATA beyond the connection window is a FLOW_CONTROL_ERROR.
void ClientEnforcesReceiveWindow() {
    net::io_context io;
    ParkedWriterClient client(io);
    RawPeer peer(client.server, 24);
    client.OpenResponse(io, peer);

    // Exactly the 65535-octet connection window: three full frames and a
    // padded one whose 255 padding octets count too (6.1).
    const std::string full(kMaxFramePayload, 'z');
    const std::string padded = std::string(1, '\xff') + std::string(16127, 'z') +
                               std::string(255, '\0');
    peer.Write(Frame(0, 0, 1, full) + Frame(0, 0, 1, full) + Frame(0, 0, 1, full) +
               Frame(0, 8, 1, padded));
    Settle(io);
    peer.Poll();
    Require(!client.writer_finished && !peer.GoAwayError(),
            "DATA within the advertised window was refused");
    Require(peer.WindowCredit(0) == 0, "credit returned before the reader took any DATA");

    peer.Write(Frame(0, 0, 1, "z"));
    RunUntil(io, [&] { peer.Poll(); return client.writer_finished && peer.GoAwayError(); },
             "DATA beyond the receive window was accepted");
    Require(client.writer_failure != nullptr, "flow-control violation did not fail the stream");
    Require(*peer.GoAwayError() == 3, "violation not reported as FLOW_CONTROL_ERROR");
    client.stream->CloseAbortive();
}

// Credit for received DATA returns when the reader takes it, so a reader
// that keeps up receives far more than one window.
void ClientReturnsCreditAsReaderTakesData() {
    net::io_context io;
    ParkedWriterClient client(io);
    RawPeer peer(client.server, 24);
    client.OpenResponse(io, peer);

    std::string messages;
    std::string expected;
    for (char fill = 'a'; fill < 'i'; ++fill) {
        const std::string data(16000, fill);
        messages += Frame(0, 0, 1, GrpcMessage(data));
        expected += data;
    }
    const size_t frame_size = messages.size() / 8 - 9;
    // Half the messages fit the connection window while nobody reads.
    peer.Write(std::string_view(messages).substr(0, messages.size() / 2));
    Settle(io);
    peer.Poll();
    Require(!client.writer_finished && peer.WindowCredit(0) == 0,
            "credit returned before the reader took any DATA");

    std::string received;
    bool reader_finished = false;
    std::exception_ptr reader_failure;
    auto reader = [&]() -> net::awaitable<void> {
        std::array<char, 4096> chunk{};
        while (received.size() < expected.size()) {
            const size_t n = co_await client.stream->AsyncRead(net::buffer(chunk));
            if (n == 0) break;
            received.append(chunk.data(), n);
        }
    };
    net::co_spawn(io, reader(), [&](std::exception_ptr error) {
        reader_failure = error;
        reader_finished = true;
    });
    RunUntil(io, [&] { peer.Poll(); return peer.WindowCredit(0) == 4 * frame_size; },
             "reader did not return the credit of the DATA it took");
    peer.Write(std::string_view(messages).substr(messages.size() / 2));
    RunUntil(io, [&] { return reader_finished; }, "reader did not receive every message");
    if (reader_failure) std::rethrow_exception(reader_failure);
    Require(received == expected, "reader received corrupted data");
    RunUntil(io, [&] {
        peer.Poll();
        return peer.WindowCredit(0) == 8 * frame_size && peer.WindowCredit(1) == 8 * frame_size;
    }, "credit returned does not match the DATA taken");
    Require(!peer.GoAwayError() && !client.writer_finished, "in-window DATA failed the client");

    client.stream->CloseAbortive();
    RunUntil(io, [&] { return client.writer_finished; }, "client writer did not finish");
}

class WritingSink final : public ::InboundTransportStreamHandler {
public:
    WritingSink(net::io_context& io, size_t size) : release(io, 1), payload(size, 'y') {}

    net::awaitable<void> OnInboundTransportStream(
        std::unique_ptr<::AsyncStream> stream,
        ::InboundTransportMetadata) override {
        try {
            (void)co_await stream->AsyncWrite(net::buffer(payload));
            written = true;
        } catch (const ::IoSystemError&) {
        }
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        (void)co_await release.async_receive(net::as_tuple(net::use_awaitable));
        stream->CloseAbortive();
    }

    net::experimental::channel<void(::IoErrorCode)> release;
    std::string payload;
    bool written = false;
};

// The server honours the client's SETTINGS_INITIAL_WINDOW_SIZE per stream and
// the 65535-octet connection window until WINDOW_UPDATE grants more.
void ServerWaitsForPeerWindows() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket client(io), accepted(io);
    client.connect(acceptor.local_endpoint());
    acceptor.accept(accepted);
    auto raw = std::make_unique<::TcpStream>(std::move(accepted));
    auto sink = std::make_shared<WritingSink>(io, 100000);
    const auto settings = GrpcSettings();
    bool returned = false;
    std::exception_ptr failure;
    auto build = [&]() -> net::awaitable<void> {
        (void)co_await ::BuildInboundTransport(io, std::move(raw), settings, nullptr, 0, sink);
    };
    net::co_spawn(io, build(), [&](std::exception_ptr error) {
        failure = error;
        returned = true;
    });

    RawPeer peer(client, 0);
    peer.Write(std::string("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") +
               Frame(4, 0, 0, InitialWindowSetting(16384)) +
               Frame(1, 4, 1, GrpcRequestHeaders()));
    RunUntil(io, [&] { peer.Poll(); return peer.DataBytes(1) >= 16384 || returned; },
             "server did not use the stream window");
    Settle(io);
    peer.Poll();
    Require(!sink->written && peer.DataBytes(1) == 16384,
            "server exceeded the peer's SETTINGS_INITIAL_WINDOW_SIZE");
    Require(peer.SettingsAcks() == 1, "server did not acknowledge SETTINGS");

    peer.Write(Frame(8, 0, 1, U32(1u << 20)));
    RunUntil(io, [&] { peer.Poll(); return peer.DataBytes(1) >= kDefaultWindow || returned; },
             "server did not use the stream WINDOW_UPDATE");
    Settle(io);
    peer.Poll();
    Require(!sink->written && peer.DataBytes(1) == kDefaultWindow,
            "server exceeded the connection window");

    peer.Write(Frame(8, 0, 0, U32(1u << 20)));
    const size_t expected = sink->payload.size() + 9;
    RunUntil(io, [&] { peer.Poll(); return (sink->written && peer.DataBytes(1) == expected) || returned; },
             "server did not resume after the connection WINDOW_UPDATE");
    Require(peer.LargestData() <= kMaxFramePayload, "server exceeded SETTINGS_MAX_FRAME_SIZE");

    ::IoErrorCode ignored;
    client.close(ignored);
    Require(sink->release.try_send(::IoErrorCode{}), "sink release failed");
    RunUntil(io, [&] { return returned; }, "server session did not finish");
    if (failure) std::rethrow_exception(failure);
}

}  // namespace

TEST(Http2FlowControl, Contract) {
    try {
        ClientWaitsForPeerWindows();
        ClientEnforcesReceiveWindow();
        ClientReturnsCreditAsReaderTakesData();
        ServerWaitsForPeerWindows();
        std::puts("HTTP/2 flow control: client and server honour peer windows");
        return;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "HTTP/2 flow control: %s\n", error.what());
        FAIL() << error.what();
    }
}
