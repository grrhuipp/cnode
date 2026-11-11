#include "transport_coordinator_fixture.hpp"
#include <gtest/gtest.h>

#include "common/allocator.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/tls_stream.hpp"
#include "transport/internet/transport_stack.hpp"
#include "transport/internet/stream_settings.hpp"
#include "transport/internet/transport_security.hpp"
#include "transport/internet/ws_stream.hpp"
#include "transport/internet/http1_handshake.hpp"

#include <asio/co_spawn.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/read.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>
#include <asio/write.hpp>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <tuple>
#include <utility>
#include <vector>
#include <stdexcept>
#include <string>

#include <netinet/tcp.h>
#include <sys/socket.h>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;

class TransportBehavior : public testing::Test {
protected:
    void SetUp() override { ::transport::internet::TlsStream::InitializeIo(); }
    void TearDown() override {
        ::memory::reject_next_process_allocation = false;
        EXPECT_EQ(::memory::detail::test_buffers_live, 0);
    }
};

class HttpDiagnosticBehavior : public TransportBehavior {
protected:
    void SetUp() override {
        TransportBehavior::SetUp();
        auto name = (std::filesystem::temp_directory_path() / "cnode-http-logs-XXXXXX").string();
        ASSERT_NE(::mkdtemp(name.data()), nullptr);
        directory = name;
        ASSERT_TRUE(::infra::Log::Init({.level = infra::LogLevel::TRACE, .log_dir = directory,
                                .access_path = {}, .error_path = "error.log", .max_days = 1,
                                .rotate_daily = false, .gzip = false}));
    }
    void TearDown() override {
        ::infra::Log::Shutdown();
        if (!directory.empty()) std::filesystem::remove_all(directory);
        TransportBehavior::TearDown();
    }
    void ExpectRedactedDiagnostics() {
        ::infra::Log::Shutdown();
        std::ifstream input(directory / "error.log");
        ASSERT_TRUE(input.is_open());
        std::string diagnostics;
        for (std::string line; std::getline(input, line);) {
            for (unsigned char ch : line) {
                EXPECT_GE(ch, 0x20);
                EXPECT_NE(ch, 0x7f);
            }
            diagnostics += line + '\n';
        }
        EXPECT_FALSE(diagnostics.empty());
        for (const std::string_view secret : {
                "review_password", "review_token", "review_fragment", "forged_log_line"})
            EXPECT_EQ(diagnostics.find(secret), std::string::npos) << secret;
    }
    std::filesystem::path directory;
};
std::span<const uint8_t> Bytes(std::string_view value) {
    return {reinterpret_cast<const uint8_t*>(value.data()), value.size()};
}
void Prepend(::transport::AsyncStream& stream, std::string_view value) {
    stream.PrependReadData(Bytes(value));
}
std::string Flatten(const ::buf::MultiBuffer& data) {
    std::string result;
    for (const auto* buffer : data) {
        const auto bytes = buffer->Bytes();
        result.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
    return result;
}

// The peer is a real TCP/Asio TLS endpoint, independent of cnode's transport.
// Every case exercises one of the four HTTP handshake call sites, both byte
// layers, and segmented/coalesced headers with payload larger than a TLS record.
void Case(bool outbound, bool tls, bool upgrade, bool fragmented, bool abortive) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    net::experimental::channel<void(::IoErrorCode)> peer_finished(io, 1);
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer_socket(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer_socket);
    auto raw = std::make_unique<::transport::internet::TcpStream>(std::move(socket));
    const int native = raw->NativeHandle();
    raw->SetIdleTimeout(3s);
    raw->SetReadTimeout(2s);
    raw->SetWriteTimeout(2s);
    (void)raw->StartPhaseDeadline(3s);

    const auto fixtures = std::filesystem::path(CNODE_TEST_SOURCE_DIR) / "tests/fixtures/anytls-pool";
    ::transport::internet::StreamSettings settings;
    settings.network_mode = upgrade ? ::transport::internet::NetworkMode::HttpUpgrade : ::transport::internet::NetworkMode::Http;
    settings.http.path = settings.http_upgrade.path = "/up";
    settings.http.host = settings.http_upgrade.host = "localhost";
    settings.http.method = "GET";
    settings.security_mode = tls ? ::transport::internet::SecurityMode::Tls : ::transport::internet::SecurityMode::None;
    settings.tls.alpn = {"http/1.1"};
    settings.tls.allow_insecure = true;
    settings.tls.server_name = "localhost";
    if (!outbound) {
        settings.tls.cert_file = (fixtures / "cert.pem").string();
        settings.tls.key_file = (fixtures / "key.pem").string();
    }
    ::transport::internet::LoadTlsPemMaterial(settings.tls);
    settings = ::transport::internet::NormalizeStreamSettings(settings);
    const ::transport::internet::TransportSecurity security(
        settings, outbound ? ::transport::internet::StreamEndpointRole::Outbound : ::transport::internet::StreamEndpointRole::Inbound);
    net::ssl::context context(net::ssl::context::tls);
    context.set_verify_mode(net::ssl::verify_none);
    if (tls && outbound) {
        context.use_certificate_chain_file((fixtures / "cert.pem").string());
        context.use_private_key_file((fixtures / "key.pem").string(), net::ssl::context::pem);
    }
    net::ssl::stream<::tcp::socket> secured(std::move(peer_socket), context);
    std::string payload(24017, '\0');
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i % 251);
    const std::string request = "GET /up HTTP/1.1\r\nHost: localhost\r\n" +
        std::string(upgrade ? "Connection: Upgrade\r\nUpgrade: websocket\r\n" : "") + "\r\n";
    const std::string response = upgrade
        ? "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        : "HTTP/1.1 200 OK\r\n\r\n";
    bool peer_eof = false, cancelled = false;
    size_t completed = 0;
    std::exception_ptr error;
    std::unique_ptr<::transport::AsyncStream> stream;

    auto peer = [&]<typename Peer>(Peer& wire) -> net::awaitable<void> {
        if (outbound) {
            std::string header;
            char byte;
            do {
                co_await net::async_read(wire, net::buffer(&byte, 1), net::use_awaitable);
                header += byte;
            } while (!header.ends_with("\r\n\r\n"));
            EXPECT_TRUE(header.starts_with("GET /up HTTP/1.1\r\n")) << "unexpected outbound HTTP request";
        }
        const auto& header = outbound ? response : request;
        if (fragmented) {
            for (size_t offset = 0; offset < header.size() - 2; offset += 7) {
                const size_t size = std::min<size_t>(7, header.size() - 2 - offset);
                co_await net::async_write(wire, net::buffer(header.data() + offset, size), net::use_awaitable);
                net::steady_timer delay(io, 1ms);
                co_await delay.async_wait(net::use_awaitable);
            }
            const auto suffix = header.substr(header.size() - 2) + payload;
            co_await net::async_write(wire, net::buffer(suffix), net::use_awaitable);
        } else {
            const auto combined = header + payload;
            co_await net::async_write(wire, net::buffer(combined), net::use_awaitable);
        }
        if (!outbound) {
            std::string record_header;
            char byte;
            do {
                co_await net::async_read(wire, net::buffer(&byte, 1), net::use_awaitable);
                record_header += byte;
            } while (!record_header.ends_with("\r\n\r\n"));
            EXPECT_TRUE(record_header.starts_with(upgrade ? "HTTP/1.1 101 " : "HTTP/1.1 200 ")) << "unexpected inbound response";
        }
        std::array<char, 3> ack{};
        co_await net::async_read(wire, net::buffer(ack), net::use_awaitable);
        EXPECT_EQ(std::string_view(ack.data(), ack.size()), "ack") << "cancellation disturbed writes";
        co_await net::async_write(wire, net::buffer("end", 3), net::use_awaitable);
        char byte;
        auto [ec, n] = co_await wire.async_read_some(net::buffer(&byte, 1), net::as_tuple(net::use_awaitable));
        if (abortive) {
            EXPECT_EQ(n, 0);
            EXPECT_TRUE(ec == net::error::connection_reset ||
                        ec == net::ssl::error::stream_truncated || (!tls && ec == net::error::eof));
        } else {
            EXPECT_EQ(ec, net::error::eof);
            EXPECT_EQ(n, 0);
        }
        peer_eof = true;
    };
    auto peer_task = [&]() -> net::awaitable<void> {
        if (tls) {
            co_await secured.async_handshake(outbound ? net::ssl::stream_base::server : net::ssl::stream_base::client,
                                             net::use_awaitable);
            co_await peer(secured);
            if (!abortive) co_await secured.async_shutdown(net::use_awaitable);
        } else {
            co_await peer(secured.next_layer());
            if (!abortive) secured.next_layer().shutdown(::tcp::socket::shutdown_send);
        }
        EXPECT_TRUE(peer_finished.try_send(::IoErrorCode{})) << "peer shutdown completion was lost";
    };
    auto product = [&]() -> net::awaitable<void> {
        if (!outbound && !tls && !fragmented) {
            // A previous byte-level handshake can already have several blocks
            // retained. The HTTP read consumes only its first 8KB; its own
            // read-ahead must be returned in front of the still-retained tail.
            std::string retained;
            std::array<char, ::buf::Buffer::kSize> block{};
            while (retained.size() < request.size() + payload.size()) {
                const size_t n = co_await raw->AsyncRead(net::buffer(
                    block.data(), std::min(block.size(), request.size() + payload.size() - retained.size())));
                EXPECT_NE(n, 0) << "preexisting byte-layer residual truncated";
                if (n == 0) throw std::runtime_error("cannot continue with truncated residual");
                retained.append(block.data(), n);
            }
            raw->PrependReadData(Bytes(retained));
        }
        ::transport::internet::TransportBuildResult built;
        if (outbound) {
            built = co_await ::transport::internet::BuildOutboundTransport(std::move(raw), settings, security.Context());
        } else {
            built = co_await ::transport::internet::BuildInboundTransport(transport_coordinator.Coordinator(), io, std::move(raw), settings, security.Context());
        }
        EXPECT_TRUE(built.has_value()) << "HTTP transport handshake failed";
        if (!built || !*built) throw std::runtime_error("cannot read from failed HTTP handshake");
        stream = std::move(*built);
        EXPECT_EQ(stream->NativeHandle(), native) << "handshake changed underlying socket ownership";
        stream->ClearPhaseDeadline();
        // Force a prepend while the actual read end still has handshake residual.
        // This prefix must precede both that residual and unread SSL/socket input.
        Prepend(*stream, "prefix");
        const auto pending_live = ::memory::detail::test_buffers_live;
        ::memory::reject_next_process_allocation = true;
        bool failed = false;
        try { Prepend(*stream, "must-not-appear"); } catch (const std::bad_alloc&) { failed = true; }
        catch (...) { ::memory::reject_next_process_allocation = false; throw; }
        ::memory::reject_next_process_allocation = false;
        EXPECT_TRUE(failed);
        EXPECT_EQ(::memory::detail::test_buffers_live, pending_live);
        std::string received;
        std::array<char, 3> small{};
        for (size_t i = 0; i < 5; ++i) {
            const size_t n = co_await stream->AsyncRead(net::buffer(small));
            EXPECT_NE(n, 0) << "small read lost handshake payload";
            if (n == 0) throw std::runtime_error("cannot continue after payload EOF");
            received.append(small.data(), n);
        }
        while (received.size() < payload.size() + 6) {
            auto buffers = co_await stream->ReadMultiBuffer();
            EXPECT_NE(buffers.byte_size(), 0) << "multi-buffer read truncated payload";
            if (buffers.empty()) throw std::runtime_error("cannot continue after payload EOF");
            received += Flatten(buffers);
        }
        EXPECT_EQ(received, "prefix" + payload) << "read-ahead lost, duplicated, decrypted at wrong layer, or reordered";
        EXPECT_EQ(::memory::detail::test_buffers_live, 0) << "consumed handshake residual retained payload blocks";
        net::steady_timer cancel(io, 5ms);
        cancel.async_wait([&](::IoErrorCode ec) { if (!ec) stream->Cancel(); });
        try {
            if (fragmented) {
                (void)co_await stream->ReadMultiBuffer();
            } else {
                (void)co_await stream->AsyncRead(net::buffer(small));
            }
        } catch (const ::IoSystemError& failure) {
            if (failure.code() != ::io_error::operation_aborted) throw;
            cancelled = true;
        }
        EXPECT_TRUE(cancelled);
        EXPECT_TRUE(stream->IsOpen());
        co_await stream->AsyncWrite(net::buffer("ack", 3));
        received.clear();
        while (received.size() < 3) {
            const size_t n = co_await stream->AsyncRead(net::buffer(small));
            EXPECT_NE(n, 0) << "transport failed to resume after cancellation";
            if (n == 0) throw std::runtime_error("cannot continue after resumed read EOF");
            received.append(small.data(), n);
        }
        EXPECT_EQ(received, "end") << "resumed transport corrupted input";
        if (!abortive) {
            co_await stream->AsyncShutdownWrite();
            co_await stream->AsyncShutdownWrite();
            Prepend(*stream, "discard-on-shutdown");
            stream->ShutdownRead();
            stream->ShutdownRead();
            EXPECT_EQ(co_await stream->AsyncRead(net::buffer(small)), 0) << "read shutdown leaked retained plaintext";
            EXPECT_EQ((co_await stream->ReadMultiBuffer()).byte_size(), 0) << "read shutdown leaked multi-buffer data";
            // Join the peer's graceful half-close before a repeated abortive close
            // can reset its socket; otherwise its shutdown_send races with RST.
            co_await peer_finished.async_receive(net::use_awaitable);
        } else {
            Prepend(*stream, "discard-on-abortive-close");
        }
        stream->CloseAbortive();
        stream->CloseAbortive();
        stream->Close();
        EXPECT_FALSE(stream->IsOpen()) << "repeated close left transport open";
        EXPECT_EQ(co_await stream->AsyncRead(net::buffer(small)), 0) << "closed transport leaked read-ahead";
        EXPECT_EQ((co_await stream->ReadMultiBuffer()).byte_size(), 0) << "closed transport leaked multi-buffer data";
        EXPECT_EQ(::memory::detail::test_buffers_live, 0) << "shutdown/close retained payload blocks";
    };
    auto finish = [&](std::exception_ptr failure) {
        if (failure && !error) {
            error = failure;
            peer_finished.close();
            if (stream) stream->CloseAbortive();
            if (raw) raw->Close();
            ::IoErrorCode ignored;
            secured.next_layer().close(ignored);
        }
        ++completed;
    };
    net::co_spawn(io, peer_task(), finish);
    net::co_spawn(io, product(), finish);
    io.run_for(5s);
    EXPECT_EQ(completed, 2);
    if (completed != 2) {
        peer_finished.close();
        if (stream) stream->CloseAbortive();
        if (raw) raw->Close();
        ::IoErrorCode ignored;
        secured.next_layer().close(ignored);
        io.restart();
        io.run();
    }
    if (error) std::rethrow_exception(error);
    EXPECT_TRUE(cancelled);
    EXPECT_TRUE(peer_eof);
}


void WriteTimeoutResetsQueuedPayload() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    socket.set_option(net::socket_base::send_buffer_size(4096));
    peer.set_option(net::socket_base::receive_buffer_size(4096));
    ::transport::internet::TcpStream stream(std::move(socket));
    stream.SetWriteTimeout(1s);
    bool completed = false;
    std::exception_ptr error;
    auto exercise = [&]() -> net::awaitable<void> {
        // No peer reads until the blocked writer's deadline has fired. A
        // graceful close would leave the kernel draining this queued payload.
        const std::string payload(1024 * 1024, 'x');
        bool cancelled = false;
        try { (void)co_await stream.AsyncWrite(net::buffer(payload)); }
        catch (const ::IoSystemError& failure) {
            EXPECT_EQ(failure.code(), ::io_error::operation_aborted) << "write deadline failed with unrelated I/O error";
            cancelled = true;
        }
        EXPECT_TRUE(cancelled);
        EXPECT_TRUE(stream.ConsumeWriteTimeout());
        EXPECT_FALSE(stream.IsOpen());
        std::array<char, 8192> buffer{};
        for (;;) {
            auto [ec, size] = co_await peer.async_read_some(
                net::buffer(buffer), net::as_tuple(net::use_awaitable));
            if (ec) {
                EXPECT_EQ(ec, net::error::connection_reset) << "write deadline gracefully drained payload instead of resetting";
                break;
            }
            EXPECT_NE(size, 0) << "write deadline peer read made no progress";
            if (size == 0) throw std::runtime_error("cannot continue without read progress");
        }
    };
    net::co_spawn(io, exercise(), [&](std::exception_ptr failure) {
        error = failure;
        completed = true;
    });
    io.run_for(3s);
    EXPECT_TRUE(completed);
    if (!completed) {
        stream.CloseAbortive();
        ::IoErrorCode ignored;
        peer.close(ignored);
        io.restart();
        io.run();
    }
    if (error) std::rethrow_exception(error);
}

void ExistingTcpResidual() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    ::transport::internet::TcpStream stream(std::move(socket));
    // More than eight blocks exercises spill metadata while the old residual
    // is transferred behind the new prefix without copying its payload.
    const std::string tail(10 * ::buf::Buffer::kSize, 't');
    stream.PrependReadData(Bytes(tail));
    stream.PrependReadData(Bytes("head"));
    bool done = false;
    std::exception_ptr error;
    auto read = [&]() -> net::awaitable<void> {
        char byte{};
        EXPECT_EQ(co_await stream.AsyncRead(net::buffer(&byte, 1)), 1);
        EXPECT_EQ(byte, 'h');
        auto data = co_await stream.ReadMultiBuffer();
        EXPECT_EQ(Flatten(data), "ead" + tail) << "preexisting residual was lost or reordered";
        data.clear();
        stream.PrependReadData(Bytes("discard"));
        stream.Close();
        EXPECT_EQ((co_await stream.ReadMultiBuffer()).byte_size(), 0) << "close leaked old residual";
    };
    net::co_spawn(io, read(), [&](std::exception_ptr failure) { error = failure; done = true; });
    io.run_for(1s);
    EXPECT_TRUE(done);
    if (!done) {
        stream.CloseAbortive();
        io.restart();
        io.run();
    }
    if (error) std::rethrow_exception(error);
}

void TlsReadTermination(bool multi_buffer, bool clean) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer_socket(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer_socket);
    const auto fixtures = std::filesystem::path(CNODE_TEST_SOURCE_DIR) / "tests/fixtures/anytls-pool";
    net::ssl::context server_context(net::ssl::context::tls_server);
    server_context.use_certificate_chain_file((fixtures / "cert.pem").string());
    server_context.use_private_key_file((fixtures / "key.pem").string(), net::ssl::context::pem);
    ::transport::internet::TlsConfig client_config;
    client_config.allow_insecure = true;
    auto client_context = ::transport::internet::SslContext::CreateClient(client_config);
    ASSERT_NE(client_context, nullptr);
    net::ssl::stream<::tcp::socket> peer(std::move(peer_socket), server_context);
    ::transport::internet::TlsStream stream(std::make_unique<::transport::internet::TcpStream>(std::move(socket)),
                           *client_context, false);
    std::exception_ptr failure;
    unsigned completed = 0;
    auto send = [&]() -> net::awaitable<void> {
        co_await peer.async_handshake(net::ssl::stream_base::server, net::use_awaitable);
        const std::array<char, 1> data{'x'};
        co_await net::async_write(peer, net::buffer(data), net::use_awaitable);
        if (clean) {
            co_await peer.async_shutdown(net::use_awaitable);
        } else {
            peer.next_layer().shutdown(::tcp::socket::shutdown_both);
            peer.next_layer().close();
        }
    };
    auto receive = [&]() -> net::awaitable<void> {
        const bool handshaken = co_await stream.Handshake();
        EXPECT_TRUE(handshaken);
        if (!handshaken) throw std::runtime_error("cannot read from failed TLS handshake");
        if (multi_buffer) {
            EXPECT_EQ(Flatten(co_await stream.ReadMultiBuffer()), "x") << "TLS fixture payload changed";
        } else {
            char byte{};
            EXPECT_EQ(co_await stream.AsyncRead(net::buffer(&byte, 1)), 1);
            EXPECT_EQ(byte, 'x');
        }
        bool truncated = false;
        try {
            if (multi_buffer) {
                EXPECT_EQ((co_await stream.ReadMultiBuffer()).byte_size(), 0) << "unexpected TLS payload";
            } else {
                char byte{};
                EXPECT_EQ(co_await stream.AsyncRead(net::buffer(&byte, 1)), 0) << "unexpected TLS payload";
            }
        } catch (const ::IoSystemError& error) {
            if (error.code() != net::ssl::error::stream_truncated) throw;
            truncated = true;
        }
        EXPECT_EQ(truncated, !clean) << "TLS truncation was confused with authenticated EOF";
        if (clean) co_await stream.AsyncShutdownWrite();
    };
    auto finish = [&](std::exception_ptr error) {
        if (error && !failure) {
            failure = error;
            stream.CloseAbortive();
            ::IoErrorCode ignored;
            peer.next_layer().close(ignored);
        }
        ++completed;
    };
    net::co_spawn(io, send(), finish);
    net::co_spawn(io, receive(), finish);
    io.run_for(3s);
    EXPECT_EQ(completed, 2);
    if (completed != 2) {
        stream.CloseAbortive();
        ::IoErrorCode ignored;
        peer.next_layer().close(ignored);
        io.restart();
        io.run();
    }
    if (failure) std::rethrow_exception(failure);
}

// Independent wire encoder/decoder: do not validate cnode with its own framing.
std::string WsWireFrame(uint8_t opcode, std::string_view payload, bool masked, bool fin = true) {
    std::string frame;
    frame.push_back(static_cast<char>((fin ? 0x80 : 0) | opcode));
    const unsigned mask_bit = masked ? 0x80 : 0;
    if (payload.size() < 126) {
        frame.push_back(static_cast<char>(mask_bit | payload.size()));
    } else if (payload.size() <= 65535) {
        frame.push_back(static_cast<char>(mask_bit | 126));
        frame.push_back(static_cast<char>(payload.size() >> 8));
        frame.push_back(static_cast<char>(payload.size()));
    } else {
        frame.push_back(static_cast<char>(mask_bit | 127));
        for (int shift = 56; shift >= 0; shift -= 8)
            frame.push_back(static_cast<char>(static_cast<uint64_t>(payload.size()) >> shift));
    }
    constexpr std::array<uint8_t, 4> mask{0x13, 0x57, 0x9b, 0xdf};
    if (masked) frame.append(reinterpret_cast<const char*>(mask.data()), mask.size());
    const size_t offset = frame.size();
    frame.append(payload);
    if (masked)
        for (size_t i = 0; i < payload.size(); ++i)
            frame[offset + i] = static_cast<char>(static_cast<uint8_t>(payload[i]) ^ mask[i % 4]);
    return frame;
}

struct WsWireHeader {
    uint8_t opcode = 0;
    size_t size = 0;
    std::array<uint8_t, 4> mask{};
    bool masked = false;
};

net::awaitable<WsWireHeader> ReadWsWireHeader(::tcp::socket& peer, bool masked) {
    std::array<uint8_t, 2> bytes{};
    co_await net::async_read(peer, net::buffer(bytes), net::use_awaitable);
    EXPECT_EQ((bytes[0] & 0xf0), 0x80) << "WS writer emitted fragmented/reserved header";
    WsWireHeader header;
    header.opcode = bytes[0] & 0x0f;
    header.masked = (bytes[1] & 0x80) != 0;
    EXPECT_EQ(header.masked, masked) << "WS writer used wrong mask direction";
    const unsigned length = bytes[1] & 0x7f;
    uint64_t size = length;
    if (length >= 126) {
        std::array<uint8_t, 8> extended{};
        const size_t count = length == 126 ? 2 : 8;
        co_await net::async_read(peer, net::buffer(extended.data(), count), net::use_awaitable);
        size = 0;
        for (size_t i = 0; i < count; ++i) size = (size << 8) | extended[i];
        if (length == 126) {
            EXPECT_GE(size, 126);
        } else {
            EXPECT_GE(size, 65536);
        }
    }
    EXPECT_LE(size, 4 * 1024 * 1024) << "WS writer emitted an unexpected payload size";
    if (size > 4 * 1024 * 1024) throw std::runtime_error("cannot allocate unbounded WS fixture payload");
    header.size = static_cast<size_t>(size);
    if (masked) co_await net::async_read(peer, net::buffer(header.mask), net::use_awaitable);
    co_return header;
}

net::awaitable<std::string> ReadWsWirePayload(::tcp::socket& peer, const WsWireHeader& header) {
    std::string payload(header.size, '\0');
    if (!payload.empty())
        co_await net::async_read(peer, net::buffer(payload), net::use_awaitable);
    if (header.masked)
        for (size_t i = 0; i < payload.size(); ++i)
            payload[i] = static_cast<char>(static_cast<uint8_t>(payload[i]) ^ header.mask[i % 4]);
    co_return payload;
}

net::awaitable<std::string> ReadWsWireFrame(
    ::tcp::socket& peer, bool masked, uint8_t opcode) {
    const auto header = co_await ReadWsWireHeader(peer, masked);
    EXPECT_EQ(header.opcode, opcode) << "WS writer interleaved or misclassified a frame";
    co_return co_await ReadWsWirePayload(peer, header);
}

net::awaitable<void> ReadWireEof(::tcp::socket& peer) {
    char byte{};
    const auto [error, size] = co_await peer.async_read_some(
        net::buffer(&byte, 1), net::as_tuple(net::use_awaitable));
    EXPECT_EQ(error, net::error::eof);
    EXPECT_EQ(size, 0);
}

void WsResume(bool client, bool multi_buffer, size_t size, size_t cut, uint8_t opcode = 2) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    ::transport::internet::BaseWsStream stream(std::make_unique<::transport::internet::TcpStream>(std::move(socket)), client);
    std::string payload(size, '\0');
    for (size_t i = 0; i < size; ++i) payload[i] = static_cast<char>(i % 251);
    if (opcode == 8) payload = size == 0 ? "" : std::string("\x03\xe8", 2) + "bye";
    std::string frame;
    if (opcode == 1) {
        payload = std::string("\xe2\x82\xac", 3) + "tail";
        frame = WsWireFrame(1, std::string_view(payload).substr(0, 1), !client, false) +
                WsWireFrame(10, "ignored", !client) + WsWireFrame(9, "probe", !client) +
                WsWireFrame(0, std::string_view(payload).substr(1, 2), !client) +
                WsWireFrame(2, "tail", !client);
    } else {
        frame = WsWireFrame(opcode, payload, !client);
    }
    ASSERT_LT(cut, frame.size());
    // Handshake residual is deterministic: the entire prefix is consumed before
    // the first socket wait, then Cancel interrupts that actual lower read.
    ::buf::MultiBuffer residual;
    ASSERT_TRUE(::buf::AppendSpanToMultiBuffer(
        {reinterpret_cast<const uint8_t*>(frame.data()), cut}, residual));
    stream.SetPendingMultiBuffer(std::move(residual));
    const std::string application = opcode == 2 || opcode == 1 ? payload : "application";
    bool cancelled = false;
    size_t completed = 0;
    std::exception_ptr failure;
    auto receive = [&]() -> net::awaitable<void> {
        std::string received;
        std::array<char, 4096> buffer{};
        const auto read = [&]() -> net::awaitable<std::string> {
            if (multi_buffer) co_return Flatten(co_await stream.ReadMultiBuffer());
            const size_t n = co_await stream.AsyncRead(net::buffer(buffer));
            co_return std::string(buffer.data(), n);
        };
        try {
            while (true) {
                const auto bytes = co_await read();
                EXPECT_FALSE(bytes.empty()) << "WS cancellation was converted to EOF";
                if (bytes.empty()) throw std::runtime_error("cannot continue after WS EOF");
                received += bytes;
            }
        } catch (const ::IoSystemError& error) {
            if (error.code() != net::error::operation_aborted) throw;
            cancelled = true;
        }
        EXPECT_TRUE(stream.IsOpen()) << "WS read cancellation closed the connection";
        if (opcode == 2) {
            const size_t header_size = (size < 126 ? 2 : size <= 65535 ? 4 : 10) + (client ? 0 : 4);
            const size_t prefix = cut > header_size ? cut - header_size : 0;
            EXPECT_EQ(received, payload.substr(0, prefix)) << "WS read waited to fill its caller buffer before delivering available payload";
        }
        co_await stream.AsyncWrite(net::buffer("ack", 3));
        if (opcode == 8) {
            EXPECT_TRUE((co_await read()).empty()) << "complete WS Close leaked application bytes";
        } else {
            while (received.size() < application.size()) {
                const auto bytes = co_await read();
                EXPECT_FALSE(bytes.empty()) << "WS resumed with premature EOF";
                if (bytes.empty()) throw std::runtime_error("cannot continue after WS EOF");
                received += bytes;
            }
            EXPECT_EQ(received, application) << "WS cancellation lost, repeated, or remasked bytes";
            co_await stream.AsyncShutdownWrite();
            co_await stream.AsyncShutdownWrite();
        }
    };
    auto wire = [&]() -> net::awaitable<void> {
        EXPECT_EQ(co_await ReadWsWireFrame(peer, client, 2), "ack") << "WS cancellation disturbed writes";
        std::string suffix = frame.substr(cut);
        if (opcode == 9) suffix += WsWireFrame(2, application, !client);
        co_await net::async_write(peer, net::buffer(suffix), net::use_awaitable);
        if (opcode == 9 || opcode == 1)
            EXPECT_EQ(co_await ReadWsWireFrame(peer, client, 10), (opcode == 1 ? "probe" : payload)) << "WS PONG changed PING payload";
        const auto close = co_await ReadWsWireFrame(peer, client, 8);
        EXPECT_EQ(close, (opcode == 8 ? payload : std::string("\x03\xe8", 2))) << "WS Close payload was not preserved";
        co_await ReadWireEof(peer);
    };
    auto finish = [&](std::exception_ptr error) {
        if (error && !failure) {
            failure = error;
            stream.CloseAbortive();
            ::IoErrorCode ignored;
            peer.close(ignored);
        }
        ++completed;
    };
    net::co_spawn(io, receive(), finish);
    net::post(io, [&] { stream.Cancel(); });
    net::co_spawn(io, wire(), finish);
    io.run_for(3s);
    EXPECT_EQ(completed, 2);
    if (completed != 2) {
        stream.CloseAbortive();
        ::IoErrorCode ignored;
        peer.close(ignored);
        io.restart();
        io.run();
    }
    if (failure) std::rethrow_exception(failure);
    EXPECT_TRUE(cancelled);
}

enum class WsConcurrent { Ping, Close, Cancel };

void WsWriteBoundary(WsConcurrent action, bool owned) {
    net::io_context io;
    net::experimental::channel<void(::IoErrorCode)> close_now(io, 1);
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    socket.set_option(net::socket_base::send_buffer_size(4096));
    ::transport::internet::BaseWsStream stream(std::make_unique<::transport::internet::TcpStream>(std::move(socket)), true);
    std::string payload(1024 * 1024 + 19, '\0');
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i % 251);
    bool data_done = false, control_done = false;
    bool write_cancelled = false, close_cancelled = false;
    size_t completed = 0;
    std::exception_ptr failure;
    auto send = [&]() -> net::awaitable<void> {
        try {
            if (owned) {
                ::buf::MultiBuffer buffers;
                size_t offset = 0;
                while (offset < payload.size()) {
                    ::buf::BufferGuard buffer{::buf::Buffer::New()};
                    if (!buffer) throw std::bad_alloc();
                    const size_t count = std::min(payload.size() - offset,
                                                  static_cast<size_t>(buffer->Available()));
                    std::memcpy(buffer->Tail().data(), payload.data() + offset, count);
                    buffer->Produce(static_cast<uint32_t>(count));
                    buffers.push_back(std::move(buffer));
                    offset += count;
                }
                co_await stream.WriteMultiBuffer(std::move(buffers));
            } else {
                const std::array<net::const_buffer, 3> buffers{
                    net::buffer(payload.data(), 3),
                    net::buffer(payload.data() + 3, 65536),
                    net::buffer(payload.data() + 65539, payload.size() - 65539)};
                co_await stream.WriteBuffers(buffers);
            }
            data_done = true;
        } catch (const ::IoSystemError& error) {
            if (action != WsConcurrent::Cancel || error.code() != net::error::operation_aborted) throw;
            write_cancelled = true;
            EXPECT_FALSE(stream.IsOpen()) << "cancelled partial WS frame did not abort transport";
        }
    };
    auto control = [&]() -> net::awaitable<void> {
        if (action == WsConcurrent::Ping) {
            std::array<char, 32> buffer{};
            const size_t n = co_await stream.AsyncRead(net::buffer(buffer));
            EXPECT_EQ(std::string_view(buffer.data(), n), "ready") << "WS PING escaped as application payload";
        } else {
            co_await close_now.async_receive(net::use_awaitable);
        }
        try {
            co_await stream.AsyncShutdownWrite();
            co_await stream.AsyncShutdownWrite();
            control_done = true;
        } catch (const ::IoSystemError& error) {
            if (action != WsConcurrent::Cancel || error.code() != net::error::operation_aborted) throw;
            close_cancelled = true;
        }
    };
    auto wire = [&]() -> net::awaitable<void> {
        const auto header = co_await ReadWsWireHeader(peer, true);
        EXPECT_EQ(header.opcode, 2);
        EXPECT_EQ(header.size, payload.size());
        EXPECT_FALSE(data_done) << "WS write fixture did not establish backpressure";
        if (action == WsConcurrent::Ping) {
            const auto input = WsWireFrame(9, "probe", false) + WsWireFrame(2, "ready", false);
            co_await net::async_write(peer, net::buffer(input), net::use_awaitable);
        } else {
            EXPECT_TRUE(close_now.try_send(::IoErrorCode{})) << "WS concurrent close signal was lost";
            co_await net::post(io, net::use_awaitable);
            EXPECT_FALSE(control_done) << "WS Close completed in the middle of a data frame";
        }
        if (action == WsConcurrent::Cancel) {
            stream.Cancel();
            co_return;
        }
        EXPECT_EQ(co_await ReadWsWirePayload(peer, header), payload) << "WS control frame was inserted inside physical data payload";
        if (action == WsConcurrent::Ping)
            EXPECT_EQ(co_await ReadWsWireFrame(peer, true, 10), "probe") << "WS backpressured PONG changed payload";
        EXPECT_EQ(co_await ReadWsWireFrame(peer, true, 8), std::string("\x03\xe8", 2)) << "WS concurrent Close was incomplete";
        co_await ReadWireEof(peer);
    };
    auto finish = [&](std::exception_ptr error) {
        if (error && !failure) {
            failure = error;
            close_now.close();
            stream.CloseAbortive();
            ::IoErrorCode ignored;
            peer.close(ignored);
        }
        ++completed;
    };
    net::co_spawn(io, send(), finish);
    net::co_spawn(io, control(), finish);
    net::co_spawn(io, wire(), finish);
    io.run_for(5s);
    EXPECT_EQ(completed, 3);
    if (completed != 3) {
        close_now.close();
        stream.CloseAbortive();
        ::IoErrorCode ignored;
        peer.close(ignored);
        io.restart();
        io.run();
    }
    if (failure) std::rethrow_exception(failure);
    if (action == WsConcurrent::Cancel) {
        EXPECT_TRUE(write_cancelled);
        EXPECT_TRUE(close_cancelled);
    } else {
        EXPECT_TRUE(data_done);
        EXPECT_TRUE(control_done);
    }
}

void WsReject(std::string_view frame, bool client, bool multi_buffer) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    ::transport::internet::BaseWsStream stream(std::make_unique<::transport::internet::TcpStream>(std::move(socket)), client);
    ::buf::MultiBuffer residual;
    ASSERT_TRUE(::buf::AppendSpanToMultiBuffer(
        {reinterpret_cast<const uint8_t*>(frame.data()), frame.size()}, residual));
    stream.SetPendingMultiBuffer(std::move(residual));
    peer.shutdown(::tcp::socket::shutdown_send);
    bool rejected = false, done = false;
    std::exception_ptr failure;
    auto receive = [&]() -> net::awaitable<void> {
        try {
            if (multi_buffer) {
                (void)co_await stream.ReadMultiBuffer();
            } else {
                std::array<char, 256> bytes{};
                (void)co_await stream.AsyncRead(net::buffer(bytes));
            }
        } catch (const ::IoSystemError& error) {
            EXPECT_NE(error.code(), net::error::operation_aborted) << "WS protocol failure became cancellation";
            rejected = true;
        }
        EXPECT_TRUE(rejected);
        EXPECT_FALSE(stream.IsOpen());
    };
    net::co_spawn(io, receive(), [&](std::exception_ptr error) { failure = error; done = true; });
    io.run_for(1s);
    EXPECT_TRUE(done);
    if (!done) {
        stream.CloseAbortive();
        io.restart();
        io.run();
    }
    if (failure) std::rethrow_exception(failure);
}


void UpgradeHeaderTokens(bool outbound, bool websocket,
                         std::string_view connection, bool accepted) {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    auto raw = std::make_unique<::transport::internet::TcpStream>(std::move(socket));
    raw->SetIdleTimeout(2s);
    ::transport::internet::StreamSettings settings;
    settings.network_mode = websocket ? ::transport::internet::NetworkMode::Ws : ::transport::internet::NetworkMode::HttpUpgrade;
    settings.ws.path = settings.http_upgrade.path = "/up";
    settings.security_mode = ::transport::internet::SecurityMode::None;
    settings = ::transport::internet::NormalizeStreamSettings(settings);
    std::exception_ptr error;
    size_t completed = 0;
    auto finish = [&](std::exception_ptr failure) {
        if (failure && !error) {
            error = failure;
            if (raw) raw->Close();
            ::IoErrorCode ignored;
            peer.close(ignored);
        }
        ++completed;
    };
    auto wire = [&]() -> net::awaitable<void> {
        std::string message;
        if (outbound) {
            std::string request;
            char byte;
            do {
                co_await net::async_read(peer, net::buffer(&byte, 1), net::use_awaitable);
                request += byte;
            } while (!request.ends_with("\r\n\r\n"));
            message = "HTTP/1.1 101 Switching Protocols\r\n";
            if (websocket) {
                const auto key = common::TrimAscii(
                    ::transport::internet::ExtractHeaderValueCI(request, "Sec-WebSocket-Key"));
                const auto accept = ::ws::EncodeWsAccept(key);
                message += "Sec-WebSocket-Accept: ";
                message += std::string_view(accept.data(), accept.size());
                message += "\r\n";
            }
        } else {
            message = "GET /up HTTP/1.1\r\nHost: localhost\r\n"
                      "Sec-WebSocket-Version: 13\r\n"
                      "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
        }
        message += "Upgrade: WebSocket\r\n";
        message += connection;
        message += "\r\n";
        co_await net::async_write(peer, net::buffer(message), net::use_awaitable);
    };
    auto product = [&]() -> net::awaitable<void> {
        ::transport::internet::TransportBuildResult built;
        if (outbound) {
            built = co_await ::transport::internet::BuildOutboundTransport(std::move(raw), settings, nullptr);
        } else {
            built = co_await ::transport::internet::BuildInboundTransport(transport_coordinator.Coordinator(), io, std::move(raw), settings, nullptr);
        }
        EXPECT_EQ(built.has_value(), accepted) << "Connection header token handshake mismatch";
        if (built && *built) (*built)->Close();
    };
    net::co_spawn(io, wire(), finish);
    net::co_spawn(io, product(), finish);
    io.run_for(3s);
    EXPECT_EQ(completed, 2);
    if (completed != 2) {
        if (raw) raw->Close();
        ::IoErrorCode ignored;
        peer.close(ignored);
        io.restart();
        io.run();
    }
    if (error) std::rethrow_exception(error);
}

void ChunkExtensionBody(std::string_view wire, bool accepted, bool multi_buffer) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    auto raw = std::make_unique<::transport::internet::TcpStream>(std::move(socket));
    raw->SetIdleTimeout(2s);
    auto stream = ::transport::internet::MakeHttp1BodyStream(
        std::move(raw), ::transport::internet::Http1BodyChunked{}, false);
    std::exception_ptr error;
    size_t completed = 0;
    auto finish = [&](std::exception_ptr failure) {
        if (failure && !error) {
            error = failure;
            stream->Close();
            ::IoErrorCode ignored;
            peer.close(ignored);
        }
        ++completed;
        // The stream is retained by this fixture, not by either coroutine.
        // Once both peers have joined, retire its idle timer as well; otherwise
        // every successful grammar rejection keeps io.run alive for two seconds.
        if (completed == 2) stream->Close();
    };
    auto sender = [&]() -> net::awaitable<void> {
        // Separate asynchronous writes exercise parser state at every byte.
        for (const char& byte : wire)
            co_await net::async_write(peer, net::buffer(&byte, 1), net::use_awaitable);
        peer.shutdown(::tcp::socket::shutdown_send);
    };
    auto receiver = [&]() -> net::awaitable<void> {
        bool rejected = false;
        std::string body;
        try {
            for (;;) {
                if (multi_buffer) {
                    auto buffers = co_await stream->ReadMultiBuffer();
                    if (buffers.empty()) break;
                    body += Flatten(buffers);
                } else {
                    std::array<char, 2> bytes;
                    const auto n = co_await stream->AsyncRead(net::buffer(bytes));
                    if (n == 0) break;
                    body.append(bytes.data(), n);
                }
            }
        } catch (const ::IoSystemError& failure) {
            EXPECT_EQ(failure.code(), ::io_error::invalid_argument) << "chunk boundary failed with unrelated I/O error";
            rejected = true;
        }
        EXPECT_NE(rejected, accepted) << "transport chunk grammar acceptance mismatch";
        if (accepted) EXPECT_EQ(body, "OK") << "transport chunk decoder leaked framing bytes";
    };
    net::co_spawn(io, sender(), finish);
    net::co_spawn(io, receiver(), finish);
    io.run_for(3s);
    EXPECT_EQ(completed, 2);
    if (completed != 2) {
        stream->Close();
        ::IoErrorCode ignored;
        peer.close(ignored);
        io.restart();
        io.run();
    }
    if (error) std::rethrow_exception(error);
}


class CloseHttpLogStream final : public ::transport::internet::InboundTransportStreamHandler {
public:
    net::awaitable<void> OnInboundTransportStream(
        std::unique_ptr<::transport::AsyncStream> stream, ::transport::internet::InboundTransportMetadata) override {
        stream->Close();
        co_return;
    }
};

// Observe actual transport responses and emitted diagnostics together. The
// logger must not silently "fix" protocol input to achieve redaction.
void HttpLogHandshake(std::string_view network, bool outbound,
                      std::string_view line, bool accepted,
                      std::string_view path = "/up",
                      std::string_view host = "localhost") {
    net::io_context io;
    TransportCoordinatorFixture transport_coordinator{io};
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    auto raw = std::make_unique<::transport::internet::TcpStream>(std::move(socket));
    raw->SetIdleTimeout(2s);
    ::transport::internet::StreamSettings settings;
    settings.network_mode = transport::internet::ParseNetworkMode(network);
    settings.http.force_http2 = common::EqualsAsciiCI(network, "h2");
    settings.http.path = settings.http_upgrade.path = settings.ws.path =
        settings.xhttp.path = path;
    settings.http.method = "GET";
    settings.xhttp.mode = ::transport::internet::XHttpMode::Auto;
    if (outbound) {
        settings.http.host = settings.http_upgrade.host = host;
        settings.ws.headers.emplace("Host", host);
    }
    settings = ::transport::internet::NormalizeStreamSettings(settings);
    std::exception_ptr error;
    size_t completed = 0;
    auto finish = [&](std::exception_ptr failure) {
        if (failure && !error) {
            error = failure;
            if (raw) raw->Close();
            ::IoErrorCode ignored;
            peer.close(ignored);
        }
        ++completed;
    };
    auto wire = [&]() -> net::awaitable<void> {
        std::string request;
        if (outbound) {
            char byte;
            do {
                co_await net::async_read(peer, net::buffer(&byte, 1), net::use_awaitable);
                request += byte;
            } while (!request.ends_with("\r\n\r\n"));
            EXPECT_NE(request.find(path), std::string::npos) << "HTTP log redaction changed the outbound request target";
        }
        std::string message(line);
        message += "\r\nHost: ";
        message += host;
        message += "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                   "Sec-WebSocket-Version: 13\r\n"
                   "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                   "User-Agent: http://user:review_password@example.com/?token=review_token#review_fragment\r\n"
                   "Content-Length: 0\r\n";
        if (outbound && network == "ws") {
            const auto key = common::TrimAscii(
                ::transport::internet::ExtractHeaderValueCI(request, "Sec-WebSocket-Key"));
            const auto accept = ::ws::EncodeWsAccept(key);
            message += "Sec-WebSocket-Accept: ";
            message += std::string_view(accept.data(), accept.size());
            message += "\r\n";
        }
        message += "\r\n";
        co_await net::async_write(peer, net::buffer(message), net::use_awaitable);
        peer.shutdown(::tcp::socket::shutdown_send);
        if (!outbound && accepted) {
            std::string response;
            char byte;
            do {
                co_await net::async_read(peer, net::buffer(&byte, 1), net::use_awaitable);
                response += byte;
            } while (!response.ends_with("\r\n\r\n"));
            EXPECT_TRUE(response.starts_with(network == "ws" || network == "httpupgrade"
                        ? "HTTP/1.1 101 " : "HTTP/1.1 200 ")) << "HTTP log redaction changed handshake response";
        }
    };
    auto product = [&]() -> net::awaitable<void> {
        ::transport::internet::TransportBuildResult built;
        if (outbound) {
            built = co_await ::transport::internet::BuildOutboundTransport(std::move(raw), settings, nullptr);
        } else {
            const std::shared_ptr<::transport::internet::InboundTransportStreamHandler> sink =
                network == "xhttp" ? std::make_shared<CloseHttpLogStream>() : nullptr;
            built = co_await ::transport::internet::BuildInboundTransport(transport_coordinator.Coordinator(), io, std::move(raw), settings, nullptr, 0, sink);
        }
        EXPECT_EQ(built.has_value(), accepted) << "HTTP log redaction changed request acceptance";
        if (built && *built) (*built)->Close();
    };
    net::co_spawn(io, wire(), finish);
    net::co_spawn(io, product(), finish);
    io.run_for(3s);
    EXPECT_EQ(completed, 2);
    if (completed != 2) {
        if (raw) raw->Close();
        ::IoErrorCode ignored;
        peer.close(ignored);
        io.restart();
        io.run();
    }
    if (error) std::rethrow_exception(error);
}

TEST_F(TransportBehavior, WriteDeadlineResetsQueuedPayload) {
    WriteTimeoutResetsQueuedPayload();
}

TEST_F(TransportBehavior, PrependPreservesExistingTcpResidualAndCloseDiscardsIt) {
    ExistingTcpResidual();
}

class HttpReadAhead : public TransportBehavior,
                     public testing::WithParamInterface<std::tuple<bool, bool, bool, bool, bool>> {};
TEST_P(HttpReadAhead, PreservesReadAheadThroughCancellationAndShutdown) {
    const auto [outbound, tls, upgrade, fragmented, abortive] = GetParam();
    Case(outbound, tls, upgrade, fragmented, abortive);
}
INSTANTIATE_TEST_SUITE_P(TransportModes, HttpReadAhead, testing::Combine(testing::Bool(), testing::Bool(), testing::Bool(), testing::Bool(), testing::Bool()), ([](const auto& info) { const auto [outbound, tls, upgrade, fragmented, abortive] = info.param;
return std::string(outbound ? "Outbound" : "Inbound") + (tls ? "Tls" : "Tcp") +
    (upgrade ? "Upgrade" : "Http") + (fragmented ? "Fragmented" : "Coalesced") +
    (abortive ? "Abortive" : "Graceful"); }));

class TlsTermination : public TransportBehavior,
                       public testing::WithParamInterface<std::tuple<bool, bool>> {};
TEST_P(TlsTermination, DistinguishesAuthenticatedEofFromTruncatedTls) {
    const auto [multi_buffer, clean] = GetParam();
    TlsReadTermination(multi_buffer, clean);
}
INSTANTIATE_TEST_SUITE_P(ReadModes, TlsTermination, testing::Combine(testing::Bool(), testing::Bool()), ([](const auto& info) { const auto [multi, clean] = info.param;
return std::string(multi ? "MultiBuffer" : "SmallRead") + (clean ? "CloseNotify" : "Truncated"); }));

enum class ResumeBoundary { ShortLength, Extended16, Extended64, Mask, Payload, Ping, Close, EmptyClose, Text };
class WsReadResume : public TransportBehavior,
                     public testing::WithParamInterface<std::tuple<bool, bool, ResumeBoundary>> {};
TEST_P(WsReadResume, CancellationPreservesPartialFrameStateAndAllowsWrites) {
    const auto [client, multi, boundary] = GetParam();
    switch (boundary) {
        case ResumeBoundary::ShortLength: WsResume(client, multi, 17, 1); break;
        case ResumeBoundary::Extended16: WsResume(client, multi, 257, 3); break;
        case ResumeBoundary::Extended64: WsResume(client, multi, 65539, 5); break;
        case ResumeBoundary::Mask: WsResume(client, multi, 17, 4); break;
        case ResumeBoundary::Payload: WsResume(client, multi, 257, (client ? 4 : 8) + 3); break;
        case ResumeBoundary::Ping: WsResume(client, multi, 9, (client ? 2 : 6) + 2, 9); break;
        case ResumeBoundary::Close: WsResume(client, multi, 5, (client ? 2 : 6) + 1, 8); break;
        case ResumeBoundary::EmptyClose: WsResume(client, multi, 0, 1, 8); break;
        case ResumeBoundary::Text: WsResume(client, multi, 7, 1, 1); break;
    }
}
std::vector<std::tuple<bool, bool, ResumeBoundary>> ResumeCases() {
    std::vector<std::tuple<bool, bool, ResumeBoundary>> cases;
    for (bool client : {false, true})
        for (bool multi : {false, true})
            for (auto boundary : {ResumeBoundary::ShortLength, ResumeBoundary::Extended16,
                    ResumeBoundary::Extended64, ResumeBoundary::Mask, ResumeBoundary::Payload,
                    ResumeBoundary::Ping, ResumeBoundary::Close, ResumeBoundary::EmptyClose, ResumeBoundary::Text})
                if (!client || boundary != ResumeBoundary::Mask) cases.emplace_back(client, multi, boundary);
    return cases;
}
INSTANTIATE_TEST_SUITE_P(FrameBoundaries, WsReadResume, testing::ValuesIn(ResumeCases()), ([](const auto& info) { const auto [client, multi, boundary] = info.param;
constexpr const char* names[]{"ShortLength", "Extended16", "Extended64", "Mask", "Payload",
                             "Ping", "Close", "EmptyClose", "Text"};
return std::string(client ? "Client" : "Server") + (multi ? "Multi" : "Small") +
    names[static_cast<size_t>(boundary)]; }));

class WsConcurrentWrite : public TransportBehavior,
                          public testing::WithParamInterface<std::tuple<WsConcurrent, bool>> {};
TEST_P(WsConcurrentWrite, SerializesControlFramesAndAbortsCancelledPartialWrite) {
    const auto [action, owned] = GetParam();
    WsWriteBoundary(action, owned);
}
INSTANTIATE_TEST_SUITE_P(ControlAndOwnership, WsConcurrentWrite, testing::Combine(testing::Values(WsConcurrent::Ping, WsConcurrent::Close, WsConcurrent::Cancel), testing::Bool()), ([](const auto& info) { const auto [action, owned] = info.param;
const char* name = action == WsConcurrent::Ping ? "Ping" : action == WsConcurrent::Close ? "Close" : "Cancel";
return std::string(name) + (owned ? "OwnedBuffers" : "BorrowedBuffers"); }));

enum class InvalidWsFrame {
    ReservedBits, ReservedDataOpcode, ReservedControlOpcode, WrongMask, FragmentedPing, OverlongPing,
    UnexpectedContinuation, NewDataDuringContinuation, ShortClose, InvalidCloseCode, InvalidCloseUtf8,
    InvalidTextUtf8, Noncanonical16, Noncanonical64, HighLengthBit, OversizedPayload, TruncatedHeader, TruncatedPayload
};
std::string InvalidFrame(InvalidWsFrame fault, bool masked) {
    switch (fault) {
        case InvalidWsFrame::ReservedBits: {
            auto frame = WsWireFrame(2, "bad", masked);
            frame[0] = static_cast<char>(0xc2);
            return frame;
        }
        case InvalidWsFrame::ReservedDataOpcode: return WsWireFrame(3, "bad", masked);
        case InvalidWsFrame::ReservedControlOpcode: return WsWireFrame(11, "bad", masked);
        case InvalidWsFrame::WrongMask: return WsWireFrame(2, "bad", !masked);
        case InvalidWsFrame::FragmentedPing: return WsWireFrame(9, "bad", masked, false);
        case InvalidWsFrame::OverlongPing: return WsWireFrame(9, std::string(126, 'x'), masked);
        case InvalidWsFrame::UnexpectedContinuation: return WsWireFrame(0, "bad", masked);
        case InvalidWsFrame::NewDataDuringContinuation:
            return WsWireFrame(2, "", masked, false) + WsWireFrame(2, "bad", masked);
        case InvalidWsFrame::ShortClose: return WsWireFrame(8, "x", masked);
        case InvalidWsFrame::InvalidCloseCode: return WsWireFrame(8, std::string("\x03\xed", 2), masked);
        case InvalidWsFrame::InvalidCloseUtf8: return WsWireFrame(8, std::string("\x03\xe8\xc0\x80", 4), masked);
        case InvalidWsFrame::InvalidTextUtf8: return WsWireFrame(1, std::string("\xe2", 1), masked);
        case InvalidWsFrame::TruncatedHeader: return std::string(1, static_cast<char>(0x82));
        case InvalidWsFrame::TruncatedPayload: {
            auto frame = WsWireFrame(2, "truncated", masked);
            frame.resize(frame.size() - 9);
            return frame;
        }
        default: break;
    }
    const char direction = masked ? static_cast<char>(0x80) : 0;
    if (fault == InvalidWsFrame::Noncanonical16)
        return {static_cast<char>(0x82), static_cast<char>(direction | 126), 0, 125};
    std::string extended{static_cast<char>(0x82), static_cast<char>(direction | 127),
                        0, 0, 0, 0, 0, 0, static_cast<char>(0xff), static_cast<char>(0xff)};
    if (fault == InvalidWsFrame::HighLengthBit) extended[2] = static_cast<char>(0x80);
    if (fault == InvalidWsFrame::OversizedPayload) {
        extended[7] = 0x40;
        extended[8] = 0;
        extended[9] = 1;
    }
    return extended;
}
class WsMalformedFrame : public TransportBehavior,
                         public testing::WithParamInterface<std::tuple<bool, bool, InvalidWsFrame>> {};
TEST_P(WsMalformedFrame, RejectsProtocolViolationWithoutReturningDataOrCleanEof) {
    const auto [client, multi, fault] = GetParam();
    WsReject(InvalidFrame(fault, !client), client, multi);
}
INSTANTIATE_TEST_SUITE_P(ProtocolFaults, WsMalformedFrame, testing::Combine(
    testing::Bool(), testing::Bool(), testing::Values(
        InvalidWsFrame::ReservedBits, InvalidWsFrame::ReservedDataOpcode, InvalidWsFrame::ReservedControlOpcode,
        InvalidWsFrame::WrongMask, InvalidWsFrame::FragmentedPing, InvalidWsFrame::OverlongPing,
        InvalidWsFrame::UnexpectedContinuation, InvalidWsFrame::NewDataDuringContinuation,
        InvalidWsFrame::ShortClose, InvalidWsFrame::InvalidCloseCode, InvalidWsFrame::InvalidCloseUtf8,
        InvalidWsFrame::InvalidTextUtf8, InvalidWsFrame::Noncanonical16, InvalidWsFrame::Noncanonical64,
        InvalidWsFrame::HighLengthBit, InvalidWsFrame::OversizedPayload,
        InvalidWsFrame::TruncatedHeader, InvalidWsFrame::TruncatedPayload)));

struct ConnectionTokens { const char* headers; bool accepted; };
class HttpUpgradeTokens : public TransportBehavior,
                         public testing::WithParamInterface<std::tuple<bool, bool, ConnectionTokens>> {};
TEST_P(HttpUpgradeTokens, RequiresAnUpgradeTokenAcrossAllConnectionHeaders) {
    const auto [outbound, websocket, tokens] = GetParam();
    UpgradeHeaderTokens(outbound, websocket, tokens.headers, tokens.accepted);
}
INSTANTIATE_TEST_SUITE_P(DirectionsAndModes, HttpUpgradeTokens, testing::Combine(
    testing::Bool(), testing::Bool(), testing::Values(
        ConnectionTokens{"Connection: keep-alive\r\ncOnNeCtIoN: UpGrAdE\r\n", true},
        ConnectionTokens{"Connection: , keep-alive, ,UPGRADE,\r\n", true},
        ConnectionTokens{"Connection: Upgrade\r\nConnection: keep-alive\r\n", true},
        ConnectionTokens{"", false}, ConnectionTokens{"Connection: x-upgrade\r\n", false},
        ConnectionTokens{"Connection: upgraded\r\n", false},
        ConnectionTokens{"Connection: keep-alive\r\nConnection: not-upgrade\r\n", false})));

struct ChunkBody { const char* wire; bool accepted; };
class HttpChunkGrammar : public TransportBehavior,
                        public testing::WithParamInterface<std::tuple<bool, ChunkBody>> {};
TEST_P(HttpChunkGrammar, DecodesValidExtensionsAndRejectsMalformedOrTruncatedFraming) {
    const auto [multi, body] = GetParam();
    ChunkExtensionBody(body.wire, body.accepted, multi);
}
INSTANTIATE_TEST_SUITE_P(ReadModesAndGrammar, HttpChunkGrammar, testing::Combine(
    testing::Bool(), testing::Values(
        ChunkBody{"2 \t; name = \"a;\\\"b\\\\c\";flag\r\nOK\r\n0\r\n\r\n", true},
        ChunkBody{"2;x=\"unterminated\r\nOK\r\n0\r\n\r\n", false},
        ChunkBody{"2;x=\r\nOK\r\n0\r\n\r\n", false}, ChunkBody{"2;\r\nOK\r\n0\r\n\r\n", false},
        ChunkBody{"2 0\r\nOK\r\n0\r\n\r\n", false}, ChunkBody{"2\nOK\r\n0\r\n\r\n", false},
        ChunkBody{"2\r\nOK\n0\r\n\r\n", false}, ChunkBody{"2\r\nO", false},
        ChunkBody{"0\r\n", false}, ChunkBody{"10000000000000000\r\nOK\r\n0\r\n\r\n", false})));

enum class DiagnosticRequest {
    Normal, ExtraSpaces, TrailingSecret, VersionAfterSecret, MissingVersion, EmptyVersion,
    SecretVersion, MalformedVersion, QuerySecret, SecretHost, AbsoluteTarget, AuthorityTarget,
    TripleSlashTarget, EmptyAuthorityTarget, MissingHostTarget, MissingSlashTarget, ControlTarget, SecretMethod
};
constexpr std::string_view kSecretUrl =
    "http://user:review_password@example.com/?token=review_token#review_fragment";
class HttpInboundDiagnostics : public HttpDiagnosticBehavior,
                              public testing::WithParamInterface<std::tuple<const char*, DiagnosticRequest>> {};
TEST_P(HttpInboundDiagnostics, RedactsUntrustedInputWithoutChangingHandshakeAcceptance) {
    const auto [network, fault] = GetParam();
    const bool xhttp = std::string_view(network) == "xhttp";
    const bool ws = std::string_view(network) == "ws";
    const std::string method = xhttp ? "POST" : "GET";
    const std::string target = xhttp ? "/up/" : "/up";
    const std::string start = method + " " + target;
    std::string line = start + " HTTP/1.1";
    std::string host = "localhost";
    bool accepted = true;
    switch (fault) {
        case DiagnosticRequest::Normal: break;
        case DiagnosticRequest::ExtraSpaces: line = method + "   " + target + "   HTTP/1.1"; break;
        case DiagnosticRequest::TrailingSecret: line = start + " HTTP/1.1 " + std::string(kSecretUrl); accepted = !ws; break;
        case DiagnosticRequest::VersionAfterSecret: line = start + " HTTP/1.1 " + std::string(kSecretUrl) + " HTTP/1.1"; break;
        case DiagnosticRequest::MissingVersion: line = start; accepted = false; break;
        case DiagnosticRequest::EmptyVersion: line = start + " "; accepted = !ws; break;
        case DiagnosticRequest::SecretVersion: line = start + " " + std::string(kSecretUrl); accepted = !ws; break;
        case DiagnosticRequest::MalformedVersion:
            line = start + " HTTP/1.review_password?review_token#review_fragment"; accepted = !ws; break;
        case DiagnosticRequest::QuerySecret: line = start + "?token=review_token#review_fragment HTTP/1.1"; break;
        case DiagnosticRequest::SecretHost: host = kSecretUrl; break;
        case DiagnosticRequest::SecretMethod: line = std::string(kSecretUrl) + " " + target + " HTTP/1.1"; accepted = false; break;
        default: {
            constexpr const char* invalid_targets[]{
                "http://user:review_password@example.com/up?token=review_token#review_fragment",
                "//user:review_password@example.com/up?token=review_token#review_fragment",
                "///user:review_password@example.com/up?token=review_token#review_fragment",
                "http:///user:review_password@example.com/up?token=review_token#review_fragment",
                "http://user:review_password@/up?token=review_token#review_fragment",
                "http:/user:review_password@example.com/up?token=review_token#review_fragment",
                "/up\nforged_log_line?token=review_token#review_fragment"};
            line = method + " " + invalid_targets[static_cast<size_t>(fault) -
                static_cast<size_t>(DiagnosticRequest::AbsoluteTarget)] + " HTTP/1.1";
            accepted = false;
            break;
        }
    }
    HttpLogHandshake(network, false, line, accepted, "/up", host);
    ExpectRedactedDiagnostics();
}
INSTANTIATE_TEST_SUITE_P(NetworksAndUntrustedFields, HttpInboundDiagnostics, testing::Combine(
    testing::Values("http", "httpupgrade", "ws", "xhttp"), testing::Values(
        DiagnosticRequest::Normal, DiagnosticRequest::ExtraSpaces, DiagnosticRequest::TrailingSecret,
        DiagnosticRequest::VersionAfterSecret, DiagnosticRequest::MissingVersion, DiagnosticRequest::EmptyVersion,
        DiagnosticRequest::SecretVersion, DiagnosticRequest::MalformedVersion, DiagnosticRequest::QuerySecret,
        DiagnosticRequest::SecretHost, DiagnosticRequest::AbsoluteTarget, DiagnosticRequest::AuthorityTarget,
        DiagnosticRequest::TripleSlashTarget, DiagnosticRequest::EmptyAuthorityTarget,
        DiagnosticRequest::MissingHostTarget, DiagnosticRequest::MissingSlashTarget,
        DiagnosticRequest::ControlTarget, DiagnosticRequest::SecretMethod)));

TEST_F(HttpDiagnosticBehavior, RedactsXhttpDownlinkFragmentWithoutRejectingSession) {
    HttpLogHandshake("xhttp", false, "GET /up/session#review_fragment HTTP/1.1", true);
    ExpectRedactedDiagnostics();
}

enum class DiagnosticResponse { RejectedReason, AbsolutePath, MalformedAbsolutePath, PublicAtSignPath };
class HttpOutboundDiagnostics : public HttpDiagnosticBehavior,
                               public testing::WithParamInterface<std::tuple<const char*, DiagnosticResponse>> {};
TEST_P(HttpOutboundDiagnostics, RedactsResponseAndConfiguredTargetWithoutChangingWireRequest) {
    const auto [network, input] = GetParam();
    const std::string response = std::string_view(network) == "http" ? "HTTP/1.1 200 OK" : "HTTP/1.1 101 Switching Protocols";
    switch (input) {
        case DiagnosticResponse::RejectedReason:
            HttpLogHandshake(network, true, "HTTP/1.1 400 " + std::string(kSecretUrl), false); break;
        case DiagnosticResponse::AbsolutePath:
            HttpLogHandshake(network, true, response, true,
                "http://user:review_password@example.com/up?token=review_token#review_fragment", kSecretUrl); break;
        case DiagnosticResponse::MalformedAbsolutePath:
            HttpLogHandshake(network, true, response, true,
                "http:///user:review_password@example.com/up?token=review_token#review_fragment"); break;
        case DiagnosticResponse::PublicAtSignPath:
            HttpLogHandshake(network, true, response, true, "/public/@name?token=review_token#review_fragment"); break;
    }
    ExpectRedactedDiagnostics();
}
INSTANTIATE_TEST_SUITE_P(NetworksAndUntrustedFields, HttpOutboundDiagnostics, testing::Combine(
    testing::Values("http", "httpupgrade", "ws"), testing::Values(
        DiagnosticResponse::RejectedReason, DiagnosticResponse::AbsolutePath,
        DiagnosticResponse::MalformedAbsolutePath, DiagnosticResponse::PublicAtSignPath)));

struct UpgradePath { const char* request; const char* configured; bool accepted; };
class HttpUpgradePath : public TransportBehavior,
                        public testing::WithParamInterface<std::tuple<const char*, UpgradePath>> {};
TEST_P(HttpUpgradePath, IgnoresQueryButRequiresExactPathIncludingRoot) {
    const auto [network, path] = GetParam();
    HttpLogHandshake(network, false, path.request, path.accepted, path.configured);
}
INSTANTIATE_TEST_SUITE_P(NetworksAndPaths, HttpUpgradePath, testing::Combine(
    testing::Values("ws", "httpupgrade"), testing::Values(
        UpgradePath{"GET /up?ed=2048 HTTP/1.1", "/up", true},
        UpgradePath{"GET /down HTTP/1.1", "/up", false},
        UpgradePath{"GET /up/child HTTP/1.1", "/up", false},
        UpgradePath{"GET /?ed=2048 HTTP/1.1", "/", true},
        UpgradePath{"GET /up HTTP/1.1", "/", false},
        UpgradePath{"GET /up?ed=2048 HTTP/1.1", "/", false})));
}  // namespace
