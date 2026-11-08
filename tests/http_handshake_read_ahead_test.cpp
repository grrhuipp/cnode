#include <gtest/gtest.h>

#include "common/allocator.hpp"
#include "infra/log.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/tls_stream.hpp"
#include "transport/internet/tls_config.hpp"
#include "transport/internet/transport_stack.hpp"
#include "transport/internet/transport_security.hpp"
#include "transport/internet/ws_stream.hpp"
#include "../src/transport/internet/http1_handshake.hpp"

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
#include <iostream>
#include <stdexcept>
#include <string>

#include <netinet/tcp.h>
#include <sys/socket.h>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;
void Require(bool yes, const char* why) {
    if (!yes) throw std::runtime_error(why);
}
std::span<const uint8_t> Bytes(std::string_view value) {
    return {reinterpret_cast<const uint8_t*>(value.data()), value.size()};
}
void Prepend(::AsyncStream& stream, std::string_view value) {
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
    net::experimental::channel<void(::IoErrorCode)> peer_finished(io, 1);
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer_socket(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer_socket);
    auto raw = std::make_unique<::TcpStream>(std::move(socket));
    const int native = raw->NativeHandle();
    raw->SetIdleTimeout(3s);
    raw->SetReadTimeout(2s);
    raw->SetWriteTimeout(2s);
    (void)raw->StartPhaseDeadline(3s);

    const auto fixtures = std::filesystem::path(ACPP_TEST_SOURCE_DIR) / "tests/fixtures/anytls-pool";
    ::StreamSettings settings;
    settings.network = upgrade ? "httpupgrade" : "http";
    settings.http.path = settings.http_upgrade.path = "/up";
    settings.http.host = settings.http_upgrade.host = "localhost";
    settings.http.method = "GET";
    settings.security = tls ? "tls" : "none";
    settings.tls.alpn = {"http/1.1"};
    settings.tls.allow_insecure = true;
    settings.tls.server_name = "localhost";
    if (!outbound) {
        settings.tls.cert_file = (fixtures / "cert.pem").string();
        settings.tls.key_file = (fixtures / "key.pem").string();
    }
    ::LoadTlsPemMaterial(settings.tls);
    settings = ::NormalizeStreamSettings(settings);
    const ::TransportSecurity security(
        settings, outbound ? ::StreamEndpointRole::Outbound : ::StreamEndpointRole::Inbound);
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
    std::unique_ptr<::AsyncStream> stream;

    auto peer = [&]<typename Peer>(Peer& wire) -> net::awaitable<void> {
        if (outbound) {
            std::string header;
            char byte;
            do {
                co_await net::async_read(wire, net::buffer(&byte, 1), net::use_awaitable);
                header += byte;
            } while (!header.ends_with("\r\n\r\n"));
            Require(header.starts_with("GET /up HTTP/1.1\r\n"), "unexpected outbound HTTP request");
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
            Require(record_header.starts_with(upgrade ? "HTTP/1.1 101 " : "HTTP/1.1 200 "), "unexpected inbound response");
        }
        std::array<char, 3> ack{};
        co_await net::async_read(wire, net::buffer(ack), net::use_awaitable);
        Require(std::string_view(ack.data(), ack.size()) == "ack", "cancellation disturbed writes");
        co_await net::async_write(wire, net::buffer("end", 3), net::use_awaitable);
        char byte;
        auto [ec, n] = co_await wire.async_read_some(net::buffer(&byte, 1), net::as_tuple(net::use_awaitable));
        if (abortive) {
            Require(n == 0 && (ec == net::error::connection_reset ||
                    ec == net::ssl::error::stream_truncated || (!tls && ec == net::error::eof)),
                    "abortive close sent TLS close_notify or left the peer waiting");
        } else {
            Require(ec == net::error::eof && n == 0, "graceful shutdown omitted EOF or TLS close_notify");
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
        Require(peer_finished.try_send(::IoErrorCode{}), "peer shutdown completion was lost");
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
                Require(n != 0, "preexisting byte-layer residual truncated");
                retained.append(block.data(), n);
            }
            raw->PrependReadData(Bytes(retained));
        }
        ::TransportBuildResult built;
        if (outbound) {
            built = co_await ::BuildOutboundTransport(std::move(raw), settings, security.Context());
        } else {
            built = co_await ::BuildInboundTransport(io, std::move(raw), settings, security.Context());
        }
        Require(built.has_value(), "HTTP transport handshake failed");
        stream = std::move(*built);
        Require(stream->NativeHandle() == native, "handshake changed underlying socket ownership");
        stream->ClearPhaseDeadline();
        // Force a prepend while the actual read end still has handshake residual.
        // This prefix must precede both that residual and unread SSL/socket input.
        Prepend(*stream, "prefix");
        const auto pending_live = ::memory::detail::test_buffers_live;
        ::memory::reject_next_pmr_allocation = true;
        bool failed = false;
        try { Prepend(*stream, "must-not-appear"); } catch (const std::bad_alloc&) { failed = true; }
        Require(failed && ::memory::detail::test_buffers_live == pending_live,
                "prepend OOM changed retained data ownership");
        std::string received;
        std::array<char, 3> small{};
        for (size_t i = 0; i < 5; ++i) {
            const size_t n = co_await stream->AsyncRead(net::buffer(small));
            Require(n != 0, "small read lost handshake payload");
            received.append(small.data(), n);
        }
        while (received.size() < payload.size() + 6) {
            auto buffers = co_await stream->ReadMultiBuffer();
            Require(buffers.byte_size() != 0, "multi-buffer read truncated payload");
            received += Flatten(buffers);
        }
        Require(received == "prefix" + payload, "read-ahead lost, duplicated, decrypted at wrong layer, or reordered");
        Require(::memory::detail::test_buffers_live == 0,
                "consumed handshake residual retained payload blocks");
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
        Require(cancelled && stream->IsOpen(), "pending read cancellation closed or stalled transport");
        co_await stream->AsyncWrite(net::buffer("ack", 3));
        received.clear();
        while (received.size() < 3) {
            const size_t n = co_await stream->AsyncRead(net::buffer(small));
            Require(n != 0, "transport failed to resume after cancellation");
            received.append(small.data(), n);
        }
        Require(received == "end", "resumed transport corrupted input");
        if (!abortive) {
            co_await stream->AsyncShutdownWrite();
            co_await stream->AsyncShutdownWrite();
            Prepend(*stream, "discard-on-shutdown");
            stream->ShutdownRead();
            stream->ShutdownRead();
            Require(co_await stream->AsyncRead(net::buffer(small)) == 0, "read shutdown leaked retained plaintext");
            Require((co_await stream->ReadMultiBuffer()).byte_size() == 0, "read shutdown leaked multi-buffer data");
            // Join the peer's graceful half-close before a repeated abortive close
            // can reset its socket; otherwise its shutdown_send races with RST.
            co_await peer_finished.async_receive(net::use_awaitable);
        } else {
            Prepend(*stream, "discard-on-abortive-close");
        }
        stream->CloseAbortive();
        stream->CloseAbortive();
        stream->Close();
        Require(!stream->IsOpen(), "repeated close left transport open");
        Require(co_await stream->AsyncRead(net::buffer(small)) == 0, "closed transport leaked read-ahead");
        Require((co_await stream->ReadMultiBuffer()).byte_size() == 0, "closed transport leaked multi-buffer data");
        Require(::memory::detail::test_buffers_live == 0, "shutdown/close retained payload blocks");
    };
    auto finish = [&](std::exception_ptr failure) {
        if (failure && !error) {
            error = failure;
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
    if (error) std::rethrow_exception(error);
    Require(completed == 2 && cancelled && peer_eof, "handshake/cancellation/shutdown failed to join");
}

void ConnectedSocketOptions() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    const auto native = socket.native_handle();
    ::TcpStream stream(std::move(socket));
    const auto require_option = [&](int level, int option, int expected) {
        int value = 0;
        socklen_t size = sizeof(value);
        const int status = ::getsockopt(native, level, option, &value, &size);
        Require(status == 0 && value == expected,
                "connected TCP socket has incorrect keepalive settings");
    };
    require_option(SOL_SOCKET, SO_KEEPALIVE, 1);
    require_option(IPPROTO_TCP, TCP_KEEPIDLE, 60);
    require_option(IPPROTO_TCP, TCP_KEEPINTVL, 10);
    require_option(IPPROTO_TCP, TCP_KEEPCNT, 6);
}

void WriteTimeoutResetsQueuedPayload() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    socket.set_option(net::socket_base::send_buffer_size(4096));
    peer.set_option(net::socket_base::receive_buffer_size(4096));
    ::TcpStream stream(std::move(socket));
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
            Require(failure.code() == ::io_error::operation_aborted,
                    "write deadline failed with unrelated I/O error");
            cancelled = true;
        }
        Require(cancelled && stream.ConsumeWriteTimeout() && !stream.IsOpen(),
                "write deadline did not cancel and retire its socket");
        std::array<char, 8192> buffer{};
        for (;;) {
            auto [ec, size] = co_await peer.async_read_some(
                net::buffer(buffer), net::as_tuple(net::use_awaitable));
            if (ec) {
                Require(ec == net::error::connection_reset,
                        "write deadline gracefully drained payload instead of resetting");
                break;
            }
            Require(size != 0, "write deadline peer read made no progress");
        }
    };
    net::co_spawn(io, exercise(), [&](std::exception_ptr failure) {
        error = failure;
        completed = true;
    });
    io.run_for(3s);
    if (error) std::rethrow_exception(error);
    Require(completed, "write deadline left queued payload or native readiness unjoined");
}

void ExistingTcpResidual() {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    ::TcpStream stream(std::move(socket));
    // More than eight blocks exercises spill metadata while the old residual
    // is transferred behind the new prefix without copying its payload.
    const std::string tail(10 * ::buf::Buffer::kSize, 't');
    stream.PrependReadData(Bytes(tail));
    stream.PrependReadData(Bytes("head"));
    bool done = false;
    std::exception_ptr error;
    auto read = [&]() -> net::awaitable<void> {
        char byte;
        Require(co_await stream.AsyncRead(net::buffer(&byte, 1)) == 1 && byte == 'h', "prepend did not precede old residual");
        auto data = co_await stream.ReadMultiBuffer();
        Require(Flatten(data) == "ead" + tail, "preexisting residual was lost or reordered");
        data.clear();
        stream.PrependReadData(Bytes("discard"));
        stream.Close();
        Require((co_await stream.ReadMultiBuffer()).byte_size() == 0, "close leaked old residual");
    };
    net::co_spawn(io, read(), [&](std::exception_ptr failure) { error = failure; done = true; });
    io.run_for(1s);
    if (error) std::rethrow_exception(error);
    Require(done && !::memory::reject_next_pmr_allocation, "TCP residual test stalled");
}

void TlsReadTermination(bool multi_buffer, bool clean) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer_socket(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer_socket);
    const auto fixtures = std::filesystem::path(ACPP_TEST_SOURCE_DIR) / "tests/fixtures/anytls-pool";
    net::ssl::context server_context(net::ssl::context::tls_server);
    server_context.use_certificate_chain_file((fixtures / "cert.pem").string());
    server_context.use_private_key_file((fixtures / "key.pem").string(), net::ssl::context::pem);
    ::TlsConfig client_config;
    client_config.allow_insecure = true;
    auto client_context = ::SslContext::CreateClient(client_config);
    Require(bool(client_context), "TLS termination client context creation failed");
    net::ssl::stream<::tcp::socket> peer(std::move(peer_socket), server_context);
    ::TlsStream stream(std::make_unique<::TcpStream>(std::move(socket)),
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
        Require(co_await stream.Handshake(), "TLS termination fixture handshake failed");
        if (multi_buffer) {
            Require(Flatten(co_await stream.ReadMultiBuffer()) == "x", "TLS fixture payload changed");
        } else {
            char byte{};
            Require(co_await stream.AsyncRead(net::buffer(&byte, 1)) == 1 && byte == 'x',
                    "TLS fixture payload changed");
        }
        bool truncated = false;
        try {
            if (multi_buffer) {
                Require((co_await stream.ReadMultiBuffer()).byte_size() == 0, "unexpected TLS payload");
            } else {
                char byte{};
                Require(co_await stream.AsyncRead(net::buffer(&byte, 1)) == 0, "unexpected TLS payload");
            }
        } catch (const ::IoSystemError& error) {
            if (error.code() != net::ssl::error::stream_truncated) throw;
            truncated = true;
        }
        Require(truncated == !clean, "TLS truncation was confused with authenticated EOF");
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
    if (failure) std::rethrow_exception(failure);
    Require(completed == 2, "TLS termination fixture did not join");
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
    Require((bytes[0] & 0xf0) == 0x80, "WS writer emitted fragmented/reserved header");
    WsWireHeader header;
    header.opcode = bytes[0] & 0x0f;
    header.masked = (bytes[1] & 0x80) != 0;
    Require(header.masked == masked, "WS writer used wrong mask direction");
    const unsigned length = bytes[1] & 0x7f;
    uint64_t size = length;
    if (length >= 126) {
        std::array<uint8_t, 8> extended{};
        const size_t count = length == 126 ? 2 : 8;
        co_await net::async_read(peer, net::buffer(extended.data(), count), net::use_awaitable);
        size = 0;
        for (size_t i = 0; i < count; ++i) size = (size << 8) | extended[i];
        Require((length == 126 && size >= 126) || (length == 127 && size >= 65536),
                "WS writer used noncanonical length");
    }
    Require(size <= 4 * 1024 * 1024, "WS writer emitted an unexpected payload size");
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
    Require(header.opcode == opcode, "WS writer interleaved or misclassified a frame");
    co_return co_await ReadWsWirePayload(peer, header);
}

net::awaitable<void> RequireWireEof(::tcp::socket& peer) {
    char byte{};
    const auto [error, size] = co_await peer.async_read_some(
        net::buffer(&byte, 1), net::as_tuple(net::use_awaitable));
    Require(error == net::error::eof && size == 0, "WS Close was duplicated or omitted TCP EOF");
}

void WsResume(bool client, bool multi_buffer, size_t size, size_t cut, uint8_t opcode = 2) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    ::BaseWsStream stream(std::make_unique<::TcpStream>(std::move(socket)), 0, client);
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
    Require(cut < frame.size(), "invalid WS cancellation fixture boundary");
    // Handshake residual is deterministic: the entire prefix is consumed before
    // the first socket wait, then Cancel interrupts that actual lower read.
    stream.SetPendingData(reinterpret_cast<const uint8_t*>(frame.data()), cut);
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
                Require(!bytes.empty(), "WS cancellation was converted to EOF");
                received += bytes;
            }
        } catch (const ::IoSystemError& error) {
            if (error.code() != net::error::operation_aborted) throw;
            cancelled = true;
        }
        Require(stream.IsOpen(), "WS read cancellation closed the connection");
        if (opcode == 2) {
            const size_t header_size = (size < 126 ? 2 : size <= 65535 ? 4 : 10) + (client ? 0 : 4);
            const size_t prefix = cut > header_size ? cut - header_size : 0;
            Require(received == payload.substr(0, prefix),
                    "WS read waited to fill its caller buffer before delivering available payload");
        }
        co_await stream.AsyncWrite(net::buffer("ack", 3));
        if (opcode == 8) {
            Require((co_await read()).empty(), "complete WS Close leaked application bytes");
        } else {
            while (received.size() < application.size()) {
                const auto bytes = co_await read();
                Require(!bytes.empty(), "WS resumed with premature EOF");
                received += bytes;
            }
            Require(received == application, "WS cancellation lost, repeated, or remasked bytes");
            co_await stream.AsyncShutdownWrite();
            co_await stream.AsyncShutdownWrite();
        }
    };
    auto wire = [&]() -> net::awaitable<void> {
        Require(co_await ReadWsWireFrame(peer, client, 2) == "ack", "WS cancellation disturbed writes");
        std::string suffix = frame.substr(cut);
        if (opcode == 9) suffix += WsWireFrame(2, application, !client);
        co_await net::async_write(peer, net::buffer(suffix), net::use_awaitable);
        if (opcode == 9 || opcode == 1)
            Require(co_await ReadWsWireFrame(peer, client, 10) == (opcode == 1 ? "probe" : payload),
                    "WS PONG changed PING payload");
        const auto close = co_await ReadWsWireFrame(peer, client, 8);
        Require(close == (opcode == 8 ? payload : std::string("\x03\xe8", 2)),
                "WS Close payload was not preserved");
        co_await RequireWireEof(peer);
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
    if (failure) std::rethrow_exception(failure);
    Require(completed == 2 && cancelled, "WS cancellation fixture did not join");
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
    ::WsClientStream stream(std::make_unique<::TcpStream>(std::move(socket)), 0);
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
            Require(!stream.IsOpen(), "cancelled partial WS frame did not abort transport");
        }
    };
    auto control = [&]() -> net::awaitable<void> {
        if (action == WsConcurrent::Ping) {
            std::array<char, 32> buffer{};
            const size_t n = co_await stream.AsyncRead(net::buffer(buffer));
            Require(std::string_view(buffer.data(), n) == "ready", "WS PING escaped as application payload");
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
        Require(header.opcode == 2 && header.size == payload.size(), "WS write lost physical data-frame boundary");
        Require(!data_done, "WS write fixture did not establish backpressure");
        if (action == WsConcurrent::Ping) {
            const auto input = WsWireFrame(9, "probe", false) + WsWireFrame(2, "ready", false);
            co_await net::async_write(peer, net::buffer(input), net::use_awaitable);
        } else {
            Require(close_now.try_send(::IoErrorCode{}), "WS concurrent close signal was lost");
            co_await net::post(io, net::use_awaitable);
            Require(!control_done, "WS Close completed in the middle of a data frame");
        }
        if (action == WsConcurrent::Cancel) {
            stream.Cancel();
            co_return;
        }
        Require(co_await ReadWsWirePayload(peer, header) == payload,
                "WS control frame was inserted inside physical data payload");
        if (action == WsConcurrent::Ping)
            Require(co_await ReadWsWireFrame(peer, true, 10) == "probe", "WS backpressured PONG changed payload");
        Require(co_await ReadWsWireFrame(peer, true, 8) == std::string("\x03\xe8", 2),
                "WS concurrent Close was incomplete");
        co_await RequireWireEof(peer);
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
    if (failure) std::rethrow_exception(failure);
    Require(completed == 3, "WS concurrent-write fixture did not join");
    Require(action == WsConcurrent::Cancel ? write_cancelled && close_cancelled
                                           : data_done && control_done,
            "WS write/close cancellation lost its actual completion type");
}

void WsReject(std::string_view frame, bool client, bool multi_buffer) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    ::BaseWsStream stream(std::make_unique<::TcpStream>(std::move(socket)), 0, client);
    stream.SetPendingData(reinterpret_cast<const uint8_t*>(frame.data()), frame.size());
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
            Require(error.code() != net::error::operation_aborted, "WS protocol failure became cancellation");
            rejected = true;
        }
        Require(rejected && !stream.IsOpen(), "invalid/truncated WS frame became data or clean EOF");
    };
    net::co_spawn(io, receive(), [&](std::exception_ptr error) { failure = error; done = true; });
    io.run_for(1s);
    if (failure) std::rethrow_exception(failure);
    Require(done && rejected, "WS invalid-frame fixture did not join");
}

void WsProtocolBoundaries() {
    for (bool client : {false, true}) {
        for (bool multi_buffer : {false, true}) {
            WsResume(client, multi_buffer, 17, 1);
            WsResume(client, multi_buffer, 257, 3);
            WsResume(client, multi_buffer, 65539, 5);
            if (!client) WsResume(client, multi_buffer, 17, 4);
            WsResume(client, multi_buffer, 257, (client ? 4 : 8) + 3);
            WsResume(client, multi_buffer, 9, (client ? 2 : 6) + 2, 9);
            WsResume(client, multi_buffer, 5, (client ? 2 : 6) + 1, 8);
            WsResume(client, multi_buffer, 0, 1, 8);
            WsResume(client, multi_buffer, 7, 1, 1);

            const bool masked = !client;
            std::string reserved = WsWireFrame(2, "bad", masked);
            reserved[0] = static_cast<char>(0xc2);
            WsReject(reserved, client, multi_buffer);
            for (uint8_t opcode : {uint8_t{3}, uint8_t{11}})
                WsReject(WsWireFrame(opcode, "bad", masked), client, multi_buffer);
            WsReject(WsWireFrame(2, "bad", !masked), client, multi_buffer);
            WsReject(WsWireFrame(9, "bad", masked, false), client, multi_buffer);
            WsReject(WsWireFrame(9, std::string(126, 'x'), masked), client, multi_buffer);
            WsReject(WsWireFrame(0, "bad", masked), client, multi_buffer);
            WsReject(WsWireFrame(2, "", masked, false) + WsWireFrame(2, "bad", masked),
                     client, multi_buffer);
            WsReject(WsWireFrame(8, "x", masked), client, multi_buffer);
            WsReject(WsWireFrame(8, std::string("\x03\xed", 2), masked), client, multi_buffer);
            WsReject(WsWireFrame(8, std::string("\x03\xe8\xc0\x80", 4), masked), client, multi_buffer);
            WsReject(WsWireFrame(1, std::string("\xe2", 1), masked), client, multi_buffer);
            const char direction = masked ? static_cast<char>(0x80) : 0;
            std::string extended{static_cast<char>(0x82), static_cast<char>(direction | 126), 0, 125};
            WsReject(extended, client, multi_buffer);
            extended = std::string{static_cast<char>(0x82), static_cast<char>(direction | 127),
                                   0, 0, 0, 0, 0, 0, static_cast<char>(0xff), static_cast<char>(0xff)};
            WsReject(extended, client, multi_buffer);
            extended[2] = static_cast<char>(0x80);
            WsReject(extended, client, multi_buffer);
            extended[2] = 0;
            extended[7] = 0x40;
            extended[8] = 0;
            extended[9] = 1;
            WsReject(extended, client, multi_buffer);
            WsReject(std::string(1, static_cast<char>(0x82)), client, multi_buffer);
            const auto truncated = WsWireFrame(2, "truncated", masked);
            WsReject(std::string_view(truncated).substr(0, truncated.size() - 9), client, multi_buffer);
        }
    }
    for (bool owned : {false, true})
        for (auto action : {WsConcurrent::Ping, WsConcurrent::Close, WsConcurrent::Cancel})
            WsWriteBoundary(action, owned);
}

void UpgradeHeaderTokens(bool outbound, bool websocket,
                         std::string_view connection, bool accepted) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    auto raw = std::make_unique<::TcpStream>(std::move(socket));
    raw->SetIdleTimeout(2s);
    ::StreamSettings settings;
    settings.network = websocket ? "ws" : "httpupgrade";
    settings.ws.path = settings.http_upgrade.path = "/up";
    settings.security = "none";
    settings = ::NormalizeStreamSettings(settings);
    std::exception_ptr error;
    size_t completed = 0;
    auto finish = [&](std::exception_ptr failure) {
        if (failure && !error) { error = failure; io.stop(); }
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
                const auto key = ::transport::internet::TrimAscii(
                    ::transport::internet::ExtractHeaderValueCI(request, "Sec-WebSocket-Key"));
                message += "Sec-WebSocket-Accept: " + ::ws::ComputeWsAccept(key) + "\r\n";
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
        ::TransportBuildResult built;
        if (outbound) {
            built = co_await ::BuildOutboundTransport(std::move(raw), settings, nullptr);
        } else {
            built = co_await ::BuildInboundTransport(io, std::move(raw), settings, nullptr);
        }
        Require(built.has_value() == accepted, "Connection header token handshake mismatch");
        if (built) (*built)->Close();
    };
    net::co_spawn(io, wire(), finish);
    net::co_spawn(io, product(), finish);
    io.run();
    if (error) std::rethrow_exception(error);
    Require(completed == 2, "Connection token handshake stalled");
}

void ChunkExtensionBody(std::string_view wire, bool accepted, bool multi_buffer) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    auto raw = std::make_unique<::TcpStream>(std::move(socket));
    raw->SetIdleTimeout(2s);
    auto stream = ::transport::internet::MakeHttp1BodyStream(
        std::move(raw), ::transport::internet::Http1BodyChunked{}, false);
    std::exception_ptr error;
    size_t completed = 0;
    auto finish = [&](std::exception_ptr failure) {
        if (failure && !error) { error = failure; io.stop(); }
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
            Require(failure.code() == ::io_error::invalid_argument,
                    "chunk boundary failed with unrelated I/O error");
            rejected = true;
        }
        Require(rejected != accepted, "transport chunk grammar acceptance mismatch");
        if (accepted) Require(body == "OK", "transport chunk decoder leaked framing bytes");
    };
    net::co_spawn(io, sender(), finish);
    net::co_spawn(io, receiver(), finish);
    io.run();
    if (error) std::rethrow_exception(error);
    Require(completed == 2, "chunk boundary parser stalled");
}

void HttpBoundaryCases() {
    for (bool outbound : {false, true}) {
        for (bool websocket : {false, true}) {
            for (const std::string_view headers : {
                     "Connection: keep-alive\r\ncOnNeCtIoN: UpGrAdE\r\n",
                     "Connection: , keep-alive, ,UPGRADE,\r\n",
                     "Connection: Upgrade\r\nConnection: keep-alive\r\n"})
                UpgradeHeaderTokens(outbound, websocket, headers, true);
            for (const std::string_view headers : {
                     "", "Connection: x-upgrade\r\n", "Connection: upgraded\r\n",
                     "Connection: keep-alive\r\nConnection: not-upgrade\r\n"})
                UpgradeHeaderTokens(outbound, websocket, headers, false);
        }
    }
    for (bool multi_buffer : {false, true}) {
        ChunkExtensionBody("2 \t; name = \"a;\\\"b\\\\c\";flag\r\nOK\r\n0\r\n\r\n",
                           true, multi_buffer);
        for (const std::string_view body : {
                 "2;x=\"unterminated\r\nOK\r\n0\r\n\r\n",
                 "2;x=\r\nOK\r\n0\r\n\r\n", "2;\r\nOK\r\n0\r\n\r\n",
                 "2 0\r\nOK\r\n0\r\n\r\n", "2\nOK\r\n0\r\n\r\n",
                 "2\r\nOK\n0\r\n\r\n", "2\r\nO", "0\r\n",
                 "10000000000000000\r\nOK\r\n0\r\n\r\n"})
            ChunkExtensionBody(body, false, multi_buffer);
    }
}

class CloseHttpLogStream final : public ::InboundTransportStreamHandler {
public:
    net::awaitable<void> OnInboundTransportStream(
        std::unique_ptr<::AsyncStream> stream, ::InboundTransportMetadata) override {
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
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    auto raw = std::make_unique<::TcpStream>(std::move(socket));
    raw->SetIdleTimeout(2s);
    ::StreamSettings settings;
    settings.network = network;
    settings.http.path = settings.http_upgrade.path = settings.ws.path =
        settings.xhttp.path = path;
    settings.http.method = "GET";
    settings.xhttp.mode = ::XHttpMode::Auto;
    if (outbound) {
        settings.http.host = settings.http_upgrade.host = host;
        settings.ws.headers.emplace("Host", host);
    }
    settings = ::NormalizeStreamSettings(settings);
    std::exception_ptr error;
    size_t completed = 0;
    auto finish = [&](std::exception_ptr failure) {
        if (failure && !error) { error = failure; io.stop(); }
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
            Require(request.find(path) != std::string::npos,
                    "HTTP log redaction changed the outbound request target");
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
            const auto key = ::transport::internet::TrimAscii(
                ::transport::internet::ExtractHeaderValueCI(request, "Sec-WebSocket-Key"));
            message += "Sec-WebSocket-Accept: " + ::ws::ComputeWsAccept(key) + "\r\n";
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
            Require(response.starts_with(network == "ws" || network == "httpupgrade"
                        ? "HTTP/1.1 101 " : "HTTP/1.1 200 "),
                    "HTTP log redaction changed handshake response");
        }
    };
    auto product = [&]() -> net::awaitable<void> {
        ::TransportBuildResult built;
        if (outbound) {
            built = co_await ::BuildOutboundTransport(std::move(raw), settings, nullptr);
        } else {
            const std::shared_ptr<::InboundTransportStreamHandler> sink =
                network == "xhttp" ? std::make_shared<CloseHttpLogStream>() : nullptr;
            built = co_await ::BuildInboundTransport(io, std::move(raw), settings, nullptr, 0, sink);
        }
        Require(built.has_value() == accepted, "HTTP log redaction changed request acceptance");
        if (built && *built) (*built)->Close();
    };
    net::co_spawn(io, wire(), finish);
    net::co_spawn(io, product(), finish);
    io.run();
    if (error) std::rethrow_exception(error);
    Require(completed == 2, "HTTP log redaction handshake stalled");
}

void HttpLogRedaction() {
    auto name = (std::filesystem::temp_directory_path() / "cnode-http-logs-XXXXXX").string();
    Require(::mkdtemp(name.data()) != nullptr, "HTTP log test directory creation failed");
    const std::filesystem::path directory(name);
    try {
        Require(::Log::Init("trace", directory, 1, {}, "error.log", false, false),
                "HTTP log test initialization failed");
        constexpr std::string_view secret_url =
            "http://user:review_password@example.com/?token=review_token#review_fragment";
        for (const std::string_view network : {"http", "httpupgrade", "ws", "xhttp"}) {
            const std::string method = network == "xhttp" ? "POST" : "GET";
            const std::string target = network == "xhttp" ? "/up/" : "/up";
            const std::string start = method + " " + target;
            HttpLogHandshake(network, false, start + " HTTP/1.1", true);
            HttpLogHandshake(network, false, method + "   " + target + "   HTTP/1.1", true);
            HttpLogHandshake(network, false,
                start + " HTTP/1.1 " + std::string(secret_url), network != "ws");
            // WS tolerates extra tokens when the final version is HTTP/1.1.
            HttpLogHandshake(network, false,
                start + " HTTP/1.1 " + std::string(secret_url) + " HTTP/1.1", true);
            HttpLogHandshake(network, false, start, false);
            HttpLogHandshake(network, false, start + " ", network != "ws");
            HttpLogHandshake(network, false,
                start + " " + std::string(secret_url), network != "ws");
            HttpLogHandshake(network, false,
                start + " HTTP/1.review_password?review_token#review_fragment", network != "ws");
            HttpLogHandshake(network, false,
                start + "?token=review_token#review_fragment HTTP/1.1", network != "ws");
            HttpLogHandshake(network, false,
                start + " HTTP/1.1", true, "/up", secret_url);
            for (const std::string_view invalid_target : {
                    "http://user:review_password@example.com/up?token=review_token#review_fragment",
                    "//user:review_password@example.com/up?token=review_token#review_fragment",
                    "///user:review_password@example.com/up?token=review_token#review_fragment",
                    "http:///user:review_password@example.com/up?token=review_token#review_fragment",
                    "http://user:review_password@/up?token=review_token#review_fragment",
                    "http:/user:review_password@example.com/up?token=review_token#review_fragment",
                    "/up\nforged_log_line?token=review_token#review_fragment"}) {
                HttpLogHandshake(network, false, method + " " + std::string(invalid_target) + " HTTP/1.1", false);
            }
            HttpLogHandshake(network, false,
                std::string(secret_url) + " " + target + " HTTP/1.1", false);
        }
        HttpLogHandshake("xhttp", false,
            "GET /up/session#review_fragment HTTP/1.1", true);
        for (const std::string_view network : {"http", "httpupgrade", "ws"}) {
            HttpLogHandshake(network, true, std::string("HTTP/1.1 400 ") + std::string(secret_url), false);
            const std::string response = network == "http" ? "HTTP/1.1 200 OK" : "HTTP/1.1 101 Switching Protocols";
            HttpLogHandshake(network, true, response, true,
                "http://user:review_password@example.com/up?token=review_token#review_fragment",
                secret_url);
            HttpLogHandshake(network, true, response, true,
                "http:///user:review_password@example.com/up?token=review_token#review_fragment");
            HttpLogHandshake(network, true, response, true, "/public/@name?token=review_token#review_fragment");
        }
        ::Log::Shutdown();
        std::ifstream input(directory / "error.log");
        Require(input.is_open(), "HTTP diagnostics were not written");
        std::string diagnostics;
        for (std::string line; std::getline(input, line);) {
            for (unsigned char ch : line)
                Require(ch >= 0x20 && ch != 0x7f, "HTTP diagnostic contains a raw control character");
            diagnostics += line + '\n';
        }
        for (const std::string_view secret : {
                "review_password", "review_token", "review_fragment", "forged_log_line"})
            Require(diagnostics.find(secret) == std::string::npos, "HTTP diagnostics leaked untrusted input");
        for (const std::string_view marker : {
                "HTTPUpgrade server request line='GET /up HTTP/1.1'",
                "WebSocket server rejected path mismatch",
                "XHTTP server H1 request line='POST /up/ HTTP/1.1'",
                "XHTTP server split downlink ready session=session ",
                "client request rejected", "WebSocket client upgrade rejected",
                "[invalid HTTP target]", "[invalid version]", "[invalid method]",
                "example.com/up", "/public/@name"})
            Require(diagnostics.find(marker) != std::string::npos, "HTTP diagnostic coverage missing");
    } catch (...) {
        ::Log::Shutdown();
        std::filesystem::remove_all(directory);
        throw;
    }
    std::filesystem::remove_all(directory);
}
}  // namespace

TEST(HttpHandshakeReadAhead, Contract) {
    ::TlsStream::InitializeIo();
    ::memory::ThreadMemoryResource resource;
    auto* previous = std::pmr::set_default_resource(&resource);
    bool passed = true;
    try {
        ConnectedSocketOptions();
        WriteTimeoutResetsQueuedPayload();
        ExistingTcpResidual();
        for (bool multi_buffer : {false, true})
            for (bool clean : {true, false})
                TlsReadTermination(multi_buffer, clean);
        WsProtocolBoundaries();
        HttpBoundaryCases();
        HttpLogRedaction();
        for (bool outbound : {false, true})
            for (bool tls : {false, true})
                for (bool upgrade : {false, true})
                    for (bool fragmented : {false, true})
                        for (bool abortive : {false, true})
                            Case(outbound, tls, upgrade, fragmented, abortive);
        Require(::memory::detail::test_buffers_live == 0, "test retained payload blocks");
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        passed = false;
    }
    std::pmr::set_default_resource(previous);
    { ASSERT_TRUE(passed); return; }
}
