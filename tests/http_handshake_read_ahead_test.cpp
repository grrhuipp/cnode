#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/tls_stream.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"

#include <asio/co_spawn.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/read.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>
#include <asio/write.hpp>
#include <array>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
namespace net = acpp::net;
using namespace std::chrono_literals;
void Require(bool yes, const char* why) {
    if (!yes) throw std::runtime_error(why);
}
std::span<const uint8_t> Bytes(std::string_view value) {
    return {reinterpret_cast<const uint8_t*>(value.data()), value.size()};
}
void Prepend(acpp::AsyncStream& stream, std::string_view value) {
    if (auto* tls = dynamic_cast<acpp::TlsStream*>(&stream)) tls->PrependReadData(Bytes(value));
    else static_cast<acpp::TcpStream&>(stream).PrependReadData(Bytes(value));
}
std::string Flatten(const acpp::buf::MultiBuffer& data) {
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
    net::experimental::channel<void(acpp::IoErrorCode)> peer_finished(io, 1);
    acpp::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    acpp::tcp::socket socket(io), peer_socket(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer_socket);
    auto raw = std::make_unique<acpp::TcpStream>(std::move(socket));
    const int native = raw->NativeHandle();
    raw->SetIdleTimeout(3s);
    raw->SetReadTimeout(2s);
    raw->SetWriteTimeout(2s);
    (void)raw->StartPhaseDeadline(3s);

    const auto fixtures = std::filesystem::path(ACPP_TEST_SOURCE_DIR) / "tests/fixtures/anytls-pool";
    acpp::StreamSettings settings;
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
    settings = acpp::NormalizeStreamSettings(settings);
    net::ssl::context context(net::ssl::context::tls);
    context.set_verify_mode(net::ssl::verify_none);
    if (tls && outbound) {
        context.use_certificate_chain_file((fixtures / "cert.pem").string());
        context.use_private_key_file((fixtures / "key.pem").string(), net::ssl::context::pem);
    }
    net::ssl::stream<acpp::tcp::socket> secured(std::move(peer_socket), context);
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
    std::unique_ptr<acpp::AsyncStream> stream;

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
            std::string header;
            char byte;
            do {
                co_await net::async_read(wire, net::buffer(&byte, 1), net::use_awaitable);
                header += byte;
            } while (!header.ends_with("\r\n\r\n"));
            Require(header.starts_with(upgrade ? "HTTP/1.1 101 " : "HTTP/1.1 200 "), "unexpected inbound response");
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
            if (!abortive) secured.next_layer().shutdown(acpp::tcp::socket::shutdown_send);
        }
        Require(peer_finished.try_send(acpp::IoErrorCode{}), "peer shutdown completion was lost");
    };
    auto product = [&]() -> net::awaitable<void> {
        if (!outbound && !tls && !fragmented) {
            // A previous byte-level handshake can already have several blocks
            // retained. The HTTP read consumes only its first 8KB; its own
            // read-ahead must be returned in front of the still-retained tail.
            std::string retained;
            std::array<char, acpp::buf::Buffer::kSize> block{};
            while (retained.size() < request.size() + payload.size()) {
                const size_t n = co_await raw->AsyncRead(net::buffer(
                    block.data(), std::min(block.size(), request.size() + payload.size() - retained.size())));
                Require(n != 0, "preexisting byte-layer residual truncated");
                retained.append(block.data(), n);
            }
            raw->PrependReadData(Bytes(retained));
        }
        auto built = outbound ? co_await acpp::BuildOutboundTransport(std::move(raw), settings)
                              : co_await acpp::BuildInboundTransport(io, std::move(raw), settings);
        Require(built.has_value(), "HTTP transport handshake failed");
        stream = std::move(*built);
        Require(stream->NativeHandle() == native, "handshake changed underlying socket ownership");
        stream->ClearPhaseDeadline();
        // Force a prepend while the actual read end still has handshake residual.
        // This prefix must precede both that residual and unread SSL/socket input.
        Prepend(*stream, "prefix");
        const auto pending_live = acpp::memory::detail::test_buffers_live;
        acpp::memory::reject_next_pmr_allocation = true;
        bool failed = false;
        try { Prepend(*stream, "must-not-appear"); } catch (const std::bad_alloc&) { failed = true; }
        Require(failed && acpp::memory::detail::test_buffers_live == pending_live,
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
            Require(acpp::buf::HasData(buffers), "multi-buffer read truncated payload");
            received += Flatten(buffers);
        }
        Require(received == "prefix" + payload, "read-ahead lost, duplicated, decrypted at wrong layer, or reordered");
        Require(acpp::memory::detail::test_buffers_live == 0,
                "consumed handshake residual retained payload blocks");
        net::steady_timer cancel(io, 5ms);
        cancel.async_wait([&](acpp::IoErrorCode ec) { if (!ec) stream->Cancel(); });
        if (fragmented) {
            auto buffers = co_await stream->ReadMultiBuffer();
            cancelled = !acpp::buf::HasData(buffers);
        } else {
            cancelled = co_await stream->AsyncRead(net::buffer(small)) == 0;
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
            Require(!acpp::buf::HasData(co_await stream->ReadMultiBuffer()), "read shutdown leaked multi-buffer data");
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
        Require(!acpp::buf::HasData(co_await stream->ReadMultiBuffer()), "closed transport leaked multi-buffer data");
        Require(acpp::memory::detail::test_buffers_live == 0, "shutdown/close retained payload blocks");
    };
    auto finish = [&](std::exception_ptr failure) {
        if (failure && !error) {
            error = failure;
            if (stream) stream->CloseAbortive();
            if (raw) raw->Close();
            acpp::IoErrorCode ignored;
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

void ExistingTcpResidual() {
    net::io_context io;
    acpp::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    acpp::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    acpp::TcpStream stream(std::move(socket));
    // More than eight blocks exercises spill metadata while the old residual
    // is transferred behind the new prefix without copying its payload.
    const std::string tail(10 * acpp::buf::Buffer::kSize, 't');
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
        Require(!acpp::buf::HasData(co_await stream.ReadMultiBuffer()), "close leaked old residual");
    };
    net::co_spawn(io, read(), [&](std::exception_ptr failure) { error = failure; done = true; });
    io.run_for(1s);
    if (error) std::rethrow_exception(error);
    Require(done && !acpp::memory::reject_next_pmr_allocation, "TCP residual test stalled");
}
}  // namespace

int main() {
    acpp::memory::ThreadPoolFacade resource;
    auto* previous = std::pmr::set_default_resource(&resource);
    bool passed = true;
    try {
        ExistingTcpResidual();
        for (bool outbound : {false, true})
            for (bool tls : {false, true})
                for (bool upgrade : {false, true})
                    for (bool fragmented : {false, true})
                        for (bool abortive : {false, true})
                            Case(outbound, tls, upgrade, fragmented, abortive);
        Require(acpp::memory::detail::test_buffers_live == 0, "test retained payload blocks");
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        passed = false;
    }
    std::pmr::set_default_resource(previous);
    return passed ? 0 : 1;
}
