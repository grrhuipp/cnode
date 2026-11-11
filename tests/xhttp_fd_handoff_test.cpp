#include <gtest/gtest.h>

#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/tls_stream.hpp"
#include "infra/config_types.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <asio/write.hpp>
#include <array>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

void Require(bool condition, const char* what) {
    if (!condition) throw std::runtime_error(what);
}

TEST(XhttpFdHandoff, TcpStaticBoundaryDetachAndRestorePreservesPrefixAndStream) {
    // io_b runs on this thread, io_a on thread_a; only detached native state crosses.
    net::io_context io_b, io_a;
    tcp::acceptor acceptor(io_b, {net::ip::address_v4::loopback(), 0});
    tcp::socket client_sock(io_b), server_sock(io_b);
    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto server_stream = std::make_unique<TcpStream>(std::move(server_sock));
    const std::string payload = "POST /fixture/s1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello";
    net::write(client_sock, net::buffer(payload));

    std::array<uint8_t, 32> head_buf{};
    auto read_fut = net::co_spawn(
        io_b, server_stream->AsyncRead(net::buffer(head_buf)), net::use_future);
    io_b.run();
    const size_t n = read_fut.get();
    Require(n == head_buf.size(), "initial head read incomplete");

    auto detached = server_stream->DetachForHandoff({head_buf.data(), n});
    Require(detached.has_value(), "TCP DetachForHandoff failed");
    server_stream.reset();

    std::string received;
    auto restore_fut = net::co_spawn(
        io_a,
        [&, state = std::move(*detached)]() mutable -> net::awaitable<void> {
            auto restored = TcpStream::RestoreFromHandoff(io_a, std::move(state));
            Require(restored != nullptr, "TCP RestoreFromHandoff failed");
            std::array<uint8_t, 128> buf{};
            while (received.size() < payload.size()) {
                const size_t r = co_await restored->AsyncRead(net::buffer(buf));
                Require(r > 0, "unexpected EOF on restored TCP stream");
                received.append(reinterpret_cast<const char*>(buf.data()), r);
            }
            const std::string reply = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            co_await restored->AsyncWrite(net::buffer(reply));
        },
        net::use_future);
    std::thread thread_a([&] { io_a.run(); });
    restore_fut.get();
    thread_a.join();

    EXPECT_EQ(received, payload);
    std::array<char, 64> reply_buf{};
    const size_t reply_n = client_sock.read_some(net::buffer(reply_buf));
    EXPECT_EQ(std::string_view(reply_buf.data(), reply_n),
              "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
}

TEST(XhttpFdHandoff, TlsStaticBoundaryDetachAndRestorePreservesSessionAndPlaintext) {
    TlsStream::InitializeIo();
    TlsConfig tls_cfg;
    tls_cfg.server_name = "localhost";
    auto server_ctx = SslContext::CreateServerAutoSign(tls_cfg);
    tls_cfg.allow_insecure = true;
    auto client_ctx = SslContext::CreateClient(tls_cfg);
    Require(server_ctx && client_ctx, "failed to create TLS contexts");

    net::io_context io_b, io_a;
    tcp::acceptor acceptor(io_b, {net::ip::address_v4::loopback(), 0});
    tcp::socket raw_client(io_b), raw_server(io_b);
    raw_client.connect(acceptor.local_endpoint());
    acceptor.accept(raw_server);

    std::unique_ptr<TlsStream> client_tls;
    std::unique_ptr<TlsStream> server_tls;
    const std::string payload = "POST /fixture/tls-s1 HTTP/1.1\r\nHost: localhost\r\n\r\nbody-bytes";
    std::array<uint8_t, 24> prefix{};
    size_t prefix_n = 0;

    auto client_fut = net::co_spawn(
        io_b,
        [&]() -> net::awaitable<void> {
            client_tls = co_await WrapTlsClient(
                std::make_unique<TcpStream>(std::move(raw_client)), *client_ctx, "localhost");
            Require(client_tls != nullptr, "client TLS handshake failed");
            co_await client_tls->AsyncWrite(net::buffer(payload));
        },
        net::use_future);

    auto server_fut = net::co_spawn(
        io_b,
        [&]() -> net::awaitable<void> {
            server_tls = co_await WrapTlsServer(
                std::make_unique<TcpStream>(std::move(raw_server)), *server_ctx);
            Require(server_tls != nullptr, "server TLS handshake failed");
            prefix_n = co_await server_tls->AsyncRead(net::buffer(prefix));
        },
        net::use_future);

    io_b.run();
    client_fut.get();
    server_fut.get();
    Require(prefix_n == prefix.size(), "initial TLS read incomplete");

    auto detached = server_tls->DetachForHandoff({prefix.data(), prefix_n});
    Require(detached.has_value(), "TLS DetachForHandoff failed");
    server_tls.reset();

    std::string received;
    auto restore_fut = net::co_spawn(
        io_a,
        [&, state = std::move(*detached)]() mutable -> net::awaitable<void> {
            auto restored = TlsStream::RestoreFromHandoff(io_a, std::move(state));
            Require(restored != nullptr, "TLS RestoreFromHandoff failed");
            std::array<uint8_t, 128> buf{};
            while (received.size() < payload.size()) {
                const size_t r = co_await restored->AsyncRead(net::buffer(buf));
                Require(r > 0, "unexpected EOF on restored TLS stream");
                received.append(reinterpret_cast<const char*>(buf.data()), r);
            }
        },
        net::use_future);
    std::thread thread_a([&] { io_a.run(); });
    restore_fut.get();
    thread_a.join();

    EXPECT_EQ(received, payload);
}

}  // namespace
