#include <gtest/gtest.h>

#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "transport/internet/tls_config.hpp"
#include "transport/internet/tls_stream.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <asio/write.hpp>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <array>
#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <memory_resource>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;

void Require(bool value, const char* why) {
    if (!value) throw std::runtime_error(why);
}

class Resource final : public std::pmr::memory_resource {
public:
    std::size_t large_live = 0;
private:
    void* do_allocate(std::size_t size, std::size_t alignment) override {
        void* p = pool.allocate(size, alignment);
        if (size >= ::buf::Buffer::kSize) large_live += size;
        return p;
    }
    void do_deallocate(void* p, std::size_t size, std::size_t alignment) override {
        if (size >= ::buf::Buffer::kSize) large_live -= size;
        pool.deallocate(p, size, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
    ::memory::ThreadMemoryResource pool;
};

// An independent public-API TLS peer. Memory BIOs are test wire capture only:
// they let the test split an authenticated TLS record at an exact byte boundary.
class Peer {
public:
    Peer(::tcp::socket socket, SSL_CTX* context, bool server)
        : socket(std::move(socket)), ssl(SSL_new(context), SSL_free) {
        Require(ssl != nullptr, "peer SSL allocation failed");
        BIO* input = BIO_new(BIO_s_mem());
        BIO* output = BIO_new(BIO_s_mem());
        if (!input || !output) {
            BIO_free(input);
            BIO_free(output);
            throw std::bad_alloc();
        }
        BIO_set_mem_eof_return(input, -1);
        SSL_set_bio(ssl.get(), input, output);
        if (server) SSL_set_accept_state(ssl.get());
        else SSL_set_connect_state(ssl.get());
    }

    std::vector<uint8_t> TakeOutput() {
        BIO* output = SSL_get_wbio(ssl.get());
        std::vector<uint8_t> bytes(BIO_ctrl_pending(output));
        if (!bytes.empty())
            Require(BIO_read(output, bytes.data(), static_cast<int>(bytes.size())) ==
                        static_cast<int>(bytes.size()), "peer BIO output was incomplete");
        return bytes;
    }

    net::awaitable<void> Flush() {
        const auto bytes = TakeOutput();
        if (!bytes.empty()) co_await net::async_write(socket, net::buffer(bytes), net::use_awaitable);
    }

    net::awaitable<void> Feed() {
        std::array<uint8_t, 16384> bytes;
        const auto n = co_await socket.async_read_some(net::buffer(bytes), net::use_awaitable);
        Require(BIO_write(SSL_get_rbio(ssl.get()), bytes.data(), static_cast<int>(n)) ==
                    static_cast<int>(n), "peer BIO input was incomplete");
    }

    net::awaitable<void> Handshake() {
        for (;;) {
            ERR_clear_error();
            const int rc = SSL_do_handshake(ssl.get());
            const int error = rc > 0 ? SSL_ERROR_NONE : SSL_get_error(ssl.get(), rc);
            co_await Flush();
            if (rc > 0) co_return;
            Require(error == SSL_ERROR_WANT_READ, "peer handshake failed");
            co_await Feed();
        }
    }

    std::vector<uint8_t> Encrypt(std::string_view plain) {
        ERR_clear_error();
        const int n = SSL_write(ssl.get(), plain.data(), static_cast<int>(plain.size()));
        Require(n == static_cast<int>(plain.size()), "peer encryption failed");
        return TakeOutput();
    }

    net::awaitable<std::string> Read(std::size_t count) {
        std::string result;
        while (result.size() < count) {
            std::array<char, 8192> plain;
            ERR_clear_error();
            const int n = SSL_read(ssl.get(), plain.data(), static_cast<int>(plain.size()));
            const int error = n > 0 ? SSL_ERROR_NONE : SSL_get_error(ssl.get(), n);
            co_await Flush();
            if (n > 0) result.append(plain.data(), static_cast<std::size_t>(n));
            else if (error == SSL_ERROR_ZERO_RETURN) break;
            else {
                Require(error == SSL_ERROR_WANT_READ, "peer decryption failed");
                co_await Feed();
            }
        }
        co_return result;
    }

    ::tcp::socket socket;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl;
};

struct Fixture {
    explicit Fixture(bool product_server = false, bool large_chain = false,
                     const Resource* resource = nullptr) {
        const auto dir = std::filesystem::path(ACPP_TEST_SOURCE_DIR) / "tests/fixtures/anytls-pool";
        ::TlsConfig server_config;
        server_config.cert_file = (dir / "cert.pem").string();
        server_config.key_file = (dir / "key.pem").string();
        ::LoadTlsPemMaterial(server_config);
        server_config.alpn = {"h2"};
        server_config.min_version = ::TlsVersion::V1_3;
        server = ::SslContext::CreateServer(server_config);
        ::TlsConfig client_config;
        client_config.allow_insecure = true;
        client_config.alpn = {"h2"};
        client = ::SslContext::CreateClient(client_config);
        Require(server && client, "TLS fixture contexts failed");
        SSL_CTX_set_num_tickets(server->Native(), 0);
        SSL_CTX_set_max_cert_list(client->Native(), 512 * 1024);
        if (large_chain) {
            X509* certificate = SSL_CTX_get0_certificate(server->Native());
            const int size = i2d_X509(certificate, nullptr);
            Require(size > 0, "certificate encoding failed");
            for (int bytes = size; bytes < 160 * 1024; bytes += size)
                Require(SSL_CTX_add1_chain_cert(server->Native(), certificate) == 1,
                        "large certificate chain preparation failed");
        }
        ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
        ::tcp::socket socket(io), other(io);
        socket.connect(acceptor.local_endpoint());
        acceptor.accept(other);
        socket.set_option(net::socket_base::send_buffer_size(4096));
        socket.set_option(net::socket_base::receive_buffer_size(32768));
        other.set_option(net::socket_base::send_buffer_size(4096));
        other.set_option(net::socket_base::receive_buffer_size(32768));
        peer = std::make_unique<Peer>(std::move(other),
            product_server ? client->Native() : server->Native(), !product_server);
        stream = std::make_unique<::TlsStream>(
            std::make_unique<::TcpStream>(std::move(socket)),
            product_server ? *server : *client, product_server);
        if (resource) retained_before_handshake = resource->large_live;
        try {
            auto first = net::co_spawn(io, stream->Handshake(), net::use_future);
            auto second = net::co_spawn(io, peer->Handshake(), net::use_future);
            Require(Wait(first), "product handshake failed");
            Wait(second);
            if (!product_server) Require(stream->NegotiatedAlpn() == "h2", "negotiated ALPN was lost");
        } catch (...) {
            CloseAndJoin();
            throw;
        }
    }

    ~Fixture() { CloseAndJoin(); }

    void CloseAndJoin() {
        stream->CloseAbortive();
        ::IoErrorCode ignored;
        peer->socket.close(ignored);
        io.restart();
        io.run();
    }

    template<class T> T Wait(std::future<T>& result) {
        io.restart();
        io.run_for(3s);
        if (result.wait_for(0s) != std::future_status::ready) {
            CloseAndJoin();
            throw std::runtime_error("TLS operation did not complete");
        }
        return result.get();
    }

    net::io_context io;
    std::unique_ptr<::SslContext> server, client;
    std::unique_ptr<Peer> peer;
    std::unique_ptr<::TlsStream> stream;
    std::size_t retained_before_handshake = 0;
};

struct JoinPending {
    ~JoinPending() { fixture.CloseAndJoin(); }
    Fixture& fixture;
};

std::string Flatten(::buf::MultiBuffer data) {
    std::string result;
    while (!data.empty()) {
        auto buffer = data.pop_front();
        const auto bytes = buffer->Bytes();
        result.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
    return result;
}

net::awaitable<std::string> ReadBytes(::TlsStream& stream, std::size_t count) {
    std::string result;
    while (result.size() < count) {
        auto data = co_await stream.ReadMultiBuffer();
        Require(!data.empty(), "TLS payload ended early");
        result += Flatten(std::move(data));
    }
    co_return result;
}

void FragmentedAndCoalesced(Resource& resource) {
    Fixture fixture;
    const auto idle_bytes = resource.large_live;
    auto first = fixture.peer->Encrypt(std::string(9000, 'a'));
    const auto second = fixture.peer->Encrypt("second-record");
    first.insert(first.end(), second.begin(), second.end());
    net::write(fixture.peer->socket, net::buffer(first.data(), 3));
    auto read = net::co_spawn(fixture.io, fixture.stream->ReadMultiBuffer(), net::use_future);
    fixture.io.restart();
    fixture.io.run_for(20ms);
    Require(read.wait_for(0s) != std::future_status::ready, "partial TLS header completed a read");
    Require(::memory::detail::test_buffers_live == 0 && resource.large_live == idle_bytes,
            "partial record wait retained a relay or ciphertext staging buffer");
    fixture.stream->Cancel();
    bool cancelled = false;
    try { (void)fixture.Wait(read); }
    catch (const ::IoSystemError& error) {
        if (error.code() != net::error::operation_aborted) throw;
        cancelled = true;
    }
    Require(cancelled && fixture.stream->IsOpen(),
            "partial-record cancellation was EOF or closed TLS");
    read = net::co_spawn(fixture.io, fixture.stream->ReadMultiBuffer(), net::use_future);
    net::write(fixture.peer->socket, net::buffer(first.data() + 3, first.size() - 3));
    std::string plain = Flatten(fixture.Wait(read));
    while (plain.size() < 9013) {
        auto next = net::co_spawn(fixture.io, fixture.stream->ReadMultiBuffer(), net::use_future);
        plain += Flatten(fixture.Wait(next));
    }
    Require(plain == std::string(9000, 'a') + "second-record", "coalesced TLS records lost their suffix");
    Require(resource.large_live == idle_bytes, "completed TLS read retained operation payload");

    const auto record = fixture.peer->Encrypt("after-resource-failure");
    net::write(fixture.peer->socket, net::buffer(record));
    char prefix = 0;
    auto consume = net::co_spawn(fixture.io,
        fixture.stream->AsyncRead(net::buffer(&prefix, 1)), net::use_future);
    Require(fixture.Wait(consume) == 1 && prefix == 'a', "OOM fixture did not retain plaintext");
    // SSL_pending now avoids socket-wait allocation; the next PMR request is
    // the relay Buffer itself, not a coroutine or asynchronous socket handler.
    ::memory::reject_next_pmr_allocation = true;
    bool rejected = false;
    try {
        auto failed = net::co_spawn(fixture.io, fixture.stream->ReadMultiBuffer(), net::use_future);
        (void)fixture.Wait(failed);
    } catch (const std::bad_alloc&) { rejected = true; }
    const bool consumed_fault = !::memory::reject_next_pmr_allocation;
    ::memory::reject_next_pmr_allocation = false;
    Require(rejected && consumed_fault && fixture.stream->IsOpen(),
            "read allocation failure became EOF or closed TLS");
    auto retry = net::co_spawn(fixture.io, fixture.stream->ReadMultiBuffer(), net::use_future);
    Require(Flatten(fixture.Wait(retry)) == "fter-resource-failure", "OOM consumed retained plaintext");
}

void DuplexKeyUpdate(Resource& resource) {
    Fixture fixture;
    const auto idle_bytes = resource.large_live;
    const std::string payload(512 * 1024, 'w');
    const std::array<net::const_buffer, 1> buffers{net::buffer(payload)};
    Require(fixture.stream->DeferWriteCancellation(), "TLS cancellation deferral unavailable");
    net::cancellation_signal cancellation;
    JoinPending join{fixture};
    auto write = net::co_spawn(fixture.io, fixture.stream->WriteBuffers(buffers),
        net::bind_cancellation_slot(cancellation.slot(), net::use_future));
    fixture.io.restart();
    fixture.io.run_for(20ms);
    Require(write.wait_for(0s) != std::future_status::ready, "backpressure fixture did not suspend write");
    cancellation.emit(net::cancellation_type::all);
    Require(SSL_key_update(fixture.peer->ssl.get(), SSL_KEY_UPDATE_REQUESTED) == 1,
            "peer KeyUpdate failed");
    const auto incoming = fixture.peer->Encrypt("concurrent-control-record");
    net::write(fixture.peer->socket, net::buffer(incoming));
    auto read = net::co_spawn(fixture.io, fixture.stream->ReadMultiBuffer(), net::use_future);
    auto received = net::co_spawn(fixture.io, fixture.peer->Read(payload.size()), net::use_future);
    try { fixture.Wait(write); }
    catch (const ::IoSystemError& error) {
        if (error.code() != net::error::operation_aborted) throw;
    }
    Require(fixture.Wait(received) == payload, "logical cancellation truncated or interleaved physical TLS output");
    Require(Flatten(fixture.Wait(read)) == "concurrent-control-record", "full-duplex TLS control record stalled");
    Require(resource.large_live == idle_bytes, "completed duplex TLS operation retained ciphertext");

    auto close = net::co_spawn(fixture.io, fixture.stream->AsyncShutdownWrite(), net::use_future);
    auto eof = net::co_spawn(fixture.io, fixture.peer->Read(1), net::use_future);
    fixture.Wait(close);
    Require(fixture.Wait(eof).empty(), "TLS half-close did not send close_notify");
    const auto response = fixture.peer->Encrypt("after-half-close");
    net::write(fixture.peer->socket, net::buffer(response));
    auto remaining = net::co_spawn(fixture.io, fixture.stream->ReadMultiBuffer(), net::use_future);
    Require(Flatten(fixture.Wait(remaining)) == "after-half-close", "TLS write half-close discarded peer data");
    ERR_clear_error();
    Require(SSL_shutdown(fixture.peer->ssl.get()) >= 0, "peer close_notify failed");
    auto flush = net::co_spawn(fixture.io, fixture.peer->Flush(), net::use_future);
    auto finished = net::co_spawn(fixture.io, fixture.stream->ReadMultiBuffer(), net::use_future);
    fixture.Wait(flush);
    Require(fixture.Wait(finished).empty(), "peer close_notify was not authenticated EOF");
}

void BidirectionalBackpressure() {
    Fixture fixture;
    const std::string outbound(512 * 1024, 'u');
    const std::string inbound(512 * 1024, 'd');
    const auto encrypted = fixture.peer->Encrypt(inbound);
    JoinPending join{fixture};
    auto outgoing = net::co_spawn(fixture.io,
        fixture.stream->AsyncWrite(net::buffer(outbound)), net::use_future);
    auto incoming = net::async_write(
        fixture.peer->socket, net::buffer(encrypted), net::use_future);
    fixture.io.restart();
    fixture.io.run_for(20ms);
    Require(outgoing.wait_for(0s) != std::future_status::ready &&
                incoming.wait_for(0s) != std::future_status::ready,
            "duplex fixture did not backpressure both physical writers");
    auto product_read = net::co_spawn(fixture.io,
        ReadBytes(*fixture.stream, inbound.size()), net::use_future);
    auto peer_read = net::co_spawn(fixture.io,
        fixture.peer->Read(outbound.size()), net::use_future);
    Require(fixture.Wait(outgoing) == outbound.size(), "product duplex write was incomplete");
    Require(fixture.Wait(incoming) == encrypted.size(), "peer duplex write was incomplete");
    Require(fixture.Wait(product_read) == inbound && fixture.Wait(peer_read) == outbound,
            "TLS physical write gate blocked concurrent inbound progress");
}

void LargeHandshake(Resource& resource) {
    Fixture fixture(true, true, &resource);
    Require(resource.large_live == fixture.retained_before_handshake,
            "large handshake retained its output flight");
    const auto record = fixture.peer->Encrypt("after-large-flight");
    net::write(fixture.peer->socket, net::buffer(record));
    auto read = net::co_spawn(fixture.io, fixture.stream->ReadMultiBuffer(), net::use_future);
    Require(Flatten(fixture.Wait(read)) == "after-large-flight", "large handshake corrupted record sequence");
}

void ReadDeadline() {
    Fixture fixture;
    fixture.stream->SetReadTimeout(1s);
    auto read = net::co_spawn(fixture.io, fixture.stream->ReadMultiBuffer(), net::use_future);
    bool timed_out = false;
    try { (void)fixture.Wait(read); }
    catch (const ::IoSystemError& error) {
        if (error.code() != net::error::operation_aborted) throw;
        timed_out = true;
    }
    Require(timed_out && fixture.stream->ConsumeReadTimeout() &&
                !fixture.stream->IsOpen(), "TLS readable wait escaped the physical read deadline");
}
}  // namespace

TEST(TlsRecordBuffer, Contract) {
    ::TlsStream::InitializeIo();
    Resource resource;
    auto* previous = std::pmr::set_default_resource(&resource);
    bool passed = true;
    try {
        FragmentedAndCoalesced(resource);
        DuplexKeyUpdate(resource);
        BidirectionalBackpressure();
        LargeHandshake(resource);
        ReadDeadline();
        Require(resource.large_live == 0 && ::memory::detail::test_buffers_live == 0,
                "TLS test retained operation payload");
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        passed = false;
    }
    std::pmr::set_default_resource(previous);
    { ASSERT_TRUE(passed); return; }
}

namespace {
class TlsReadShutdown : public testing::TestWithParam<std::string> {};

TEST_P(TlsReadShutdown, PendingReadEndsWithoutClosingWriteDirection) {
    TlsStream::InitializeIo();
    Fixture fixture;
    const bool multi_buffer = GetParam().starts_with("multi");
    if (GetParam().ends_with("partial")) {
        const auto record = fixture.peer->Encrypt("discarded-peer-payload");
        net::write(fixture.peer->socket, net::buffer(record.data(), 3));
    }
    std::array<char, 64> target{};
    auto read = net::co_spawn(fixture.io, [&]() -> net::awaitable<std::size_t> {
        if (multi_buffer)
            co_return (co_await fixture.stream->ReadMultiBuffer()).byte_size();
        co_return co_await fixture.stream->AsyncRead(net::buffer(target));
    }, net::use_future);
    JoinPending join{fixture};
    fixture.io.restart();
    fixture.io.run_for(20ms);
    ASSERT_NE(read.wait_for(0s), std::future_status::ready);

    fixture.stream->ShutdownRead();
    EXPECT_EQ(fixture.Wait(read), 0);
    ASSERT_TRUE(fixture.stream->IsOpen());
    auto eof = net::co_spawn(fixture.io,
        fixture.stream->AsyncRead(net::buffer(target)), net::use_future);
    EXPECT_EQ(fixture.Wait(eof), 0);

    const std::string payload = "write-after-local-read-shutdown";
    auto write = net::co_spawn(fixture.io,
        fixture.stream->AsyncWrite(net::buffer(payload)), net::use_future);
    auto received = net::co_spawn(fixture.io,
        fixture.peer->Read(payload.size()), net::use_future);
    EXPECT_EQ(fixture.Wait(write), payload.size());
    EXPECT_EQ(fixture.Wait(received), payload);
    auto shutdown = net::co_spawn(fixture.io,
        fixture.stream->AsyncShutdownWrite(), net::use_future);
    auto closed = net::co_spawn(fixture.io, fixture.peer->Read(1), net::use_future);
    fixture.Wait(shutdown);
    EXPECT_TRUE(fixture.Wait(closed).empty());
    EXPECT_NE(SSL_get_shutdown(fixture.peer->ssl.get()) & SSL_RECEIVED_SHUTDOWN, 0);
}

INSTANTIATE_TEST_SUITE_P(ReadModes, TlsReadShutdown,
    testing::Values("multi-idle", "span-idle", "multi-partial", "span-partial"));
} // namespace
