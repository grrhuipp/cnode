#include <gtest/gtest.h>

#include "common/allocator.hpp"
#include "transport/internet/tcp_stream.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <asio/write.hpp>
#include <chrono>
#include <future>
#include <stdexcept>
#include <vector>
#include <sys/socket.h>

namespace {
using namespace std::chrono_literals;

struct ReadFixture {
    net::io_context io;
    tcp::acceptor acceptor{io, {net::ip::address_v4::loopback(), 0}};
    tcp::socket socket{io}, peer{io};
    std::unique_ptr<TcpStream> stream;

    ReadFixture() {
        socket.open(tcp::v4());
        socket.set_option(net::socket_base::receive_buffer_size(256 * 1024));
        socket.connect(acceptor.local_endpoint());
        acceptor.accept(peer);
    }
    ~ReadFixture() {
        memory::reject_next_pmr_allocation = false;
        if (stream) stream->Close();
        IoErrorCode ignored;
        peer.close(ignored);
        socket.close(ignored);
        io.restart();
        io.run();
    }
    void Start() {
        stream = std::make_unique<TcpStream>(std::move(socket));
        stream->SetReadTimeout(2s);
    }
    void Preload(const std::vector<uint8_t>& payload) {
        // Establish actual queued bytes without consuming them, before cnode
        // makes the descriptor nonblocking. No timing or packet-size assumption.
        const timeval timeout{2, 0};
        if (::setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO,
                         &timeout, sizeof(timeout)) != 0)
            throw std::runtime_error("cannot bound preload peek");
        net::write(peer, net::buffer(payload));
        std::vector<uint8_t> peek(payload.size());
        if (::recv(socket.native_handle(), peek.data(), peek.size(), MSG_PEEK | MSG_WAITALL)
                != static_cast<ssize_t>(peek.size()) || peek != payload)
            throw std::runtime_error("cannot establish queued TCP payload");
    }
    template<class T> T Finish(std::future<T> future) {
        io.restart();
        io.run_for(3s);
        if (future.wait_for(0s) != std::future_status::ready)
            throw std::runtime_error("TCP read did not complete within deadline");
        return future.get();
    }
};

std::vector<uint8_t> Payload(std::size_t bytes) {
    std::vector<uint8_t> result(bytes);
    for (std::size_t index = 0; index < bytes; ++index)
        result[index] = static_cast<uint8_t>((index * 131 + index / 251) & 255);
    return result;
}

net::awaitable<std::vector<uint8_t>> ReadToEof(TcpStream& stream) {
    std::vector<uint8_t> result;
    for (;;) {
        auto batch = co_await stream.ReadMultiBuffer();
        if (batch.empty()) break;
        if (batch.byte_size() > buf::Buffer::kSize)
            throw std::runtime_error("TCP read exceeded one payload buffer");
        for (const auto* buffer : batch) {
            const auto bytes = buffer->Bytes();
            result.insert(result.end(), bytes.begin(), bytes.end());
        }
    }
    co_return result;
}

TEST(TcpRead, QueuedPayloadAndFinPreserveBytesAcrossBoundedBatches) {
    for (const std::size_t bytes : {1u, 8191u, 8192u, 8193u, 65536u, 131089u}) {
        SCOPED_TRACE(bytes);
        ReadFixture fixture;
        const auto payload = Payload(bytes);
        fixture.Preload(payload);
        fixture.peer.shutdown(tcp::socket::shutdown_send);
        fixture.Start();
        memory::detail::test_buffers_peak = 0;
        auto reading = net::co_spawn(fixture.io, ReadToEof(*fixture.stream), net::use_future);
        EXPECT_EQ(fixture.Finish(std::move(reading)), payload);
        EXPECT_EQ(memory::detail::test_buffers_live, 0u);
        EXPECT_LE(memory::detail::test_buffers_peak, 1u);
    }
}

TEST(TcpRead, AllocationFailureDoesNotConsumeQueuedInput) {
    ReadFixture fixture;
    const auto payload = Payload(65536);
    fixture.Preload(payload);
    fixture.peer.shutdown(tcp::socket::shutdown_send);
    fixture.Start();
    fixture.stream->SetReadTimeout(0s);
    memory::detail::test_buffers_peak = 0;
    memory::reject_next_pmr_allocation = true;
    auto attempt = [&]() -> net::awaitable<void> {
        (void)co_await fixture.stream->ReadMultiBuffer();
    };
    auto failed = net::co_spawn(fixture.io, attempt(), net::use_future);
    EXPECT_THROW(fixture.Finish(std::move(failed)), std::bad_alloc);
    EXPECT_FALSE(memory::reject_next_pmr_allocation);
    EXPECT_EQ(memory::detail::test_buffers_peak, 0u);
    EXPECT_EQ(memory::detail::test_buffers_live, 0u);
    fixture.stream->SetReadTimeout(2s);
    auto retry = net::co_spawn(fixture.io, ReadToEof(*fixture.stream), net::use_future);
    EXPECT_EQ(fixture.Finish(std::move(retry)), payload);
    EXPECT_EQ(memory::detail::test_buffers_live, 0u);
    EXPECT_LE(memory::detail::test_buffers_peak, 1u);
}

TEST(TcpRead, PeerResetIsAnErrorNotCleanEof) {
    ReadFixture fixture;
    fixture.Start();
    fixture.peer.set_option(net::socket_base::linger(true, 0));
    fixture.peer.close();
    auto attempt = [&]() -> net::awaitable<void> {
        (void)co_await fixture.stream->ReadMultiBuffer();
    };
    auto reading = net::co_spawn(fixture.io, attempt(), net::use_future);
    try {
        fixture.Finish(std::move(reading));
        FAIL() << "peer reset was reported as successful completion";
    } catch (const IoSystemError& error) {
        EXPECT_EQ(error.code(), io_error::connection_reset);
    }
    EXPECT_EQ(memory::detail::test_buffers_live, 0u);
}

TEST(TcpRead, IdleReadBorrowsNoPayloadAndCancellationPreservesQueuedInput) {
    ReadFixture fixture;
    fixture.Start();
    auto attempt = [&]() -> net::awaitable<void> {
        (void)co_await fixture.stream->ReadMultiBuffer();
    };
    auto cancelled = net::co_spawn(fixture.io, attempt(), net::use_future);
    fixture.io.run_for(1ms);
    ASSERT_NE(cancelled.wait_for(0s), std::future_status::ready);
    EXPECT_EQ(memory::detail::test_buffers_live, 0u);
    const auto payload = Payload(8193);
    net::write(fixture.peer, net::buffer(payload));
    fixture.stream->Cancel();
    EXPECT_THROW(fixture.Finish(std::move(cancelled)), IoSystemError);
    EXPECT_EQ(memory::detail::test_buffers_live, 0u);
    fixture.peer.shutdown(tcp::socket::shutdown_send);
    auto retry = net::co_spawn(fixture.io, ReadToEof(*fixture.stream), net::use_future);
    EXPECT_EQ(fixture.Finish(std::move(retry)), payload);
    EXPECT_EQ(memory::detail::test_buffers_live, 0u);
}
} // namespace
