#include <gtest/gtest.h>

#include "transport/internet/tcp_stream.hpp"
#include "common/allocator.hpp"

#include <asio/bind_allocator.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/read.hpp>
#include <asio/use_future.hpp>
#include <asio/write.hpp>

#include <array>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;

class AsioOperationAllocatorTest : public ::testing::Test {
protected:
    AsioOperationAllocatorTest()
        : acceptor_(io_, {net::ip::address_v4::loopback(), 0}),
          peer_(io_), stream_(Connect()) {}

    ::tcp::socket Connect() {
        ::tcp::socket socket(io_);
        socket.connect(acceptor_.local_endpoint());
        acceptor_.accept(peer_);
        return socket;
    }

    net::io_context io_;
    ::tcp::acceptor acceptor_;
    ::tcp::socket peer_;
    ::transport::internet::TcpStream stream_;
};

TEST_F(AsioOperationAllocatorTest, NativeWriteDeliversEveryByteToPeer) {
    constexpr std::array<char, 4> sent{'a', '\0', 'b', '\xff'};
    std::array<char, sent.size()> received{};
    auto written = net::co_spawn(io_, [&]() -> net::awaitable<std::size_t> {
        std::size_t offset = 0;
        while (offset < sent.size()) {
            const auto count = co_await stream_.AsyncWrite(
                net::buffer(sent.data() + offset, sent.size() - offset));
            if (count == 0) break;
            offset += count;
        }
        co_return offset;
    }, net::use_future);
    auto read = net::co_spawn(io_, [&]() -> net::awaitable<std::size_t> {
        co_return co_await net::async_read(peer_, net::buffer(received), net::use_awaitable);
    }, net::use_future);
    io_.run_for(3s);
    const bool completed = written.wait_for(0s) == std::future_status::ready &&
                           read.wait_for(0s) == std::future_status::ready;
    if (!completed) {
        stream_.Close();
        peer_.close();
        io_.restart();
        io_.run();
    }
    ASSERT_TRUE(completed);
    EXPECT_EQ(written.get(), sent.size());
    EXPECT_EQ(read.get(), received.size());
    EXPECT_EQ(received, sent);
}

TEST_F(AsioOperationAllocatorTest, NativeReadReturnsPeerPayload) {
    constexpr std::array<char, 4> sent{'x', '\0', 'y', '\xff'};
    std::array<char, sent.size()> received{};
    net::write(peer_, net::buffer(sent));
    auto result = net::co_spawn(io_, [&]() -> net::awaitable<void> {
        std::size_t offset = 0;
        while (offset < received.size()) {
            const auto count = co_await stream_.AsyncRead(net::buffer(received.data() + offset,
                                                                     received.size() - offset));
            if (count == 0) break;
            offset += count;
        }
    }, net::use_future);
    io_.run_for(3s);
    const bool completed = result.wait_for(0s) == std::future_status::ready;
    if (!completed) {
        stream_.Close();
        io_.restart();
        io_.run();
    }
    ASSERT_TRUE(completed);
    result.get();
    EXPECT_EQ(received, sent);
}

enum class ReadKind { Readiness, Bytes, MultiBuffer };
class NativeReadCancellation : public AsioOperationAllocatorTest,
                               public ::testing::WithParamInterface<ReadKind> {};

TEST_P(NativeReadCancellation, CancelsPendingOperationWithoutClosingConnection) {
    net::cancellation_signal cancellation;
    bool cancelled = false;
    auto read = [&]() -> net::awaitable<void> {
        try {
            switch (GetParam()) {
            case ReadKind::Readiness:
                cancelled = co_await stream_.WaitReadable() == net::error::operation_aborted;
                break;
            case ReadKind::Bytes: {
                char byte{};
                (void)co_await stream_.AsyncRead(net::buffer(&byte, 1));
                break;
            }
            case ReadKind::MultiBuffer:
                (void)co_await stream_.ReadMultiBuffer();
                break;
            }
        } catch (const ::IoSystemError& error) {
            if (error.code() != ::io_error::operation_aborted) throw;
            cancelled = true;
        }
    };
    auto result = net::co_spawn(io_, read(),
        net::bind_cancellation_slot(cancellation.slot(), net::use_future));
    io_.poll();
    EXPECT_EQ(result.wait_for(0s), std::future_status::timeout);
    cancellation.emit(net::cancellation_type::terminal);
    io_.run_for(1s);
    const bool completed = result.wait_for(0s) == std::future_status::ready;
    if (!completed) {
        stream_.Close();
        io_.restart();
        io_.run();
    }
    ASSERT_TRUE(completed);
    result.get();
    EXPECT_TRUE(cancelled);
    EXPECT_TRUE(peer_.is_open());
    EXPECT_TRUE(stream_.IsOpen());
    const char sent = 'r';
    net::write(peer_, net::buffer(&sent, 1));
    char received{};
    io_.restart();
    auto reused = net::co_spawn(io_, stream_.AsyncRead(net::buffer(&received, 1)), net::use_future);
    io_.run();
    EXPECT_EQ(reused.get(), 1u);
    EXPECT_EQ(received, sent);
}

INSTANTIATE_TEST_SUITE_P(AllNativeReads, NativeReadCancellation,
    ::testing::Values(ReadKind::Readiness, ReadKind::Bytes, ReadKind::MultiBuffer));

TEST_F(AsioOperationAllocatorTest, QueuedReadinessOwnsPayloadUntilCallbackCompletes) {
    auto payload = ::buf::BufferGuard{::buf::Buffer::New()};
    ASSERT_TRUE(payload);
    bool consumed = false;
    bool released = false;
    struct CompletionLifetime {
        bool& released;
        ~CompletionLifetime() { released = true; }
    };
    auto lifetime = std::make_shared<CompletionLifetime>(released);
    std::weak_ptr<CompletionLifetime> pending = lifetime;
    peer_.async_wait(::tcp::socket::wait_read,
        net::bind_allocator(::memory::ProcessAllocator<std::byte>{},
            [&, payload = std::move(payload), lifetime = std::move(lifetime)](::IoErrorCode error) {
                EXPECT_FALSE(error);
                if (error) return;
                const auto count = peer_.read_some(net::buffer(payload->Tail().data(), 1));
                payload->Produce(static_cast<uint32_t>(count));
                consumed = payload->Bytes()[0] == 'q';
            }));
    EXPECT_FALSE(pending.expired());
    const char value = 'q';
    auto written = net::co_spawn(io_, stream_.AsyncWrite(net::buffer(&value, 1)), net::use_future);
    io_.run_for(1s);
    const bool completed = written.wait_for(0s) == std::future_status::ready && consumed;
    if (!completed) {
        stream_.Close();
        peer_.close();
        io_.restart();
        io_.run();
    }
    ASSERT_TRUE(completed);
    EXPECT_EQ(written.get(), 1u);
    EXPECT_TRUE(pending.expired());
    EXPECT_TRUE(released);
}

TEST(AsioOperationAllocator, ReactorDestructionReleasesPendingHandlerOnShutdownThread) {
    auto reactor = std::make_unique<net::io_context>();
    auto timer = std::make_unique<net::steady_timer>(*reactor, 1h);
    std::thread::id destruction_thread;
    bool called = false;
    struct Capture {
        std::thread::id& destruction_thread;
        ~Capture() { destruction_thread = std::this_thread::get_id(); }
    };
    auto capture = std::make_shared<Capture>(destruction_thread);
    std::weak_ptr<Capture> pending = capture;
    timer->async_wait(net::bind_allocator(::memory::ProcessAllocator<std::byte>{},
        [capture = std::move(capture), &called](::IoErrorCode) { called = true; }));
    EXPECT_FALSE(pending.expired());
    std::thread::id shutdown_thread;
    std::thread shutdown([&] {
        shutdown_thread = std::this_thread::get_id();
        timer.reset();
        reactor.reset();
    });
    shutdown.join();
    EXPECT_FALSE(called);
    EXPECT_TRUE(pending.expired());
    EXPECT_EQ(destruction_thread, shutdown_thread);
}
}  // namespace
