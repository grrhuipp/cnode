#include <gtest/gtest.h>

#include "transport/internet/tcp_stream.hpp"
#include "common/allocator.hpp"
#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/bind_allocator.hpp>
#include <asio/post.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/steady_timer.hpp>
#include <iostream>
#include <stdexcept>

namespace {
namespace net = ::net;
using namespace std::chrono_literals;
void Require(bool yes, const char* why) { if (!yes) throw std::runtime_error(why); }
class CountingResource : public std::pmr::memory_resource {
public:
    explicit CountingResource(std::pmr::memory_resource* upstream) : upstream(upstream) {}
    size_t allocations = 0, live = 0;
    bool wrong_thread = false, fail_next = false;
private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (std::exchange(fail_next, false)) throw std::bad_alloc();
        void* p = upstream->allocate(bytes, alignment);
        wrong_thread |= std::this_thread::get_id() != owner;
        ++allocations; ++live; return p;
    }
    void do_deallocate(void* p, size_t bytes, size_t alignment) override {
        wrong_thread |= std::this_thread::get_id() != owner;
        --live; upstream->deallocate(p, bytes, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& r) const noexcept override { return &r == this; }
    std::pmr::memory_resource* upstream;
    std::thread::id owner = std::this_thread::get_id();
};

void TestIO(CountingResource& resource) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    ::TcpStream stream(std::move(socket));
    constexpr size_t count = 128;
    size_t completed = 0;
    std::exception_ptr error;
    auto echo = [&]() -> net::awaitable<void> {
        char byte;
        for (size_t i = 0; i < count; ++i) {
            co_await net::async_read(peer, net::buffer(&byte, 1), net::use_awaitable);
            co_await net::async_write(peer, net::buffer(&byte, 1), net::use_awaitable);
        }
    };
    auto request = [&]() -> net::awaitable<void> {
        const auto before = resource.allocations;
        const auto live = resource.live;
        char byte = 'a';
        for (size_t i = 0; i < count; ++i) {
            Require(co_await stream.AsyncWrite(net::buffer(&byte, 1)) == 1, "write failed");
            Require(resource.live == live, "write operation must release before resuming its caller");
            Require(co_await stream.AsyncRead(net::buffer(&byte, 1)) == 1 && byte == 'a', "read failed");
            Require(resource.live == live, "read operation must release before resuming its caller");
        }
        Require(resource.allocations == before,
                "native TCP operations must not allocate from the private PMR resource");
    };
    auto finish = [&](std::exception_ptr e) {
        if (e && !error) { error = e; stream.Close(); peer.close(); }
        ++completed;
    };
    net::co_spawn(io, echo(), finish);
    net::co_spawn(io, request(), finish);
    io.run_for(3s);
    Require(completed == 2, "TCP allocation test stalled");
    if (error) std::rethrow_exception(error);

    io.restart();
    net::cancellation_signal signal;
    net::steady_timer timer(io, 5ms);
    bool cancelled = false;
    const auto before = resource.allocations;
    const auto live = resource.live;
    net::co_spawn(io, stream.WaitReadable(), net::bind_cancellation_slot(signal.slot(),
        [&](std::exception_ptr e, ::IoErrorCode ec) {
            cancelled = e || ec == net::error::operation_aborted;
        }));
    timer.async_wait([&](::IoErrorCode ec) { if (!ec) signal.emit(net::cancellation_type::terminal); });
    io.run_for(1s);
    Require(cancelled && resource.allocations == before && resource.live == live,
            "cancellation must release process-allocated socket operations without touching private PMR");
}

void TestReadCancellation(CountingResource& resource, bool multi_buffer) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    ::TcpStream stream(std::move(socket));
    net::cancellation_signal signal;
    net::steady_timer timer(io, 5ms);
    bool completed = false, cancelled = false;
    std::exception_ptr error;
    const auto before = resource.allocations;
    auto read = [&]() -> net::awaitable<void> {
        try {
            if (multi_buffer) {
                (void)co_await stream.ReadMultiBuffer();
            } else {
                char byte{};
                (void)co_await stream.AsyncRead(net::buffer(&byte, 1));
            }
        } catch (const ::IoSystemError& failure) {
            if (failure.code() != ::io_error::operation_aborted) throw;
            cancelled = true;
        }
    };
    net::co_spawn(io, read(), net::bind_cancellation_slot(signal.slot(),
        [&](std::exception_ptr e) { error = e; completed = true; }));
    timer.async_wait([&](::IoErrorCode ec) {
        if (!ec) signal.emit(net::cancellation_type::terminal);
    });
    io.run_for(1s);
    if (error) std::rethrow_exception(error);
    Require(completed && cancelled && resource.allocations == before,
            "read cancellation must not allocate native operations from private PMR");
    Require(peer.is_open() && stream.IsOpen(), "cancellation must not close the connection");
}

void TestPrivateAllocatorIsolation(CountingResource& resource) {
    net::io_context io;
    ::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    ::TcpStream stream(std::move(socket));
    net::cancellation_signal signal;
    net::steady_timer timer(io, 5ms);
    bool cancelled = false;
    resource.fail_next = true;
    net::co_spawn(io, stream.WaitReadable(), net::bind_cancellation_slot(signal.slot(),
        [&](std::exception_ptr error, ::IoErrorCode ec) {
            if (error) std::rethrow_exception(error);
            cancelled = ec == net::error::operation_aborted;
        }));
    timer.async_wait([&](::IoErrorCode ec) {
        if (!ec) signal.emit(net::cancellation_type::terminal);
    });
    io.run_for(1s);
    const bool untouched = std::exchange(resource.fail_next, false);
    Require(cancelled && untouched,
            "native operation initiation must not consult the private allocation resource");
}

void TestQueuedReadinessAcrossMigration() {
    using namespace ::memory;
    AllocationDomain domain;
    net::io_context reactor, destination;
    ::tcp::acceptor acceptor(reactor, {net::ip::address_v4::loopback(), 0});
    ::tcp::socket socket(reactor), peer(reactor);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    ::buf::Buffer* payload = nullptr;
    bool delivered = false;
    bool consumed = false;
    {
        ScopedAllocationDomain lease(domain);
        payload = ::buf::Buffer::New();
        Require(payload != nullptr, "payload allocation failed");
        const auto outstanding = domain.OutstandingAllocations();
        socket.async_wait(::tcp::socket::wait_read,
            net::bind_allocator(ProcessAllocator<std::byte>{},
                [&](::IoErrorCode ec) {
                    // Reactor completion transports metadata only. No payload
                    // access or private-object destruction occurs on this thread.
                    delivered = !ec;
                    net::post(destination, net::bind_allocator(ProcessAllocator<std::byte>{}, [&, ec] {
                        ScopedAllocationDomain migrated(domain);
                        Require(!ec, "readiness failed");
                        const auto count = socket.read_some(net::buffer(payload->Tail().data(), 1));
                        payload->Produce(static_cast<uint32_t>(count));
                        consumed = payload->Bytes()[0] == 'q';
                        ::buf::Buffer::Free(payload);
                        payload = nullptr;
                    }));
                }));
        Require(domain.OutstandingAllocations() == outstanding,
                "queued operation must not borrow the connection domain");
    }
    const char value = 'q';
    peer.write_some(net::buffer(&value, 1));
    std::thread completion([&] { reactor.run_for(1s); });
    completion.join();
    Require(delivered && !consumed, "completion must be retained before owner resumes");
    std::thread migrated([&] { destination.run(); });
    migrated.join();
    Require(consumed && !payload, "new owner must consume readiness and destroy payload");
}

void TestPendingOperationDestruction() {
    using namespace ::memory;
    AllocationDomain domain;
    auto reactor = std::make_unique<net::io_context>();
    auto timer = std::make_unique<net::steady_timer>(*reactor, 1h);
    {
        ScopedAllocationDomain lease(domain);
        timer->async_wait(net::bind_allocator(ProcessAllocator<std::byte>{},
            [](::IoErrorCode) {}));
        Require(domain.OutstandingAllocations() == 0,
                "pending operation storage must belong to process allocator");
    }
    // Asio destroys the still-pending handler without calling it and without
    // entering a domain when its reactor is destroyed on another thread.
    std::thread shutdown([&] { timer.reset(); reactor.reset(); });
    shutdown.join();
}
} // namespace

TEST(AsioOperationAllocator, Contract) {
    ::memory::ThreadMemoryResource pool;
    CountingResource resource(&pool);
    auto original = std::pmr::set_default_resource(&resource);
    bool passed = true;
    try {
        TestIO(resource);
        TestReadCancellation(resource, false);
        TestReadCancellation(resource, true);
        TestPrivateAllocatorIsolation(resource);
        TestQueuedReadinessAcrossMigration();
        TestPendingOperationDestruction();
        Require(resource.live == 0 && !resource.wrong_thread,
                "all private scheduler allocations must be released on their owner");
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; passed = false; }
    std::pmr::set_default_resource(original);
    { ASSERT_TRUE(passed); return; }
}
