#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/common/allocator.hpp"
#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/steady_timer.hpp>
#include <iostream>
#include <stdexcept>

namespace {
namespace net = acpp::net;
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
    acpp::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    acpp::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    acpp::TcpStream stream(std::move(socket));
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
        Require(resource.allocations >= before + 2 * count,
                "real TCP read/write operations must use the associated PMR allocator");
        std::cout << "TCP read/write operations=" << 2 * count << " PMR allocations="
                  << resource.allocations - before << '\n';
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
        [&](std::exception_ptr e, acpp::IoErrorCode ec) {
            cancelled = e || ec == net::error::operation_aborted;
        }));
    timer.async_wait([&](acpp::IoErrorCode ec) { if (!ec) signal.emit(net::cancellation_type::terminal); });
    io.run_for(1s);
    Require(cancelled && resource.allocations > before && resource.live == live,
            "cancellation must release its PMR socket operation on the owner");
}

void TestInitiationFailure(CountingResource& resource) {
    net::io_context io;
    acpp::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    acpp::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    acpp::TcpStream stream(std::move(socket));
    bool failed = false;
    resource.fail_next = true;
    net::co_spawn(io, stream.WaitReadable(), [&](std::exception_ptr e, acpp::IoErrorCode) {
        if (e) { try { std::rethrow_exception(e); } catch (const std::bad_alloc&) { failed = true; } }
    });
    // Asio may propagate initiation allocation failure out of io_context::run
    // rather than into the suspended awaitable. Both paths must destroy owners.
    try { io.run_for(1s); } catch (const std::bad_alloc&) { failed = true; }
    Require(failed && !resource.fail_next, "must exercise actual operation allocation failure");
}
}

int main() {
    acpp::memory::ThreadPoolFacade pool;
    CountingResource resource(&pool);
    auto original = std::pmr::set_default_resource(&resource);
    bool passed = true;
    try {
        TestIO(resource);
        TestInitiationFailure(resource);
        Require(resource.live == 0 && !resource.wrong_thread, "all operations and scheduler allocations must be released on owner");
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; passed = false; }
    std::pmr::set_default_resource(original);
    return passed ? 0 : 1;
}
