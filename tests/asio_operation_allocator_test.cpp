#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include <asio/co_spawn.hpp>
#include <asio/bind_allocator.hpp>
#include <asio/strand.hpp>
#include <thread>
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
class TimeoutSchedulerScope final {
public:
    explicit TimeoutSchedulerScope(net::any_io_executor executor) : executor_(std::move(executor)) {
        acpp::TimeoutScheduler::Install(executor_);
    }
    ~TimeoutSchedulerScope() { acpp::TimeoutScheduler::ReleaseForExecutor(executor_); }
private:
    net::any_io_executor executor_;
};
void Require(bool yes, const char* why) { if (!yes) throw std::runtime_error(why); }
void TestIO() {
    net::io_context io;
    TimeoutSchedulerScope scheduler_scope(io.get_executor());
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
        const auto before = acpp::memory::data_allocations.load();
        const auto live = acpp::memory::live_data_allocations.load();
        char byte = 'a';
        for (size_t i = 0; i < count; ++i) {
            Require(co_await stream.AsyncWrite(net::buffer(&byte, 1)) == 1, "write failed");
            Require(acpp::memory::live_data_allocations.load() == live, "write operation must release before resuming its caller");
            Require(co_await stream.AsyncRead(net::buffer(&byte, 1)) == 1 && byte == 'a', "read failed");
            Require(acpp::memory::live_data_allocations.load() == live, "read operation must release before resuming its caller");
        }
        Require(acpp::memory::data_allocations.load() >= before + 2 * count,
                "real TCP read/write operations must use the associated PMR allocator");
        std::cout << "TCP read/write operations=" << 2 * count << " PMR allocations="
                  << acpp::memory::data_allocations.load() - before << '\n';
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
    const auto before = acpp::memory::data_allocations.load();
    const auto live = acpp::memory::live_data_allocations.load();
    net::co_spawn(io, stream.WaitReadable(), net::bind_cancellation_slot(signal.slot(),
        [&](std::exception_ptr e, acpp::IoErrorCode ec) {
            cancelled = e || ec == net::error::operation_aborted;
        }));
    timer.async_wait([&](acpp::IoErrorCode ec) { if (!ec) signal.emit(net::cancellation_type::terminal); });
    io.run_for(1s);
    Require(cancelled && acpp::memory::data_allocations.load() > before && acpp::memory::live_data_allocations.load() == live,
            "cancellation must release its socket operation before returning");
}

void TestReadCancellation(bool multi_buffer) {
    net::io_context io;
    TimeoutSchedulerScope scheduler_scope(io.get_executor());
    acpp::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    acpp::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    acpp::TcpStream stream(std::move(socket));
    net::cancellation_signal signal;
    net::steady_timer timer(io, 5ms);
    bool completed = false, cancelled = false;
    std::exception_ptr error;
    const auto before = acpp::memory::data_allocations.load();
    auto read = [&]() -> net::awaitable<void> {
        if (multi_buffer) {
            auto buffers = co_await stream.ReadMultiBuffer();
            cancelled = !acpp::buf::HasData(buffers);
        } else {
            char byte{};
            cancelled = co_await stream.AsyncRead(net::buffer(&byte, 1)) == 0;
        }
    };
    net::co_spawn(io, read(), net::bind_cancellation_slot(signal.slot(),
        [&](std::exception_ptr e) { error = e; completed = true; }));
    timer.async_wait([&](acpp::IoErrorCode ec) {
        if (!ec) signal.emit(net::cancellation_type::terminal);
    });
    io.run_for(1s);
    if (error) std::rethrow_exception(error);
    Require(completed && cancelled && acpp::memory::data_allocations.load() > before,
            "read cancellation must propagate through the allocator-bound operation");
    Require(peer.is_open() && stream.IsOpen(), "cancellation must not close the connection");
}

void TestInitiationFailure() {
    net::io_context io;
    TimeoutSchedulerScope scheduler_scope(io.get_executor());
    acpp::tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    acpp::tcp::socket socket(io), peer(io);
    socket.connect(acceptor.local_endpoint());
    acceptor.accept(peer);
    acpp::TcpStream stream(std::move(socket));
    bool failed = false;
    const auto rejected = acpp::memory::rejected_data_allocations.load();
    auto wait = [&]() -> net::awaitable<acpp::IoErrorCode> {
        acpp::memory::reject_next_data_allocation = true;
        co_return co_await stream.WaitReadable();
    };
    net::co_spawn(io, wait(), [&](std::exception_ptr e, acpp::IoErrorCode) {
        if (e) { try { std::rethrow_exception(e); } catch (const std::bad_alloc&) { failed = true; } }
    });
    // Asio may propagate initiation allocation failure out of io_context::run
    // rather than into the suspended awaitable. Both paths must destroy owners.
    try { io.run_for(1s); } catch (const std::bad_alloc&) { failed = true; }
    Require(failed && !acpp::memory::reject_next_data_allocation.load() &&
            acpp::memory::rejected_data_allocations.load() == rejected + 1,
            "must exercise actual operation allocation failure");
}
void TestCrossThreadOperationRelease() {
    net::io_context io;
    TimeoutSchedulerScope scheduler_scope(io.get_executor());
    const auto owner = net::make_strand(io);
    net::steady_timer timer(owner, 1ms);
    const auto before = acpp::memory::data_allocations.load();
    const auto live = acpp::memory::live_data_allocations.load();
    bool completed = false;
    const auto caller = std::this_thread::get_id();
    timer.async_wait(net::bind_allocator(acpp::memory::DataAllocator<std::byte>{},
        [&](acpp::IoErrorCode error) {
            Require(!error && std::this_thread::get_id() != caller,
                    "completion must execute on a shared-context run thread");
            completed = true;
        }));
    Require(acpp::memory::data_allocations.load() > before,
            "timer operation must allocate through the associated allocator");
    std::thread worker([&] { io.run(); });
    worker.join();
    Require(completed && acpp::memory::live_data_allocations.load() == live,
            "operation initiated on another thread must release all storage");
}
} // namespace

int main() {
    const auto live = acpp::memory::live_data_allocations.load();
    try {
        TestIO();
        TestReadCancellation(false);
        TestReadCancellation(true);
        TestInitiationFailure();
        TestCrossThreadOperationRelease();
        Require(acpp::memory::live_data_allocations.load() == live,
                "success, cancellation and initiation failure must release all operation storage");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
