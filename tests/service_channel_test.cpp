#include "acppnode/runtime/channel.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/strand.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>

#include <array>
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
using namespace acpp;

void Check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

using Gate = net::experimental::concurrent_channel<void(IoErrorCode)>;

net::awaitable<void> Wait(Gate& gate, std::promise<void>& waiting, bool& joined) {
    waiting.set_value();
    co_await gate.async_receive(net::use_awaitable);
    joined = true;
}

net::awaitable<void> Exercise(ServiceChannel& channel, Gate& gate, std::promise<void>& waiting) {
    co_await channel.Call([] {});
    Check(channel.Outstanding() == 0, "successful call must release its token");

    bool failed = false;
    try {
        co_await channel.Call([] { throw std::runtime_error("expected"); });
    } catch (const std::runtime_error&) {
        failed = true;
    }
    Check(failed && channel.Outstanding() == 0, "failed call must release its token");

    auto reserved = channel.TryReserve();
    Check(static_cast<bool>(reserved), "cleanup reservation must be admitted");
    Check(!channel.TryReserve(), "TryReserve must return empty when capacity is full");
    bool rejected = false;
    try {
        co_await channel.Call([] {});
    } catch (const ServiceChannelFull&) {
        rejected = true;
    }
    Check(rejected, "ordinary call must reject when reserved cleanup fills capacity");
    co_await channel.CallReserved(reserved, [] {});
    Check(channel.Outstanding() == 1, "reserved cleanup must retain its reservation");
    reserved = {};
    Check(channel.Outstanding() == 0, "destroying a reservation must return its token");

    bool joined = false;
    bool cancelled = false;
    try {
        co_await channel.PostCommitted(Wait(gate, waiting, joined));
    } catch (const net::system_error& error) {
        cancelled = error.code() == net::error::operation_aborted;
    }
    Check(cancelled && joined && channel.Outstanding() == 0,
          "cancelled committed call must join before reporting cancellation");
}

void CheckCrossThreadCapacity(net::io_context& io) {
    ServiceChannel channel(io.get_executor(), 7);
    std::vector<ServiceChannel::Reservation> reservations(64);
    std::atomic<size_t> acquired{0};
    std::array<std::thread, 4> threads;
    for (auto& thread : threads) {
        thread = std::thread([&] {
            for (;;) {
                auto reservation = channel.TryReserve();
                if (!reservation) break;
                const auto index = acquired.fetch_add(1, std::memory_order_relaxed);
                reservations[index] = std::move(reservation);
            }
        });
    }
    for (auto& thread : threads) thread.join();
    Check(acquired == 7 && channel.Outstanding() == 7,
          "concurrent admission must not exceed channel capacity");
    reservations.clear();
    Check(channel.Outstanding() == 0, "cross-thread reservation destruction must return tokens");
}
}

int main() {
    net::io_context io;
    auto work = net::make_work_guard(io);
    ServiceChannel channel(net::make_strand(io), 1);
    Gate gate(io, 1);
    std::array<std::thread, 4> workers;
    for (auto& worker : workers) worker = std::thread([&] { io.run(); });
    int status = 0;
    try {
        CheckCrossThreadCapacity(io);
        net::cancellation_signal cancellation;
        std::promise<void> waiting;
        auto is_waiting = waiting.get_future();
        auto future = net::co_spawn(net::make_strand(io), Exercise(channel, gate, waiting),
            net::bind_cancellation_slot(cancellation.slot(), net::use_future));
        is_waiting.get();
        cancellation.emit(net::cancellation_type::all);
        Check(gate.try_send(IoErrorCode{}), "release committed operation after cancellation");
        future.get();
        std::cout << "service channel capacity, reservation cleanup, failure and cancellation PASS\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        status = 1;
    }
    work.reset();
    if (status) io.stop();
    for (auto& worker : workers) worker.join();
    return status;
}
