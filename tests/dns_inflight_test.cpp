#include "app/dns/inflight_resolves.hpp"
#include "acppnode/app/dns/dns_worker.hpp"
#include "acppnode/common/allocator.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include <array>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <new>
#include <stdexcept>
#include <thread>

namespace {

using acpp::app::dns::DnsResult;
using acpp::app::dns::InflightResolves;
namespace net = acpp::net;
using namespace std::chrono_literals;

thread_local size_t fail_size = 0;
thread_local size_t injected_failures = 0;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

enum class Failure { None, Query, ResultCopy };

net::awaitable<DnsResult> Query(net::io_context& io, size_t& calls, Failure failure) {
    ++calls;
    co_await net::post(io, net::use_awaitable);
    if (failure == Failure::Query) throw std::runtime_error("query failed");
    DnsResult result;
    result.addresses.assign(400, net::ip::make_address("192.0.2.1"));
    if (failure == Failure::ResultCopy) {
        fail_size = result.addresses.size() * sizeof(net::ip::address);
    }
    co_return result;
}

void TestCompletion(Failure failure) {
    net::io_context io;
    InflightResolves inflight(io);
    size_t calls = 0;
    size_t completed = 0;
    constexpr size_t clients = 5;
    std::array<DnsResult, clients> results;
    std::array<std::exception_ptr, clients> errors;
    net::steady_timer watchdog(io, 2s);
    bool timed_out = false;
    watchdog.async_wait([&](const acpp::IoErrorCode& error) {
        if (!error) { timed_out = true; io.stop(); }
    });
    const auto failures_before = injected_failures;
    for (size_t i = 0; i < clients; ++i) {
        net::co_spawn(io, inflight.Run("coalesced.example", [&] {
            return Query(io, calls, failure);
        }), [&, i](std::exception_ptr error, DnsResult result) {
            errors[i] = error;
            results[i] = std::move(result);
            if (++completed == clients) watchdog.cancel();
        });
    }
    io.run();
    fail_size = 0;
    Require(!timed_out && completed == clients && calls == 1,
            "one query must complete every subscriber even when the owner fails");
    if (failure == Failure::ResultCopy) {
        Require(injected_failures == failures_before + 1,
                "the result-copy allocation failure must actually be injected");
    }
    Require(static_cast<bool>(errors[0]) == (failure != Failure::None),
            "the query owner must retain its own operation or result-copy error");
    for (size_t i = 1; i < clients; ++i) {
        Require(!errors[i], "one client's exception must not propagate to other clients");
        if (failure == Failure::Query) {
            Require(results[i].error == acpp::ErrorCode::DNS_RESOLVE_FAILED,
                    "abandoned queries must publish a terminal failure");
        } else {
            Require(results[i].Ok() && results[i].addresses.size() == 400,
                    "successful answers must survive an owner's result-copy failure");
        }
    }

    io.restart();
    bool retried = false;
    net::co_spawn(io, inflight.Run("coalesced.example", [&] {
        return Query(io, calls, Failure::None);
    }), [&](std::exception_ptr error, DnsResult result) {
        retried = !error && result.Ok();
    });
    io.run_for(1s);
    Require(retried && calls == 2,
            "completion must remove the inflight entry so a later request can start");
}

net::awaitable<DnsResult> GatedQuery(
    net::experimental::channel<void(acpp::IoErrorCode)>& gate, size_t& calls) {
    ++calls;
    (void)co_await gate.async_receive(net::as_tuple(net::use_awaitable));
    DnsResult result;
    result.addresses.push_back(net::ip::make_address("192.0.2.7"));
    co_return result;
}

void TestSubscriberCancellation() {
    net::io_context io;
    InflightResolves inflight(io);
    net::experimental::channel<void(acpp::IoErrorCode)> gate(io);
    net::cancellation_signal cancel;
    size_t calls = 0;
    std::array<DnsResult, 3> results;
    std::array<std::exception_ptr, 3> errors;
    size_t completed = 0;
    auto query = [&] { return GatedQuery(gate, calls); };
    auto handler = [&](size_t i) {
        return [&, i](std::exception_ptr error, DnsResult result) {
            errors[i] = error;
            results[i] = std::move(result);
            ++completed;
        };
    };
    net::co_spawn(io, inflight.Run("cancel.example", query), handler(0));
    net::co_spawn(io, inflight.Run("cancel.example", query),
                  net::bind_cancellation_slot(cancel.slot(), handler(1)));
    net::co_spawn(io, inflight.Run("cancel.example", query), handler(2));
    net::post(io, [&] {
        cancel.emit(net::cancellation_type::terminal);
        net::post(io, [&] { gate.close(); });
    });
    io.run_for(1s);
    Require(completed == 3 && calls == 1 && !errors[0] && !errors[2] &&
                results[0].Ok() && results[2].Ok(),
            "cancelling one subscriber must not cancel the owner or another subscriber");
    Require(errors[1] || results[1].error == acpp::ErrorCode::CANCELLED,
            "the cancelled subscriber must observe cancellation");
}

void TestDNSWorker() {
    acpp::app::dns::Config config;
    config.servers = {{net::ip::make_address("127.0.0.1"), 53}};
    net::io_context main_context;
    auto main_guard = net::make_work_guard(main_context);
    acpp::app::dns::DNSWorker worker(main_context, config, 8);
    net::io_context first_io;
    net::io_context second_io;
    acpp::app::dns::DNS first(worker);
    acpp::app::dns::DNS second(worker);
    std::array<DnsResult, 2> answers;
    std::array<std::exception_ptr, 2> failures;
    size_t completed = 0;
    auto finish = [&] {
        net::post(main_context, [&] {
            if (++completed == 2) main_guard.reset();
        });
    };
    net::co_spawn(first_io, first.Resolve("192.0.2.1"),
                  [&](std::exception_ptr error, DnsResult result) {
                      failures[0] = error;
                      answers[0] = std::move(result);
                      finish();
                  });
    net::co_spawn(second_io, second.Resolve("192.0.2.2"),
                  [&](std::exception_ptr error, DnsResult result) {
                      failures[1] = error;
                      answers[1] = std::move(result);
                      finish();
                  });
    std::thread first_thread([&] { first_io.run(); });
    std::thread second_thread([&] { second_io.run(); });
    main_context.run();
    first_thread.join();
    second_thread.join();
    Require(!failures[0] && !failures[1] && answers[0].Ok() && answers[1].Ok() &&
                answers[0].addresses[0] == net::ip::make_address("192.0.2.1") &&
                answers[1].addresses[0] == net::ip::make_address("192.0.2.2"),
            "multiple caller executors must receive owned answers from one DNS Worker");
}

void TestDNSWorkerCancellation() {
    net::io_context caller;
    net::ip::udp::socket sink(caller, {net::ip::address_v4::loopback(), 0});
    acpp::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    config.timeout_sec = 2;
    acpp::app::dns::DNSWorker worker(caller, config, 8);
    acpp::app::dns::DNS client(worker);
    net::cancellation_signal signal;
    bool completed = false;
    net::co_spawn(caller, client.Resolve("cancel-dns-worker.example"),
        net::bind_cancellation_slot(signal.slot(),
            [&](std::exception_ptr, DnsResult) { completed = true; }));
    net::steady_timer timer(caller, 50ms);
    timer.async_wait([&](const acpp::IoErrorCode& ec) {
        if (!ec) signal.emit(net::cancellation_type::terminal);
    });
    caller.run_for(1s);
    Require(completed, "cancellation must stop waiting for the main control Worker's DNS service");
}

void TestDNSWorkerCapacity() {
    net::io_context main_context;
    net::ip::udp::socket sink(main_context, {net::ip::address_v4::loopback(), 0});
    acpp::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    config.timeout_sec = 2;
    acpp::app::dns::DNSWorker worker(main_context, config, 1);
    acpp::app::dns::DNS client(worker);
    net::cancellation_signal cancel;
    bool owner_done = false;
    bool rejected = false;
    std::exception_ptr failure;
    net::steady_timer watchdog(main_context, 1s);
    watchdog.async_wait([&](const acpp::IoErrorCode& error) {
        if (!error) {
            cancel.emit(net::cancellation_type::terminal);
            sink.cancel();
        }
    });
    net::co_spawn(main_context, client.Resolve("capacity.example"),
        net::bind_cancellation_slot(cancel.slot(),
            [&](std::exception_ptr, DnsResult) { owner_done = true; }));
    // Receiving the first upstream packet proves the only mailbox slot is held.
    std::array<uint8_t, 512> query{};
    net::ip::udp::endpoint sender;
    sink.async_receive_from(net::buffer(query), sender,
        [&](const acpp::IoErrorCode& error, size_t) {
            if (error) return;
            net::co_spawn(main_context, client.Resolve("192.0.2.4"),
                [&](std::exception_ptr error, DnsResult result) {
                    failure = error;
                    rejected = result.error == acpp::ErrorCode::RESOURCE_EXHAUSTED;
                    cancel.emit(net::cancellation_type::terminal);
                    watchdog.cancel();
                });
        });
    main_context.run();
    Require(owner_done && !failure && rejected,
            "a full DNS mailbox must reject rather than queue another query");

    main_context.restart();
    bool recovered = false;
    net::co_spawn(main_context, client.Resolve("192.0.2.4"),
        [&](std::exception_ptr error, DnsResult result) {
            recovered = !error && result.Ok();
        });
    main_context.run();
    Require(recovered, "cancellation must release the DNS mailbox slot");
}

}  // namespace

void* operator new(std::size_t size) {
    // MSVC adds alignment bookkeeping to large vector allocations.
    if (fail_size && size >= fail_size && size - fail_size <= 128) {
        fail_size = 0;
        ++injected_failures;
        throw std::bad_alloc();
    }
    if (void* pointer = std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { std::free(pointer); }
int main() {
    acpp::memory::ConfigureProcessAllocator();
    bool passed = true;
    try {
        TestCompletion(Failure::None);
        TestCompletion(Failure::Query);
        TestCompletion(Failure::ResultCopy);
        TestSubscriberCancellation();
        TestDNSWorker();
        TestDNSWorkerCancellation();
        TestDNSWorkerCapacity();
    } catch (const std::exception& error) {
        fail_size = 0;
        std::cerr << error.what() << '\n';
        passed = false;
    }
    return passed ? 0 : 1;
}
