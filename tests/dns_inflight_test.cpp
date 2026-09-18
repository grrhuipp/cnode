#include "app/dns/inflight_resolves.hpp"
#include "app/dns/global_cache.hpp"
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

namespace {

using acpp::app::dns::DnsResult;
using acpp::app::dns::InflightResolves;
namespace net = acpp::net;
using namespace std::chrono_literals;

thread_local size_t fail_size = 0;
thread_local size_t fail_worker_size = 0;
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

void TestL1WarmFailure() {
    net::io_context io;
    acpp::app::dns::Config config;
    config.servers = {{net::ip::make_address("127.0.0.1"), 53}};
    acpp::app::dns::DNS dns(io, config);
    DnsResult answer;
    answer.addresses.assign(400, net::ip::make_address("192.0.2.9"));
    acpp::app::dns::GlobalDnsCache::PublishResult("warm.example", answer);
    const auto failures_before = injected_failures;
    bool completed = false;
    std::exception_ptr error;
    auto request = [&]() -> net::awaitable<void> {
        fail_worker_size = answer.addresses.size() * sizeof(net::ip::address);
        auto resolved = co_await dns.Resolve("warm.example");
        fail_worker_size = 0;
        Require(resolved.Ok() && resolved.addresses == answer.addresses &&
                    dns.GetCacheStats().entries == 0 &&
                    injected_failures == failures_before + 1,
                "failed L1 warming must preserve the available L2 answer");
        resolved = co_await dns.Resolve("warm.example");
        Require(resolved.Ok() && dns.GetCacheStats().entries == 1,
                "a cache write must recover after an allocation failure");
    };
    net::co_spawn(io, request(), [&](std::exception_ptr failure) {
        error = failure;
        completed = true;
    });
    io.run_for(1s);
    fail_worker_size = 0;
    Require(completed, "cached DNS resolution must not depend on network I/O");
    if (error) std::rethrow_exception(error);
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
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    if (fail_worker_size && size >= fail_worker_size) {
        fail_worker_size = 0;
        ++injected_failures;
        return nullptr;
    }
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void operator delete(void* pointer, const std::nothrow_t&) noexcept {
    ::operator delete(pointer);
}

int main() {
    acpp::memory::ConfigureProcessAllocator();
    try {
        TestCompletion(Failure::None);
        TestCompletion(Failure::Query);
        TestCompletion(Failure::ResultCopy);
        TestSubscriberCancellation();
        TestL1WarmFailure();
    } catch (const std::exception& error) {
        fail_size = 0;
        fail_worker_size = 0;
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
