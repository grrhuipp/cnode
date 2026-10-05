#include "app/dns/inflight_resolves.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/app/dns/dns_service.hpp"
#include "acppnode/runtime/channel.hpp"
#include "acppnode/common/allocator.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/as_tuple.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/post.hpp>
#include <asio/strand.hpp>
#include <asio/use_future.hpp>
#include <vector>
#include <asio/steady_timer.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>

namespace {

using acpp::app::dns::DnsResult;
using acpp::app::dns::InflightResolves;
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

thread_local size_t fail_size = 0;
thread_local size_t injected_failures = 0;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class DNSServiceRun final {
public:
    DNSServiceRun(net::io_context& io, acpp::app::dns::DNSService& service)
        : io_(io), service_(service), stopped_(io, 1) {
        net::co_spawn(io_, service_.Run(), [this](std::exception_ptr error) {
            stopped_.try_send(error);
        });
    }

    net::awaitable<void> CloseAndJoin() {
        co_await service_.Close();
        auto [error] = co_await stopped_.async_receive(net::as_tuple(net::use_awaitable));
        if (error) std::rethrow_exception(error);
    }

    template <typename Handler>
    void CloseAndJoin(std::exception_ptr error, Handler handler) {
        net::co_spawn(io_, CloseAndJoin(), [error, handler = std::move(handler)](std::exception_ptr close_error) mutable {
            handler(error ? error : close_error);
        });
    }

private:
    net::io_context& io_;
    acpp::app::dns::DNSService& service_;
    net::experimental::concurrent_channel<void(std::exception_ptr)> stopped_;
};

template <typename T>
concept HasSyncCacheStats = requires(const T& client) { client.GetCacheStats(); };
static_assert(!std::is_default_constructible_v<acpp::app::dns::DNS>);
static_assert(!std::is_constructible_v<acpp::app::dns::DNS,
    net::io_context&, const acpp::app::dns::Config&>);
static_assert(!HasSyncCacheStats<acpp::app::dns::DNS>);

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
    TimeoutSchedulerScope scheduler_scope(io.get_executor());
    InflightResolves inflight(io.get_executor());
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
    TimeoutSchedulerScope scheduler_scope(io.get_executor());
    InflightResolves inflight(io.get_executor());
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

void TestDNSService() {
    acpp::app::dns::Config config;
    config.servers = {{net::ip::make_address("127.0.0.1"), 53}};
    net::io_context shared_context;
    TimeoutSchedulerScope scheduler_scope(shared_context.get_executor());
    acpp::app::dns::DNSService worker(shared_context.get_executor(), config, 8);
    DNSServiceRun service_run(shared_context, worker);
    std::atomic_size_t completed = 0;
    auto first_owner = net::make_strand(shared_context);
    auto second_owner = net::make_strand(shared_context);
    acpp::app::dns::DNS first(worker), second(worker);
    std::array<DnsResult, 2> answers;
    std::array<std::exception_ptr, 2> failures;
    std::array<bool, 2> resumed_on_owner{};
    net::co_spawn(first_owner, first.Resolve("192.0.2.1"),
        [&](std::exception_ptr error, DnsResult result) {
            failures[0] = error;
            answers[0] = std::move(result);
            resumed_on_owner[0] = first_owner.running_in_this_thread();
            if (++completed == 2) service_run.CloseAndJoin({}, [&](std::exception_ptr close_error) {
                if (close_error) failures[0] = close_error;
            });
        });
    net::co_spawn(second_owner, second.Resolve("192.0.2.2"),
        [&](std::exception_ptr error, DnsResult result) {
            failures[1] = error;
            answers[1] = std::move(result);
            resumed_on_owner[1] = second_owner.running_in_this_thread();
            if (++completed == 2) service_run.CloseAndJoin({}, [&](std::exception_ptr close_error) {
                if (close_error) failures[0] = close_error;
            });
        });
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < 4; ++i) workers.emplace_back([&] { shared_context.run(); });
    for (auto& thread : workers) thread.join();
    Require(!failures[0] && !failures[1] && answers[0].Ok() && answers[1].Ok() &&
            resumed_on_owner[0] && resumed_on_owner[1] &&
            answers[0].addresses[0] == net::ip::make_address("192.0.2.1") &&
            answers[1].addresses[0] == net::ip::make_address("192.0.2.2"),
            "shared-context DNS must return owned values to each caller strand");
}

void TestDNSCloseWithFullChannel() {
    net::io_context io;
    TimeoutSchedulerScope scheduler_scope(io.get_executor());
    auto caller = net::make_strand(io);
    auto peer_owner = net::make_strand(io);
    acpp::ServiceChannel peer_channel(peer_owner, 4);
    acpp::udp::socket sink(peer_owner, {net::ip::address_v4::loopback(), 0});
    acpp::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    config.timeout_sec = 30;
    acpp::app::dns::DNSService worker(io.get_executor(), config, 1);
    DNSServiceRun service_run(io, worker);
    acpp::app::dns::DNS client(worker);
    auto pending = net::co_spawn(caller, client.Resolve("shutdown.example"), net::use_future);
    bool closed = false, rejected = false, late_request_rejected = false;
    std::exception_ptr failure;
    std::array<uint8_t, 512> query{};
    acpp::udp::endpoint sender;
    sink.async_receive_from(net::buffer(query), sender,
        [&](acpp::IoErrorCode ec, std::size_t) {
            if (ec) return;
            net::co_spawn(caller, [&]() -> net::awaitable<void> {
                auto result = co_await client.Resolve("192.0.2.4");
                rejected = result.error == acpp::ErrorCode::RESOURCE_EXHAUSTED;
                co_await worker.Close();
                co_await service_run.CloseAndJoin();
                closed = true;
                result = co_await client.Resolve("192.0.2.4");
                late_request_rejected = result.error == acpp::ErrorCode::CANCELLED;
                co_await peer_channel.Call([&] { sink.close(); });
            }, [&](std::exception_ptr error) { failure = error; });
        });
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < 4; ++i) threads.emplace_back([&] { io.run(); });
    for (auto& thread : threads) thread.join();
    Require(!failure && closed && rejected && late_request_rejected,
        "terminal reservation must close and join DNS even while lookup capacity is exhausted");
    const auto result = pending.get();
    Require(result.error == acpp::ErrorCode::CANCELLED,
        "closing DNS must finish and reclaim pending queries before returning");
}

void TestDNSRemoteInputOwnership() {
    net::io_context main_context;
    TimeoutSchedulerScope scheduler_scope(main_context.get_executor());
    net::ip::udp::socket sink(main_context, {net::ip::address_v4::loopback(), 0});
    acpp::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    acpp::app::dns::DNSService worker(main_context.get_executor(), config, 8);
    DNSServiceRun service_run(main_context, worker);
    acpp::app::dns::DNS client(worker);
    std::string domain = "192.0.2.1";
    auto task = client.Resolve(domain);
    // The remote facade must capture owned input before the task is scheduled.
    // Reusing the caller's storage must not change the submitted DNS request.
    domain.assign("192.0.2.2");
    bool completed = false;
    std::exception_ptr failure;
    DnsResult answer;
    net::co_spawn(main_context, std::move(task),
        [&](std::exception_ptr error, DnsResult result) {
            service_run.CloseAndJoin(error, [&, result = std::move(result)](std::exception_ptr final_error) {
                failure = final_error;
                answer = std::move(result);
                completed = true;
            });
        });
    main_context.run();
    Require(completed && !failure && answer.Ok() && answer.addresses.size() == 1 &&
                answer.addresses.front() == net::ip::make_address("192.0.2.1"),
            "remote DNS facade must own its input at task creation");
}

void TestDNSClientLifetime() {
    net::io_context main_context;
    TimeoutSchedulerScope scheduler_scope(main_context.get_executor());
    net::ip::udp::socket sink(main_context, {net::ip::address_v4::loopback(), 0});
    acpp::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    acpp::app::dns::DNSService worker(main_context.get_executor(), config, 8);
    DNSServiceRun service_run(main_context, worker);
    // The facade must not be captured in a deferred coroutine: the task only
    // needs its input and the DNSService, not this already-destroyed client.
    auto task = acpp::app::dns::DNS(worker).Resolve("192.0.2.3");
    bool resolved = false;
    net::co_spawn(main_context, std::move(task),
        [&](std::exception_ptr error, DnsResult result) {
            service_run.CloseAndJoin(error, [&, result = std::move(result)](std::exception_ptr final_error) {
                resolved = !final_error && result.Ok() && result.addresses.size() == 1 &&
                    result.addresses.front() == net::ip::make_address("192.0.2.3");
            });
        });
    main_context.run();
    Require(resolved, "DNS tasks must not borrow the lightweight client facade");
}

void TestDNSServiceCancellation() {
    net::io_context caller;
    TimeoutSchedulerScope scheduler_scope(caller.get_executor());
    net::ip::udp::socket sink(caller, {net::ip::address_v4::loopback(), 0});
    acpp::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    config.timeout_sec = 2;
    acpp::app::dns::DNSService worker(caller.get_executor(), config, 8);
    DNSServiceRun service_run(caller, worker);
    acpp::app::dns::DNS client(worker);
    net::cancellation_signal signal;
    bool completed = false;
    net::co_spawn(caller, client.Resolve("cancel-dns-worker.example"),
        net::bind_cancellation_slot(signal.slot(),
            [&](std::exception_ptr error, DnsResult) {
                service_run.CloseAndJoin(error, [&](std::exception_ptr) { completed = true; });
            }));
    net::steady_timer timer(caller, 50ms);
    timer.async_wait([&](const acpp::IoErrorCode& ec) {
        if (!ec) signal.emit(net::cancellation_type::terminal);
    });
    caller.run_for(1s);
    Require(completed, "cancellation must stop waiting for the shared-context DNS service");
}

void TestDNSServiceCapacity(bool stats_request) {
    net::io_context main_context;
    TimeoutSchedulerScope scheduler_scope(main_context.get_executor());
    net::ip::udp::socket sink(main_context, {net::ip::address_v4::loopback(), 0});
    acpp::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    config.timeout_sec = 2;
    acpp::app::dns::DNSService worker(main_context.get_executor(), config, 1);
    DNSServiceRun service_run(main_context, worker);
    acpp::app::dns::DNS client(worker);
    net::cancellation_signal cancel;
    bool owner_done = false;
    bool rejected = false;
    bool closed = false;
    std::exception_ptr failure;
    auto begin_recovery = [&] {
        if (owner_done && rejected && !closed) {
            service_run.CloseAndJoin({}, [&](std::exception_ptr error) {
                failure = error;
                closed = true;
            });
        }
    };
    net::steady_timer watchdog(main_context, 1s);
    watchdog.async_wait([&](const acpp::IoErrorCode& error) {
        if (!error) {
            cancel.emit(net::cancellation_type::terminal);
            sink.cancel();
        }
    });
    net::co_spawn(main_context, client.Resolve("capacity.example"),
        net::bind_cancellation_slot(cancel.slot(),
            [&](std::exception_ptr, DnsResult) { owner_done = true; begin_recovery(); }));
    // Receiving the first upstream packet proves the only channel slot is held.
    std::array<uint8_t, 512> query{};
    net::ip::udp::endpoint sender;
    sink.async_receive_from(net::buffer(query), sender,
        [&](const acpp::IoErrorCode& error, size_t) {
            if (error) return;
            if (stats_request) {
                net::co_spawn(main_context, worker.GetCacheStats(),
                    [&](std::exception_ptr error, acpp::app::dns::DnsCacheStats) {
                        failure = error;
                        try {
                            if (error) std::rethrow_exception(error);
                        } catch (const acpp::ServiceChannelFull&) {
                            rejected = true;
                            failure = {};
                        } catch (...) {}
                        rejected = true;
                        cancel.emit(net::cancellation_type::terminal);
                        watchdog.cancel();
                        begin_recovery();
                    });
            } else {
                net::co_spawn(main_context, client.Resolve("192.0.2.4"),
                    [&](std::exception_ptr error, DnsResult result) {
                        failure = error;
                        rejected = result.error == acpp::ErrorCode::RESOURCE_EXHAUSTED;
                        cancel.emit(net::cancellation_type::terminal);
                        watchdog.cancel();
                        begin_recovery();
                    });
            }
        });
    main_context.run();
    Require(owner_done && !failure && rejected,
            "capacity overload and cancellation must complete without leaking DNS work");
    Require(closed, "DNS service must close and join after capacity rejection/cancellation");
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
        TestDNSService();
        TestDNSCloseWithFullChannel();
        TestDNSRemoteInputOwnership();
        TestDNSClientLifetime();
        TestDNSServiceCancellation();
        TestDNSServiceCapacity(false);
        TestDNSServiceCapacity(true);
    } catch (const std::exception& error) {
        fail_size = 0;
        std::cerr << error.what() << '\n';
        passed = false;
    }
    return passed ? 0 : 1;
}
