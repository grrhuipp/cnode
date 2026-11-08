#include <gtest/gtest.h>

#include "app/dns/inflight_resolves.hpp"
#include "app/dns/dns_worker.hpp"
#include "app/worker_mailbox.hpp"
#include "common/allocator.hpp"

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
#include <string>
#include <thread>
#include <type_traits>

namespace {

using ::app::dns::DnsResult;
using ::app::dns::InflightResolves;
namespace net = ::net;
using namespace std::chrono_literals;

thread_local size_t fail_size = 0;
thread_local size_t injected_failures = 0;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}


enum class Failure { None, Query, IoQuery, CancelledQuery, ResultCopy };

net::awaitable<DnsResult> Query(net::io_context& io, size_t& calls, Failure failure) {
    ++calls;
    co_await net::post(io, net::use_awaitable);
    if (failure == Failure::Query) throw std::runtime_error("query failed");
    if (failure == Failure::IoQuery) throw ::IoSystemError(::io_error::connection_reset);
    if (failure == Failure::CancelledQuery) throw ::IoSystemError(::io_error::operation_aborted);
    DnsResult result;
    result.addresses.assign(400, net::ip::make_address("192.0.2.1"));
    if (failure == Failure::ResultCopy) {
        fail_size = result.addresses.size() * sizeof(net::ip::address);
    }
    co_return result;
}

void TestCompletion(Failure failure) {
    net::io_context io;
    InflightResolves inflight(io, 1);
    size_t calls = 0;
    size_t completed = 0;
    constexpr size_t clients = 5;
    std::array<DnsResult, clients> results;
    std::array<std::exception_ptr, clients> errors;
    net::steady_timer watchdog(io, 2s);
    bool timed_out = false;
    watchdog.async_wait([&](const ::IoErrorCode& error) {
        if (!error) { timed_out = true; io.stop(); }
    });
    const auto failures_before = injected_failures;
    for (size_t i = 0; i < clients; ++i) {
        net::co_spawn(io, inflight.Run("coalesced.example", [&](std::string_view) {
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
    size_t copy_failures = 0;
    for (size_t i = 0; i < clients; ++i) {
        if (failure == Failure::Query || failure == Failure::IoQuery) {
            Require(static_cast<bool>(errors[i]),
                    "every uncancelled subscriber must receive the actual query exception");
            try {
                std::rethrow_exception(errors[i]);
            } catch (const ::IoSystemError& error) {
                Require(failure == Failure::IoQuery && error.code() == ::io_error::connection_reset,
                        "non-cancellation I/O failures must preserve their concrete error code");
            } catch (const std::runtime_error& error) {
                Require(failure == Failure::Query && std::string_view(error.what()) == "query failed",
                        "query exceptions must preserve their original type and reason");
            }
        } else if (errors[i]) {
            Require(failure == Failure::ResultCopy,
                    "successful or cancelled queries must not manufacture exceptions");
            try {
                std::rethrow_exception(errors[i]);
            } catch (const std::bad_alloc&) {
                ++copy_failures;
            }
        } else if (failure == Failure::CancelledQuery) {
            Require(results[i].error == ::ErrorCode::CANCELLED,
                    "operation_aborted must remain an explicit cancellation result");
        } else {
            Require(results[i].Ok() && results[i].addresses.size() == 400,
                    "successful answers must survive another waiter's copy failure");
        }
    }
    Require(copy_failures == (failure == Failure::ResultCopy ? 1u : 0u),
            "only the waiter with a failed result copy may fail");

    io.restart();
    bool retried = false;
    net::co_spawn(io, inflight.Run("coalesced.example", [&](std::string_view) {
        return Query(io, calls, Failure::None);
    }), [&](std::exception_ptr error, DnsResult result) {
        retried = !error && result.Ok();
    });
    io.run_for(1s);
    Require(retried && calls == 2,
            "completion must erase the failed generation and return its only active quota slot");
    io.restart();
    bool joined = false;
    std::exception_ptr join_error;
    net::co_spawn(io, inflight.AsyncJoin(), [&](std::exception_ptr error) {
        join_error = error;
        joined = true;
    });
    io.run();
    if (join_error) std::rethrow_exception(join_error);
    Require(joined, "subscriber exceptions must not prevent service task-group join");
}

net::awaitable<DnsResult> GatedQuery(
    net::experimental::channel<void(::IoErrorCode)>& gate, size_t& calls) {
    ++calls;
    (void)co_await gate.async_receive(net::as_tuple(net::use_awaitable));
    DnsResult result;
    result.addresses.push_back(net::ip::make_address("192.0.2.7"));
    co_return result;
}

void TestSubscriberCancellation() {
    net::io_context io;
    InflightResolves inflight(io, 8);
    net::experimental::channel<void(::IoErrorCode)> gate(io);
    net::cancellation_signal cancel;
    size_t calls = 0;
    std::array<DnsResult, 3> results;
    std::array<std::exception_ptr, 3> errors;
    size_t completed = 0;
    auto query = [&](std::string_view) { return GatedQuery(gate, calls); };
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
    Require(errors[1] || results[1].error == ::ErrorCode::CANCELLED,
            "the cancelled subscriber must observe cancellation");
}

net::awaitable<DnsResult> DelayedCancellationQuery(
    net::experimental::channel<void(::IoErrorCode)>& gate, size_t& calls) {
    // Model an upstream whose cleanup cannot complete until its final callback.
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    co_return co_await GatedQuery(gate, calls);
}

void TestRetiredGenerationCapacity() {
    net::io_context io;
    InflightResolves inflight(io, 2);
    net::experimental::channel<void(::IoErrorCode)> old_gate(io), new_gate(io);
    net::cancellation_signal cancel;
    size_t calls = 0, survivors = 0;
    bool cancelled = false, rejected = false;
    std::exception_ptr failure;
    auto old_query = [&](std::string_view) { return DelayedCancellationQuery(old_gate, calls); };
    auto new_query = [&](std::string_view) { return GatedQuery(new_gate, calls); };
    net::co_spawn(io, inflight.Run("generation.example", old_query),
        net::bind_cancellation_slot(cancel.slot(),
            [&](std::exception_ptr error, DnsResult result) {
                cancelled = error || result.error == ::ErrorCode::CANCELLED;
            }));
    io.poll();
    cancel.emit(net::cancellation_type::terminal);
    io.poll();
    Require(cancelled && calls == 1, "last waiter cancellation must retire its generation");
    auto survivor = [&](std::exception_ptr error, DnsResult result) {
        if (error) failure = error;
        else if (result.Ok()) ++survivors;
    };
    net::co_spawn(io, inflight.Run("generation.example", new_query), survivor);
    io.poll();
    Require(calls == 2, "a new waiter must not attach to a cancelled generation");
    net::co_spawn(io, inflight.Run("capacity.example", new_query),
        [&](std::exception_ptr error, DnsResult result) {
            rejected = !error && result.error == ::ErrorCode::RESOURCE_EXHAUSTED;
        });
    io.poll();
    Require(rejected && calls == 2, "retired but unfinished queries must still consume capacity");
    old_gate.close();
    io.poll();
    net::co_spawn(io, inflight.Run("generation.example", new_query), survivor);
    io.poll();
    Require(calls == 2, "old completion must not remove the new generation's registry entry");
    new_gate.close();
    io.run();
    if (failure) std::rethrow_exception(failure);
    Require(survivors == 2, "both new-generation waiters must receive the healthy answer");
    io.restart();
    bool joined = false;
    net::co_spawn(io, inflight.AsyncJoin(), [&](std::exception_ptr error) {
        failure = error; joined = true;
    });
    io.run();
    if (failure) std::rethrow_exception(failure);
    Require(joined, "join must settle cancelled generations as well as active subscribers");
}

void TestDNSWorker() {
    ::app::dns::Config config;
    config.servers = {{net::ip::make_address("127.0.0.1"), 53}};
    net::io_context main_context;
    auto main_guard = net::make_work_guard(main_context);
    ::app::dns::DNSWorker worker(main_context, config, 8);
    net::io_context first_io;
    net::io_context second_io;
    ::app::dns::DNS first(worker);
    ::app::dns::DNS second(worker);
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

void TestDNSRemoteInputOwnership() {
    net::io_context main_context;
    net::ip::udp::socket sink(main_context, {net::ip::address_v4::loopback(), 0});
    ::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    ::app::dns::DNSWorker worker(main_context, config, 8);
    ::app::dns::DNS client(worker);
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
            failure = error;
            answer = std::move(result);
            completed = true;
        });
    main_context.run();
    Require(completed && !failure && answer.Ok() && answer.addresses.size() == 1 &&
                answer.addresses.front() == net::ip::make_address("192.0.2.1"),
            "remote DNS facade must own its input at task creation");
}

void TestDNSClientLifetime() {
    net::io_context main_context;
    net::ip::udp::socket sink(main_context, {net::ip::address_v4::loopback(), 0});
    ::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    ::app::dns::DNSWorker worker(main_context, config, 8);
    // The facade must not be captured in a deferred coroutine: the task only
    // needs its input and the DNSWorker, not this already-destroyed client.
    auto task = ::app::dns::DNS(worker).Resolve("192.0.2.3");
    bool resolved = false;
    net::co_spawn(main_context, std::move(task),
        [&](std::exception_ptr error, DnsResult result) {
            resolved = !error && result.Ok() && result.addresses.size() == 1 &&
                result.addresses.front() == net::ip::make_address("192.0.2.3");
        });
    main_context.run();
    Require(resolved, "DNS tasks must not borrow the lightweight client facade");
}

void TestDNSWorkerCancellation() {
    net::io_context caller;
    net::ip::udp::socket sink(caller, {net::ip::address_v4::loopback(), 0});
    ::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    config.timeout_sec = 2;
    ::app::dns::DNSWorker worker(caller, config, 8);
    ::app::dns::DNS client(worker);
    net::cancellation_signal signal;
    bool completed = false;
    net::co_spawn(caller, client.Resolve("cancel-dns-worker.example"),
        net::bind_cancellation_slot(signal.slot(),
            [&](std::exception_ptr, DnsResult) { completed = true; }));
    net::steady_timer timer(caller, 50ms);
    timer.async_wait([&](const ::IoErrorCode& ec) {
        if (!ec) signal.emit(net::cancellation_type::terminal);
    });
    caller.run_for(1s);
    Require(completed, "cancellation must stop waiting for the main control Worker's DNS service");
}

void TestDNSWorkerCapacity(bool stats_request) {
    net::io_context main_context;
    net::ip::udp::socket sink(main_context, {net::ip::address_v4::loopback(), 0});
    ::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    config.timeout_sec = 2;
    ::app::dns::DNSWorker worker(main_context, config, 1);
    ::app::dns::DNS client(worker);
    net::cancellation_signal cancel;
    bool owner_done = false;
    bool rejected = false;
    std::exception_ptr failure;
    net::steady_timer watchdog(main_context, 1s);
    watchdog.async_wait([&](const ::IoErrorCode& error) {
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
        [&](const ::IoErrorCode& error, size_t) {
            if (error) return;
            if (stats_request) {
                net::co_spawn(main_context, worker.GetCacheStats(),
                    [&](std::exception_ptr error, ::app::dns::DnsCacheStats) {
                        failure = error;
                        try {
                            if (error) std::rethrow_exception(error);
                        } catch (const ::WorkerMailboxFull&) {
                            rejected = true;
                            failure = {};
                        } catch (...) {}
                        cancel.emit(net::cancellation_type::terminal);
                        watchdog.cancel();
                    });
            } else {
                net::co_spawn(main_context, client.Resolve("192.0.2.4"),
                    [&](std::exception_ptr error, DnsResult result) {
                        failure = error;
                        rejected = result.error == ::ErrorCode::RESOURCE_EXHAUSTED;
                        cancel.emit(net::cancellation_type::terminal);
                        watchdog.cancel();
                    });
            }
        });
    main_context.run();
    Require(owner_done && !failure && rejected,
            "a full DNS mailbox must reject rather than queue a lookup or stats request");

    main_context.restart();
    bool recovered = false;
    if (stats_request) {
        net::co_spawn(main_context, worker.GetCacheStats(),
            [&](std::exception_ptr error, ::app::dns::DnsCacheStats) {
                recovered = !error;
            });
    } else {
        net::co_spawn(main_context, client.Resolve("192.0.2.4"),
            [&](std::exception_ptr error, DnsResult result) {
                recovered = !error && result.Ok();
            });
    }
    main_context.run();
    Require(recovered, "cancellation must release the DNS mailbox slot");
}

void TestInflightStopBeforeLeaderCompletion() {
    net::io_context io;
    auto inflight = std::make_unique<InflightResolves>(io, 8);
    net::experimental::channel<void(::IoErrorCode)> gate(io);
    size_t calls = 0, completed = 0;
    std::array<DnsResult, 3> results;
    std::array<std::exception_ptr, 3> errors;
    bool expired = false;
    for (size_t i = 0; i < results.size(); ++i) {
        net::co_spawn(io, inflight->Run("stop-inflight.example", [&](std::string_view) {
            return GatedQuery(gate, calls);
        }), [&, i](std::exception_ptr error, DnsResult result) {
            errors[i] = error;
            results[i] = std::move(result);
            ++completed;
        });
    }
    net::steady_timer watchdog(io, 2s);
    watchdog.async_wait([&](::IoErrorCode error) {
        if (!error) { expired = true; gate.close(); }
    });
    while (calls == 0 && !expired) io.run_one();
    inflight->RequestStop();
    inflight->RequestStop();
    bool joined = false;
    std::exception_ptr join_error;
    net::co_spawn(io, inflight->AsyncJoin(), [&](std::exception_ptr error) {
        join_error = error;
        joined = true;
        watchdog.cancel();
    });
    io.run();
    inflight.reset();
    if (join_error) std::rethrow_exception(join_error);
    Require(!expired && joined && completed == results.size() && calls == 1,
            "join must finish the service query and every subscriber before destruction");
    for (size_t i = 0; i < results.size(); ++i) {
        Require(!errors[i] && results[i].error == ::ErrorCode::CANCELLED,
                "late successful leader completion must not replace service cancellation");
    }
}

void TestDNSWorkerStoppedWithoutQueries() {
    net::io_context io;
    ::app::dns::Config config;
    config.servers = {{net::ip::address_v4::loopback(), 53}};
    auto worker = std::make_unique<::app::dns::DNSWorker>(io, config, 1);
    worker->RequestStop();
    worker->RequestStop();
    bool done = false;
    std::exception_ptr failure;
    auto stop = [&]() -> net::awaitable<void> {
        const auto result = co_await worker->Resolve("192.0.2.1");
        Require(result.error == ::ErrorCode::CANCELLED,
                "an unused stopped service must reject queries without starting I/O");
        co_await worker->AsyncJoin();
        co_await worker->AsyncJoin();
        worker.reset();
    };
    net::co_spawn(io, stop(), [&](std::exception_ptr error) {
        failure = error;
        done = true;
    });
    io.run();
    if (failure) std::rethrow_exception(failure);
    Require(done, "joining a never-started service must complete");
}

void TestDNSWorkerCrossExecutorStop() {
    net::io_context main_context, first_io, second_io;
    net::ip::udp::socket sink(main_context, {net::ip::address_v4::loopback(), 0});
    ::app::dns::Config config;
    config.servers = {sink.local_endpoint()};
    config.timeout_sec = 30;
    auto worker = std::make_unique<::app::dns::DNSWorker>(main_context, config, 8);
    ::app::dns::DNS first(*worker), second(*worker);
    auto guard = net::make_work_guard(main_context);
    std::array<DnsResult, 4> results;
    std::array<std::exception_ptr, 4> errors;
    size_t completed = 0;
    bool joined = false, expired = false;
    std::exception_ptr join_error;
    net::steady_timer watchdog(main_context, 2s);
    auto finish = [&] {
        if (joined && completed == results.size()) {
            guard.reset();
            watchdog.cancel();
        }
    };
    auto handler = [&](size_t i) {
        return [&, i](std::exception_ptr error, DnsResult result) {
            errors[i] = error;
            results[i] = std::move(result);
            net::post(main_context, [&] { ++completed; finish(); });
        };
    };
    net::co_spawn(first_io, first.Resolve("first-stop.example"), handler(0));
    net::co_spawn(first_io, first.Resolve("first-stop.example"), handler(1));
    net::co_spawn(second_io, second.Resolve("second-stop.example"), handler(2));
    net::co_spawn(second_io, second.Resolve("second-stop.example"), handler(3));
    size_t packets = 0;
    auto stop = [&]() -> net::awaitable<void> {
        std::array<uint8_t, 512> packet{};
        net::ip::udp::endpoint sender;
        for (; packets < 8; ++packets) {
            co_await sink.async_receive_from(net::buffer(packet), sender, net::use_awaitable);
        }
        worker->RequestStop();
        worker->RequestStop();
        co_await worker->AsyncJoin();
        sink.close();
    };
    net::co_spawn(main_context, stop(), [&](std::exception_ptr error) {
        join_error = error;
        joined = true;
        finish();
    });
    watchdog.async_wait([&](::IoErrorCode error) {
        if (error) return;
        expired = true;
        worker->RequestStop();
        sink.close();
    });
    std::thread first_thread([&] { first_io.run(); });
    std::thread second_thread([&] { second_io.run(); });
    main_context.run();
    first_thread.join();
    second_thread.join();
    // Caller executor callbacks, not just DNS registry removal, have finished.
    worker.reset();
    Require(!expired && joined && packets == 8 && completed == results.size(),
            "service stop must join real UDP leaders and cross-executor subscribers");
    if (join_error) std::rethrow_exception(join_error);
    for (size_t i = 0; i < results.size(); ++i) {
        Require(!errors[i] && results[i].error == ::ErrorCode::CANCELLED,
                "cross-executor shutdown must return owned cancellation results");
    }
}

}  // namespace

void* operator new(std::size_t size) {
    if (fail_size && size == fail_size) {
        fail_size = 0;
        ++injected_failures;
        throw std::bad_alloc();
    }
    if (void* pointer = std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { std::free(pointer); }
TEST(DnsInflight, Contract) {
    ::memory::ConfigureProcessAllocator();
    bool passed = true;
    try {
        TestCompletion(Failure::None);
        TestCompletion(Failure::Query);
        TestCompletion(Failure::IoQuery);
        TestCompletion(Failure::CancelledQuery);
        TestCompletion(Failure::ResultCopy);
        TestSubscriberCancellation();
        TestRetiredGenerationCapacity();
        TestDNSWorker();
        TestDNSRemoteInputOwnership();
        TestDNSClientLifetime();
        TestDNSWorkerCancellation();
        TestDNSWorkerCapacity(false);
        TestDNSWorkerCapacity(true);
        TestInflightStopBeforeLeaderCompletion();
        TestDNSWorkerStoppedWithoutQueries();
        TestDNSWorkerCrossExecutorStop();
    } catch (const std::exception& error) {
        fail_size = 0;
        std::cerr << error.what() << '\n';
        passed = false;
    }
    { ASSERT_TRUE(passed); return; }
}
