#include "request_task.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/steady_timer.hpp>

#include <exception>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {
namespace net = acpp::net;
using acpp::api::v2board::http::Response;
using acpp::api::v2board::http::RunRequest;
using namespace std::chrono_literals;

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

struct ExchangeState {
    bool started = false;
    bool released = false;
    bool aborted = false;
};

struct ExchangeLifetime {
    ExchangeState& state;
    explicit ExchangeLifetime(ExchangeState& value) : state(value) { state.started = true; }
    ~ExchangeLifetime() { state.released = true; }
};

enum class WaitResult { Throw, FailureValue, CompleteResponse };

net::awaitable<Response> WaitingExchange(ExchangeState& state, WaitResult result) {
    ExchangeLifetime lifetime(state);
    net::steady_timer gate(co_await net::this_coro::executor,
                          net::steady_timer::time_point::max());
    if (result == WaitResult::Throw) {
        co_await gate.async_wait(net::use_awaitable);
    } else {
        const auto [error] = co_await gate.async_wait(net::as_tuple(net::use_awaitable));
        state.aborted = error == net::error::operation_aborted;
    }
    // CompleteResponse models an already received response followed by a
    // cancelled TLS close_notify. FailureValue models a parser/DNS I/O error.
    co_return result == WaitResult::CompleteResponse
        ? Response{200, "acknowledged", "response-etag", false}
        : Response{-1, "read failed", {}, false};
}

net::awaitable<Response> ImmediateExchange(bool fail) {
    if (fail) throw std::runtime_error("original request failure");
    co_return Response{304, {}, "cached-etag", true};
}

void TestOrdinaryCompletion(bool fail) {
    net::io_context io;
    bool completed = false;
    std::exception_ptr failure;
    Response response;
    net::co_spawn(io, RunRequest(ImmediateExchange(fail), 30s),
        [&](std::exception_ptr error, Response value) {
            completed = true;
            failure = error;
            response = std::move(value);
        });
    // A long request deadline must be cancelled and drained on early completion.
    io.run();
    Require(completed && !failure, "ordinary completion must drain its deadline");
    if (fail) {
        Require(response.status == -1 && response.body == "original request failure",
                "ordinary failure must preserve its cause");
    } else {
        Require(response.status == 304 && response.not_modified && response.etag == "cached-etag",
                "ordinary completion must preserve the entire response");
    }
}

void TestTimeout(WaitResult result) {
    net::io_context io;
    ExchangeState state;
    bool completed = false;
    bool released_before_completion = false;
    std::exception_ptr failure;
    Response response;
    net::co_spawn(io, RunRequest(WaitingExchange(state, result), 20ms),
        [&](std::exception_ptr error, Response value) {
            completed = true;
            released_before_completion = state.released;
            failure = error;
            response = std::move(value);
        });
    io.run();
    Require(completed && state.started && released_before_completion && !failure,
            "timeout must join the exchange and release its resources before completion");
    if (result == WaitResult::CompleteResponse) {
        Require(state.aborted && response.status == 200 && response.body == "acknowledged" &&
                    response.etag == "response-etag",
                "cleanup cancellation must preserve an already complete response");
    } else {
        Require(response.status == -1 && response.body == "HTTP request timed out after 20 ms",
                "timeout must retain its identity for both thrown and value I/O failures");
    }
}

void TestCallerCancellation(WaitResult result) {
    net::io_context io;
    net::cancellation_signal cancellation;
    ExchangeState state;
    bool completed = false;
    bool released_before_completion = false;
    std::exception_ptr failure;
    net::co_spawn(io, RunRequest(WaitingExchange(state, result), 30s),
        net::bind_cancellation_slot(cancellation.slot(),
            [&](std::exception_ptr error, Response) {
                completed = true;
                released_before_completion = state.released;
                failure = error;
            }));
    io.poll();
    Require(state.started && !completed, "cancellation fixture must reach the suspended exchange");
    cancellation.emit(net::cancellation_type::terminal);
    io.run();
    Require(completed && released_before_completion && failure,
            "caller cancellation must join the exchange and propagate an exception");
    try {
        std::rethrow_exception(failure);
    } catch (const std::system_error& error) {
        Require(error.code() == net::error::operation_aborted,
                "caller cancellation must not be mislabeled as a request timeout");
    }
}
}  // namespace

int main() {
    try {
        TestOrdinaryCompletion(false);
        TestOrdinaryCompletion(true);
        TestTimeout(WaitResult::Throw);
        TestTimeout(WaitResult::FailureValue);
        TestTimeout(WaitResult::CompleteResponse);
        TestCallerCancellation(WaitResult::Throw);
        TestCallerCancellation(WaitResult::FailureValue);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
