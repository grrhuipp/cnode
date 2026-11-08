#pragma once

#include "http_response.hpp"

#include <asio/cancel_after.hpp>
#include <asio/co_spawn.hpp>

#include <chrono>
#include <exception>
#include <format>
#include <optional>
#include <system_error>
#include <utility>

namespace api::v2board::http {

// The timeout cancels the owning exchange coroutine and waits for its completion.
// A fully received response remains authoritative even if TLS cleanup is cancelled.
inline net::awaitable<Response> RunRequest(
    net::awaitable<Response> exchange,
    std::chrono::steady_clock::duration timeout) {
    struct RequestCancelled {};
    const auto executor = co_await net::this_coro::executor;
    const auto caller_cancellation = co_await net::this_coro::cancellation_state;
    const auto execute = [](net::awaitable<Response> task) -> net::awaitable<Response> {
        const auto cancellation = co_await net::this_coro::cancellation_state;
        try {
            auto response = co_await std::move(task);
            // DNS and HTTP parsing may represent I/O errors as values. Preserve
            // cancellation identity rather than reporting a malformed response.
            if (response.status <= 0 && cancellation.cancelled() != net::cancellation_type::none) {
                throw RequestCancelled{};
            }
            co_return response;
        } catch (const std::system_error&) {
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw RequestCancelled{};
            }
            throw;
        }
    };
    const bool throw_if_cancelled = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::optional<Response> result;
    std::exception_ptr failure;
    try {
        result.emplace(co_await net::co_spawn(executor, execute(std::move(exchange)),
            net::cancel_after(timeout, net::use_awaitable)));
    } catch (const RequestCancelled&) {
        if (caller_cancellation.cancelled() != net::cancellation_type::none) {
            failure = std::make_exception_ptr(std::system_error(net::error::operation_aborted));
        } else {
            result.emplace(Response{-1, std::format("HTTP request timed out after {} ms",
                std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count()), {}, false});
        }
    } catch (const std::system_error& error) {
        if (caller_cancellation.cancelled() != net::cancellation_type::none) {
            failure = std::current_exception();
        } else {
            result.emplace(Response{-1, error.what(), {}, false});
        }
    } catch (const std::exception& error) {
        result.emplace(Response{-1, error.what(), {}, false});
    } catch (...) {
        failure = std::current_exception();
    }
    co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
    if (failure) std::rethrow_exception(failure);
    co_return std::move(*result);
}

}  // namespace api::v2board::http
