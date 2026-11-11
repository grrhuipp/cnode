#pragma once

#include "common/asio_types.hpp"

#include <asio/this_coro.hpp>

// 读到 EOF 时区分对端关闭与本端取消：若当前协程已被取消，则抛出 operation_aborted。
namespace common {

inline net::awaitable<void> ThrowIfCancelledOnEof(const char* cancel_what = nullptr) {
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        if (cancel_what) {
            throw IoSystemError(io_error::operation_aborted, cancel_what);
        }
        throw IoSystemError(io_error::operation_aborted);
    }
}

}  // namespace common
