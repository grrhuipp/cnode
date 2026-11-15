#pragma once

#include "common/allocator.hpp"

#include <asio/awaitable.hpp>
#include <asio/cancellation_state.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/this_coro.hpp>

#include <system_error>
#include <type_traits>


namespace net = asio;
namespace io_error = asio::error;

using tcp = net::ip::tcp;
using udp = net::ip::udp;
using IoErrorCode = std::error_code;
using IoSystemError = std::system_error;

// asio's default channel traits store queued values in std::deque; RingDeque
// keeps an idle channel at zero bytes and returns storage once drained.
namespace common {

template <typename... Signatures>
struct ChannelTraits {
    template <typename... NewSignatures>
    struct rebind {
        using other = ChannelTraits<NewSignatures...>;
    };
};

template <typename R, typename... Args, typename... Signatures>
struct ChannelTraits<R(asio::error_code, Args...), Signatures...> {
    template <typename... NewSignatures>
    struct rebind {
        using other = ChannelTraits<NewSignatures...>;
    };

    template <typename Element>
    struct container {
        using type = RingDeque<Element>;
    };

    using receive_cancelled_signature = R(asio::error_code, Args...);

    template <typename F>
    static void invoke_receive_cancelled(F f) {
        const asio::error_code e = asio::experimental::error::channel_cancelled;
        static_cast<F&&>(f)(e, std::decay_t<Args>()...);
    }

    using receive_closed_signature = R(asio::error_code, Args...);

    template <typename F>
    static void invoke_receive_closed(F f) {
        const asio::error_code e = asio::experimental::error::channel_closed;
        static_cast<F&&>(f)(e, std::decay_t<Args>()...);
    }
};

using SignalChannel = net::experimental::basic_channel<
    net::any_io_executor,
    ChannelTraits<>,
    void(IoErrorCode)>;


// 读到 EOF 时区分对端关闭与本端取消：调用协程已被取消则抛出 operation_aborted。
// `cancellation` 取自调用协程的 net::this_coro::cancellation_state。
inline void ThrowIfCancelledOnEof(const net::cancellation_state& cancellation,
                                  const char* cancel_what = nullptr) {
    if (cancellation.cancelled() == net::cancellation_type::none) return;
    if (cancel_what) throw IoSystemError(io_error::operation_aborted, cancel_what);
    throw IoSystemError(io_error::operation_aborted);
}
}  // namespace common
