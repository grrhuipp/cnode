#pragma once

#include "common/allocator.hpp"

#include <asio/awaitable.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>

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
        using type = memory::RingDeque<Element>;
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
