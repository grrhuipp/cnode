#pragma once

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>

#include <system_error>

#ifdef _WIN32
#  ifdef ERROR
#    undef ERROR
#  endif
#  ifdef DOMAIN
#    undef DOMAIN
#  endif
#  ifdef WriteConsole
#    undef WriteConsole
#  endif
#  if !defined(ssize_t) && !defined(_SSIZE_T_DEFINED)
#    if defined(_WIN64)
       using ssize_t = long long;
#    else
       using ssize_t = int;
#    endif
#    define _SSIZE_T_DEFINED
#  endif
#  ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
#  endif
#endif

namespace acpp {

namespace net = asio;
namespace io_error = asio::error;

using tcp = net::ip::tcp;
using udp = net::ip::udp;
using IoErrorCode = std::error_code;
using IoSystemError = std::system_error;

}  // namespace acpp
