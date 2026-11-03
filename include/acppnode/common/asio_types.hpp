#pragma once

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>

#include <system_error>

namespace acpp {

namespace net = asio;
namespace io_error = asio::error;

using tcp = net::ip::tcp;
using udp = net::ip::udp;
using IoErrorCode = std::error_code;
using IoSystemError = std::system_error;

}  // namespace acpp
