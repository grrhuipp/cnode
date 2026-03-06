#include "acppnode/common/error.hpp"
#include <boost/asio/error.hpp>

namespace acpp {

ErrorCode MapAsioError(const boost::system::error_code& ec) {
    if (!ec) {
        return ErrorCode::OK;
    }
    
    namespace asio_error = boost::asio::error;
    
    // 常见的 Asio 错误映射
    if (ec == asio_error::eof) {
        return ErrorCode::SOCKET_EOF;
    }
    if (ec == asio_error::operation_aborted) {
        return ErrorCode::CANCELLED;
    }
    if (ec == asio_error::timed_out) {
        return ErrorCode::TIMEOUT;
    }
    if (ec == asio_error::connection_refused) {
        return ErrorCode::DIAL_REFUSED;
    }
    if (ec == asio_error::connection_reset) {
        return ErrorCode::SOCKET_CLOSED;
    }
    if (ec == asio_error::broken_pipe) {
        return ErrorCode::SOCKET_CLOSED;
    }
    if (ec == asio_error::network_unreachable) {
        return ErrorCode::DIAL_NETWORK_UNREACHABLE;
    }
    if (ec == asio_error::host_unreachable) {
        return ErrorCode::DIAL_HOST_UNREACHABLE;
    }
    if (ec == asio_error::host_not_found) {
        return ErrorCode::DNS_RESOLVE_FAILED;
    }
    if (ec == asio_error::no_recovery) {
        return ErrorCode::DNS_SERVER_FAILED;
    }
    
    // 系统错误码映射
    if (ec.category() == boost::system::system_category()) {
        switch (ec.value()) {
            case ECONNRESET:
            case EPIPE:
                return ErrorCode::SOCKET_CLOSED;
            case ECONNREFUSED:
                return ErrorCode::DIAL_REFUSED;
            case ETIMEDOUT:
                return ErrorCode::TIMEOUT;
            case ENETUNREACH:
                return ErrorCode::DIAL_NETWORK_UNREACHABLE;
            case EHOSTUNREACH:
                return ErrorCode::DIAL_HOST_UNREACHABLE;
            case EADDRINUSE:
                return ErrorCode::SOCKET_BIND_FAILED;
            case EADDRNOTAVAIL:
                return ErrorCode::SOCKET_BIND_FAILED;
            case EACCES:
            case EPERM:
                return ErrorCode::PERMISSION_DENIED;
            case EMFILE:
            case ENFILE:
            case ENOBUFS:
            case ENOMEM:
                return ErrorCode::RESOURCE_EXHAUSTED;
            default:
                break;
        }
    }
    
    // 默认映射为内部错误
    return ErrorCode::INTERNAL;
}

}  // namespace acpp
