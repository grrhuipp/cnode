#include "common/error.hpp"


ErrorCode MapAsioError(const IoErrorCode& ec) {
    if (!ec) {
        return ErrorCode::OK;
    }

    // asio::error 枚举在 POSIX 上即 system_category 的 errno，比较同时覆盖原始 errno。
    if (ec == io_error::eof) {
        return ErrorCode::SOCKET_EOF;
    }
    if (ec == io_error::operation_aborted) {
        return ErrorCode::CANCELLED;
    }
    if (ec == io_error::no_buffer_space) {
        return ErrorCode::RESOURCE_EXHAUSTED;
    }
    if (ec == io_error::timed_out) {
        return ErrorCode::TIMEOUT;
    }
    if (ec == io_error::connection_refused) {
        return ErrorCode::DIAL_REFUSED;
    }
    if (ec == io_error::connection_reset) {
        return ErrorCode::SOCKET_CLOSED;
    }
    if (ec == io_error::broken_pipe) {
        return ErrorCode::SOCKET_CLOSED;
    }
    if (ec == io_error::network_unreachable) {
        return ErrorCode::DIAL_NETWORK_UNREACHABLE;
    }
    if (ec == io_error::host_unreachable) {
        return ErrorCode::DIAL_HOST_UNREACHABLE;
    }
    if (ec == io_error::host_not_found) {
        return ErrorCode::DNS_RESOLVE_FAILED;
    }
    if (ec == io_error::no_recovery) {
        return ErrorCode::DNS_SERVER_FAILED;
    }

    if (ec.category() == std::system_category() ||
        ec.category() == net::error::get_system_category()) {
        switch (ec.value()) {
            case ECANCELED:
                return ErrorCode::CANCELLED;
            case ETIMEDOUT:
                return ErrorCode::TIMEOUT;
            case ECONNREFUSED:
                return ErrorCode::DIAL_REFUSED;
            case ECONNRESET:
            case EPIPE:
            case ENOTCONN:
                return ErrorCode::SOCKET_CLOSED;
            case ENETUNREACH:
            case ENETDOWN:
                return ErrorCode::DIAL_NETWORK_UNREACHABLE;
            case EHOSTUNREACH:
            case EHOSTDOWN:
                return ErrorCode::DIAL_HOST_UNREACHABLE;
            case EADDRINUSE:
            case EADDRNOTAVAIL:
                return ErrorCode::SOCKET_BIND_FAILED;
            case EACCES:
            case EPERM:
                return ErrorCode::PERMISSION_DENIED;
            case ENOBUFS:
            case EMFILE:
            case ENFILE:
            case ENOMEM:
                return ErrorCode::RESOURCE_EXHAUSTED;
            default:
                break;
        }
    }

    // 默认映射为内部错误
    return ErrorCode::INTERNAL;
}

