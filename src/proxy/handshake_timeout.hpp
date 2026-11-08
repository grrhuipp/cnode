#pragma once

#include "common/asio_types.hpp"
#include "common/error.hpp"
#include "transport/async_stream.hpp"
#include "transport/link_error.hpp"

#include <new>

namespace proxy {

[[nodiscard]] inline bool ConsumeStreamReadTimeout(
    AsyncStream& stream) noexcept {
    return stream.ConsumePhaseDeadline() || stream.ConsumeIdleTimeout() ||
           stream.ConsumeReadTimeout();
}

[[nodiscard]] inline ErrorCode ResolveHandshakeReadFailure(
    AsyncStream& stream,
    ErrorCode fallback = ErrorCode::SOCKET_READ_FAILED) noexcept {
    return ConsumeStreamReadTimeout(stream) ? ErrorCode::TIMEOUT : fallback;
}

[[nodiscard]] inline bool ConsumeOutboundHandshakeTimeout(
    AsyncStream& stream,
    const PhaseDeadlineHandle& deadline) noexcept {
    return deadline.Expired() || ConsumeStreamReadTimeout(stream) ||
           stream.ConsumeWriteTimeout();
}

[[nodiscard]] inline ErrorCode ClassifyHandshakeReadException(
    AsyncStream& stream,
    const IoSystemError& error) noexcept {
    if (ConsumeStreamReadTimeout(stream) || error.code() == io_error::timed_out) {
        return ErrorCode::TIMEOUT;
    }
    if (error.code() == io_error::operation_aborted) {
        return ErrorCode::CANCELLED;
    }
    return ErrorCode::SOCKET_READ_FAILED;
}

[[nodiscard]] inline ErrorCode ClassifyOutboundHandshakeException(
    AsyncStream& stream,
    const PhaseDeadlineHandle& deadline,
    ErrorCode fallback = ErrorCode::SOCKET_WRITE_FAILED) noexcept {
    try {
        throw;
    } catch (const IoSystemError& error) {
        return (ConsumeOutboundHandshakeTimeout(stream, deadline) ||
                error.code() == io_error::timed_out)
            ? ErrorCode::TIMEOUT
            : MapAsioError(error.code());
    } catch (const transport::LinkError& error) {
        return (ConsumeOutboundHandshakeTimeout(stream, deadline) ||
                error.code() == ErrorCode::TIMEOUT)
            ? ErrorCode::TIMEOUT
            : error.code();
    } catch (const std::bad_alloc&) {
        return ErrorCode::RESOURCE_EXHAUSTED;
    } catch (...) {
        return ConsumeOutboundHandshakeTimeout(stream, deadline)
            ? ErrorCode::TIMEOUT
            : fallback;
    }
}

}  // namespace proxy
