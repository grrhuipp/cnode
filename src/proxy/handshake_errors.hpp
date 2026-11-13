#pragma once

#include "common/asio_types.hpp"
#include "common/error.hpp"
#include "transport/async_stream.hpp"
#include "transport/failure.hpp"

#include <tl/expected.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <new>
#include <span>

// 握手阶段读写的超时、取消与异常分类，入站与出站共用；不含任何准入语义。
namespace proxy {

[[nodiscard]] inline bool ConsumeStreamReadTimeout(
    transport::AsyncStream& stream) noexcept {
    return stream.ConsumePhaseDeadline() || stream.ConsumeIdleTimeout() ||
           stream.ConsumeReadTimeout();
}

[[nodiscard]] inline common::ErrorCode ResolveHandshakeReadFailure(
    transport::AsyncStream& stream,
    common::ErrorCode fallback = common::ErrorCode::SOCKET_READ_FAILED) noexcept {
    return ConsumeStreamReadTimeout(stream) ? common::ErrorCode::TIMEOUT : fallback;
}

[[nodiscard]] inline common::ErrorCode ClassifyHandshakeReadException(
    transport::AsyncStream& stream,
    const IoSystemError& error) noexcept {
    if (ConsumeStreamReadTimeout(stream) || error.code() == io_error::timed_out) {
        return common::ErrorCode::TIMEOUT;
    }
    if (error.code() == io_error::operation_aborted) {
        return common::ErrorCode::CANCELLED;
    }
    return common::ErrorCode::SOCKET_READ_FAILED;
}

// 入站握手响应写失败的分类：写超时与阶段截止期归为 TIMEOUT，不计作读失败。
[[nodiscard]] inline common::ErrorCode ClassifyHandshakeWriteException(
    transport::AsyncStream& stream,
    const IoSystemError& error) noexcept {
    if (stream.ConsumePhaseDeadline() || stream.ConsumeIdleTimeout() ||
        stream.ConsumeWriteTimeout() || error.code() == io_error::timed_out) {
        return common::ErrorCode::TIMEOUT;
    }
    if (error.code() == io_error::operation_aborted) {
        return common::ErrorCode::CANCELLED;
    }
    return common::ErrorCode::SOCKET_WRITE_FAILED;
}

// 本次握手在这次读之前是否已经收到过字节，决定 EOF 的含义。
enum class HandshakeProgress : uint8_t {
    NotStarted,
    Started,
};

// 唯一的握手精确读：填满 `out` 才返回成功。
// 握手首字节前 EOF 是对端正常关闭 → SOCKET_EOF；收到任何握手字节后 EOF 是
// 异常截断 → PROTOCOL_DECODE_FAILED；已触发的读、空闲或阶段超时优先归为 TIMEOUT。
[[nodiscard]] inline net::awaitable<tl::expected<void, common::ErrorCode>> ReadHandshakeExact(
    transport::AsyncStream& stream,
    std::span<uint8_t> out,
    HandshakeProgress progress) {
    bool started = progress == HandshakeProgress::Started;
    while (!out.empty()) {
        size_t n = 0;
        try {
            n = co_await stream.AsyncRead(net::buffer(out.data(), out.size()));
        } catch (const IoSystemError& error) {
            if (error.code() == io_error::eof) {
                co_return tl::unexpected(ResolveHandshakeReadFailure(stream, started
                    ? common::ErrorCode::PROTOCOL_DECODE_FAILED : common::ErrorCode::SOCKET_EOF));
            }
            co_return tl::unexpected(ClassifyHandshakeReadException(stream, error));
        } catch (const std::bad_alloc&) {
            co_return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
        }
        if (n == 0) {
            co_return tl::unexpected(ResolveHandshakeReadFailure(
                stream,
                started ? common::ErrorCode::PROTOCOL_DECODE_FAILED : common::ErrorCode::SOCKET_EOF));
        }
        started = true;
        out = out.subspan(n);
    }
    co_return tl::expected<void, common::ErrorCode>{};
}

[[nodiscard]] inline bool ConsumeOutboundHandshakeTimeout(
    transport::AsyncStream& stream,
    const transport::PhaseDeadlineToken& deadline) noexcept {
    return deadline.Expired() || ConsumeStreamReadTimeout(stream) ||
           stream.ConsumeWriteTimeout();
}

// 出站握手异常分类：只能在 catch 块内调用。类型分类交给
// transport::ClassifyFailure，本函数只叠加握手截止期语义。
[[nodiscard]] inline common::ErrorCode ClassifyOutboundHandshakeException(
    transport::AsyncStream& stream,
    const transport::PhaseDeadlineToken& deadline,
    common::ErrorCode fallback = common::ErrorCode::SOCKET_WRITE_FAILED) noexcept {
    const common::ErrorCode code = transport::ClassifyFailure(std::current_exception(), fallback);
    if (code == common::ErrorCode::RESOURCE_EXHAUSTED) return code;
    return ConsumeOutboundHandshakeTimeout(stream, deadline) || code == common::ErrorCode::TIMEOUT
        ? common::ErrorCode::TIMEOUT
        : code;
}

}  // namespace proxy
