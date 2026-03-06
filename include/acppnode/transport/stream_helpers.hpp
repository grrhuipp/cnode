#pragma once

#include "acppnode/common.hpp"
#include "acppnode/transport/async_stream.hpp"

namespace acpp {

// ============================================================================
// ReadFull / WriteFull — 通用的精确字节读写协程
//
// 循环调用 AsyncRead/AsyncWrite 直到读满/写满指定长度。
// 任何异常均被捕获并返回 false（调用方通过 bool 判断成功/失败）。
//
// 适用于：SS / VMess 等需要精确字节读写的协议流。
// ============================================================================

inline cobalt::task<bool> ReadFull(AsyncStream& stream, uint8_t* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        size_t r = 0;
        try {
            r = co_await stream.AsyncRead(net::buffer(buf + got, len - got));
        } catch (...) {
            co_return false;
        }
        if (r == 0) co_return false;
        got += r;
    }
    co_return true;
}

inline cobalt::task<bool> WriteFull(AsyncStream& stream, const uint8_t* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        size_t n = 0;
        try {
            n = co_await stream.AsyncWrite(net::buffer(buf + sent, len - sent));
        } catch (...) {
            co_return false;
        }
        if (n == 0) co_return false;
        sent += n;
    }
    co_return true;
}

}  // namespace acpp
