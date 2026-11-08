#pragma once

#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "transport/link_error.hpp"
#include "transport/cancellation.hpp"

#include <cstdint>
#include <exception>
#include <new>
#include <span>
#include <utility>

class AsyncStream;

namespace transport {

enum class EofAction : uint8_t {
    WaitForPeer,
    ShutdownPeerWrite,
    CloseLink,
};

// A clean write-side end, detected before starting a write. The read side may
// still contain previously received bytes, which relay must finish draining.
class WriteClosed final : public std::exception {
public:
    const char* what() const noexcept override { return "link write side is closed"; }
};

class MultiBufferReader {
public:
    virtual ~MultiBufferReader() noexcept = default;

    virtual net::awaitable<buf::MultiBuffer> ReadMultiBuffer() = 0;
    virtual CancellationSource& Cancellation() noexcept = 0;
    virtual EofAction ReadEofAction() const noexcept { return EofAction::WaitForPeer; }
    // Vision command 2 is a read-direction transition at an idle read boundary.
    // Wrappers retain already-read bytes; unsupported transports fail closed.
    [[nodiscard]] virtual bool EnableRawRead() noexcept { return false; }
};

class MultiBufferWriter {
public:
    virtual ~MultiBufferWriter() noexcept = default;

    virtual net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) = 0;
    virtual net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) {
        buf::MultiBuffer payload;
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            const auto bytes = std::span<const uint8_t>(
                static_cast<const uint8_t*>(buffer.data()),
                buffer.size());
            if (!buf::AppendSpanToMultiBuffer(bytes, payload)) {
                throw std::bad_alloc();
            }
        }
        co_await WriteMultiBuffer(std::move(payload));
    }
    virtual net::awaitable<void> AsyncShutdownWrite() { co_return; }
    virtual bool WriteShutdownClosesLink() const noexcept { return false; }
};

struct Link {
    MultiBufferReader* reader = nullptr;
    MultiBufferWriter* writer = nullptr;
    AsyncStream* control = nullptr;

    [[nodiscard]] bool Valid() const noexcept {
        return reader && writer;
    }
};

}  // namespace transport
