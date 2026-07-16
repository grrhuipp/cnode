#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <cstdint>
#include <new>
#include <span>
#include <utility>

namespace acpp {
class AsyncStream;
}

namespace acpp::transport {

class MultiBufferReader {
public:
    virtual ~MultiBufferReader() noexcept = default;

    virtual net::awaitable<buf::MultiBuffer> ReadMultiBuffer() = 0;
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
};

struct Link {
    MultiBufferReader* reader = nullptr;
    MultiBufferWriter* writer = nullptr;
    AsyncStream* control = nullptr;

    [[nodiscard]] bool Valid() const noexcept {
        return reader && writer;
    }
};

}  // namespace acpp::transport
