#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <span>

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
    virtual net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) = 0;
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
