#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include <asio/this_coro.hpp>

#include <array>
#include <cstddef>
#include <algorithm>
#include <span>
#include <vector>
#include <cstdint>

namespace acpp {

template <size_t StackCapacity>
class ConstBufferSpanBuilder {
public:
    static_assert(StackCapacity > 0);

    void Append(net::const_buffer buffer) {
        if (buffer.size() == 0) {
            return;
        }
        if (spill_.empty() && count_ < StackCapacity) {
            stack_[count_++] = buffer;
            return;
        }
        EnsureSpillCapacity(1);
        spill_.push_back(buffer);
    }

    void AppendBuffers(std::span<const net::const_buffer> buffers) {
        size_t non_empty = 0;
        for (const auto& buffer : buffers) {
            if (buffer.size() != 0) {
                ++non_empty;
            }
        }
        if (non_empty == 0) {
            return;
        }
        if (!spill_.empty() || count_ + non_empty > StackCapacity) {
            EnsureSpillCapacity(non_empty);
        }
        for (const auto& buffer : buffers) {
            Append(buffer);
        }
    }

    void AppendMultiBuffer(const buf::MultiBuffer& mb) {
        size_t non_empty = 0;
        for (const auto* buffer : mb) {
            if (buffer && !buffer->IsEmpty()) {
                ++non_empty;
            }
        }
        if (non_empty == 0) {
            return;
        }
        if (!spill_.empty() || count_ + non_empty > StackCapacity) {
            EnsureSpillCapacity(non_empty);
        }
        for (const auto* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            Append(net::const_buffer(bytes.data(), bytes.size()));
        }
    }

    [[nodiscard]] bool empty() const noexcept {
        return size() == 0;
    }

    [[nodiscard]] size_t size() const noexcept {
        return spill_.empty() ? count_ : spill_.size();
    }

    [[nodiscard]] std::span<const net::const_buffer> Span() const noexcept {
        if (!spill_.empty()) {
            return std::span<const net::const_buffer>(spill_.data(), spill_.size());
        }
        return std::span<const net::const_buffer>(stack_.data(), count_);
    }

private:
    void EnsureSpillCapacity(size_t additional) {
        if (!spill_.empty()) {
            spill_.reserve(spill_.size() + additional);
            return;
        }
        spill_.reserve(count_ + additional);
        spill_.insert(
            spill_.end(),
            stack_.begin(),
            stack_.begin() + static_cast<std::ptrdiff_t>(count_));
    }

    std::array<net::const_buffer, StackCapacity> stack_{};
    memory::ThreadLocalVector<net::const_buffer> spill_;
    size_t count_ = 0;
};

template <typename Reader>
[[nodiscard]] net::awaitable<buf::MultiBuffer> ReadMultiBufferOrThrowOnCancel(
    Reader& reader, const char* cancel_what = nullptr) {
    buf::MultiBuffer raw = co_await reader.ReadMultiBuffer();
    if (raw.byte_size() == 0) {
        const auto cancellation = co_await net::this_coro::cancellation_state;
        if (cancellation.cancelled() != net::cancellation_type::none) {
            if (cancel_what) {
                throw IoSystemError(io_error::operation_aborted, cancel_what);
            }
            throw IoSystemError(io_error::operation_aborted);
        }
    }
    co_return raw;
}

}  // namespace acpp
