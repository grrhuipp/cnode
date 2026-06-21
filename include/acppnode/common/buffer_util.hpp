#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <array>
#include <cstddef>
#include <algorithm>
#include <span>
#include <vector>
#include <cstdint>

namespace acpp {

// 释放空闲缓冲区：当 capacity 超过 keep_capacity 时，释放全部内存
template <class ByteContainer>
inline void ReleaseIdleBuffer(ByteContainer& buf, size_t keep_capacity) {
    if (buf.capacity() > keep_capacity) {
        ByteContainer().swap(buf);
    }
}

template <class ByteContainer>
inline void EnsureAppendCapacity(ByteContainer& buf,
                                 size_t additional,
                                 size_t min_slack = 8192) {
    const size_t required = buf.size() + additional;
    if (required <= buf.capacity()) {
        return;
    }
    const size_t grown = buf.capacity() + (buf.capacity() / 2) + min_slack;
    buf.reserve(std::max(required, grown));
}

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
        if (buffers.empty()) {
            return;
        }
        if (spill_.empty() && count_ + buffers.size() > StackCapacity) {
            EnsureSpillCapacity(buffers.size());
        }
        for (const auto& buffer : buffers) {
            Append(buffer);
        }
    }

    void AppendMultiBuffer(const buf::MultiBuffer& mb) {
        if (mb.empty()) {
            return;
        }
        if (spill_.empty() && count_ + mb.size() > StackCapacity) {
            EnsureSpillCapacity(mb.size());
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

}  // namespace acpp
