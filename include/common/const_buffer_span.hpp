#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/multi_buffer.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace common {

template <size_t StackCapacity>
class ConstBufferSpanBuilder {
public:
    static_assert(StackCapacity > 0);

    ConstBufferSpanBuilder() noexcept = default;

    void Append(net::const_buffer buffer) {
        if (buffer.size() == 0) {
            return;
        }
        if (!spill_ && count_ < StackCapacity) {
            stack_[count_++] = buffer;
            return;
        }
        EnsureSpillCapacity(1);
        spill_->push_back(buffer);
    }

    void AppendBuffers(std::span<const net::const_buffer> buffers) {
        const size_t available = spill_
            ? spill_->capacity() - spill_->size() : StackCapacity - count_;
        size_t additional = buffers.size();
        if (additional > available) {
            additional = 0;
            for (const auto& buffer : buffers) {
                if (buffer.size() != 0) ++additional;
            }
        }
        if (additional == 0) return;
        if (additional > available) {
            const auto current = Span();
            const auto source = reinterpret_cast<uintptr_t>(buffers.data());
            const auto base = reinterpret_cast<uintptr_t>(current.data());
            const bool aliases = source >= base && source - base < current.size_bytes();
            const size_t offset = aliases ? (source - base) / sizeof(net::const_buffer) : 0;
            EnsureSpillCapacity(additional);
            if (aliases) buffers = Span().subspan(offset, buffers.size());
        }
        for (const auto& buffer : buffers) {
            if (buffer.size() != 0) AppendPrepared(buffer);
        }
    }

    void AppendMultiBuffer(const MultiBuffer& mb) {
        const auto bytes = mb.FrontSpan();
        if (!bytes.empty()) {
            Append(net::const_buffer(bytes.data(), bytes.size()));
        }
    }
    void AppendMultiBuffer(const MultiBuffer&&) = delete;

    void Clear() noexcept {
        spill_.reset();
        count_ = 0;
    }

    [[nodiscard]] bool empty() const noexcept {
        return size() == 0;
    }

    [[nodiscard]] size_t size() const noexcept {
        return spill_ && !spill_->empty() ? spill_->size() : count_;
    }

    [[nodiscard]] std::span<const net::const_buffer> Span() const& noexcept {
        if (spill_ && !spill_->empty()) {
            return std::span<const net::const_buffer>(spill_->data(), spill_->size());
        }
        return std::span<const net::const_buffer>(stack_.data(), count_);
    }
    std::span<const net::const_buffer> Span() const&& = delete;

private:
    void AppendPrepared(net::const_buffer buffer) {
        if (spill_) spill_->push_back(buffer);
        else stack_[count_++] = buffer;
    }

    void EnsureSpillCapacity(size_t additional) {
        CheckTestAllocationFault();
        const bool preparing = !spill_;
        if (preparing) spill_.emplace();
        try {
            const size_t used = size();
            const size_t maximum = spill_->max_size();
            if (additional > maximum - used) throw std::bad_alloc();
            const size_t needed = used + additional;
            const size_t current = spill_->capacity();
            const size_t doubled = current <= maximum / 2 ? current * 2 : maximum;
            spill_->reserve(std::max({needed, StackCapacity * 2, doubled}));
            if (preparing) {
                spill_->insert(spill_->end(), stack_.begin(), stack_.begin() + count_);
                count_ = 0;
            }
        } catch (...) {
            if (preparing) spill_.reset();
            throw;
        }
    }

    std::array<net::const_buffer, StackCapacity> stack_;
    std::optional<std::vector<net::const_buffer>> spill_;
    size_t count_ = 0;
};

}  // namespace common
