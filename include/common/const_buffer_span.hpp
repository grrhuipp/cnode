#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"

#include <array>
#include <cstddef>
#include <algorithm>
#include <span>
#include <optional>
#include <cstdint>
#include <memory_resource>
#include <vector>


namespace common {

template <size_t StackCapacity>
class ConstBufferSpanBuilder {
public:
    static_assert(StackCapacity > 0);

    // Spilled descriptors live in `resource`; none named means the process layer.
    ConstBufferSpanBuilder() noexcept = default;
    explicit ConstBufferSpanBuilder(std::pmr::memory_resource* resource) noexcept
        : resource_(memory::ResourceOrProcess(resource)) {}

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
        // Existing capacity also guarantees borrowed descriptors cannot move.
        if (additional > available) {
            additional = 0;
            for (const auto& buffer : buffers) {
                if (buffer.size() != 0) ++additional;
            }
        }
        if (additional == 0) return;
        if (additional > available) {
            // A borrowed subspan must follow the descriptors if spill storage moves.
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

    void AppendMultiBuffer(const buf::MultiBuffer& mb) {
        const size_t available = spill_
            ? spill_->capacity() - spill_->size() : StackCapacity - count_;
        // Count exact non-empty descriptors only if the slot upper bound would grow storage.
        if (mb.size() > available) {
            size_t non_empty = 0;
            for (const auto* buffer : mb) {
                if (buffer && !buffer->IsEmpty()) ++non_empty;
            }
            if (non_empty == 0) return;
            if (non_empty > available) EnsureSpillCapacity(non_empty);
        }
        for (const auto* buffer : mb) {
            if (!buffer) continue;
            const auto bytes = buffer->Bytes();
            if (!bytes.empty())
                AppendPrepared(net::const_buffer(bytes.data(), bytes.size()));
        }
    }
    void AppendMultiBuffer(const buf::MultiBuffer&&) = delete;

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
    // Batch callers reserve the entire append before borrowing the destination.
    void AppendPrepared(net::const_buffer buffer) {
        if (spill_) spill_->push_back(buffer);
        else stack_[count_++] = buffer;
    }

    void EnsureSpillCapacity(size_t additional) {
        const bool preparing = !spill_;
        if (preparing) spill_.emplace(resource_);
        // Keep the inline prefix visible until the spill is populated.
        try {
            const size_t used = size();
            const size_t maximum = spill_->max_size();
            if (additional > maximum - used)
                throw std::length_error("buffer span size overflow");
            const size_t required = used + additional;
            if (required > spill_->capacity()) {
                const size_t capacity = std::max(StackCapacity, spill_->capacity());
                const size_t grown = capacity > maximum / 2 ? maximum : capacity * 2;
                spill_->reserve(std::max(required, grown));
            }
            if (preparing) {
                spill_->insert(spill_->end(), stack_.begin(),
                    stack_.begin() + static_cast<std::ptrdiff_t>(count_));
                count_ = 0;
            }
        } catch (...) {
            if (preparing) spill_.reset();
            throw;
        }
    }

    std::pmr::memory_resource* resource_ = memory::process_resource();
    std::array<net::const_buffer, StackCapacity> stack_;
    std::optional<std::pmr::vector<net::const_buffer>> spill_;
    size_t count_ = 0;
};

}  // namespace common
