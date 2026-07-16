#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"

#include <limits>
#include <span>

namespace acpp::buf {

// Presents fragmented buffer storage as one contiguous byte span. A single
// non-empty input buffer remains zero-copy; fragmented input is copied once.
class ContiguousBufferView {
public:
    explicit ContiguousBufferView(const MultiBuffer& buffers) {
        const Buffer* single = nullptr;
        size_t buffer_count = 0;
        size_t total_size = 0;
        for (const Buffer* buffer : buffers) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            AddSize(buffer->Len(), total_size);
            single = buffer;
            ++buffer_count;
        }
        if (buffer_count == 1) {
            bytes_ = single->Bytes();
            return;
        }
        owned_.reserve(total_size);
        for (const Buffer* buffer : buffers) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            owned_.insert(owned_.end(), bytes.begin(), bytes.end());
        }
        bytes_ = owned_;
    }

    explicit ContiguousBufferView(
        std::span<const net::const_buffer> buffers) {
        const net::const_buffer* single = nullptr;
        size_t buffer_count = 0;
        size_t total_size = 0;
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            if (!buffer.data()) {
                throw IoSystemError(
                    io_error::invalid_argument,
                    "buffer sequence contains a null data pointer");
            }
            AddSize(buffer.size(), total_size);
            single = &buffer;
            ++buffer_count;
        }
        if (buffer_count == 1) {
            bytes_ = std::span<const uint8_t>(
                static_cast<const uint8_t*>(single->data()), single->size());
            return;
        }
        owned_.reserve(total_size);
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            owned_.insert(owned_.end(), data, data + buffer.size());
        }
        bytes_ = owned_;
    }

    [[nodiscard]] std::span<const uint8_t> Bytes() const noexcept {
        return bytes_;
    }

private:
    static void AddSize(size_t size, size_t& total_size) {
        if (size > std::numeric_limits<size_t>::max() - total_size) {
            throw IoSystemError(
                io_error::message_size, "buffer sequence is too large");
        }
        total_size += size;
    }

    memory::ByteVector owned_;
    std::span<const uint8_t> bytes_;
};

}  // namespace acpp::buf
