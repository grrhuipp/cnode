#include "grpc_hunk.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <optional>

namespace acpp::transport::internet {
namespace {

bool ReadVarint(std::span<const uint8_t> bytes, size_t& offset, uint64_t& value) noexcept {
    value = 0;
    for (unsigned shift = 0; shift < 64 && offset < bytes.size(); shift += 7) {
        const uint8_t byte = bytes[offset++];
        if (shift == 63 && byte > 1) return false;
        value |= uint64_t(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) return true;
    }
    return false;
}

bool ReadKey(std::span<const uint8_t> bytes, size_t& offset, uint32_t& key) noexcept {
    uint64_t value = 0;
    if (!ReadVarint(bytes, offset, value) || value > UINT32_MAX || (value >> 3) == 0) return false;
    key = static_cast<uint32_t>(value);
    return true;
}

bool SkipField(std::span<const uint8_t> bytes, size_t& offset, uint32_t key, unsigned depth) noexcept {
    uint64_t size = 0;
    switch (key & 7) {
    case 0:
        return ReadVarint(bytes, offset, size);
    case 1:
        size = 8;
        break;
    case 2:
        if (!ReadVarint(bytes, offset, size)) return false;
        break;
    case 3:
        if (depth == 100) return false;
        while (offset < bytes.size()) {
            uint32_t nested = 0;
            if (!ReadKey(bytes, offset, nested)) return false;
            if ((nested & 7) == 4) return (nested >> 3) == (key >> 3);
            if (!SkipField(bytes, offset, nested, depth + 1)) return false;
        }
        return false;
    case 5:
        size = 4;
        break;
    default:
        return false;
    }
    if (size > bytes.size() - offset) return false;
    offset += static_cast<size_t>(size);
    return true;
}

struct DataField { size_t offset = 0; size_t size = 0; };

std::optional<DataField> DecodeMessage(std::span<const uint8_t> bytes) noexcept {
    DataField data;
    size_t offset = 0;
    while (offset < bytes.size()) {
        uint32_t key = 0;
        if (!ReadKey(bytes, offset, key)) return std::nullopt;
        if (key == 0x0a) {
            uint64_t size = 0;
            if (!ReadVarint(bytes, offset, size) || size > bytes.size() - offset) return std::nullopt;
            data = {offset, static_cast<size_t>(size)};
            offset += data.size;
        } else if (!SkipField(bytes, offset, key, 0)) {
            return std::nullopt;
        }
    }
    return data;
}

}  // namespace

std::expected<size_t, std::string_view> GrpcHunkDecoder::Feed(std::span<const uint8_t> bytes) {
    size_t consumed = 0;
    while (consumed < bytes.size() && Payload().empty()) {
        if (prefix_size_ < prefix_.size()) {
            const size_t size = std::min(prefix_.size() - prefix_size_, bytes.size() - consumed);
            std::memcpy(prefix_.data() + prefix_size_, bytes.data() + consumed, size);
            prefix_size_ += size;
            consumed += size;
            if (prefix_size_ != prefix_.size()) break;
            if (prefix_[0] != 0) return std::unexpected("gRPC compressed messages are unsupported");
            message_size_ = (uint32_t(prefix_[1]) << 24) | (uint32_t(prefix_[2]) << 16) |
                            (uint32_t(prefix_[3]) << 8) | prefix_[4];
            if (message_size_ > kMaxGrpcHunkMessageSize)
                return std::unexpected("gRPC message exceeds 4 MiB");
        }
        const size_t size = std::min(message_size_ - message_.size(), bytes.size() - consumed);
        if (size) {
            const size_t required = message_.size() + size;
            if (required > message_.capacity()) {
                const size_t capacity = std::max(required, std::min(kMaxGrpcHunkMessageSize,
                    std::max(size_t{256}, message_.capacity() + message_.capacity() / 2)));
                message_.reserve(capacity);
            }
            message_.insert(message_.end(), bytes.begin() + consumed, bytes.begin() + consumed + size);
            consumed += size;
        }
        if (message_.size() != message_size_) break;
        const auto data = DecodeMessage(message_);
        if (!data) return std::unexpected("invalid gRPC Hunk protobuf message");
        prefix_size_ = message_size_ = 0;
        data_offset_ = data->offset;
        data_end_ = data->offset + data->size;
        if (Payload().empty()) Clear();
    }
    return consumed;
}

std::span<const uint8_t> GrpcHunkDecoder::Payload() const noexcept {
    return std::span<const uint8_t>(message_).subspan(data_offset_, data_end_ - data_offset_);
}

void GrpcHunkDecoder::Consume(size_t size) noexcept {
    assert(size <= data_end_ - data_offset_);
    data_offset_ += size;
    if (data_offset_ == data_end_) Clear();
}

void GrpcHunkDecoder::Clear() noexcept {
    prefix_size_ = message_size_ = data_offset_ = data_end_ = 0;
    memory::ByteVector{}.swap(message_);
}

}  // namespace acpp::transport::internet
