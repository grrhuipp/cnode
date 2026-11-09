#include "grpc_hunk.hpp"
#include "common/byte_reader.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <optional>

namespace transport::internet {
namespace {

bool ReadKey(ByteReader& reader, uint32_t& key) noexcept {
    const auto value = reader.ReadVarintU64();
    if (!value || *value > UINT32_MAX || (*value >> 3) == 0) return false;
    key = static_cast<uint32_t>(*value);
    return true;
}

bool SkipField(ByteReader& reader, uint32_t key, unsigned depth) noexcept {
    switch (key & 7) {
    case 0:
        return reader.ReadVarintU64().has_value();
    case 1:
        return reader.Skip(8);
    case 2: {
        const auto size = reader.ReadVarintU64();
        if (!size || *size > reader.Remaining()) return false;
        return reader.Skip(static_cast<size_t>(*size));
    }
    case 3:
        if (depth == 100) return false;
        while (!reader.Empty()) {
            uint32_t nested = 0;
            if (!ReadKey(reader, nested)) return false;
            if ((nested & 7) == 4) return (nested >> 3) == (key >> 3);
            if (!SkipField(reader, nested, depth + 1)) return false;
        }
        return false;
    case 5:
        return reader.Skip(4);
    default:
        return false;
    }
}

struct DataField { size_t offset = 0; size_t size = 0; };

std::optional<DataField> DecodeMessage(std::span<const uint8_t> bytes) noexcept {
    DataField data;
    ByteReader reader(bytes);
    while (!reader.Empty()) {
        uint32_t key = 0;
        if (!ReadKey(reader, key)) return std::nullopt;
        if (key == 0x0a) {
            const auto size = reader.ReadVarintU64();
            if (!size || *size > reader.Remaining()) return std::nullopt;
            data = {reader.Position(), static_cast<size_t>(*size)};
            if (!reader.Skip(data.size)) return std::nullopt;
        } else if (!SkipField(reader, key, 0)) {
            return std::nullopt;
        }
    }
    return reader.Ok() ? std::optional<DataField>(data) : std::nullopt;
}

}  // namespace

tl::expected<size_t, std::string_view> GrpcHunkDecoder::Feed(std::span<const uint8_t> bytes) {
    size_t consumed = 0;
    while (consumed < bytes.size() && Payload().empty()) {
        if (prefix_size_ < prefix_.size()) {
            const size_t size = std::min(prefix_.size() - prefix_size_, bytes.size() - consumed);
            std::memcpy(prefix_.data() + prefix_size_, bytes.data() + consumed, size);
            prefix_size_ += size;
            consumed += size;
            if (prefix_size_ != prefix_.size()) break;
            if (prefix_[0] != 0) return tl::unexpected("gRPC compressed messages are unsupported");
            message_size_ = (uint32_t(prefix_[1]) << 24) | (uint32_t(prefix_[2]) << 16) |
                            (uint32_t(prefix_[3]) << 8) | prefix_[4];
            if (message_size_ > kMaxGrpcHunkMessageSize)
                return tl::unexpected("gRPC message exceeds 4 MiB");
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
        if (!data) return tl::unexpected("invalid gRPC Hunk protobuf message");
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

}  // namespace transport::internet
