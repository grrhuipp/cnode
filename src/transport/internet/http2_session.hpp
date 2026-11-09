#pragma once

#include "common/allocator.hpp"
#include "common/byte_reader.hpp"
#include "transport/internet/transport_stack.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <tl/expected.hpp>
namespace transport::internet {

inline constexpr std::string_view kHttp2ClientPreface =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

[[nodiscard]] constexpr std::array<uint8_t, 6> EncodeInitialWindowSetting(
    uint32_t value) noexcept {
    return {{
        0,
        4,  // SETTINGS_INITIAL_WINDOW_SIZE
        static_cast<uint8_t>(value >> 24),
        static_cast<uint8_t>(value >> 16),
        static_cast<uint8_t>(value >> 8),
        static_cast<uint8_t>(value),
    }};
}
// Server receive policy (RFC 9113 5.2, 6.1, 6.9):
// - Body credit returns on logical consumption, not DATA arrival; padding and
//   discarded/reset bodies return connection credit without reopening streams.
// - The advertised stream window is capped at 4 MiB; the connection window is
//   8 MiB, so one stalled stream cannot stop an independent stream or controls.
// - Queued vector capacity is capped at 4 MiB per stream. A 16 MiB connection
//   reservation budget covers queue capacity and conservatively charged gRPC
//   assembly storage (excluding bounded container/allocator overhead).
// - gRPC assembly is a bounded internal consumer and advances credit for
//   fragmented messages larger than a stream window. Completed messages keep
//   their memory reservation until consumed or discarded.
// - XHTTP uploads retain their additional shared session budget.

// The read pump, logical requests, upload joins, close/reset work, and credit
// writer share the session's owned task group on the Worker reactor and join
// before return.
// gRPC server: reads the client preface, then serves the connection until it
// ends. Logical streams are delivered to `stream_handler`.
[[nodiscard]] net::awaitable<TransportBuildResult> DoGrpcServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id);

// h2 / XHTTP server after the caller consumed the client preface. `cfg` and
// `xhttp_cfg` are borrowed for the whole call; the session never outlives it.
[[nodiscard]] net::awaitable<TransportBuildResult> RunHttp2ServerSession(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    const XHttpConfig* xhttp_cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id);

[[nodiscard]] net::awaitable<TransportBuildResult> DoGrpcClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id);

[[nodiscard]] net::awaitable<TransportBuildResult> DoHttp2ClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id);

inline constexpr size_t kMaxGrpcHunkMessageSize = 4 * 1024 * 1024;

// Worker-local framing state. Only received bytes grow storage. A complete
// protobuf message is validated before exposing its final singular data field.
class GrpcHunkDecoder final {
public:
    GrpcHunkDecoder() = default;
    GrpcHunkDecoder(const GrpcHunkDecoder&) = delete;
    GrpcHunkDecoder& operator=(const GrpcHunkDecoder&) = delete;

    [[nodiscard]] tl::expected<size_t, std::string_view> Feed(std::span<const uint8_t> bytes) {
        size_t consumed = 0;
        while (consumed < bytes.size() && Payload().empty()) {
            if (prefix_size_ < prefix_.size()) {
                const size_t size = std::min(prefix_.size() - prefix_size_, bytes.size() - consumed);
                std::memcpy(prefix_.data() + prefix_size_, bytes.data() + consumed, size);
                prefix_size_ += size;
                consumed += size;
                if (prefix_size_ != prefix_.size()) break;
                if (prefix_[0] != 0) return tl::unexpected("gRPC compressed messages are unsupported");
                message_size_ = LoadU32BE(prefix_.data() + 1);
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

    [[nodiscard]] std::span<const uint8_t> Payload() const noexcept {
        return std::span<const uint8_t>(message_).subspan(data_offset_, data_end_ - data_offset_);
    }

    void Consume(size_t size) noexcept {
        assert(size <= data_end_ - data_offset_);
        data_offset_ += size;
        if (data_offset_ == data_end_) Clear();
    }

    void Clear() noexcept {
        prefix_size_ = message_size_ = data_offset_ = data_end_ = 0;
        memory::ByteVector{}.swap(message_);
    }

    [[nodiscard]] bool AtMessageBoundary() const noexcept { return prefix_size_ == 0; }
    [[nodiscard]] size_t NextFeedLimit() const noexcept {
        return prefix_size_ < prefix_.size()
            ? (prefix_.size() - prefix_size_)
            : (message_size_ - message_.size());
    }

private:
    struct DataField {
        size_t offset = 0;
        size_t size = 0;
    };

    [[nodiscard]] static bool ReadKey(ByteReader& reader, uint32_t& key) noexcept {
        const auto value = reader.ReadVarintU64();
        if (!value || *value > UINT32_MAX || (*value >> 3) == 0) return false;
        key = static_cast<uint32_t>(*value);
        return true;
    }

    [[nodiscard]] static bool SkipField(ByteReader& reader, uint32_t key, unsigned depth) noexcept {
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

    [[nodiscard]] static std::optional<DataField> DecodeMessage(
        std::span<const uint8_t> bytes) noexcept {
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

    std::array<uint8_t, 5> prefix_{};
    size_t prefix_size_ = 0;
    size_t message_size_ = 0;
    memory::ByteVector message_;
    size_t data_offset_ = 0;
    size_t data_end_ = 0;
};

}  // namespace transport::internet
