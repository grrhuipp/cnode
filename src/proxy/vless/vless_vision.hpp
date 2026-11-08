#pragma once

#include "common/buf/multi_buffer.hpp"
#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "transport/link.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace vless {

inline constexpr std::string_view kVisionFlow = "xtls-rprx-vision";

[[nodiscard]] bool IsVisionFlow(std::string_view flow) noexcept;

namespace detail {
inline constexpr size_t kVisionFrameContentLimit = 8192 - 21;
// `random` is uniform in [0,499] for long TLS padding, otherwise [0,255].
[[nodiscard]] constexpr uint16_t VisionPaddingSize(
    size_t content, bool long_padding, uint16_t random) noexcept {
    const size_t padding = content < 900 && long_padding
        ? random + 900 - content : random;
    const size_t available = content < kVisionFrameContentLimit
        ? kVisionFrameContentLimit - content : 0;
    return static_cast<uint16_t>(padding < available ? padding : available);
}
} // namespace detail

// Both directions observe the same TLS handshake, as in Xray TrafficState.
// Access is confined to the connection's owning Worker.
struct VisionTrafficState {
    int packets_to_filter = 8;
    bool is_tls = false;
    bool is_tls12_or_above = false;
    int32_t remaining_server_hello = -1;
    bool tls_classified = false;

    void FilterTLS(std::span<const uint8_t> data) noexcept;
};

class VisionReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return src_.ReadEofAction(); }

    VisionReader(transport::MultiBufferReader& src,
                 std::array<uint8_t, 16> user_uuid,
                 VisionTrafficState& traffic,
                 std::span<const uint8_t> initial = {});

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;

private:
    transport::MultiBufferReader& src_;
    std::array<uint8_t, 16> user_uuid_{};
    VisionTrafficState& traffic_;
    // Streaming frame cursor: header bytes, content and padding may each be
    // split across reads; content is moved out as soon as it arrives.
    buf::MultiBuffer pending_;
    std::array<uint8_t, 16 + 5> header_{};
    size_t header_read_ = 0;
    size_t content_remaining_ = 0;
    size_t padding_remaining_ = 0;
    uint8_t command_ = 0;
    bool frame_active_ = false;
    bool read_process_ = true;
    bool expect_uuid_ = true;

    void Decode(buf::MultiBuffer& out);
};

class VisionWriter final : public transport::MultiBufferWriter {
public:
    VisionWriter(transport::MultiBufferWriter& dst,
                 std::array<uint8_t, 16> user_uuid,
                 VisionTrafficState& traffic);

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;
    bool WriteShutdownClosesLink() const noexcept override {
        return dst_.WriteShutdownClosesLink();
    }

private:
    transport::MultiBufferWriter& dst_;
    std::array<uint8_t, 16> user_uuid_{};
    bool write_process_ = true;
    bool send_uuid_ = true;
    VisionTrafficState& traffic_;
};

}  // namespace vless
