#pragma once

#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/transport/link.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace acpp::vless {

inline constexpr std::string_view kVisionFlow = "xtls-rprx-vision";

[[nodiscard]] bool IsVisionFlow(std::string_view flow) noexcept;

class VisionReader final : public transport::MultiBufferReader {
public:
    VisionReader(transport::MultiBufferReader& src,
                 std::array<uint8_t, 16> user_uuid,
                 std::span<const uint8_t> initial = {});

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;

private:
    transport::MultiBufferReader& src_;
    std::array<uint8_t, 16> user_uuid_{};
    memory::ByteVector pending_;
    bool read_process_ = true;
    bool expect_uuid_ = true;

    void Feed(buf::MultiBuffer mb);
    [[nodiscard]] bool TryDecode(buf::MultiBuffer& out);
};

class VisionWriter final : public transport::MultiBufferWriter {
public:
    VisionWriter(transport::MultiBufferWriter& dst,
                 std::array<uint8_t, 16> user_uuid);

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;

private:
    transport::MultiBufferWriter& dst_;
    std::array<uint8_t, 16> user_uuid_{};
    bool write_process_ = true;
    bool send_uuid_ = true;
    int packets_to_filter_ = 8;
    bool is_tls_ = false;
    bool is_tls12_or_above_ = false;
    uint16_t remaining_server_hello_ = 0;
    uint16_t cipher_ = 0;

    void FilterTLS(std::span<const uint8_t> data) noexcept;
    [[nodiscard]] bool ShouldEndVision(std::span<const uint8_t> data) const noexcept;
    [[nodiscard]] bool AppendVisionFrameBuffers(
        buf::MultiBuffer& header_owner,
        memory::ThreadLocalVector<net::const_buffer>& out,
        std::span<const uint8_t> content,
        uint8_t command);
};

}  // namespace acpp::vless
