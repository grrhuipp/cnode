#pragma once

#include "common/asio_types.hpp"
#include "common/length_prefixed_packet_buffer.hpp"
#include "common/multi_buffer.hpp"
#include "common/const_buffer_span.hpp"
#include "common/error.hpp"
#include "common/target_address.hpp"
#include "transport/link.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>

// UDP-over-stream 协议写出一份数据报的公共步骤：校验与拼帧。
// 协议自身只负责编码各自的报头。非法数据报统一抛 transport::LinkError。
namespace proxy {

inline constexpr size_t kMaxFramedDatagramPayload = std::numeric_limits<uint16_t>::max();

// 一份已校验、待写出的数据报。target 借用 MultiBuffer 的元数据，
// 只在该 MultiBuffer 未修改期间有效。
struct RequiredUdpDatagram {
    const common::TargetAddress* target = nullptr;
    size_t payload_size = 0;
};

// 唯一的数据报写前校验。空数据报返回 nullopt（调用方直接跳过）；端点缺失、
// 混合或无效，或与 fixed_target（非空时）不是同一端点 → PROTOCOL_INVALID_ADDRESS；
// 负载超过 max_payload → PROTOCOL_ENCODE_FAILED。
[[nodiscard]] inline std::optional<RequiredUdpDatagram> RequireUdpDatagram(
    const common::MultiBuffer& mb,
    const common::TargetAddress* fixed_target,
    size_t max_payload = kMaxFramedDatagramPayload) {
    const auto datagram = common::InspectUdpDatagram(mb);
    if (datagram.status == common::UdpDatagramStatus::Empty) {
        return std::nullopt;
    }
    if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid() ||
        (fixed_target && !datagram.target->SameEndpoint(*fixed_target))) {
        throw transport::LinkError(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    if (datagram.payload_size > max_payload) {
        throw transport::LinkError(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    return RequiredUdpDatagram{.target = datagram.target,
                               .payload_size = datagram.payload_size};
}

// 散列负载版本的同一校验：返回总长度，超过 max_payload → PROTOCOL_ENCODE_FAILED。
[[nodiscard]] inline size_t RequireUdpPayloadSize(
    std::span<const net::const_buffer> payload,
    size_t max_payload = kMaxFramedDatagramPayload) {
    const auto size = common::TrySumBufferSizes(payload, max_payload);
    if (!size) {
        throw transport::LinkError(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    return *size;
}

// 报头与负载作为一次物理写出，保持帧边界完整。header 由调用方帧持有。
inline net::awaitable<void> WriteFramedDatagram(
    transport::MultiBufferWriter& writer,
    std::span<const uint8_t> header,
    const common::MultiBuffer& payload) {
    common::ConstBufferSpanBuilder<1 + common::MultiBuffer::kInlineCapacity> framed;
    framed.Append(net::buffer(header.data(), header.size()));
    framed.AppendMultiBuffer(payload);
    co_await writer.WriteBuffers(framed.Span());
}

inline net::awaitable<void> WriteFramedDatagram(
    transport::MultiBufferWriter& writer,
    std::span<const uint8_t> header,
    std::span<const net::const_buffer> payload) {
    common::ConstBufferSpanBuilder<8> framed;
    framed.Append(net::buffer(header.data(), header.size()));
    framed.AppendBuffers(payload);
    co_await writer.WriteBuffers(framed.Span());
}

}  // namespace proxy
