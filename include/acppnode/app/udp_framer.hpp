#pragma once

// ============================================================================
// udp_framer.hpp — UDP 帧编解码（variant 分发，零虚调用）
//
// UdpFramer 将协议相关的 UDP 封包格式与 relay 层解耦：
//   - relay_udp.cpp 通过自由函数调用，不感知具体协议
//   - TrojanUdpFramer / PayloadOnlyUdpFramer 由上层（session handler）创建后传入
//
// 协议实现：
//   - PayloadOnlyUdpFramer：原始载荷直通（VMess Command::UDP、通用协议）
//   - TrojanUdpFramer：见 protocol/trojan/trojan_udp_framer.hpp
// ============================================================================

#include "acppnode/app/udp_types.hpp"

#include <cstdint>
#include <cstring>
#include <variant>
#include <vector>

namespace acpp {

}  // namespace acpp

// 完整定义（variant 需要完整类型）
#include "acppnode/protocol/trojan/trojan_udp_framer.hpp"

namespace acpp {

// ============================================================================
// PayloadOnlyUdpFramer — 原始载荷直通（VMess Command::UDP / 通用协议）
//
// Feed 的数据直接作为一个 UDPPacket 输出，目标地址由构造时提供。
// Encode / EncodeTo 直接返回 pkt.data，不添加任何协议头。
// ============================================================================
class PayloadOnlyUdpFramer {
public:
    explicit PayloadOnlyUdpFramer(TargetAddress target)
        : target_(std::move(target)) {}

    void Feed(const uint8_t* data, size_t len) {
        if (len == 0) return;
        UDPPacket pkt;
        pkt.target = target_;
        pkt.data.assign(data, data + len);
        pending_ = std::move(pkt);
    }

    bool Next(UDPPacket& out) {
        if (!pending_) return false;
        out = std::move(*pending_);
        pending_.reset();
        return true;
    }

    size_t EncodeTo(const UDPPacket& pkt, uint8_t* buf, size_t buf_size) {
        if (pkt.data.size() > buf_size) return 0;
        std::memcpy(buf, pkt.data.data(), pkt.data.size());
        return pkt.data.size();
    }

    std::vector<uint8_t> Encode(const UDPPacket& pkt) {
        return pkt.data;
    }

private:
    TargetAddress target_;
    std::optional<UDPPacket> pending_;
};

// ============================================================================
// UdpFramer — variant 类型（编译期分发，零虚调用开销）
// ============================================================================
using UdpFramer = std::variant<PayloadOnlyUdpFramer, trojan::TrojanUdpFramer>;

// ── 自由函数：通过 std::visit 分发 ──────────────────────────────────────────

inline void UdpFramerFeed(UdpFramer& f, const uint8_t* data, size_t len) {
    std::visit([&](auto& impl) { impl.Feed(data, len); }, f);
}

inline bool UdpFramerNext(UdpFramer& f, UDPPacket& out) {
    return std::visit([&](auto& impl) { return impl.Next(out); }, f);
}

inline size_t UdpFramerEncodeTo(UdpFramer& f, const UDPPacket& pkt,
                                 uint8_t* buf, size_t buf_size) {
    return std::visit([&](auto& impl) { return impl.EncodeTo(pkt, buf, buf_size); }, f);
}

inline std::vector<uint8_t> UdpFramerEncode(UdpFramer& f, const UDPPacket& pkt) {
    return std::visit([&](auto& impl) { return impl.Encode(pkt); }, f);
}

}  // namespace acpp
