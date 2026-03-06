#pragma once

// ============================================================================
// trojan_udp_framer.hpp — Trojan UDP 帧编解码实现
//
// 封装 Trojan UDP 帧格式：
//   解码：[AddrType][Addr][Port][Length][CRLF][Data]（支持粘包）
//   编码：TrojanCodec::EncodeUdpPacket*
//
// 与 PayloadOnlyUdpFramer 一起通过 UdpFramer variant 使用，
// relay 层通过 UdpFramerFeed/Next/Encode 等自由函数分发。
// ============================================================================

#include "acppnode/app/udp_types.hpp"
#include "acppnode/protocol/trojan/trojan_codec.hpp"

#include <deque>
#include <vector>

namespace acpp::trojan {

// ============================================================================
// TrojanUdpFramer — Trojan UDP 帧解码器 + 编码器
// ============================================================================
class TrojanUdpFramer {
public:
    void Feed(const uint8_t* data, size_t len) {
        buffer_.insert(buffer_.end(), data, data + len);
        Parse();
    }

    bool Next(UDPPacket& out) {
        if (queue_.empty()) return false;
        out = std::move(queue_.front());
        queue_.pop_front();
        return true;
    }

    size_t EncodeTo(const UDPPacket& pkt, uint8_t* buf, size_t buf_size) {
        return TrojanCodec::EncodeUdpPacketTo(
            pkt.target, pkt.data.data(), pkt.data.size(), buf, buf_size);
    }

    std::vector<uint8_t> Encode(const UDPPacket& pkt) {
        return TrojanCodec::EncodeUdpPacket(
            pkt.target, pkt.data.data(), pkt.data.size());
    }

private:
    // 解析缓冲区（处理粘包，最大 32KB）
    static constexpr size_t kMaxBufferSize = 32768;

    std::vector<uint8_t> buffer_;
    std::deque<UDPPacket> queue_;

    void Parse() {
        while (!buffer_.empty()) {
            auto result = TrojanCodec::ParseUdpPacketEx(
                buffer_.data(), buffer_.size());

            if (result.result == TrojanCodec::UdpParseResult::SUCCESS) {
                UDPPacket pkt;
                pkt.target = result.packet->target;
                pkt.data   = std::move(result.packet->payload);
                queue_.push_back(std::move(pkt));
                buffer_.erase(buffer_.begin(), buffer_.begin() + result.consumed);

            } else if (result.result == TrojanCodec::UdpParseResult::INCOMPLETE) {
                // 数据不完整，等待更多字节；防止缓冲区无限增长
                if (buffer_.size() > kMaxBufferSize) buffer_.clear();
                break;

            } else {
                // 格式错误：丢弃一字节重同步
                buffer_.erase(buffer_.begin());
                if (buffer_.size() < 8) {
                    buffer_.clear();
                    break;
                }
            }
        }
    }
};

}  // namespace acpp::trojan
