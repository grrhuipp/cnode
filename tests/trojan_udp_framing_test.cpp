#include "udp_framing.hpp"
#include "trojan_codec.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <future>
#include <iostream>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace acpp;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

std::vector<uint8_t> Flatten(const buf::MultiBuffer& payload) {
    std::vector<uint8_t> out;
    out.reserve(buf::TotalLen(payload));
    for (const buf::Buffer* buffer : payload) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        const auto bytes = buffer->Bytes();
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

class CaptureWriter final : public transport::MultiBufferWriter {
public:
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override {
        Append(payload);
        co_return;
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        for (const auto& buffer : buffers) {
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            bytes.insert(bytes.end(), data, data + buffer.size());
        }
        co_return;
    }

    void Append(const buf::MultiBuffer& payload) {
        for (const buf::Buffer* buffer : payload) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto data = buffer->Bytes();
            bytes.insert(bytes.end(), data.begin(), data.end());
        }
    }

    std::vector<uint8_t> bytes;
};

template <typename Factory>
void Run(Factory&& factory) {
    net::io_context io_context;
    auto future = net::co_spawn(
        io_context,
        std::forward<Factory>(factory)(),
        net::use_future);
    io_context.run();
    future.get();
}

}  // namespace

int main() {
    const TargetAddress target("1.1.1.1", 53);
    const std::vector<uint8_t> source(buf::Buffer::kSize + 257, 0x6d);
    buf::MultiBuffer payload;
    Check(buf::AppendSpanToMultiBuffer(source, payload),
          "failed to allocate Trojan UDP test payload");
    for (buf::Buffer* buffer : payload) {
        if (buffer && !buffer->IsEmpty()) {
            buffer->SetUDP(target);
        }
    }

    CaptureWriter capture;
    Run([&]() -> net::awaitable<void> {
        co_await trojan::WriteUdpDatagram(capture, std::move(payload));
    });

    const auto parsed = trojan::TrojanCodec::ParseUdpPacket(
        capture.bytes.data(), capture.bytes.size());
    Check(parsed.result == trojan::TrojanCodec::UdpParseResult::SUCCESS &&
          parsed.packet && parsed.consumed == capture.bytes.size(),
          "large Trojan UDP datagram was split or malformed");
    Check(parsed.packet->payload.size() == source.size() &&
          std::equal(parsed.packet->payload.begin(), parsed.packet->payload.end(),
                     source.begin()),
          "large Trojan UDP wire payload mismatch");

    trojan::UdpFramer framer;
    size_t offset = 0;
    for (const size_t fragment : {size_t{1}, size_t{7}, size_t{4096},
                                  size_t{17}, size_t{2048}, size_t{3}}) {
        if (offset >= capture.bytes.size()) {
            break;
        }
        const size_t size = std::min(fragment, capture.bytes.size() - offset);
        framer.Feed(capture.bytes.data() + offset, size);
        offset += size;
    }
    if (offset < capture.bytes.size()) {
        framer.Feed(capture.bytes.data() + offset, capture.bytes.size() - offset);
    }

    trojan::FramedUdpPacket decoded;
    Check(framer.Next(decoded), "fragmented Trojan UDP datagram was not decoded");
    Check(decoded.target.SameEndpoint(target),
          "Trojan UDP decoded target mismatch");
    Check(decoded.payload.size() > 1 && Flatten(decoded.payload) == source,
          "Trojan UDP framer truncated multi-buffer payload");
    Check(!framer.Next(decoded),
          "one Trojan UDP datagram produced multiple logical packets");

    CaptureWriter scatter_capture;
    const std::array<net::const_buffer, 3> scatter{
        net::buffer(source.data(), 1024),
        net::buffer(source.data() + 1024, buf::Buffer::kSize - 1024),
        net::buffer(source.data() + buf::Buffer::kSize,
                    source.size() - buf::Buffer::kSize),
    };
    Run([&]() -> net::awaitable<void> {
        co_await trojan::WriteUdpDatagram(
            scatter_capture, target, scatter);
    });
    const auto scatter_parsed = trojan::TrojanCodec::ParseUdpPacket(
        scatter_capture.bytes.data(), scatter_capture.bytes.size());
    Check(scatter_parsed.result ==
              trojan::TrojanCodec::UdpParseResult::SUCCESS &&
          scatter_parsed.packet &&
          scatter_parsed.consumed == scatter_capture.bytes.size() &&
          scatter_parsed.packet->payload.size() == source.size() &&
          std::equal(scatter_parsed.packet->payload.begin(),
                     scatter_parsed.packet->payload.end(), source.begin()),
          "scatter Trojan UDP payload was split into multiple frames");

    return 0;
}
