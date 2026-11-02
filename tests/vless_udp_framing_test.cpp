#include "udp_framing.hpp"
#include "vless_codec.hpp"

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
        for (const buf::Buffer* buffer : payload) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto data = buffer->Bytes();
            bytes.insert(bytes.end(), data.begin(), data.end());
        }
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

    std::vector<uint8_t> bytes;
};

template <typename Factory>
void Run(Factory&& factory) {
    net::io_context io_context;
    auto future = net::co_spawn(
        io_context, std::forward<Factory>(factory)(), net::use_future);
    io_context.run();
    future.get();
}

buf::MultiBuffer MakeDatagram(const std::vector<uint8_t>& source,
                              const TargetAddress& target) {
    buf::MultiBuffer payload;
    Check(buf::AppendSpanToMultiBuffer(source, payload),
          "failed to allocate VLESS UDP test payload");
    for (buf::Buffer* buffer : payload) {
        if (buffer && !buffer->IsEmpty()) {
            buffer->SetUDP(target);
        }
    }
    return payload;
}

void CheckDecoded(const std::vector<uint8_t>& wire,
                  bool packet_addr,
                  const TargetAddress& target,
                  const std::vector<uint8_t>& source) {
    vless::UdpFramer framer(packet_addr);
    size_t offset = 0;
    for (const size_t fragment : {size_t{1}, size_t{7}, size_t{4096},
                                  size_t{17}, size_t{2048}, size_t{3}}) {
        if (offset >= wire.size()) {
            break;
        }
        const size_t size = std::min(fragment, wire.size() - offset);
        framer.Feed(wire.data() + offset, size);
        offset += size;
    }
    if (offset < wire.size()) {
        framer.Feed(wire.data() + offset, wire.size() - offset);
    }

    vless::FramedUdpPacket decoded;
    Check(framer.Next(decoded), "fragmented VLESS UDP datagram was not decoded");
    Check(decoded.target.has_value() == packet_addr,
          "VLESS packet-address target presence mismatch");
    if (packet_addr) {
        Check(decoded.target->SameEndpoint(target),
              "VLESS packet-address target mismatch");
    }
    Check(decoded.payload.size() > 1 && Flatten(decoded.payload) == source,
          "VLESS UDP framer truncated multi-buffer payload");
    Check(!framer.Next(decoded),
          "one VLESS UDP datagram produced multiple logical packets");
}

}  // namespace

int main() {
    const TargetAddress target("1.1.1.1", 53);
    const std::vector<uint8_t> source(buf::Buffer::kSize + 257, 0x6d);

    CaptureWriter fixed_capture;
    auto fixed_payload = MakeDatagram(source, target);
    Run([&]() -> net::awaitable<void> {
        co_await vless::WriteUdpDatagram(
            fixed_capture, std::move(fixed_payload), false);
    });
    const auto fixed_parsed = vless::Codec::ParseUdpPacket(
        fixed_capture.bytes.data(), fixed_capture.bytes.size());
    Check(fixed_parsed.result == vless::Codec::UdpParseResult::SUCCESS &&
          fixed_parsed.packet &&
          fixed_parsed.consumed == fixed_capture.bytes.size() &&
          fixed_parsed.packet->payload.size() == source.size() &&
          std::equal(fixed_parsed.packet->payload.begin(),
                     fixed_parsed.packet->payload.end(), source.begin()),
          "large VLESS UDP datagram was split or malformed");
    CheckDecoded(fixed_capture.bytes, false, target, source);

    CaptureWriter packet_addr_capture;
    auto packet_addr_payload = MakeDatagram(source, target);
    Run([&]() -> net::awaitable<void> {
        co_await vless::WriteUdpDatagram(
            packet_addr_capture, std::move(packet_addr_payload), true);
    });
    CheckDecoded(packet_addr_capture.bytes, true, target, source);

    CaptureWriter scatter_capture;
    const std::array<net::const_buffer, 3> scatter{
        net::buffer(source.data(), 1024),
        net::buffer(source.data() + 1024, buf::Buffer::kSize - 1024),
        net::buffer(source.data() + buf::Buffer::kSize,
                    source.size() - buf::Buffer::kSize),
    };
    Run([&]() -> net::awaitable<void> {
        co_await vless::WriteUdpDatagram(
            scatter_capture, target, false, scatter);
    });
    const auto scatter_parsed = vless::Codec::ParseUdpPacket(
        scatter_capture.bytes.data(), scatter_capture.bytes.size());
    Check(scatter_parsed.result == vless::Codec::UdpParseResult::SUCCESS &&
          scatter_parsed.packet &&
          scatter_parsed.consumed == scatter_capture.bytes.size() &&
          scatter_parsed.packet->payload.size() == source.size() &&
          std::equal(scatter_parsed.packet->payload.begin(),
                     scatter_parsed.packet->payload.end(), source.begin()),
          "scatter VLESS UDP payload was split into multiple frames");

    return 0;
}
