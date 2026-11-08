#include <stdexcept>
#include <gtest/gtest.h>

#include "udp_framing.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "transport/internet/tcp_stream.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/redirect_error.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

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


[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

std::vector<uint8_t> Flatten(const buf::MultiBuffer& payload) {
    std::vector<uint8_t> out;
    out.reserve(payload.byte_size());
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

buf::MultiBuffer MakeInput(std::span<const uint8_t> bytes) {
    buf::MultiBuffer input;
    Check(buf::AppendSpanToMultiBuffer(bytes, input), "input allocation failed");
    return input;
}

template <typename Fn>
void CheckRejected(Fn&& fn, std::string_view message) {
    bool rejected = false;
    try { fn(); } catch (const IoSystemError&) { rejected = true; }
    Check(rejected, message);
}

void CheckFrameBoundaries() {
    const std::array<uint8_t, 25> wire{
        1, 127, 0, 0, 1, 0, 53, 0, 0, '\r', '\n',
        1, 127, 0, 0, 1, 0, 53, 0, 3, '\r', '\n', 0x11, 0x22, 0x33};
    for (size_t split = 0; split <= wire.size(); ++split) {
        trojan::UdpFramer framer;
        trojan::FramedUdpPacket packet;
        framer.Feed(MakeInput(std::span(wire).first(split)));
        std::vector<size_t> sizes;
        while (framer.Next(packet)) {
            sizes.push_back(packet.payload.byte_size());
            Check(buf::InspectUdpDatagram(packet.payload).Valid(),
                  "Trojan frame did not produce a tagged UDP datagram");
        }
        framer.Feed(MakeInput(std::span(wire).subspan(split)));
        while (framer.Next(packet)) {
            sizes.push_back(packet.payload.byte_size());
            Check(packet.target.SameEndpoint(TargetAddress("127.0.0.1", 53)),
                  "Trojan datagram target changed");
            if (packet.payload.byte_size() != 0) {
                Check(Flatten(packet.payload) == std::vector<uint8_t>({0x11, 0x22, 0x33}),
                      "Trojan datagram payload changed");
            }
        }
        Check(sizes == std::vector<size_t>({0, 3}),
              "Trojan UDP lost an empty datagram boundary");
        framer.Finish();
    }
    for (size_t cut = 1; cut < 14; ++cut) {
        trojan::UdpFramer truncated;
        truncated.Feed(MakeInput(std::span(wire).subspan(11, cut)));
        trojan::FramedUdpPacket packet;
        Check(!truncated.Next(packet), "truncated Trojan frame delivered");
        CheckRejected([&] { truncated.Finish(); }, "truncated Trojan EOF accepted");
    }
    for (size_t corrupt : {size_t{0}, size_t{9}, size_t{10}}) {
        auto malformed = wire;
        malformed[corrupt] = 0xff;
        trojan::UdpFramer invalid;
        invalid.Feed(MakeInput(malformed));
        trojan::FramedUdpPacket packet;
        CheckRejected([&] { (void)invalid.Next(packet); }, "invalid Trojan frame accepted");
        CheckRejected([&] { (void)invalid.Next(packet); }, "Trojan stream resynchronized");
    }
    trojan::UdpFramer empty_domain;
    const std::array<uint8_t, 2> empty_domain_prefix{3, 0};
    empty_domain.Feed(MakeInput(empty_domain_prefix));
    trojan::FramedUdpPacket empty_domain_packet;
    CheckRejected([&] { (void)empty_domain.Next(empty_domain_packet); },
                  "empty Trojan domain accepted");
    trojan::UdpFramer invalid_domain;
    const std::array<uint8_t, 10> malformed_domain{
        3, 1, ' ', 0, 53, 0, 1, '\r', '\n', 0x42};
    invalid_domain.Feed(MakeInput(malformed_domain));
    trojan::FramedUdpPacket invalid_packet;
    CheckRejected([&] { (void)invalid_domain.Next(invalid_packet); },
                  "invalid domain syntax accepted");

    const std::string domain_name =
        std::string(63, 'a') + "." + std::string(63, 'b') + "." +
        std::string(63, 'c') + "." + std::string(61, 'd');
    std::vector<uint8_t> domain_frame{3, 253};
    domain_frame.insert(domain_frame.end(), domain_name.begin(), domain_name.end());
    domain_frame.insert(domain_frame.end(), {0, 53, 0, 1, '\r', '\n', 0x42});
    for (size_t split = 0; split <= domain_frame.size(); ++split) {
        trojan::UdpFramer domain;
        trojan::FramedUdpPacket packet;
        domain.Feed(MakeInput(std::span(domain_frame).first(split)));
        const bool first = domain.Next(packet);
        domain.Feed(MakeInput(std::span(domain_frame).subspan(split)));
        Check(first || domain.Next(packet), "fragmented maximum domain frame lost");
        Check(std::string_view(packet.target.host) == domain_name && packet.target.port == 53 &&
                  Flatten(packet.payload) == std::vector<uint8_t>({0x42}),
              "fragmented Trojan domain or payload corrupted");
        Check(!domain.Next(packet), "domain frame decoded twice");
        domain.Finish();
    }
    trojan::UdpFramer bounded;
    const std::vector<uint8_t> excess(buf::kPacketStreamPendingLimit + 1, 0);
    CheckRejected([&] { bounded.Feed(MakeInput(excess)); }, "unbounded Trojan input");

    std::vector<uint8_t> maximum{
        1, 127, 0, 0, 1, 0, 53, 0xff, 0xff, '\r', '\n'};
    maximum.resize(11 + 65535, 0x71);
    trojan::UdpFramer fragmented;
    for (const auto byte : maximum) {
        fragmented.Feed(MakeInput(std::span<const uint8_t>(&byte, 1)));
    }
    trojan::FramedUdpPacket packet;
    Check(fragmented.Next(packet) &&
              Flatten(packet.payload) == std::vector<uint8_t>(65535, 0x71),
          "one-byte Trojan fragments failed at maximum wire length");
    fragmented.Finish();
}

void CheckCancelledReadPreservesFrame() {
    net::io_context io;
    tcp::acceptor listener(io, tcp::endpoint(net::ip::address_v4::loopback(), 0));
    tcp::socket sender(io);
    sender.connect(listener.local_endpoint());
    tcp::socket receiver = listener.accept();
    const std::array<uint8_t, 14> wire{
        1, 127, 0, 0, 1, 0, 53, 0, 3, '\r', '\n', 0x11, 0x22, 0x33};
    net::write(sender, net::buffer(wire.data(), 12));
    trojan::UdpFramer framer;
    auto future = net::co_spawn(io, [&]() -> net::awaitable<void> {
        std::array<uint8_t, 14> bytes{};
        co_await net::async_read(receiver, net::buffer(bytes.data(), 12), net::use_awaitable);
        framer.Feed(MakeInput(std::span(bytes).first(12)));
        trojan::FramedUdpPacket packet;
        Check(!framer.Next(packet), "partial Trojan frame delivered");
        net::post(io, [&] { receiver.cancel(); });
        IoErrorCode ec;
        (void)co_await receiver.async_read_some(
            net::buffer(bytes), net::redirect_error(net::use_awaitable, ec));
        Check(ec == net::error::operation_aborted, "Trojan read was not cancelled");
        net::write(sender, net::buffer(wire.data() + 12, wire.size() - 12));
        co_await net::async_read(receiver, net::buffer(bytes.data(), 2), net::use_awaitable);
        framer.Feed(MakeInput(std::span(bytes).first(2)));
        Check(framer.Next(packet) &&
                  Flatten(packet.payload) == std::vector<uint8_t>({0x11, 0x22, 0x33}),
              "cancelled read lost retained Trojan bytes");
        Check(!framer.Next(packet), "cancelled read duplicated Trojan bytes");
        framer.Finish();
    }, net::use_future);
    io.run();
    future.get();
}
}  // namespace

TEST(TrojanUdpFraming, Contract) {
    CheckFrameBoundaries();
    CheckCancelledReadPreservesFrame();
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
    ::Run([&]() -> net::awaitable<void> {
        co_await trojan::WriteUdpDatagram(capture, std::move(payload));
    });

    const std::array<uint8_t, 11> expected_header{
        1, 1, 1, 1, 1, 0, 53,
        static_cast<uint8_t>(source.size() >> 8),
        static_cast<uint8_t>(source.size()), '\r', '\n'};
    Check(capture.bytes.size() == expected_header.size() + source.size() &&
              std::equal(expected_header.begin(), expected_header.end(), capture.bytes.begin()) &&
              std::equal(source.begin(), source.end(),
                         capture.bytes.begin() + expected_header.size()),
          "large Trojan UDP datagram was split or malformed");

    trojan::UdpFramer framer;
    size_t offset = 0;
    for (const size_t fragment : {size_t{1}, size_t{7}, size_t{4096},
                                  size_t{17}, size_t{2048}, size_t{3}}) {
        if (offset >= capture.bytes.size()) {
            break;
        }
        const size_t size = std::min(fragment, capture.bytes.size() - offset);
        framer.Feed(MakeInput(std::span(capture.bytes).subspan(offset, size)));
        offset += size;
    }
    if (offset < capture.bytes.size()) {
        framer.Feed(MakeInput(std::span(capture.bytes).subspan(offset)));
    }

    trojan::FramedUdpPacket decoded;
    Check(framer.Next(decoded), "fragmented Trojan UDP datagram was not decoded");
    Check(decoded.target.SameEndpoint(target),
          "Trojan UDP decoded target mismatch");
    Check(decoded.payload.size() > 1 && Flatten(decoded.payload) == source,
          "Trojan UDP framer truncated multi-buffer payload");
    Check(!framer.Next(decoded),
          "one Trojan UDP datagram produced multiple logical packets");
    framer.Finish();

    CaptureWriter scatter_capture;
    const std::array<net::const_buffer, 3> scatter{
        net::buffer(source.data(), 1024),
        net::buffer(source.data() + 1024, buf::Buffer::kSize - 1024),
        net::buffer(source.data() + buf::Buffer::kSize,
                    source.size() - buf::Buffer::kSize),
    };
    ::Run([&]() -> net::awaitable<void> {
        co_await trojan::WriteUdpDatagram(
            scatter_capture, target, scatter);
    });
    Check(scatter_capture.bytes == capture.bytes,
          "scatter Trojan UDP payload was split into multiple frames");

    const std::vector<uint8_t> oversized(65536, 0x42);
    const std::array<net::const_buffer, 1> oversized_buffers{net::buffer(oversized)};
    CaptureWriter rejected_capture;
    CheckRejected([&] {
        ::Run([&]() -> net::awaitable<void> {
            co_await trojan::WriteUdpDatagram(
                rejected_capture, target, oversized_buffers);
        });
    }, "oversized Trojan datagram accepted");
    Check(rejected_capture.bytes.empty(), "oversized Trojan datagram partially written");

}

TEST(TrojanUdpFraming, EmptyDatagramsAreNotEof) {
    const TargetAddress target("127.0.0.1", 53);
    CaptureWriter capture;
    ::Run([&]() -> net::awaitable<void> {
        buf::MultiBuffer empty;
        Check(buf::SetUdpTarget(empty, target), "empty UDP allocation failed");
        co_await trojan::WriteUdpDatagram(capture, std::move(empty));
        const std::array<uint8_t, 1> data{0x42};
        const std::array<net::const_buffer, 1> buffers{net::buffer(data)};
        co_await trojan::WriteUdpDatagram(capture, target, buffers);
        co_await trojan::WriteUdpDatagram(
            capture, target, std::span<const net::const_buffer>{});
    });
    Check(capture.bytes.size() == 34, "empty Trojan UDP frame header was omitted");

    net::io_context io;
    tcp::acceptor listener(io, {net::ip::address_v4::loopback(), 0});
    tcp::socket peer(io);
    peer.connect(listener.local_endpoint());
    TcpStream stream(listener.accept());
    net::write(peer, net::buffer(capture.bytes));
    peer.shutdown(tcp::socket::shutdown_send);
    trojan::UdpFramer framer;
    auto result = net::co_spawn(io, [&]() -> net::awaitable<void> {
        for (const size_t size : {size_t{0}, size_t{1}, size_t{0}}) {
            auto packet = co_await trojan::ReadUdpDatagram(stream, framer);
            const auto datagram = buf::InspectUdpDatagram(packet);
            Check(datagram.Valid() && datagram.payload_size == size &&
                      datagram.target->SameEndpoint(target),
                  "Trojan empty/data sequence became EOF or lost its target");
            if (size != 0) Check(Flatten(packet) == std::vector<uint8_t>{0x42},
                                 "Trojan UDP data changed");
        }
        Check((co_await trojan::ReadUdpDatagram(stream, framer)).empty(),
              "Trojan TCP EOF became an empty datagram");
    }, net::use_future);
    io.run();
    result.get();
}
