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
    Check(buf::SetUdpTarget(payload, target),
          "failed to tag VLESS UDP test payload");
    return payload;
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
    const std::array<uint8_t, 9> wire{0, 0, 0, 2, 0x11, 0x22, 0, 1, 0x33};
    for (size_t split = 0; split <= wire.size(); ++split) {
        vless::UdpFramer framer(false);
        vless::FramedUdpPacket packet;
        std::vector<uint8_t> decoded;
        std::vector<size_t> sizes;
        framer.Feed(MakeInput(std::span(wire).first(split)));
        while (framer.Next(packet)) {
            sizes.push_back(packet.payload.byte_size());
            auto bytes = Flatten(packet.payload);
            decoded.insert(decoded.end(), bytes.begin(), bytes.end());
        }
        framer.Feed(MakeInput(std::span(wire).subspan(split)));
        while (framer.Next(packet)) {
            sizes.push_back(packet.payload.byte_size());
            auto bytes = Flatten(packet.payload);
            decoded.insert(decoded.end(), bytes.begin(), bytes.end());
        }
        framer.Finish();
        Check(decoded == std::vector<uint8_t>({0x11, 0x22, 0x33}),
              "zero length frame damaged a following frame");
        Check(sizes == std::vector<size_t>({0, 2, 1}),
              "VLESS UDP lost an empty datagram boundary");
    }
    for (size_t cut : {size_t{1}, size_t{2}, size_t{3}}) {
        vless::UdpFramer framer(false);
        framer.Feed(MakeInput(std::span(wire).subspan(2, cut)));
        vless::FramedUdpPacket packet;
        (void)framer.Next(packet);
        CheckRejected([&] { framer.Finish(); }, "truncated frame accepted as EOF");
    }
    vless::UdpFramer invalid(true);
    const std::array<uint8_t, 6> malformed{0, 1, 0xff, 0, 1, 0x42};
    invalid.Feed(MakeInput(malformed));
    vless::FramedUdpPacket packet;
    CheckRejected([&] { (void)invalid.Next(packet); }, "invalid address accepted");
    CheckRejected([&] { (void)invalid.Next(packet); }, "invalid stream resynchronized");
    vless::UdpFramer missing_address(true);
    const std::array<uint8_t, 2> no_address{0, 0};
    missing_address.Feed(MakeInput(no_address));
    CheckRejected([&] { (void)missing_address.Next(packet); },
                  "packet-address segment without an address became a UDP message");

    vless::UdpFramer bounded(false);
    const std::vector<uint8_t> excess(buf::kPacketStreamPendingLimit + 1, 0);
    CheckRejected([&] { bounded.Feed(MakeInput(excess)); }, "unbounded retained input");
    CheckRejected([&] { (void)bounded.Next(packet); }, "overflow stream recovered");

    const std::vector<uint8_t> maximum(65535, 0x71);
    std::vector<uint8_t> large{0xff, 0xff};
    large.insert(large.end(), maximum.begin(), maximum.end());
    vless::UdpFramer fragmented(false);
    for (const auto byte : large) {
        fragmented.Feed(MakeInput(std::span<const uint8_t>(&byte, 1)));
    }
    Check(fragmented.Next(packet) && Flatten(packet.payload) == maximum,
          "one-byte fragments failed at maximum wire length");
    fragmented.Finish();
}

void CheckCancelledReadPreservesFrame() {
    net::io_context io;
    tcp::acceptor listener(io, tcp::endpoint(net::ip::address_v4::loopback(), 0));
    tcp::socket sender(io);
    sender.connect(listener.local_endpoint());
    tcp::socket receiver = listener.accept();
    const std::array<uint8_t, 5> wire{0, 3, 0x11, 0x22, 0x33};
    net::write(sender, net::buffer(wire.data(), 1));
    vless::UdpFramer framer(false);
    auto future = net::co_spawn(io, [&]() -> net::awaitable<void> {
        std::array<uint8_t, 5> bytes{};
        co_await net::async_read(receiver, net::buffer(bytes.data(), 1), net::use_awaitable);
        framer.Feed(MakeInput(std::span(bytes).first(1)));
        vless::FramedUdpPacket packet;
        Check(!framer.Next(packet), "partial frame delivered before cancellation");
        net::post(io, [&] { receiver.cancel(); });
        IoErrorCode ec;
        (void)co_await receiver.async_read_some(
            net::buffer(bytes), net::redirect_error(net::use_awaitable, ec));
        Check(ec == net::error::operation_aborted, "socket read was not cancelled");
        net::write(sender, net::buffer(wire.data() + 1, wire.size() - 1));
        co_await net::async_read(receiver, net::buffer(bytes.data(), 4), net::use_awaitable);
        framer.Feed(MakeInput(std::span(bytes).first(4)));
        Check(framer.Next(packet) &&
                  Flatten(packet.payload) == std::vector<uint8_t>({0x11, 0x22, 0x33}),
              "cancelled read lost retained VLESS bytes");
        Check(!framer.Next(packet), "cancelled read duplicated VLESS bytes");
        framer.Finish();
    }, net::use_future);
    io.run();
    future.get();
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
        framer.Feed(MakeInput(std::span(wire).subspan(offset, size)));
        offset += size;
    }
    if (offset < wire.size()) {
        framer.Feed(MakeInput(std::span(wire).subspan(offset)));
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
    framer.Finish();
}


class FragmentReader final : public transport::MultiBufferReader {
public:
    explicit FragmentReader(std::span<const uint8_t> bytes) : bytes_(bytes) {}
    transport::CancellationSource& Cancellation() noexcept override {
        return cancellation_;
    }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (offset_ == bytes_.size()) co_return buf::MultiBuffer{};
        co_return MakeInput(bytes_.subspan(offset_++, 1));
    }
private:
    transport::CancellationSource cancellation_;
    std::span<const uint8_t> bytes_;
    size_t offset_ = 0;
};

void CheckEmptyDatagramRoundTrip(bool packet_addr) {
    const TargetAddress target("127.0.0.1", 53);
    CaptureWriter capture;
    const std::vector<uint8_t> data{0x42};
    ::Run([&]() -> net::awaitable<void> {
        co_await vless::WriteUdpDatagram(
            capture, MakeDatagram({}, target), packet_addr);
        co_await vless::WriteUdpDatagram(
            capture, MakeDatagram(data, target), packet_addr);
        co_await vless::WriteUdpDatagram(
            capture, target, packet_addr, std::span<const net::const_buffer>{});
    });
    Check(capture.bytes.size() == (packet_addr ? 28 : 7),
          "VLESS UDP empty datagrams did not write real frame headers");
    FragmentReader source(capture.bytes);
    vless::UdpFramer framer(packet_addr);
    ::Run([&]() -> net::awaitable<void> {
        for (const size_t size : {size_t{0}, size_t{1}, size_t{0}}) {
            auto packet = co_await framer.ReadDatagram(source, target);
            const auto datagram = buf::InspectUdpDatagram(packet);
            Check(datagram.Valid() && datagram.payload_size == size &&
                      datagram.target->SameEndpoint(target),
                  "VLESS UDP empty/data sequence became EOF or lost its target");
            if (size != 0) Check(Flatten(packet) == data, "VLESS UDP payload changed");
        }
        Check((co_await framer.ReadDatagram(source, target)).empty(),
              "VLESS UDP clean stream EOF became an empty datagram");
    });
}
}  // namespace

TEST(VlessUdpFraming, Contract) {
    CheckFrameBoundaries();
    CheckCancelledReadPreservesFrame();
    CheckEmptyDatagramRoundTrip(false);
    CheckEmptyDatagramRoundTrip(true);
    const TargetAddress target("1.1.1.1", 53);
    const std::vector<uint8_t> source(buf::Buffer::kSize + 257, 0x6d);

    CaptureWriter fixed_capture;
    auto fixed_payload = MakeDatagram(source, target);
    ::Run([&]() -> net::awaitable<void> {
        co_await vless::WriteUdpDatagram(
            fixed_capture, std::move(fixed_payload), false);
    });
    Check(fixed_capture.bytes.size() == source.size() + 2 &&
              fixed_capture.bytes[0] == static_cast<uint8_t>(source.size() >> 8) &&
              fixed_capture.bytes[1] == static_cast<uint8_t>(source.size()) &&
              std::equal(source.begin(), source.end(), fixed_capture.bytes.begin() + 2),
          "large VLESS UDP datagram was split or malformed");
    CheckDecoded(fixed_capture.bytes, false, target, source);

    CaptureWriter packet_addr_capture;
    auto packet_addr_payload = MakeDatagram(source, target);
    ::Run([&]() -> net::awaitable<void> {
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
    ::Run([&]() -> net::awaitable<void> {
        co_await vless::WriteUdpDatagram(
            scatter_capture, target, false, scatter);
    });
    Check(scatter_capture.bytes == fixed_capture.bytes,
          "scatter VLESS UDP payload was split into multiple frames");

    const std::vector<uint8_t> oversized(65536, 0x42);
    const std::array<net::const_buffer, 1> oversized_buffers{net::buffer(oversized)};
    CaptureWriter rejected_capture;
    CheckRejected([&] {
        ::Run([&]() -> net::awaitable<void> {
            co_await vless::WriteUdpDatagram(
                rejected_capture, target, false, oversized_buffers);
        });
    }, "oversized VLESS datagram accepted");
    Check(rejected_capture.bytes.empty(), "oversized VLESS datagram partially written");

}

TEST(VlessUdpFraming, TruncatedEofCannotResume) {
    const std::array<uint8_t, 5> wire{0, 3, 0x11, 0x22, 0x33};
    for (size_t cut = 1; cut < wire.size(); ++cut) {
        SCOPED_TRACE(cut);
        vless::UdpFramer framer(false);
        framer.Feed(MakeInput(std::span(wire).first(cut)));
        vless::FramedUdpPacket packet;
        ASSERT_FALSE(framer.Next(packet));
        EXPECT_THROW(framer.Finish(), IoSystemError);
        EXPECT_THROW(framer.Feed(MakeInput(std::span(wire).subspan(cut))), IoSystemError);
        EXPECT_THROW((void)framer.Next(packet), IoSystemError);
        EXPECT_THROW(framer.Finish(), IoSystemError);
    }
}

TEST(VlessUdpFraming, CleanEofRejectsFurtherInput) {
    const std::array<uint8_t, 3> wire{0, 1, 0x73};
    vless::UdpFramer framer(false);
    framer.Feed(MakeInput(wire));
    vless::FramedUdpPacket packet;
    ASSERT_TRUE(framer.Next(packet));
    EXPECT_EQ(Flatten(packet.payload), std::vector<uint8_t>({0x73}));
    framer.Finish();
    framer.Finish();
    EXPECT_THROW(framer.Feed({}), IoSystemError);
    EXPECT_THROW(framer.Feed(MakeInput(wire)), IoSystemError);
    EXPECT_FALSE(framer.Next(packet));
    EXPECT_TRUE(packet.payload.empty());
}

TEST(VlessUdpFraming, ReadEofDoesNotConsumeAnotherTransport) {
    const std::array<uint8_t, 3> wire{0, 1, 0x73};
    const TargetAddress target("127.0.0.1", 53);
    net::io_context io;
    tcp::acceptor listener(io, {net::ip::address_v4::loopback(), 0});
    tcp::socket ended_peer(io);
    ended_peer.connect(listener.local_endpoint());
    TcpStream ended(listener.accept());
    ended_peer.shutdown(tcp::socket::shutdown_send);
    tcp::socket fresh_peer(io);
    fresh_peer.connect(listener.local_endpoint());
    TcpStream fresh(listener.accept());
    net::write(fresh_peer, net::buffer(wire));
    fresh_peer.shutdown(tcp::socket::shutdown_send);
    vless::UdpFramer framer(false);
    auto result = net::co_spawn(io, [&]() -> net::awaitable<void> {
        Check((co_await framer.ReadDatagram(ended, target)).empty(), "clean EOF produced a datagram");
        Check((co_await framer.ReadDatagram(fresh, target)).empty(),
              "finished VLESS framer consumed another transport");
        std::vector<uint8_t> retained;
        for (;;) {
            auto input = co_await fresh.ReadMultiBuffer();
            if (input.empty()) break;
            const auto bytes = Flatten(input);
            retained.insert(retained.end(), bytes.begin(), bytes.end());
        }
        Check(retained == std::vector<uint8_t>(wire.begin(), wire.end()),
              "finished VLESS framer changed another transport's bytes");
    }, net::use_future);
    io.run();
    result.get();
}

TEST(VlessUdpFraming, EmptyDatagramAllocationFailureRetiresFramer) {
    const std::array<uint8_t, 2> empty_wire{0, 0};
    const std::array<uint8_t, 3> next_wire{0, 1, 0x73};
    const TargetAddress target("127.0.0.1", 53);
    vless::UdpFramer framer(false);
    framer.Feed(MakeInput(empty_wire));
    FragmentReader source(std::span<const uint8_t>{});
    ::Run([&]() -> net::awaitable<void> {
        auto operation = framer.ReadDatagram(source, target);
        bool failed = false;
        memory::reject_next_pmr_allocation = true;
        try {
            (void)co_await std::move(operation);
        } catch (const std::bad_alloc&) {
            failed = true;
        } catch (...) {
            memory::reject_next_pmr_allocation = false;
            throw;
        }
        memory::reject_next_pmr_allocation = false;
        Check(failed, "empty VLESS datagram allocation failure was hidden");
    });
    EXPECT_THROW(framer.Feed(MakeInput(next_wire)), IoSystemError);
    vless::FramedUdpPacket packet;
    EXPECT_THROW((void)framer.Next(packet), IoSystemError);
    EXPECT_THROW(framer.Finish(), IoSystemError);
}
