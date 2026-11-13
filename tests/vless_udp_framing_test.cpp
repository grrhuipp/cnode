#include <stdexcept>
#include <limits>
#include <gtest/gtest.h>

#include "proxy/vless/vless_codec.hpp"
#include "common/length_prefixed_packet_buffer.hpp"
#include "transport/tcp_stream.hpp"
#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/redirect_error.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <future>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace {



std::vector<uint8_t> Flatten(const common::MultiBuffer& payload) {
    std::vector<uint8_t> out;
    out.reserve(payload.byte_size());
    for (const common::Buffer* buffer : payload) {
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
    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer payload) override {
        for (const common::Buffer* buffer : payload) {
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

common::MultiBuffer MakeDatagram(const std::vector<uint8_t>& source,
                              const common::TargetAddress& target) {
    common::MultiBuffer payload;
    EXPECT_TRUE((common::AppendSpanToMultiBuffer(source, payload))) << "failed to allocate VLESS UDP test payload";
    EXPECT_TRUE((common::SetUdpTarget(payload, target))) << "failed to tag VLESS UDP test payload";
    return payload;
}
common::MultiBuffer MakeInput(std::span<const uint8_t> bytes) {
    common::MultiBuffer input;
    EXPECT_TRUE((common::AppendSpanToMultiBuffer(bytes, input))) << "input allocation failed";
    return input;
}

template <typename Fn>
void ExpectLinkError(Fn&& fn, std::string_view message,
                     common::ErrorCode expected = common::ErrorCode::PROTOCOL_DECODE_FAILED) {
    try {
        fn();
        ADD_FAILURE() << message;
    } catch (const transport::LinkError& error) {
        EXPECT_EQ(error.code(), expected) << message;
    }
}

TEST(VlessUdpFraming, FragmentedEmptyAndDataFramesPreserveBoundaries) {
    const std::array<uint8_t, 9> wire{0, 0, 0, 2, 0x11, 0x22, 0, 1, 0x33};
    for (size_t split = 0; split <= wire.size(); ++split) {
        proxy::VlessUdpFramer framer(false);
        proxy::VlessFramedUdpPacket packet;
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
        EXPECT_EQ((decoded), (std::vector<uint8_t>({0x11, 0x22, 0x33}))) << "zero length frame damaged a following frame";
        EXPECT_EQ((sizes), (std::vector<size_t>({0, 2, 1}))) << "VLESS UDP lost an empty datagram boundary";
    }
}

TEST(VlessUdpFraming, MalformedPacketAddressCannotResynchronize) {
    proxy::VlessUdpFramer invalid(true);
    const std::array<uint8_t, 6> malformed{0, 1, 0xff, 0, 1, 0x42};
    invalid.Feed(MakeInput(malformed));
    proxy::VlessFramedUdpPacket packet;
    ExpectLinkError([&] { (void)invalid.Next(packet); }, "invalid address accepted");
    ExpectLinkError([&] { (void)invalid.Next(packet); }, "invalid stream resynchronized");
    proxy::VlessUdpFramer missing_address(true);
    const std::array<uint8_t, 2> no_address{0, 0};
    missing_address.Feed(MakeInput(no_address));
    ExpectLinkError([&] { (void)missing_address.Next(packet); },
                  "packet-address segment without an address became a UDP message");

}

TEST(VlessUdpFraming, PendingInputOverflowPermanentlyRetiresFramer) {
    proxy::VlessFramedUdpPacket packet;
    proxy::VlessUdpFramer bounded(false);
    const std::vector<uint8_t> excess(common::kPacketStreamPendingLimit + 1, 0);
    ExpectLinkError([&] { bounded.Feed(MakeInput(excess)); }, "unbounded retained input");
    ExpectLinkError([&] { (void)bounded.Next(packet); }, "overflow stream recovered");
    ExpectLinkError([&] { bounded.Feed({}); }, "overflow stream accepted more input");
    ExpectLinkError([&] { bounded.Finish(); }, "overflow stream accepted clean EOF");

}

TEST(VlessUdpFraming, MaximumPayloadDecodesFromOneByteFragments) {
    proxy::VlessFramedUdpPacket packet;
    const std::vector<uint8_t> maximum(65535, 0x71);
    std::vector<uint8_t> large{0xff, 0xff};
    large.insert(large.end(), maximum.begin(), maximum.end());
    proxy::VlessUdpFramer fragmented(false);
    for (const auto byte : large) {
        fragmented.Feed(MakeInput(std::span<const uint8_t>(&byte, 1)));
    }
    EXPECT_TRUE((fragmented.Next(packet) && Flatten(packet.payload) == maximum)) << "one-byte fragments failed at maximum wire length";
    fragmented.Finish();
}

TEST(VlessUdpFraming, CancelledReadPreservesPartialFrame) {
    net::io_context io;
    tcp::acceptor listener(io, tcp::endpoint(net::ip::address_v4::loopback(), 0));
    tcp::socket sender(io);
    sender.connect(listener.local_endpoint());
    tcp::socket receiver = listener.accept();
    const std::array<uint8_t, 5> wire{0, 3, 0x11, 0x22, 0x33};
    net::write(sender, net::buffer(wire.data(), 1));
    proxy::VlessUdpFramer framer(false);
    auto future = net::co_spawn(io, [&]() -> net::awaitable<void> {
        std::array<uint8_t, 5> bytes{};
        co_await net::async_read(receiver, net::buffer(bytes.data(), 1), net::use_awaitable);
        framer.Feed(MakeInput(std::span(bytes).first(1)));
        proxy::VlessFramedUdpPacket packet;
        EXPECT_FALSE((framer.Next(packet))) << "partial frame delivered before cancellation";
        net::post(io, [&] { receiver.cancel(); });
        IoErrorCode ec;
        (void)co_await receiver.async_read_some(
            net::buffer(bytes), net::redirect_error(net::use_awaitable, ec));
        EXPECT_EQ((ec), (net::error::operation_aborted)) << "socket read was not cancelled";
        net::write(sender, net::buffer(wire.data() + 1, wire.size() - 1));
        co_await net::async_read(receiver, net::buffer(bytes.data(), 4), net::use_awaitable);
        framer.Feed(MakeInput(std::span(bytes).first(4)));
        EXPECT_TRUE((framer.Next(packet) &&
                  Flatten(packet.payload) == std::vector<uint8_t>({0x11, 0x22, 0x33}))) << "cancelled read lost retained VLESS bytes";
        EXPECT_FALSE((framer.Next(packet))) << "cancelled read duplicated VLESS bytes";
        framer.Finish();
    }, net::use_future);
    io.run();
    future.get();
}

void CheckDecoded(const std::vector<uint8_t>& wire,
                  bool packet_addr,
                  const common::TargetAddress& target,
                  const std::vector<uint8_t>& source) {
    proxy::VlessUdpFramer framer(packet_addr);
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

    proxy::VlessFramedUdpPacket decoded;
    ASSERT_TRUE(framer.Next(decoded));
    ASSERT_EQ(decoded.target.has_value(), packet_addr);
    if (packet_addr) {
        EXPECT_TRUE((decoded.target->SameEndpoint(target))) << "VLESS packet-address target mismatch";
    }
    EXPECT_TRUE((!decoded.payload.empty() && Flatten(decoded.payload) == source)) << "VLESS UDP framer truncated multi-buffer payload";
    EXPECT_FALSE((framer.Next(decoded))) << "one VLESS UDP datagram produced multiple logical packets";
    framer.Finish();
}


class FragmentReader final : public transport::MultiBufferReader {
public:
    FragmentReader(std::span<const uint8_t> bytes)
        : bytes_(bytes) {}
    transport::CancellationSource& Cancellation() noexcept override {
        return cancellation_;
    }
    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        if (offset_ == bytes_.size()) co_return common::MultiBuffer{};
        co_return MakeInput(bytes_.subspan(offset_++, 1));
    }
private:
    transport::CancellationSource cancellation_;
    std::span<const uint8_t> bytes_;
    size_t offset_ = 0;
};

void CheckEmptyDatagramRoundTrip(bool packet_addr) {
    const common::TargetAddress target("127.0.0.1", 53);
    CaptureWriter capture;
    const std::vector<uint8_t> data{0x42};
    ::Run([&]() -> net::awaitable<void> {
        co_await proxy::WriteVlessUdpDatagram(
            capture, MakeDatagram({}, target), packet_addr);
        co_await proxy::WriteVlessUdpDatagram(
            capture, MakeDatagram(data, target), packet_addr);
        co_await proxy::WriteVlessUdpDatagram(
            capture, target, packet_addr, std::span<const net::const_buffer>{});
    });
    EXPECT_EQ((capture.bytes.size()), ((packet_addr ? 28 : 7))) << "VLESS UDP empty datagrams did not write real frame headers";
    FragmentReader source(capture.bytes);
    proxy::VlessUdpFramer framer(packet_addr);
    ::Run([&]() -> net::awaitable<void> {
        for (const size_t size : {size_t{0}, size_t{1}, size_t{0}}) {
            auto packet = co_await framer.ReadDatagram(source, target);
            const auto datagram = common::InspectUdpDatagram(packet);
            EXPECT_TRUE((datagram.Valid() && datagram.payload_size == size &&
                      datagram.target->SameEndpoint(target))) << "VLESS UDP empty/data sequence became EOF or lost its target";
            if (size != 0) EXPECT_EQ((Flatten(packet)), (data)) << "VLESS UDP payload changed";
        }
        EXPECT_TRUE(((co_await framer.ReadDatagram(source, target)).empty())) << "VLESS UDP clean stream EOF became an empty datagram";
    });
}
}  // namespace

TEST(VlessUdpFraming, LargeDatagramAndScatterWritePreserveMessageBoundary) {
    const common::TargetAddress target("1.1.1.1", 53);
    const std::vector<uint8_t> source(common::Buffer::kSize + 257, 0x6d);

    CaptureWriter fixed_capture;
    auto fixed_payload = MakeDatagram(source, target);
    ::Run([&]() -> net::awaitable<void> {
        co_await proxy::WriteVlessUdpDatagram(
            fixed_capture, std::move(fixed_payload), false);
    });
    EXPECT_TRUE((fixed_capture.bytes.size() == source.size() + 2 &&
              fixed_capture.bytes[0] == static_cast<uint8_t>(source.size() >> 8) &&
              fixed_capture.bytes[1] == static_cast<uint8_t>(source.size()) &&
              std::equal(source.begin(), source.end(), fixed_capture.bytes.begin() + 2))) << "large VLESS UDP datagram was split or malformed";
    CheckDecoded(fixed_capture.bytes, false, target, source);

    CaptureWriter packet_addr_capture;
    auto packet_addr_payload = MakeDatagram(source, target);
    ::Run([&]() -> net::awaitable<void> {
        co_await proxy::WriteVlessUdpDatagram(
            packet_addr_capture, std::move(packet_addr_payload), true);
    });
    CheckDecoded(packet_addr_capture.bytes, true, target, source);

    CaptureWriter scatter_capture;
    const std::array<net::const_buffer, 3> scatter{
        net::buffer(source.data(), 1024),
        net::buffer(source.data() + 1024, common::Buffer::kSize - 1024),
        net::buffer(source.data() + common::Buffer::kSize,
                    source.size() - common::Buffer::kSize),
    };
    ::Run([&]() -> net::awaitable<void> {
        co_await proxy::WriteVlessUdpDatagram(
            scatter_capture, target, false, scatter);
    });
    EXPECT_EQ((scatter_capture.bytes), (fixed_capture.bytes)) << "scatter VLESS UDP payload was split into multiple frames";

}

TEST(VlessUdpFraming, OversizedDatagramDoesNotWritePartialFrame) {
    const common::TargetAddress target("1.1.1.1", 53);
    const std::vector<uint8_t> oversized(65536, 0x42);
    const std::array<net::const_buffer, 1> oversized_buffers{net::buffer(oversized)};
    CaptureWriter rejected_capture;
    ExpectLinkError([&] {
        ::Run([&]() -> net::awaitable<void> {
            co_await proxy::WriteVlessUdpDatagram(
                rejected_capture, target, false, oversized_buffers);
        });
    }, "oversized VLESS datagram accepted", common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    EXPECT_TRUE((rejected_capture.bytes.empty())) << "oversized VLESS datagram partially written";

}

TEST(VlessUdpFraming, FixedAddressEmptyDatagramsAreNotEof) {
    CheckEmptyDatagramRoundTrip(false);
}

TEST(VlessUdpFraming, PacketAddressEmptyDatagramsAreNotEof) {
    CheckEmptyDatagramRoundTrip(true);
}

TEST(VlessUdpFraming, TruncatedEofCannotResume) {
    const std::array<uint8_t, 5> wire{0, 3, 0x11, 0x22, 0x33};
    for (size_t cut = 1; cut < wire.size(); ++cut) {
        SCOPED_TRACE(cut);
        proxy::VlessUdpFramer framer(false);
        framer.Feed(MakeInput(std::span(wire).first(cut)));
        proxy::VlessFramedUdpPacket packet;
        ASSERT_FALSE(framer.Next(packet));
        EXPECT_THROW(framer.Finish(), transport::LinkError);
        EXPECT_THROW(framer.Feed(MakeInput(std::span(wire).subspan(cut))), transport::LinkError);
        EXPECT_THROW((void)framer.Next(packet), transport::LinkError);
        EXPECT_THROW(framer.Finish(), transport::LinkError);
    }
}

TEST(VlessUdpFraming, CleanEofRejectsFurtherInput) {
    const std::array<uint8_t, 3> wire{0, 1, 0x73};
    proxy::VlessUdpFramer framer(false);
    framer.Feed(MakeInput(wire));
    proxy::VlessFramedUdpPacket packet;
    ASSERT_TRUE(framer.Next(packet));
    EXPECT_EQ(Flatten(packet.payload), std::vector<uint8_t>({0x73}));
    framer.Finish();
    framer.Finish();
    EXPECT_THROW(framer.Feed({}), transport::LinkError);
    EXPECT_THROW(framer.Feed(MakeInput(wire)), transport::LinkError);
    EXPECT_FALSE(framer.Next(packet));
    EXPECT_TRUE(packet.payload.empty());
}

TEST(VlessUdpFraming, ReadEofDoesNotConsumeAnotherTransport) {
    const std::array<uint8_t, 3> wire{0, 1, 0x73};
    const common::TargetAddress target("127.0.0.1", 53);
    net::io_context io;
    tcp::acceptor listener(io, {net::ip::address_v4::loopback(), 0});
    tcp::socket ended_peer(io);
    ended_peer.connect(listener.local_endpoint());
    transport::TcpStream ended(listener.accept());
    ended_peer.shutdown(tcp::socket::shutdown_send);
    tcp::socket fresh_peer(io);
    fresh_peer.connect(listener.local_endpoint());
    transport::TcpStream fresh(listener.accept());
    net::write(fresh_peer, net::buffer(wire));
    fresh_peer.shutdown(tcp::socket::shutdown_send);
    proxy::VlessUdpFramer framer(false);
    auto result = net::co_spawn(io, [&]() -> net::awaitable<void> {
        EXPECT_TRUE(((co_await framer.ReadDatagram(ended, target)).empty())) << "clean EOF produced a datagram";
        EXPECT_TRUE(((co_await framer.ReadDatagram(fresh, target)).empty())) << "finished VLESS framer consumed another transport";
        std::vector<uint8_t> retained;
        for (;;) {
            auto input = co_await fresh.ReadMultiBuffer();
            if (input.empty()) break;
            const auto bytes = Flatten(input);
            retained.insert(retained.end(), bytes.begin(), bytes.end());
        }
        EXPECT_EQ((retained), (std::vector<uint8_t>(wire.begin(), wire.end()))) << "finished VLESS framer changed another transport's bytes";
    }, net::use_future);
    io.run();
    result.get();
}

TEST(VlessUdpFraming, EmptyDatagramAllocationFailureRetiresFramer) {
    const std::array<uint8_t, 2> empty_wire{0, 0};
    const std::array<uint8_t, 3> next_wire{0, 1, 0x73};
    const common::TargetAddress target("127.0.0.1", 53);
    proxy::VlessUdpFramer framer(false);
    framer.Feed(MakeInput(empty_wire));
    FragmentReader source(std::span<const uint8_t>{});
    ::Run([&]() -> net::awaitable<void> {
        auto operation = framer.ReadDatagram(source, target);
        bool failed = false;
        common::reject_next_process_allocation = true;
        try {
            (void)co_await std::move(operation);
        } catch (const std::bad_alloc&) {
            failed = true;
        } catch (...) {
            common::reject_next_process_allocation = false;
            throw;
        }
        common::reject_next_process_allocation = false;
        EXPECT_TRUE((failed)) << "empty VLESS datagram allocation failure was hidden";
    });
    EXPECT_THROW(framer.Feed(MakeInput(next_wire)), transport::LinkError);
    proxy::VlessFramedUdpPacket packet;
    EXPECT_THROW((void)framer.Next(packet), transport::LinkError);
    EXPECT_THROW(framer.Finish(), transport::LinkError);
}

TEST(VlessUdpFraming, PacketAddressCountsTowardWireLength) {
    const common::TargetAddress target("127.0.0.1", 53);
    constexpr size_t kAddressSize = 1 + sizeof(net::ip::address_v4::bytes_type) + sizeof(uint16_t);
    constexpr size_t kPayloadLimit = std::numeric_limits<uint16_t>::max() - kAddressSize;
    CaptureWriter capture;
    std::vector<uint8_t> payload(kPayloadLimit, 0x42);
    ::Run([&]() -> net::awaitable<void> {
        const std::array<net::const_buffer, 1> buffers{net::buffer(payload)};
        co_await proxy::WriteVlessUdpDatagram(capture, target, true, buffers);
    });
    EXPECT_EQ(capture.bytes.size(), std::numeric_limits<uint16_t>::max() + sizeof(uint16_t));
    payload.push_back(0x43);
    CaptureWriter rejected;
    try {
        ::Run([&]() -> net::awaitable<void> {
            const std::array<net::const_buffer, 1> buffers{net::buffer(payload)};
            co_await proxy::WriteVlessUdpDatagram(rejected, target, true, buffers);
        });
        FAIL() << "packet-address framing exceeded its wire length";
    } catch (const transport::LinkError& error) {
        EXPECT_EQ(error.code(), common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    EXPECT_TRUE(rejected.bytes.empty());
}
