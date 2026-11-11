#include <stdexcept>
#include <gtest/gtest.h>

#include "proxy/uot/uot.hpp"

#include "proxy/shadowsocks/shadowsocks_protocol.hpp"
#include "common/address_codec.hpp"

#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory_resource>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {



std::vector<uint8_t> Flatten(const buf::MultiBuffer& mb) {
    std::vector<uint8_t> out;
    out.reserve(mb.byte_size());
    for (const buf::Buffer* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        const auto bytes = buffer->Bytes();
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

buf::MultiBuffer MakePacket(std::string_view payload, const TargetAddress& target) {
    buf::MultiBuffer packet;
    if (!buf::AppendSpanToMultiBuffer(
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(payload.data()), payload.size()), packet) ||
        !buf::SetUdpTarget(packet, target)) {
        throw std::runtime_error("packet fixture allocation failed");
    }
    return packet;
}

class CaptureWriter final : public transport::MultiBufferWriter {
public:
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        for (const buf::Buffer* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto span = buffer->Bytes();
            bytes.insert(bytes.end(), span.begin(), span.end());
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

class FragmentReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }

    FragmentReader(std::vector<uint8_t> bytes,
                   std::vector<size_t> fragments)
        : bytes_(std::move(bytes)), fragments_(std::move(fragments)) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (offset_ >= bytes_.size()) {
            co_return buf::MultiBuffer{};
        }
        const size_t requested = fragment_index_ < fragments_.size()
            ? fragments_[fragment_index_++]
            : bytes_.size() - offset_;
        const size_t size = std::min(requested, bytes_.size() - offset_);
        buf::MultiBuffer out;
        if (!buf::AppendSpanToMultiBuffer(
                std::span<const uint8_t>(bytes_.data() + offset_, size), out)) {
            throw std::runtime_error("reader fixture allocation failed");
        }
        offset_ += size;
        co_return out;
    }

private:
    transport::CancellationSource cancellation_;

    std::vector<uint8_t> bytes_;
    std::vector<size_t> fragments_;
    size_t offset_ = 0;
    size_t fragment_index_ = 0;
};

class FramedEndpointDouble final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    explicit FramedEndpointDouble(std::vector<uint8_t> input = {},
                                  std::vector<size_t> fragments = {})
        : reader_(std::move(input), std::move(fragments)) {}

    transport::CancellationSource& Cancellation() noexcept override {
        return reader_.Cancellation();
    }

    void Cancel() noexcept { ++cancel_calls; }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        ++read_calls;
        co_return co_await reader_.ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer) override {
        co_return;
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        ++write_calls;
        std::vector<uint8_t> before;
        for (const auto& buffer : buffers) {
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            before.insert(before.end(), data, data + buffer.size());
        }
        if (suspend_write) {
            auto executor = co_await net::this_coro::executor;
            net::steady_timer timer(executor);
            timer.expires_after(std::chrono::milliseconds(1));
            co_await timer.async_wait(net::use_awaitable);
            resumed = true;
            std::vector<uint8_t> after;
            for (const auto& buffer : buffers) {
                const auto* data = static_cast<const uint8_t*>(buffer.data());
                after.insert(after.end(), data, data + buffer.size());
            }
            EXPECT_EQ(after, before);
        }
        if (throw_on_write) {
            throw std::runtime_error("synthetic write failure");
        }
        bytes.insert(bytes.end(), before.begin(), before.end());
    }

    FragmentReader reader_;
    std::vector<uint8_t> bytes;
    size_t read_calls = 0;
    size_t write_calls = 0;
    size_t cancel_calls = 0;
    bool suspend_write = false;
    bool resumed = false;
    bool throw_on_write = false;
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

TEST(UotSs2022, V2BoardSs2022Keys) {
    const auto cipher = ss::ParseCipherMethod("2022-blake3-aes-256-gcm");
    ASSERT_TRUE(cipher.has_value());

    constexpr std::string_view uuid = "01234567-89ab-cdef-0123-456789abcdef";
    constexpr std::string_view prefix = "01234567-89ab-cdef-0123-456789ab";
    constexpr std::string_view user_psk =
        "MDEyMzQ1NjctODlhYi1jZGVmLTAxMjMtNDU2Nzg5YWI=";
    constexpr std::string_view server_psk =
        "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";

    const auto uuid_key = ss::Build2022UserKeyFromUuid(uuid, *cipher);
    ASSERT_EQ(uuid_key.size, 32u);
    EXPECT_EQ(std::memcmp(uuid_key.data(), prefix.data(), prefix.size()), 0);

    const auto decoded_user = ss::Decode2022Psk(user_psk, cipher->key_size);
    ASSERT_EQ(decoded_user.size, uuid_key.size);
    EXPECT_EQ(std::memcmp(decoded_user.data(), uuid_key.data(), uuid_key.size), 0);

    const auto decoded_server = ss::Decode2022Psk(server_psk, cipher->key_size);
    EXPECT_EQ(decoded_server.size, 32u);
    EXPECT_TRUE(ss::Decode2022Psk(
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYw", cipher->key_size).empty());
}

TEST(UotSs2022, MagicAddressesRequireExactMatches) {
    EXPECT_TRUE(proxy::uot::VersionFromMagicAddress(
        TargetAddress(proxy::uot::kMagicAddress, 0)) == proxy::uot::Version::V2);
    EXPECT_TRUE(proxy::uot::VersionFromMagicAddress(
        TargetAddress(proxy::uot::kV1MagicAddress, 0)) ==
            proxy::uot::Version::V1);
    EXPECT_TRUE(!proxy::uot::VersionFromMagicAddress(
        TargetAddress("prefix.sp.v2.udp-over-tcp.arpa", 0)));
 }

TEST(UotSs2022, RequestEncodesDestinationAndPort) {
    const TargetAddress target("dns.example", 53);
    const auto request = proxy::uot::EncodeRequest(false, target);
    ASSERT_TRUE(request.has_value());
    const auto bytes = request->span();
    ASSERT_EQ(bytes.size(), 16u);
    EXPECT_EQ(bytes[0], 0);
    EXPECT_EQ(bytes[1], 3);
    EXPECT_EQ(bytes[2], 11);
    EXPECT_EQ(bytes[bytes.size() - 2], 0);
    EXPECT_EQ(bytes.back(), 53);
}

TEST(UotSs2022, ConnectPacketRoundTrip) {
    const TargetAddress target("1.1.1.1", 53);
    CaptureWriter capture;
    proxy::uot::PacketWriter writer(capture, true, target);
    ::Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket("alpha", target));
        co_await writer.WriteMultiBuffer(MakePacket("beta-payload", target));
    });

    FragmentReader source(capture.bytes, {1, 1, 2, 3, 1, 4, 2});
    proxy::uot::PacketReader reader(source, true, target);
    ::Run([&]() -> net::awaitable<void> {
        auto first = co_await reader.ReadMultiBuffer();
        auto second = co_await reader.ReadMultiBuffer();
        EXPECT_TRUE(Flatten(first) == std::vector<uint8_t>({'a','l','p','h','a'}));
        EXPECT_TRUE(Flatten(second) == std::vector<uint8_t>(
            {'b','e','t','a','-','p','a','y','l','o','a','d'}));
        const auto datagram = buf::InspectUdpDatagram(first);
        EXPECT_TRUE(datagram.Valid());
        EXPECT_NE(datagram.target, nullptr);
        if (!datagram.Valid() || !datagram.target) co_return;
        EXPECT_TRUE(datagram.target->SameEndpoint(target));
    });
}

TEST(UotSs2022, LargeConnectPacketRoundTrip) {
    const TargetAddress target("1.1.1.1", 53);
    const std::string large_payload(buf::Buffer::kSize + 257, '\x6d');

    CaptureWriter capture;
    proxy::uot::PacketWriter writer(capture, true, target);
    ::Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket(large_payload, target));
    });

    ASSERT_EQ(capture.bytes.size(), large_payload.size() + 2);
    const size_t wire_length =
        (static_cast<size_t>(capture.bytes[0]) << 8) | capture.bytes[1];
    EXPECT_TRUE(wire_length == large_payload.size());

    FragmentReader source(capture.bytes, {1, 2, 4096, 17, 2048, 3, 1024});
    proxy::uot::PacketReader reader(source, true, target);
    ::Run([&]() -> net::awaitable<void> {
        auto decoded = co_await reader.ReadMultiBuffer();
        EXPECT_TRUE(Flatten(decoded) == std::vector<uint8_t>(
            large_payload.begin(), large_payload.end()));
    });
}

class UotPacketMode : public testing::TestWithParam<bool> {};

TEST_P(UotPacketMode, EmptyDatagramsPreserveSequenceAndTargets) {
    const TargetAddress first("1.1.1.1", 53);
    const TargetAddress second("8.8.8.8", 5353);
    const bool connect = GetParam();
        CaptureWriter capture;
        proxy::uot::PacketWriter writer(capture, connect, first);
        const auto& last = connect ? first : second;
        ::Run([&]() -> net::awaitable<void> {
            co_await writer.WriteMultiBuffer({});
            EXPECT_TRUE(capture.bytes.empty());
            co_await writer.WriteMultiBuffer(MakePacket("", first));
            co_await writer.WriteMultiBuffer(MakePacket("data", first));
            if (connect) {
                co_await writer.WriteBuffers(std::span<const net::const_buffer>{});
            } else {
                co_await writer.WriteMultiBuffer(MakePacket("", last));
            }
        });
        EXPECT_EQ(capture.bytes.size(), connect ? 10u : 31u);
        FragmentReader source(capture.bytes, {1, 1, 1, 1, 1, 1, 1, 1});
        proxy::uot::PacketReader reader(source, connect, first);
        ::Run([&]() -> net::awaitable<void> {
            const std::array<size_t, 3> sizes{0, 4, 0};
            for (size_t index = 0; index < sizes.size(); ++index) {
                const size_t size = sizes[index];
                auto packet = co_await reader.ReadMultiBuffer();
                const auto datagram = buf::InspectUdpDatagram(packet);
                EXPECT_TRUE(datagram.Valid());
                EXPECT_NE(datagram.target, nullptr);
                if (!datagram.Valid() || !datagram.target) co_return;
                EXPECT_EQ(datagram.payload_size, size);
                EXPECT_TRUE(datagram.target->SameEndpoint(index == 2 ? last : first));
                if (size != 0) EXPECT_TRUE(Flatten(packet) == std::vector<uint8_t>({'d','a','t','a'}));
            }
            EXPECT_TRUE((co_await reader.ReadMultiBuffer()).empty());
        });
}

TEST(UotSs2022, V1FirstEmptyDatagramSurvivesPreparation) {
    const TargetAddress target("dns.example", 53);
    CaptureWriter capture;
    proxy::uot::PacketWriter writer(capture, false, target);
    ::Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket("", target));
        co_await writer.WriteMultiBuffer(MakePacket("next", target));
    });
    FragmentReader source(capture.bytes, {1, 2, 3, 1});
    ::Run([&]() -> net::awaitable<void> {
        auto prepared = co_await proxy::uot::ReadUotRequestHeader(
            proxy::uot::Version::V1, source, {});
        EXPECT_TRUE(prepared.has_value());
        if (!prepared) co_return;
        EXPECT_TRUE(prepared->destination.SameEndpoint(target));
        auto empty = std::move(prepared->initial_decoded);
        proxy::uot::PacketReader reader(source, std::move(*prepared));
        const auto datagram = buf::InspectUdpDatagram(empty);
        EXPECT_TRUE(datagram.Valid());
        EXPECT_NE(datagram.target, nullptr);
        if (!datagram.Valid() || !datagram.target) co_return;
        EXPECT_EQ(datagram.payload_size, 0u);
        EXPECT_TRUE(datagram.target->SameEndpoint(target));
        EXPECT_TRUE(Flatten(co_await reader.ReadMultiBuffer()) ==
                  std::vector<uint8_t>({'n','e','x','t'}));
        EXPECT_TRUE((co_await reader.ReadMultiBuffer()).empty());
    });
}

TEST(UotSs2022, FramedOwnedWritePreservesPayloadAcrossSuspension) {
    const TargetAddress target("1.1.1.1", 53);
    FramedEndpointDouble underlying;
    underlying.suspend_write = true;
    proxy::uot::FramedEndpoint endpoint(underlying, true, target);
    auto pending = endpoint.WriteMultiBuffer(MakePacket("framed", target));
    EXPECT_EQ(underlying.write_calls, 0u);
    ::Run([&]() -> net::awaitable<void> { co_await std::move(pending); });
    EXPECT_TRUE(underlying.resumed);
    EXPECT_EQ(underlying.bytes, std::vector<uint8_t>({0, 6, 'f', 'r', 'a', 'm', 'e', 'd'}));
}

TEST(UotSs2022, FramedBorrowedWritePreservesPayloadAcrossSuspension) {
    const TargetAddress target("1.1.1.1", 53);
    FramedEndpointDouble underlying;
    underlying.suspend_write = true;
    proxy::uot::FramedEndpoint endpoint(underlying, true, target);
    const std::array<uint8_t, 4> payload{'n', 'e', 'x', 't'};
    const std::array<net::const_buffer, 1> buffers{net::buffer(payload)};
    auto pending = endpoint.WriteBuffers(buffers);
    EXPECT_EQ(underlying.write_calls, 0u);
    ::Run([&]() -> net::awaitable<void> { co_await std::move(pending); });
    EXPECT_TRUE(underlying.resumed);
    EXPECT_EQ(underlying.bytes, std::vector<uint8_t>({0, 4, 'n', 'e', 'x', 't'}));
}

TEST(UotSs2022, FramedEndpointForwardsCancellation) {
    FramedEndpointDouble underlying;
    proxy::uot::FramedEndpoint endpoint(underlying, true, TargetAddress("1.1.1.1", 53));
    endpoint.Cancel();
    EXPECT_EQ(underlying.cancel_calls, 1u);
}

TEST(UotSs2022, FramedReadReassemblesFragmentedFrames) {
    const TargetAddress target("1.1.1.1", 53);
    FramedEndpointDouble underlying(
        {0, 6, 'f', 'r', 'a', 'm', 'e', 'd', 0, 4, 'n', 'e', 'x', 't'}, {1, 1, 2, 1, 3});
    proxy::uot::FramedEndpoint endpoint(underlying, true, target);
    auto pending = endpoint.ReadMultiBuffer();
    EXPECT_EQ(underlying.read_calls, 0u);
    ::Run([&]() -> net::awaitable<void> {
        auto first = co_await std::move(pending);
        EXPECT_EQ(Flatten(first), std::vector<uint8_t>({'f','r','a','m','e','d'}));
        auto next = co_await endpoint.ReadMultiBuffer();
        EXPECT_EQ(Flatten(next), std::vector<uint8_t>({'n','e','x','t'}));
        EXPECT_TRUE((co_await endpoint.ReadMultiBuffer()).empty());
    });
}

TEST(UotSs2022, FramedEndpointWriteException) {
    const TargetAddress target("1.1.1.1", 53);
    FramedEndpointDouble underlying;
    underlying.throw_on_write = true;
    proxy::uot::FramedEndpoint endpoint(underlying, true, target);
    EXPECT_THROW(::Run([&]() -> net::awaitable<void> {
        co_await endpoint.WriteMultiBuffer(MakePacket("failure", target));
    }), std::runtime_error);
}

TEST(UotSs2022, NonConnectRequestAndPackets) {
    const TargetAddress initial("dns.example", 53);
    const TargetAddress second("8.8.8.8", 5353);

    const auto request = proxy::uot::EncodeRequest(false, initial);
    ASSERT_TRUE(request.has_value());

    CaptureWriter capture;
    capture.bytes.insert(
        capture.bytes.end(), request->span().begin(), request->span().end());
    proxy::uot::PacketWriter writer(capture, false, initial);
    ::Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket("one", initial));
        co_await writer.WriteMultiBuffer(MakePacket("two-two", second));
    });

    FragmentReader source(capture.bytes, {1, 2, 1, 3, 2, 5, 1, 4});
    ::Run([&]() -> net::awaitable<void> {
        auto decoded_request = co_await proxy::uot::ReadUotRequestHeader(
            proxy::uot::Version::V2, source, {});
        EXPECT_TRUE(decoded_request.has_value());
        if (!decoded_request) co_return;
        EXPECT_FALSE(decoded_request->is_connect);
        EXPECT_TRUE(decoded_request->destination.SameEndpoint(initial));

        proxy::uot::PacketReader reader(source, std::move(*decoded_request));
        auto first = co_await reader.ReadMultiBuffer();
        auto next = co_await reader.ReadMultiBuffer();
        EXPECT_TRUE(Flatten(first) == std::vector<uint8_t>({'o','n','e'}));
        EXPECT_TRUE(Flatten(next) == std::vector<uint8_t>({'t','w','o','-','t','w','o'}));
        const auto first_datagram = buf::InspectUdpDatagram(first);
        const auto next_datagram = buf::InspectUdpDatagram(next);
        EXPECT_TRUE(first_datagram.Valid());
        EXPECT_TRUE(next_datagram.Valid());
        EXPECT_NE(first_datagram.target, nullptr);
        EXPECT_NE(next_datagram.target, nullptr);
        if (!first_datagram.target || !next_datagram.target) co_return;
        EXPECT_TRUE(first_datagram.target->SameEndpoint(initial));
        EXPECT_TRUE(next_datagram.target->SameEndpoint(second));
    });
}

// Exercise the public wire codec independently of each protocol's handshake.
class UotAddressCodec : public testing::TestWithParam<AddressWireFormat> {
protected:
    const std::array<TargetAddress, 3> targets{
        TargetAddress("192.0.2.1", 0x1234),
        TargetAddress("2001:db8::1", 0x1234),
        TargetAddress("example.com", 0x1234)};
    const std::array<ForwardedMetadataView, 3> metadata_cases{
        ForwardedMetadataView{.user_id = 424242, .user_email = "alice@example.com",
            .client_ip = net::ip::make_address("203.0.113.99")},
        ForwardedMetadataView{.user_id = 0, .user_email = "only-email@example.com",
            .client_ip = std::nullopt},
        ForwardedMetadataView{.user_id = 7, .user_email = {},
            .client_ip = net::ip::make_address("2001:db8::abcd")}};
};

TEST_P(UotAddressCodec, WireTypesAndByteOrderRemainInteroperable) {
    const auto format = GetParam();
    for (const auto& target : targets) {
        SCOPED_TRACE(target.host);
        std::array<uint8_t, kMaxEncodedAddressSize> encoded{};
        const size_t size = EncodeAddressTo(target, encoded.data(), encoded.size(), format);
        ASSERT_EQ(size, AddressEncodedSize(target));
        ASSERT_GT(size, 0u);
            const size_t type_pos = format == AddressWireFormat::PortFirst ? 2 : 0;
            const uint8_t expected_type = target.IsDomain()
                ? (format == AddressWireFormat::Socks5 ? 3 : 2)
                : target.IsIPv4() ? (format == AddressWireFormat::Uot ? 0 : 1)
                : format == AddressWireFormat::Socks5 ? 4
                : format == AddressWireFormat::PortFirst ? 3 : 1;
            EXPECT_EQ(encoded[type_pos], expected_type);
            const size_t port_pos = format == AddressWireFormat::PortFirst ? 0 : size - 2;
            EXPECT_EQ(encoded[port_pos], 0x12);
            EXPECT_EQ(encoded[port_pos + 1], 0x34);
            const auto* body = encoded.data() + type_pos + 1;
            if (target.IsIPv4()) {
                const std::array<uint8_t, 4> expected{192, 0, 2, 1};
                EXPECT_TRUE(std::equal(expected.begin(), expected.end(), body));
            } else if (target.IsIPv6()) {
                const std::array<uint8_t, 16> expected{
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
                EXPECT_TRUE(std::equal(expected.begin(), expected.end(), body));
            } else {
                EXPECT_TRUE(body[0] == 11 && std::memcmp(body + 1, "example.com", 11) == 0);
            }
            EXPECT_EQ(EncodeAddressTo(target, encoded.data(), size - 1, format), 0u);
    }
}

TEST_P(UotAddressCodec, SplitDecodeReportsConsumedAndRequired) {
    const auto format = GetParam();
    for (const auto& target : targets) {
        SCOPED_TRACE(target.host);
        std::array<uint8_t, kMaxEncodedAddressSize> encoded{};
        const size_t size = EncodeAddressTo(target, encoded.data(), encoded.size(), format);
        ASSERT_EQ(size, AddressEncodedSize(target));
        ASSERT_GT(size, 0u);
        for (size_t split = 0; split <= size; ++split) {
            SCOPED_TRACE(split);
            const auto parsed = DecodeAddress(std::span<const uint8_t>(encoded.data(), split), format);
            EXPECT_EQ(parsed.status, split == size ? AddressDecodeStatus::Complete : AddressDecodeStatus::Incomplete);
            if (split == size) {
                EXPECT_EQ(parsed.consumed, size);
                EXPECT_TRUE(parsed.target.SameEndpoint(target));
            } else {
                EXPECT_EQ(parsed.consumed, 0u);
                EXPECT_GT(parsed.required, split);
            }
        }
    }
}

TEST_P(UotAddressCodec, IncrementalReadPreservesCallerPrefixAndFollowingByte) {
    const auto format = GetParam();
    for (const auto& target : targets) {
        SCOPED_TRACE(target.host);
        std::array<uint8_t, kMaxEncodedAddressSize> encoded{};
        const size_t size = EncodeAddressTo(target, encoded.data(), encoded.size(), format);
        ASSERT_EQ(size, AddressEncodedSize(target));
        ASSERT_GT(size, 0u);
        for (size_t split = 0; split <= size; ++split) {
            SCOPED_TRACE(split);
                std::vector<uint8_t> input{0xaa};
                input.insert(input.end(), encoded.begin(), encoded.begin() + size);
                input.push_back(0xbb);
                FragmentReader source(input, {1, split ? split : 1, 1});
                buf::MultiBuffer pending;
                ::Run([&]() -> net::awaitable<void> {
                    auto decoded = co_await ReadAddress(source, pending, format, 1);
                    EXPECT_TRUE(decoded.has_value());
                    if (!decoded) co_return;
                    EXPECT_EQ(decoded->consumed, size);
                    EXPECT_TRUE(decoded->target.SameEndpoint(target));
                    EXPECT_GE(pending.byte_size(), size + 1);
                    if (pending.byte_size() < size + 1) co_return;
                    pending.DropPrefixBytes(size + 1);
                    if (pending.byte_size() == 0) {
                        auto remaining = co_await source.ReadMultiBuffer();
                        remaining.MoveTo(pending, true);
                    }
                    EXPECT_EQ(Flatten(pending), std::vector<uint8_t>{0xbb});
                });
        }
    }
}

TEST_P(UotAddressCodec, TruncatedInputFailsAtEof) {
    const auto format = GetParam();
    for (const auto& target : targets) {
        SCOPED_TRACE(target.host);
        std::array<uint8_t, kMaxEncodedAddressSize> encoded{};
        const size_t size = EncodeAddressTo(target, encoded.data(), encoded.size(), format);
        ASSERT_EQ(size, AddressEncodedSize(target));
        ASSERT_GT(size, 0u);
        for (size_t split = 0; split < size; ++split) {
            SCOPED_TRACE(split);
                FragmentReader truncated(std::vector<uint8_t>(encoded.begin(), encoded.begin() + split), {1, 2});
                buf::MultiBuffer incomplete;
                ::Run([&]() -> net::awaitable<void> {
                    auto decoded = co_await ReadAddress(truncated, incomplete, format);
                    EXPECT_FALSE(decoded.has_value());
                    if (!decoded) EXPECT_EQ(decoded.error(), ErrorCode::PROTOCOL_DECODE_FAILED);
                });
        }
    }
}

TEST_P(UotAddressCodec, UnknownWireTypeIsInvalid) {
    const auto format = GetParam();
    for (const auto& target : targets) {
        SCOPED_TRACE(target.host);
        std::array<uint8_t, kMaxEncodedAddressSize> encoded{};
        const size_t size = EncodeAddressTo(target, encoded.data(), encoded.size(), format);
        ASSERT_EQ(size, AddressEncodedSize(target));
        ASSERT_GT(size, 0u);
        const size_t type_pos = format == AddressWireFormat::PortFirst ? 2 : 0;
        encoded[type_pos] = 0xff;
        EXPECT_EQ(DecodeAddress(std::span<const uint8_t>(encoded.data(), size), format).status,
                  AddressDecodeStatus::Invalid);
    }
}

TEST_P(UotAddressCodec, EmptyAndMaximumDomainLengthBoundaries) {
    const auto format = GetParam();
        std::array<uint8_t, kMaxBaseEncodedAddressSize> domain{};
        const size_t type_pos = format == AddressWireFormat::PortFirst ? 2 : 0;
        domain[type_pos] = format == AddressWireFormat::Socks5 ? 3 : 2;
        domain[type_pos + 1] = 0;
        EXPECT_TRUE(DecodeAddress(domain, format, {.require_non_empty_domain = true}).status ==
                  AddressDecodeStatus::Invalid);
        domain[type_pos + 1] = 255;
        EXPECT_TRUE(DecodeAddress(std::span<const uint8_t>(domain.data(), domain.size() - 1),
                            format).status == AddressDecodeStatus::Incomplete &&
              DecodeAddress(domain, format).consumed == domain.size());
}

TEST_P(UotAddressCodec, MetadataRoundTripsAcrossInputSplits) {
    const auto format = GetParam();
    for (const auto& target : targets) {
        for (const auto& meta : metadata_cases) {
            SCOPED_TRACE(target.host);
            SCOPED_TRACE(meta.user_id);
            std::array<uint8_t, kMaxEncodedAddressSize> encoded{};
            const size_t size = EncodeAddressTo(target, encoded.data(), encoded.size(), format, meta);
            ASSERT_EQ(size, AddressEncodedSize(target, meta));
            ASSERT_GT(size, AddressEncodedSize(target));
            for (size_t split = 0; split <= size; ++split) {
                SCOPED_TRACE(split);
                const auto parsed = DecodeAddress(std::span<const uint8_t>(encoded.data(), split), format);
                EXPECT_EQ(parsed.status, split == size ? AddressDecodeStatus::Complete : AddressDecodeStatus::Incomplete);
                if (split != size) continue;
                EXPECT_EQ(parsed.consumed, size);
                EXPECT_TRUE(parsed.target.SameEndpoint(target));
                ASSERT_TRUE(parsed.forwarded.has_value());
                EXPECT_EQ(parsed.forwarded->user_id, meta.user_id);
                EXPECT_EQ(parsed.forwarded->user_email, meta.user_email);
                EXPECT_EQ(parsed.forwarded->client_ip, meta.client_ip);
            }
        }
    }
}

TEST_P(UotAddressCodec, DisallowedMetadataLeavesNoDecodedTarget) {
    const auto format = GetParam();
    for (const auto& target : targets) {
        for (const auto& meta : metadata_cases) {
            SCOPED_TRACE(target.host);
            SCOPED_TRACE(meta.user_id);
            std::array<uint8_t, kMaxEncodedAddressSize> encoded{};
            const size_t size = EncodeAddressTo(target, encoded.data(), encoded.size(), format, meta);
            ASSERT_EQ(size, AddressEncodedSize(target, meta));
            ASSERT_GT(size, AddressEncodedSize(target));
                const auto disallowed = DecodeAddress(
                    std::span<const uint8_t>(encoded.data(), size),
                    format, {.allow_metadata = false});
                EXPECT_EQ(disallowed.status, AddressDecodeStatus::Invalid);
                EXPECT_FALSE(disallowed.target.IsValid());
                EXPECT_FALSE(disallowed.forwarded.has_value());
        }
    }
}

TEST_P(UotAddressCodec, MalformedMetadataLeavesNoDecodedTarget) {
    const auto format = GetParam();
    for (const auto& target : targets) {
        for (const auto& meta : metadata_cases) {
            SCOPED_TRACE(target.host);
            SCOPED_TRACE(meta.user_id);
            std::array<uint8_t, kMaxEncodedAddressSize> encoded{};
            const size_t size = EncodeAddressTo(target, encoded.data(), encoded.size(), format, meta);
            ASSERT_EQ(size, AddressEncodedSize(target, meta));
            ASSERT_GT(size, AddressEncodedSize(target));
                auto malformed = encoded;
                malformed[size - 1] = 0;
                if ((meta.user_email.empty() && meta.inbound_tag.empty())) {
                    malformed[AddressEncodedSize(target) + 1] = 0xFF;
                } else {
                    malformed[AddressEncodedSize(target) + 1] |= 0x80;
                }
                const auto rejected_meta = DecodeAddress(
                    std::span<const uint8_t>(malformed.data(), size), format);
                EXPECT_EQ(rejected_meta.status, AddressDecodeStatus::Invalid);
                EXPECT_FALSE(rejected_meta.target.IsValid());
                EXPECT_FALSE(rejected_meta.forwarded.has_value());
        }
    }
}

INSTANTIATE_TEST_SUITE_P(WireFormats, UotAddressCodec,
    testing::Values(AddressWireFormat::Socks5, AddressWireFormat::PortFirst, AddressWireFormat::Uot),
    [](const testing::TestParamInfo<AddressWireFormat>& info) {
        switch (info.param) {
        case AddressWireFormat::Socks5: return "Socks5";
        case AddressWireFormat::PortFirst: return "PortFirst";
        case AddressWireFormat::Uot: return "Uot";
        }
        return "Unknown";
    });

TEST_P(UotPacketMode, CompletePacketIsFollowedByEof) {
    const bool connect = GetParam();
    const TargetAddress target("192.0.2.1", 53);
    CaptureWriter capture;
    proxy::uot::PacketWriter writer(capture, connect, target);
    ::Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket("end", target));
    });
    FragmentReader source(capture.bytes, {1, 1, 2});
    proxy::uot::PacketReader reader(source, connect, target);
    ::Run([&]() -> net::awaitable<void> {
        EXPECT_EQ(Flatten(co_await reader.ReadMultiBuffer()), std::vector<uint8_t>({'e','n','d'}));
        EXPECT_TRUE((co_await reader.ReadMultiBuffer()).empty());
    });
}

TEST_P(UotPacketMode, EmptyTransportIsEofNotAnEmptyDatagram) {
    FragmentReader source({}, {});
    proxy::uot::PacketReader reader(source, GetParam(), TargetAddress("192.0.2.1", 53));
    ::Run([&]() -> net::awaitable<void> {
        EXPECT_TRUE((co_await reader.ReadMultiBuffer()).empty());
    });
}

TEST_P(UotPacketMode, TruncatedFrameFailsWithProtocolDecodeError) {
    const bool connect = GetParam();
    const TargetAddress target("192.0.2.1", 53);
    CaptureWriter capture;
    proxy::uot::PacketWriter writer(capture, connect, target);
    ::Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket("end", target));
    });
    for (size_t length = 1; length < capture.bytes.size(); ++length) {
        SCOPED_TRACE(length);
        FragmentReader source(std::vector<uint8_t>(capture.bytes.begin(), capture.bytes.begin() + length),
                              {1, 1, 2});
        proxy::uot::PacketReader reader(source, connect, target);
        EXPECT_THROW({
            try {
                ::Run([&]() -> net::awaitable<void> { (void)co_await reader.ReadMultiBuffer(); });
            } catch (const transport::LinkError& error) {
                EXPECT_EQ(error.code(), ErrorCode::PROTOCOL_DECODE_FAILED);
                throw;
            }
        }, transport::LinkError);
    }
}

INSTANTIATE_TEST_SUITE_P(Modes, UotPacketMode, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "Connect" : "NonConnect";
    });

TEST(UotSs2022, NonConnectIpPacketDecodesFromPendingWithUnusedDomainRequestAndReleasesPayload) {
    const std::string domain = std::string(63, 'a') + "." +
        std::string(63, 'b') + "." + std::string(61, 'c');
    const std::array<uint8_t, 12> wire{0, 192, 0, 2, 7, 0x14, 0xe9, 0, 3, 'u', 'd', 'p'};
    for (const bool prepared_constructor : {false, true}) {
        SCOPED_TRACE(prepared_constructor);
#ifdef CNODE_TEST_BUFFER_STATS
        const auto live_before = memory::detail::test_buffers_live;
#endif
        {
            buf::MultiBuffer pending;
            ASSERT_TRUE(buf::AppendSpanToMultiBuffer(wire, pending));
            FragmentReader source({}, {});
            std::optional<proxy::uot::PacketReader> reader;
            TargetAddress unused(domain, 53);
            if (prepared_constructor) {
                proxy::uot::PreparedRequest prepared;
                prepared.destination = std::move(unused);
                prepared.pending = std::move(pending);
                reader.emplace(source, std::move(prepared));
            } else {
                reader.emplace(source, false, std::move(unused), std::move(pending));
            }
            ASSERT_NO_THROW(::Run([&]() -> net::awaitable<void> {
                auto packet = co_await reader->ReadMultiBuffer();
                const auto datagram = buf::InspectUdpDatagram(packet);
                EXPECT_TRUE(datagram.Valid());
                EXPECT_NE(datagram.target, nullptr);
                if (!datagram.Valid() || !datagram.target) co_return;
                EXPECT_TRUE(datagram.target->SameEndpoint(TargetAddress("192.0.2.7", 5353)));
                EXPECT_EQ(Flatten(packet), std::vector<uint8_t>({'u', 'd', 'p'}));
            }));
        }
#ifdef CNODE_TEST_BUFFER_STATS
        EXPECT_EQ(memory::detail::test_buffers_live, live_before);
#endif
    }
}

}  // namespace

