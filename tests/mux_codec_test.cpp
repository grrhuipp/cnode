#include <gtest/gtest.h>
#include "common/mux_codec.hpp"
#include "common/multi_buffer.hpp"
#include "common/length_prefixed_packet_buffer.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <new>
#include <optional>
#include <vector>

namespace {
std::optional<::common::FrameHeader> Decode(std::span<const uint8_t> frame, size_t split) {
    ::common::MultiBuffer input, suffix;
    split = std::min(split, frame.size());
    if (!input.AppendSpan(frame.first(split)) ||
        !suffix.AppendSpan(frame.subspan(split))) {
        throw std::bad_alloc();
    }
    suffix.MoveTo(input);
    return ::common::DecodeFrame(input);
}

class TruncatedXudp : public testing::TestWithParam<std::vector<uint8_t>> {};
TEST_P(TruncatedXudp, EofRejectsPartialLengthOrPayload) {
    common::MultiBuffer input, packet;
    ASSERT_TRUE(input.AppendSpan(GetParam()));
    common::LengthPrefixedPacketBuffer decoder;
    ASSERT_TRUE(decoder.Append(std::move(input)));
    EXPECT_EQ(decoder.Pop(packet), common::LengthPrefixedPacketBuffer::PopResult::NeedMore);
    EXPECT_FALSE(decoder.Finish());
}
INSTANTIATE_TEST_SUITE_P(Boundaries, TruncatedXudp,
    testing::Values(std::vector<uint8_t>{0}, std::vector<uint8_t>{0, 2, 0x41}));

struct PayloadCase { size_t size; bool udp; };
class MuxPayload : public testing::TestWithParam<PayloadCase> {};
TEST_P(MuxPayload, PreservesPayloadLengthAcrossBufferLayouts) {
    const auto item = GetParam();
    std::array<uint8_t, common::kMaxFrameHeaderBytes> header{};
    const size_t count = item.udp
        ? common::EncodeNewHeaderTo(header, 9, common::NetworkType::UDP,
              common::TargetAddress("example.com", 53), item.size, true)
        : common::EncodeKeepDataHeaderTo(header, 7, item.size);
    ASSERT_NE(count, 0u);
    std::vector<uint8_t> wire(header.begin(), header.begin() + count);
    wire.insert(wire.end(), item.size, 0x5a);
    for (size_t split : {size_t(0), size_t(3), count, wire.size()}) {
        SCOPED_TRACE(split);
        const auto decoded = Decode(wire, split);
        ASSERT_TRUE(decoded);
        EXPECT_EQ(decoded->frame_size, wire.size());
        EXPECT_TRUE(decoded->has_data);
        EXPECT_EQ(decoded->data_len, item.size);
    }
}
INSTANTIATE_TEST_SUITE_P(Boundaries, MuxPayload, testing::Values(
    PayloadCase{0, false}, PayloadCase{std::numeric_limits<uint16_t>::max(), false},
    PayloadCase{common::Buffer::kSize + 257, true}));

class MuxUdpNew : public testing::TestWithParam<bool> {};
TEST_P(MuxUdpNew, DistinguishesControlFromEmptyDataAtEveryHeaderSplit) {
    std::array<uint8_t, common::kMaxFrameHeaderBytes> header{};
    const size_t count = common::EncodeNewHeaderTo(header, 7, common::NetworkType::UDP,
        common::TargetAddress("example.com", 53), 0, GetParam());
    ASSERT_NE(count, 0u);
    const auto wire = std::span(header).first(count);
    for (size_t split = 0; split <= count; ++split) {
        SCOPED_TRACE(split);
        const auto decoded = Decode(wire, split);
        ASSERT_TRUE(decoded);
        EXPECT_EQ(decoded->has_data, GetParam());
        EXPECT_EQ(decoded->data_len, 0u);
        EXPECT_EQ(decoded->frame_size, count);
    }
}
INSTANTIATE_TEST_SUITE_P(DataPresence, MuxUdpNew, testing::Bool());

class OversizedMuxPayload : public testing::TestWithParam<int> {};
TEST_P(OversizedMuxPayload, RejectsLengthRatherThanTruncating) {
    std::array<uint8_t, common::kMaxFrameHeaderBytes> header{};
    const size_t size = size_t(std::numeric_limits<uint16_t>::max()) + 1;
    const common::TargetAddress target("example.com", 53);
    switch (GetParam()) {
    case 0: EXPECT_EQ(common::EncodeKeepDataHeaderTo(header, 7, size), 0u); break;
    case 1: EXPECT_EQ(common::EncodeNewHeaderTo(header, 7, common::NetworkType::UDP, target, size, true), 0u); break;
    case 2: EXPECT_EQ(common::EncodeKeepUDPHeaderTo(header, 7, target, size), 0u); break;
    }
}
INSTANTIATE_TEST_SUITE_P(FrameKinds, OversizedMuxPayload, testing::Values(0, 1, 2));

class InvalidMuxTarget : public testing::TestWithParam<int> {};
TEST_P(InvalidMuxTarget, RejectsInvalidTargetOrNetworkBeforeEncoding) {
    std::array<uint8_t, common::kMaxFrameHeaderBytes> header{};
    common::TargetAddress target("example.com", GetParam() < 2 ? 0 : 53);
    auto network = common::NetworkType::TCP;
    if (GetParam() == 2) {
        target.type = common::AddressType::Domain;
        target.host.assign(256, 'a');
    }
    if (GetParam() == 3) network = static_cast<common::NetworkType>(0xff);
    if (GetParam() == 1) {
        EXPECT_EQ(common::EncodeKeepUDPHeaderTo(header, 7, target, 0), 0u);
    } else {
        EXPECT_EQ(common::EncodeNewHeaderTo(header, 7, network, target, 0, false), 0u);
    }
}
INSTANTIATE_TEST_SUITE_P(Faults, InvalidMuxTarget, testing::Values(0, 1, 2, 3));

class InvalidMuxFrame : public testing::TestWithParam<std::vector<uint8_t>> {};
TEST_P(InvalidMuxFrame, RejectsMalformedMetadataInContiguousAndFragmentedInput) {
    for (size_t split : {GetParam().size(), size_t(3)}) {
        const auto decoded = Decode(GetParam(), split);
        ASSERT_TRUE(decoded);
        EXPECT_EQ(decoded->frame_size, 0u);
    }
}
INSTANTIATE_TEST_SUITE_P(Faults, InvalidMuxFrame, testing::Values(
    std::vector<uint8_t>{0, 4, 0, 7, static_cast<uint8_t>(common::SessionStatus::NEW), 0},
    std::vector<uint8_t>{0, 0x13, 0, 7, static_cast<uint8_t>(common::SessionStatus::NEW), 0,
        static_cast<uint8_t>(common::NetworkType::TCP), 0, 0, 2, 11,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'},
    std::vector<uint8_t>{0, 11, 0, 7, static_cast<uint8_t>(common::SessionStatus::NEW), 0,
        static_cast<uint8_t>(common::NetworkType::TCP), 0, 80, 2, 3, 'a', ' ', 'b'},
    std::vector<uint8_t>{0, 5, 0, 0, static_cast<uint8_t>(common::SessionStatus::KEEPALIVE), 0, 0xaa},
    std::vector<uint8_t>{2, 0, 0}));

class MuxGlobalId : public testing::TestWithParam<size_t> {};
TEST_P(MuxGlobalId, AcceptsExactlyEightBytesOfGlobalIdMetadata) {
    std::array<uint8_t, common::kMaxFrameHeaderBytes> header{};
    const auto count = common::EncodeNewHeaderTo(header, 7, common::NetworkType::UDP,
        common::TargetAddress("example.com", 53), 0, false);
    ASSERT_GE(count, 2u);
    std::vector<uint8_t> wire(header.begin(), header.begin() + count);
    const auto meta = (size_t(wire[0]) << 8 | wire[1]) + GetParam();
    wire.insert(wire.end(), GetParam(), 0x42);
    wire[0] = static_cast<uint8_t>(meta >> 8);
    wire[1] = static_cast<uint8_t>(meta);
    for (size_t split : {wire.size(), size_t(5)}) {
        const auto decoded = Decode(wire, split);
        ASSERT_TRUE(decoded);
        EXPECT_EQ(decoded->frame_size, GetParam() == 8 ? wire.size() : 0u);
    }
}
INSTANTIATE_TEST_SUITE_P(Lengths, MuxGlobalId, testing::Values(size_t(8), size_t(9)));
}  // namespace

TEST(XudpCodec, RecoversDatagramLargerThanSingleBuffer) {
    const std::vector<uint8_t> packet(common::Buffer::kSize + 257, 0x39);
    std::vector<uint8_t> wire{static_cast<uint8_t>(packet.size() >> 8), static_cast<uint8_t>(packet.size())};
    wire.insert(wire.end(), packet.begin(), packet.end());
    common::MultiBuffer input, output;
    ASSERT_TRUE(input.AppendSpan(wire));
    common::LengthPrefixedPacketBuffer decoder;
    ASSERT_TRUE(decoder.Append(std::move(input)));
    EXPECT_EQ(decoder.Pop(output), common::LengthPrefixedPacketBuffer::PopResult::Packet);
    std::vector<uint8_t> recovered(packet.size());
    EXPECT_EQ(output.CopyPrefixTo(recovered), packet.size());
    EXPECT_EQ(recovered, packet);
    EXPECT_EQ(decoder.PendingBytes(), 0u);
    EXPECT_TRUE(decoder.Finish());
}

TEST(XudpCodec, EmptyPacketConsumesItsHeaderWithoutCorruptingSuccessor) {
    const std::array<uint8_t, 5> wire{0, 0, 0, 1, 0x4f};
    common::MultiBuffer input, output;
    ASSERT_TRUE(input.AppendSpan(wire));
    common::LengthPrefixedPacketBuffer decoder;
    ASSERT_TRUE(decoder.Append(std::move(input)));
    EXPECT_EQ(decoder.Pop(output), common::LengthPrefixedPacketBuffer::PopResult::Packet);
    EXPECT_TRUE(output.empty());
    EXPECT_EQ(decoder.PendingBytes(), 3u);
    EXPECT_EQ(decoder.Pop(output), common::LengthPrefixedPacketBuffer::PopResult::Packet);
    EXPECT_EQ(output.byte_size(), 1u);
    EXPECT_TRUE(decoder.Finish());
}

TEST(MuxCodec, RejectsPayloadLengthWithoutDataOption) {
    std::array<uint8_t, common::kMaxFrameHeaderBytes> header{};
    EXPECT_EQ(common::EncodeNewHeaderTo(header, 7, common::NetworkType::UDP,
        common::TargetAddress("example.com", 53), 1, false), 0u);
}

TEST(MuxCodec, RejectsUnknownOptionBitsAcrossLayouts) {
    std::array<uint8_t, common::kMaxFrameHeaderBytes> header{};
    const auto count = common::EncodeKeepDataHeaderTo(header, 7, 0);
    ASSERT_GT(count, 5u);
    header[5] |= 0x80;
    for (size_t split : {count, size_t(3)}) {
        const auto decoded = Decode(std::span(header).first(count), split);
        ASSERT_TRUE(decoded);
        EXPECT_EQ(decoded->frame_size, 0u);
    }
}
