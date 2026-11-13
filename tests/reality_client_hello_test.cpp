#include <gtest/gtest.h>

#include "transport/reality_tls.hpp"
#include <algorithm>
#include <array>
#include <tuple>
#include <vector>

namespace {
using Reader = ::transport::RealityClientHelloReader;
std::vector<uint8_t> Records(const std::vector<uint8_t>& hello, size_t fragment) {
    std::vector<uint8_t> wire;
    for (size_t offset = 0; offset < hello.size();) {
        const auto count = std::min(fragment, hello.size() - offset);
        wire.insert(wire.end(), {22, 3, 1, static_cast<uint8_t>(count >> 8), static_cast<uint8_t>(count)});
        wire.insert(wire.end(), hello.begin() + offset, hello.begin() + offset + count);
        offset += count;
    }
    return wire;
}
void Feed(Reader& reader, std::span<const uint8_t> wire, size_t fragment) {
    while (!wire.empty() && reader.State() == Reader::Status::Reading) {
        const size_t count = std::min({wire.size(), fragment, reader.ReadSize()});
        reader.Append(wire.first(count));
        wire = wire.subspan(count);
    }
}
}
namespace {
std::vector<uint8_t> Hello() {
    std::vector<uint8_t> hello(20000, 0x55);
    hello[0] = 1;
    hello[1] = 0;
    hello[2] = static_cast<uint8_t>((hello.size() - 4) >> 8);
    hello[3] = static_cast<uint8_t>(hello.size() - 4);
    return hello;
}

class RealityHelloFragments : public testing::TestWithParam<std::tuple<size_t, size_t>> {};
TEST_P(RealityHelloFragments, ReassemblesTranscriptAndPreservesReplayWireBytes) {
    const auto [record, tcp] = GetParam();
    const auto hello = Hello();
    const auto wire = Records(hello, record);
    Reader reader;
    Feed(reader, wire, tcp);
    ASSERT_EQ(reader.State(), Reader::Status::Complete);
    EXPECT_TRUE(std::ranges::equal(reader.Hello(), hello));
    EXPECT_TRUE(std::ranges::equal(reader.TakeWire(), wire));
}
INSTANTIATE_TEST_SUITE_P(RecordAndTcpSplits, RealityHelloFragments, testing::Combine(
    testing::Values(size_t{1}, size_t{2}, size_t{3}, size_t{17}, size_t{16384}),
    testing::Values(size_t{1}, size_t{4}, size_t{4096})));

TEST(RealityClientHello, RejectsOversizedHandshakeBeforeReadingBody) {
    const std::array<uint8_t, 9> wire{22, 3, 3, 0, 4, 1, 0xff, 0xff, 0xff};
    Reader reader;
    Feed(reader, wire, 1);
    EXPECT_EQ(reader.State(), Reader::Status::Invalid);
    EXPECT_EQ(reader.Hello().size(), 4);
}

TEST(RealityClientHello, IncompleteRecordRemainsPending) {
    const auto wire = Records(Hello(), 13);
    Reader reader;
    Feed(reader, std::span(wire).first(wire.size() - 1), 1);
    EXPECT_EQ(reader.State(), Reader::Status::Reading);
}

class RealityInvalidRecord : public testing::TestWithParam<std::array<uint8_t, 5>> {};
TEST_P(RealityInvalidRecord, RejectsHeaderWithoutReadingPayload) {
    Reader reader;
    Feed(reader, GetParam(), 1);
    EXPECT_EQ(reader.State(), Reader::Status::Invalid);
    EXPECT_TRUE(reader.Hello().empty());
}
INSTANTIATE_TEST_SUITE_P(Headers, RealityInvalidRecord, testing::Values(
    std::array<uint8_t, 5>{22, 3, 3, 0, 0}, std::array<uint8_t, 5>{22, 3, 3, 0x40, 1},
    std::array<uint8_t, 5>{23, 3, 3, 0, 1}));

TEST(RealityClientHello, RejectsNonTlsProbeAfterFirstByte) {
    Reader reader;
    const std::array<uint8_t, 1> wire{'G'};
    reader.Append(wire);
    EXPECT_EQ(reader.State(), Reader::Status::Invalid);
}
}  // namespace
