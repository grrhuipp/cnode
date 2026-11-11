#include <gtest/gtest.h>

#include "allocation_hook.hpp"
#include "proxy/anytls_padding.hpp"

#include <array>
#include <new>
#include <string>
#include <string_view>

namespace {
bool measuring = false;
size_t total_requested = 0;
constexpr size_t kAllocationLimit = 1024 * 1024;

void MeasurePaddingAllocation(std::size_t size) {
    if (!measuring) return;
    total_requested += size;
    if (size > kAllocationLimit) throw std::bad_alloc();
}

class AllocationMeasurement {
public:
    AllocationMeasurement() { total_requested = 0; measuring = true; }
    ~AllocationMeasurement() { measuring = false; }
};

using namespace ::anytls;
constexpr std::array invalid{
    "", "stop=0\n0=30-30", "stop=-1\n0=30-30", "stop=4294967296\n0=30-30",
    "stop=\n0=30-30", "stop=+1\n0=30-30", "stop=1x\n0=30-30",
    "0=30-30", "stop=1\n0=-1-30", "stop=1\n0=30-", "stop=1\n0=30-2147483648",
    "stop=2\n0=c,99-99\n1=64-65", "stop=2\n0=65536-65536\n1=64-65",
    "stop=2\n0=65534-65537\n1=64-65", "stop=2\n0=45-45,50-50\n1=64-65",
    "stop=2\n0=0-10\n1=64-65", "stop=2\n0=garbage\n1=64-65",
    "stop=2\n0=\n1=64-65", "stop=2\n0=45-45,\n1=64-65",
    "stop=2\n0=45-45\n0=bad\n1=64-65", "stop=2\n0=bad\n0=45-45\n1=64-65",
    "stop=2\n1=65536-65536", "stop=2\n1=65534-65537", "stop=2\n1=1-2147483647",
    "stop=2\n1=256-256,c,65536-65536", "stop=2\n1=256-256\n1=65536-65536",
    "stop=2\n1=65536-65536\n1=256-256",
    "stop=2\n1=30-30\nstop=invalid", "stop=2\n1=30-30\nstop=0\nstop=2"};
class InvalidPadding : public testing::TestWithParam<const char*> {};
TEST_P(InvalidPadding, RejectsMalformedPolicy) {
    EXPECT_FALSE(ParsePaddingScheme(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(InvalidFields, InvalidPadding, testing::ValuesIn(invalid));

class SparsePadding : public testing::TestWithParam<const char*> {};
TEST_P(SparsePadding, LargeIndicesDoNotDriveUnboundedAllocation) {
    std::optional<PaddingScheme> parsed;
    {
        AllocationMeasurement measurement;
        try { parsed = ParsePaddingScheme(GetParam()); }
        catch (const std::bad_alloc&) {}
    }
    ASSERT_TRUE(parsed);
    EXPECT_LE(total_requested, 64 * 1024);
}
INSTANTIATE_TEST_SUITE_P(IndexBoundaries, SparsePadding, testing::Values(
    "stop=8\n0=30-30\n1=64-65\n7=96-96\n",
    "stop=2\n1=64-65\n2147483647=64-65\n",
    "stop=2147483647\n2147483646=64-65\n0=30-30\n",
    "stop=2\n2147483647=64-65\n1=64-65\n2147483647=96-96\n",
    "stop=2147483647\n1073741823=64-65\n2147483646=96-96\n",
    "stop=4294967295\n4294967294=64-65\n4294967295=96-96\n"));

TEST(AnytlsPadding, IgnoresInvalidRecordIndicesWithoutInventingPadding) {
    for (const auto text : {"stop=1\n", "stop=2\n1=0-10", "stop=2\n-1=30-30",
            "stop=2\n4294967296=30-30", "stop=2\n1x=30-30", "stop=2\n+1=30-30"}) {
        SCOPED_TRACE(text);
        const auto parsed = ParsePaddingScheme(text);
        ASSERT_TRUE(parsed);
        EXPECT_EQ(parsed->Raw(), text);
        EXPECT_EQ(parsed->SampleAuthPaddingSize(), 0);
        EXPECT_TRUE(parsed->RecordFor(0).empty());
        EXPECT_TRUE(parsed->RecordFor(1).empty());
    }
}

TEST(AnytlsPadding, SparseRecordsSeparateAuthAndHonorLastValidDuplicate) {
    const std::string raw = " \tstop=4294967295\r\n\n4294967294=64-65\n7=96-96\n"
        "0=45-45\n7=80-80\n7=invalid\n1= 120-100 , c , 32-32 \r\n4294967295=99-99\n";
    const auto scheme = ParsePaddingScheme(raw);
    ASSERT_TRUE(scheme);
    EXPECT_EQ(scheme->Raw(), raw);
    EXPECT_EQ(scheme->SampleAuthPaddingSize(), 45);
    EXPECT_TRUE(scheme->RecordFor(0).empty());
    EXPECT_TRUE(scheme->RecordFor(2).empty());
    EXPECT_TRUE(scheme->RecordFor(UINT32_MAX).empty());
    ASSERT_EQ(scheme->RecordFor(7).size(), 1);
    EXPECT_EQ(scheme->RecordFor(7)[0].SampleSize(), 80);
    ASSERT_EQ(scheme->RecordFor(UINT32_MAX - 1).size(), 1);
    EXPECT_EQ(scheme->RecordFor(UINT32_MAX - 1)[0].SampleSize(), 64);
    const auto ranges = scheme->RecordFor(1);
    ASSERT_EQ(ranges.size(), 3);
    EXPECT_EQ(ranges[1].SampleSize(), -1);
    EXPECT_EQ(ranges[2].SampleSize(), 32);
    for (size_t index = 0; index < 2048; ++index) {
        const auto size = ranges[0].SampleSize();
        EXPECT_GE(size, 100);
        EXPECT_LT(size, 120);
    }
}

TEST(AnytlsPadding, MissingAuthRecordDoesNotFallBackToFramePadding) {
    for (const auto text : {"stop=1\n0=0-0", "stop=1\n1=99-99", "stop=2\n1=99-99"}) {
        const auto parsed = ParsePaddingScheme(text);
        ASSERT_TRUE(parsed);
        EXPECT_EQ(parsed->SampleAuthPaddingSize(), 0);
    }
}

TEST(AnytlsPadding, AuthRangesNormalizeReversedHalfOpenBounds) {
    for (const auto text : {"stop=2\n0=45-77\n1=99-99", "stop=1\n0= 77-45 \r\n"}) {
        const auto parsed = ParsePaddingScheme(text);
        ASSERT_TRUE(parsed);
        for (size_t index = 0; index < 2048; ++index) {
            const auto size = parsed->SampleAuthPaddingSize();
            EXPECT_GE(size, 45);
            EXPECT_LT(size, 77);
        }
    }
}

TEST(AnytlsPadding, AuthBoundaryAndLastStopAndDuplicateWin) {
    const auto boundary = ParsePaddingScheme("stop=2\n0=65535-65535\nstop=1");
    ASSERT_TRUE(boundary);
    EXPECT_EQ(boundary->SampleAuthPaddingSize(), 65535);
    EXPECT_TRUE(boundary->RecordFor(1).empty());
    const auto upper = ParsePaddingScheme("stop=1\n0=65536-65535");
    ASSERT_TRUE(upper);
    EXPECT_EQ(upper->SampleAuthPaddingSize(), 65535);
    EXPECT_TRUE(upper->RecordFor(0).empty());
    const auto duplicate = ParsePaddingScheme("stop=1\n0=45-45\n0=91-91");
    ASSERT_TRUE(duplicate);
    EXPECT_EQ(duplicate->SampleAuthPaddingSize(), 91);
}

TEST(AnytlsPadding, FrameSizesCoverBufferAndWireBoundaries) {
    for (const int size : {1, 7, 8, 8191, 8192, 8193, 16384, 65535}) {
        SCOPED_TRACE(size);
        const auto parsed = ParsePaddingScheme("stop=2\n1=" + std::to_string(size) + "-" + std::to_string(size));
        ASSERT_TRUE(parsed);
        ASSERT_EQ(parsed->RecordFor(1).size(), 1);
        EXPECT_EQ(parsed->RecordFor(1)[0].SampleSize(), size);
    }
    for (const auto text : {"stop=2\n1=65535-65536", "stop=2\n1=65536-65535"}) {
        const auto parsed = ParsePaddingScheme(text);
        ASSERT_TRUE(parsed);
        ASSERT_EQ(parsed->RecordFor(1).size(), 1);
        EXPECT_EQ(parsed->RecordFor(1)[0].SampleSize(), 65535);
    }
}

TEST(AnytlsPadding, SparseStorageScalesWithPresentRecords) {
    std::string many = "stop=4294967295\n";
    for (uint32_t index = 0; index < 2048; ++index)
        many += std::to_string(UINT32_MAX - 1 - index * 1000000) + "=64-65\n";
    std::optional<PaddingScheme> parsed;
    {
        AllocationMeasurement measurement;
        try { parsed = ParsePaddingScheme(many); }
        catch (const std::bad_alloc&) {}
    }
    ASSERT_TRUE(parsed);
    EXPECT_LT(total_requested, many.size() * 16);
    for (uint32_t index = 0; index < 2048; ++index)
        EXPECT_EQ(parsed->RecordFor(UINT32_MAX - 1 - index * 1000000).size(), 1);
}
}  // namespace

constinit allocation_hook::Hooks allocation_hook::hooks{.before_new = MeasurePaddingAllocation};
