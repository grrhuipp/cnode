#include <gtest/gtest.h>

#include "allocation_hook.hpp"
#include "transport/internet/http2_session.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <new>
#include <string_view>
#include <vector>

namespace {
using namespace ::transport::internet;
bool measuring = false;
size_t largest = 0, allocated = 0, denied = 0, live_large = 0, peak_large = 0;
size_t allocation_limit = kMaxGrpcHunkMessageSize;
struct Allocation { void* pointer = nullptr; size_t size = 0; };
std::array<Allocation, 64> tracked;

struct Measurement {
    explicit Measurement(size_t limit = kMaxGrpcHunkMessageSize) {
        largest = allocated = denied = live_large = peak_large = 0;
        tracked = {};
        allocation_limit = limit;
        measuring = true;
    }
    ~Measurement() { measuring = false; }
};

void Forget(void* pointer) noexcept {
    for (auto& item : tracked) if (item.pointer == pointer && pointer) {
        live_large -= item.size;
        item = {};
        break;
    }
}

void Measure(std::size_t size) {
    if (!measuring) return;
    largest = std::max(largest, size);
    allocated += size;
    if (size > allocation_limit) { ++denied; throw std::bad_alloc(); }
}

void TrackLarge(void* pointer, std::size_t size) noexcept {
    if (!measuring || size <= 4096) return;
    for (auto& item : tracked) if (!item.pointer) {
        item = {pointer, size}; live_large += size;
        peak_large = std::max(peak_large, live_large);
        return;
    }
    std::abort();
}
}  // namespace

constinit allocation_hook::Hooks allocation_hook::hooks{
    .before_new = Measure, .after_new = TrackLarge, .before_delete = Forget};

namespace {
using Bytes = std::vector<uint8_t>;

std::array<uint8_t, 5> Prefix(uint32_t size) {
    return {0, uint8_t(size >> 24), uint8_t(size >> 16), uint8_t(size >> 8), uint8_t(size)};
}
void Varint(Bytes& bytes, uint32_t value) {
    do { bytes.push_back(uint8_t(value & 127) | (value >= 128 ? 128 : 0)); value >>= 7; } while (value);
}
Bytes Frame(const Bytes& message) {
    const auto prefix = Prefix(static_cast<uint32_t>(message.size()));
    Bytes bytes(prefix.begin(), prefix.end());
    bytes.insert(bytes.end(), message.begin(), message.end());
    return bytes;
}
struct HunkCase {
    const char* name;
    Bytes wire;
    std::string_view expected;
    bool valid;
};

class GrpcHunkWire : public testing::TestWithParam<HunkCase> {};
TEST_P(GrpcHunkWire, DecodesOnlyCompleteValidatedMessagesAcrossFragmentBoundaries) {
    const auto& scenario = GetParam();
    const auto& bytes = scenario.wire;
    for (size_t fragment : {size_t{1}, size_t{2}, size_t{5}, size_t{13}, size_t{8192}}) {
        SCOPED_TRACE(fragment);
        GrpcHunkDecoder decoder;
        Bytes decoded;
        bool accepted = true;
        size_t offset = 0;
        while (offset < bytes.size()) {
            const auto result = decoder.Feed(std::span<const uint8_t>(bytes).subspan(
                offset, std::min(fragment, bytes.size() - offset)));
            if (!result) { accepted = false; break; }
            ASSERT_GT(*result, 0u);
            offset += *result;
            const auto payload = decoder.Payload();
            decoded.insert(decoded.end(), payload.begin(), payload.end());
            if (!payload.empty()) decoder.Consume(payload.size());
        }
        accepted &= decoder.AtMessageBoundary();
        EXPECT_EQ(accepted, scenario.valid);
        if (scenario.valid)
            EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(decoded.data()), decoded.size()),
                      scenario.expected);
        else
            EXPECT_TRUE(decoded.empty()) << "invalid message exposed data before full validation";
    }
}

std::vector<HunkCase> WireCases() {
    std::vector<HunkCase> cases{
        {"Payload", Frame({0x0a, 3, 'a', 'b', 'c'}), "abc", true},
        {"EmptyMessage", Frame({}), "", true},
        {"EmptyPayload", Frame({0x0a, 0}), "", true},
        {"LastPayloadWins", Frame({0x0a, 3, 'o', 'l', 'd', 0x0a, 3, 'n', 'e', 'w'}), "new", true},
        {"EmptyLastPayloadWins", Frame({0x0a, 3, 'o', 'l', 'd', 0x0a, 0}), "", true},
        {"UnknownFields", Frame({0x10, 0x96, 1, 0x1a, 1, 'x', 0x0a, 1, 'a', 0x25, 0, 0, 0, 0}), "a", true},
        {"UnknownNestedGroups", Frame({0x13, 0x1b, 0x20, 1, 0x1c, 0x14, 0x0a, 1, 'g'}), "g", true},
        {"UnknownWireTypeForKnownField", Frame({0x08, 0, 0x0a, 1, 'a'}), "a", true},
        {"ZeroFieldNumber", Frame({0}), "", false},
        {"InvalidTrailingField", Frame({0x0a, 1, 'a', 0}), "", false},
        {"TruncatedUnknownField", Frame({0x0a, 1, 'a', 0x1a, 4, 0}), "", false},
        {"TruncatedPayload", Frame({0x0a, 2, 'a'}), "", false},
        {"TruncatedLength", Frame({0x0a, 0x80}), "", false},
        {"MismatchedGroup", Frame({0x13, 0x1c}), "", false},
        {"UnexpectedEndGroup", Frame({0x14}), "", false},
        {"InvalidWireTypeSix", Frame({0x16}), "", false},
        {"InvalidWireTypeSeven", Frame({0x17}), "", false},
        {"TruncatedFixed64", Frame({0x19, 0, 0}), "", false},
        {"OverflowingFieldKey", Frame({0x80, 0x80, 0x80, 0x80, 0x10, 0}), "", false},
    };
    Bytes varint{0x10};
    varint.insert(varint.end(), 9, 0xff);
    varint.push_back(1);
    cases.push_back({"MaximumVarint", Frame(varint), "", true});
    varint.back() = 2;
    cases.push_back({"OverflowingVarint", Frame(varint), "", false});
    Bytes groups(100, 0x13);
    groups.insert(groups.end(), 100, 0x14);
    cases.push_back({"MaximumGroupDepth", Frame(groups), "", true});
    groups.insert(groups.begin(), 0x13);
    groups.push_back(0x14);
    cases.push_back({"ExcessiveGroupDepth", Frame(groups), "", false});
    auto compressed = Frame({});
    compressed[0] = 1;
    cases.push_back({"UnsupportedCompression", std::move(compressed), "", false});
    Bytes combined = Frame({});
    for (const auto& body : {Bytes{0x0a, 1, 'a'}, Bytes{0x0a, 0}, Bytes{0x0a, 1, 'b'}}) {
        const auto next = Frame(body);
        combined.insert(combined.end(), next.begin(), next.end());
    }
    cases.push_back({"ConsecutiveMessages", std::move(combined), "ab", true});
    return cases;
}
INSTANTIATE_TEST_SUITE_P(WireCases, GrpcHunkWire, testing::ValuesIn(WireCases()),
    [](const testing::TestParamInfo<HunkCase>& info) { return info.param.name; });

class GrpcHunkPrefix : public testing::TestWithParam<uint32_t> {};
TEST_P(GrpcHunkPrefix, ValidatesDeclaredLengthWithoutAllocatingBody) {
    GrpcHunkDecoder decoder;
    bool accepted;
    {
        Measurement measurement(1024 * 1024);
        accepted = static_cast<bool>(decoder.Feed(Prefix(GetParam())));
    }
    EXPECT_EQ(accepted, GetParam() <= kMaxGrpcHunkMessageSize);
    EXPECT_EQ(largest, 0u);
    EXPECT_EQ(allocated, 0u);
    EXPECT_EQ(denied, 0u);
}
INSTANTIATE_TEST_SUITE_P(DeclaredLengths, GrpcHunkPrefix,
    testing::Values(1024u, 4194304u, 4194305u, UINT32_MAX));

TEST(GrpcHunk, PartialBodyDoesNotAllocateDeclaredMessageLength) {
    GrpcHunkDecoder decoder;
    ASSERT_TRUE(decoder.Feed(Prefix(static_cast<uint32_t>(kMaxGrpcHunkMessageSize))));
    bool accepted;
    {
        Measurement measurement;
        const std::array<uint8_t, 2> bytes{0x0a, 0xff};
        accepted = static_cast<bool>(decoder.Feed(bytes));
    }
    EXPECT_TRUE(accepted);
    EXPECT_TRUE(decoder.Payload().empty());
    EXPECT_FALSE(decoder.AtMessageBoundary());
    EXPECT_LE(largest, 4096u);
    EXPECT_EQ(denied, 0u);
}

class TruncatedGrpcHunk : public testing::TestWithParam<size_t> {};
TEST_P(TruncatedGrpcHunk, DoesNotExposePartialPayload) {
    const auto complete = Frame({0x0a, 3, 'a', 'b', 'c'});
    GrpcHunkDecoder decoder;
    const auto result = decoder.Feed(std::span<const uint8_t>(complete).first(GetParam()));
    EXPECT_TRUE(result);
    EXPECT_TRUE(decoder.Payload().empty());
    EXPECT_FALSE(decoder.AtMessageBoundary());
}
INSTANTIATE_TEST_SUITE_P(EveryCut, TruncatedGrpcHunk,
    testing::Range(size_t{1}, size_t{10}));

TEST(GrpcHunk, MaximumMessageHonorsStorageBudgetAndReleasesConsumedStorage) {
    Bytes large{0x0a};
    Varint(large, static_cast<uint32_t>(kMaxGrpcHunkMessageSize - 5));
    large.resize(kMaxGrpcHunkMessageSize, 0x5a);
    GrpcHunkDecoder decoder;
    ASSERT_TRUE(decoder.Feed(Prefix(static_cast<uint32_t>(large.size()))));
    bool accepted = true;
    bool exposed_early = false;
    {
        Measurement measurement;
        for (size_t offset = 0; offset < large.size();) {
            const auto result = decoder.Feed(std::span<const uint8_t>(large).subspan(
                offset, std::min(size_t{16384}, large.size() - offset)));
            if (!result || *result == 0) { accepted = false; break; }
            offset += *result;
            if (offset != large.size()) exposed_early |= !decoder.Payload().empty();
        }
    }
    ASSERT_TRUE(accepted);
    EXPECT_FALSE(exposed_early);
    const auto payload = decoder.Payload();
    EXPECT_EQ(payload.size(), kMaxGrpcHunkMessageSize - 5);
    EXPECT_TRUE(std::all_of(payload.begin(), payload.end(),
                          [](uint8_t value) { return value == 0x5a; }));
    EXPECT_EQ(denied, 0u);
    EXPECT_LE(largest, kMaxGrpcHunkMessageSize);
    EXPECT_LE(live_large, kMaxGrpcHunkMessageSize);
    EXPECT_LE(peak_large, 2 * kMaxGrpcHunkMessageSize);
    decoder.Consume(payload.size());
    EXPECT_EQ(live_large, 0u);
}
} // namespace
