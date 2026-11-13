#include <gtest/gtest.h>

#include "common/const_buffer_span.hpp"
#include "common/initial_payload.hpp"

#include <array>
#include <cstring>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

using ContiguousView = ::common::ContiguousBufferView;
template<class T>
concept BorrowableContiguousBytes = requires(T&& view) {
    std::forward<T>(view).Bytes();
};
static_assert(std::is_constructible_v<ContiguousView, ::common::MultiBuffer&>);
static_assert(std::is_constructible_v<ContiguousView, const ::common::MultiBuffer&>);
static_assert(!std::is_constructible_v<ContiguousView, ::common::MultiBuffer&&>);
static_assert(!std::is_constructible_v<ContiguousView, const ::common::MultiBuffer&&>);
static_assert(std::is_constructible_v<ContiguousView, std::span<const ::net::const_buffer>>);
static_assert(BorrowableContiguousBytes<ContiguousView&>);
static_assert(BorrowableContiguousBytes<const ContiguousView&>);
static_assert(!BorrowableContiguousBytes<ContiguousView&&>);
static_assert(!BorrowableContiguousBytes<const ContiguousView&&>);

template<class T>
concept BorrowableUdpInfo = requires(T&& packet) {
    ::common::InspectUdpDatagram(std::forward<T>(packet));
};
static_assert(BorrowableUdpInfo<::common::MultiBuffer&>);
static_assert(BorrowableUdpInfo<const ::common::MultiBuffer&>);
static_assert(!BorrowableUdpInfo<::common::MultiBuffer&&>);
static_assert(!BorrowableUdpInfo<const ::common::MultiBuffer&&>);

template<class T>
concept BorrowablePrefix = requires(T&& payload) {
    std::forward<T>(payload).PrefixSpan(1);
};
template<class T>
concept BorrowableFront = requires(T&& payload) {
    std::forward<T>(payload).FrontSpan();
};
template<class T>
concept BorrowableDescriptors = requires(T&& builder) {
    std::forward<T>(builder).Span();
};
template<class T>
concept AppendablePacket = requires(::common::ConstBufferSpanBuilder<2>& builder, T&& payload) {
    builder.AppendMultiBuffer(std::forward<T>(payload));
};
template<class T>
concept ExtractableInitialPayload = requires(T&& payload) {
    std::forward<T>(payload).MoveToMultiBuffer();
};
static_assert(BorrowablePrefix<::common::MultiBuffer&>);
static_assert(BorrowablePrefix<const ::common::MultiBuffer&>);
static_assert(!BorrowablePrefix<::common::MultiBuffer&&>);
static_assert(!BorrowablePrefix<const ::common::MultiBuffer&&>);
static_assert(BorrowableFront<::common::MultiBuffer&>);
static_assert(BorrowableFront<const ::common::MultiBuffer&>);
static_assert(!BorrowableFront<::common::MultiBuffer&&>);
static_assert(!BorrowableFront<const ::common::MultiBuffer&&>);
static_assert(BorrowableDescriptors<::common::ConstBufferSpanBuilder<2>&>);
static_assert(BorrowableDescriptors<const ::common::ConstBufferSpanBuilder<2>&>);
static_assert(!BorrowableDescriptors<::common::ConstBufferSpanBuilder<2>&&>);
static_assert(!BorrowableDescriptors<const ::common::ConstBufferSpanBuilder<2>&&>);
static_assert(AppendablePacket<::common::MultiBuffer&>);
static_assert(AppendablePacket<const ::common::MultiBuffer&>);
static_assert(!AppendablePacket<::common::MultiBuffer&&>);
static_assert(!AppendablePacket<const ::common::MultiBuffer&&>);
static_assert(ExtractableInitialPayload<::common::InitialPayload&&>);
static_assert(!ExtractableInitialPayload<::common::InitialPayload&>);
static_assert(!ExtractableInitialPayload<const ::common::InitialPayload&>);
static_assert(!ExtractableInitialPayload<const ::common::InitialPayload&&>);

std::string Flatten(std::span<const ::net::const_buffer> buffers) {
    std::string result;
    for (const auto& buffer : buffers)
        result.append(static_cast<const char*>(buffer.data()), buffer.size());
    return result;
}

TEST(BufferSpanBuilder, SelfAppendSurvivesInlineAndSpilledGrowth) {
    const std::string text = "abc";
    ::common::ConstBufferSpanBuilder<2> builder;
    builder.Append(::net::buffer(text.data(), 1));
    builder.Append(::net::buffer(text.data() + 1, 1));
    builder.AppendBuffers(builder.Span());
    ASSERT_EQ(Flatten(builder.Span()), "abab");

    builder.Append(::net::buffer(text.data() + 2, 1));
    builder.AppendBuffers(builder.Span().subspan(1));
    EXPECT_EQ(Flatten(builder.Span()), "ababcbabc");

    builder.Clear();
    builder.Append(::net::buffer(text));
    builder.AppendBuffers(builder.Span());
    EXPECT_EQ(Flatten(builder.Span()), "abcabc");
}

TEST(BufferSpanBuilder, AppendingExternalBuffersPreservesOrderAndSkipsEmptyViews) {
    const std::string text = "abc";
    const std::array<::net::const_buffer, 5> buffers{
        ::net::buffer(text.data(), 1), {},
        ::net::buffer(text.data() + 1, 1), {},
        ::net::buffer(text.data() + 2, 1)};
    ::common::ConstBufferSpanBuilder<1> builder;
    builder.AppendBuffers(buffers);
    builder.AppendBuffers(buffers);
    EXPECT_EQ(Flatten(builder.Span()), "abcabc");
    for (const auto& buffer : builder.Span()) EXPECT_EQ(buffer.size(), 1u);
}

TEST(BufferSpanBuilder, FailedSpillPreservesBorrowedDescriptorsAndCanRetry) {
    const std::string text = "abc";
    for (const bool already_spilled : {false, true}) {
        SCOPED_TRACE(already_spilled);
        ::common::ConstBufferSpanBuilder<2> builder;
        builder.Append(::net::buffer(text.data(), 1));
        builder.Append(::net::buffer(text.data() + 1, 1));
        if (already_spilled) builder.AppendBuffers(builder.Span());
        const auto borrowed = builder.Span();
        const auto expected = Flatten(borrowed);
        ::common::reject_next_process_allocation = true;
        EXPECT_THROW(builder.AppendBuffers(borrowed), std::bad_alloc);
        ::common::reject_next_process_allocation = false;
        EXPECT_EQ(builder.Span().data(), borrowed.data());
        EXPECT_EQ(Flatten(builder.Span()), expected);
        builder.AppendBuffers(borrowed);
        EXPECT_EQ(Flatten(builder.Span()), expected + expected);
        builder.Clear();
        builder.Append(::net::buffer(text));
        EXPECT_EQ(Flatten(builder.Span()), text);
    }
}

TEST(BufferSpanBuilder, SelfAppendWithinCapacityKeepsBorrowedStorage) {
    const std::string text = "abc";
    ::common::ConstBufferSpanBuilder<4> builder;
    builder.Append(::net::buffer(text.data(), 1));
    builder.Append(::net::buffer(text.data() + 1, 1));
    auto* storage = builder.Span().data();
    ::common::reject_next_process_allocation = true;
    builder.AppendBuffers(builder.Span());
    EXPECT_EQ(builder.Span().data(), storage);
    EXPECT_EQ(Flatten(builder.Span()), "abab");
    EXPECT_THROW(builder.Append(::net::buffer(text.data() + 2, 1)), std::bad_alloc);
    ::common::reject_next_process_allocation = false;
    EXPECT_EQ(Flatten(builder.Span()), "abab");
    builder.Append(::net::buffer(text.data() + 2, 1));
    storage = builder.Span().data();
    ::common::reject_next_process_allocation = true;
    builder.AppendBuffers(builder.Span().subspan(3, 2));
    builder.AppendBuffers(builder.Span().last(1));
    EXPECT_EQ(builder.Span().data(), storage);
    EXPECT_EQ(Flatten(builder.Span()), "ababcbcc");
    EXPECT_THROW(builder.AppendBuffers(builder.Span().last(1)), std::bad_alloc);
    ::common::reject_next_process_allocation = false;
    EXPECT_EQ(builder.Span().data(), storage);
    EXPECT_EQ(Flatten(builder.Span()), "ababcbcc");
    builder.AppendBuffers(builder.Span().last(1));
    EXPECT_EQ(Flatten(builder.Span()), "ababcbccc");
}

TEST(BufferSpanBuilder, MultiBufferPreservesSliceAcrossInlineAndSpilledAppends) {
    ::common::MultiBuffer payload;
    ::common::BufferGuard block{::common::Buffer::New()};
    ASSERT_TRUE(block);
    std::memcpy(block->Tail().data(), "abc", 3);
    block->Produce(3);
    block->Advance(1);
    const void* slice = block->Bytes().data();
    payload.push_back(std::move(block));

    ::common::ConstBufferSpanBuilder<4> builder;
    const std::string prefix = "P";
    builder.Append(::net::buffer(prefix));
    std::string expected = prefix;
    for (size_t appended = 1; appended <= 5; ++appended) {
        builder.AppendMultiBuffer(payload);
        expected += "bc";
        EXPECT_EQ(Flatten(builder.Span()), expected);
        ASSERT_EQ(builder.size(), appended + 1);
        for (size_t index = 1; index <= appended; ++index) {
            EXPECT_EQ(builder.Span()[index].data(), slice);
            EXPECT_EQ(builder.Span()[index].size(), 2u);
        }
    }
    builder.Clear();
    payload.clear();
}

TEST(BufferSpanBuilder, ContiguousMultiBufferAlwaysBorrowsZeroCopy) {
    const auto live_before = ::common::test_buffers_live;
    std::array<uint8_t, 6> expected{0, 0x42, 0, 0x7f, 0x80, 0xff};
    ::common::MultiBuffer source;
    ASSERT_TRUE(source.AppendSpan(expected));
    {
        const ContiguousView view(std::as_const(source));
        EXPECT_EQ(view.Bytes().data(), source.FrontSpan().data());
        (*source.begin())->Bytes()[1] = expected[1] = 0x99;
        ASSERT_EQ(view.Bytes().size(), expected.size());
        EXPECT_TRUE(std::equal(view.Bytes().begin(), view.Bytes().end(), expected.begin()));
    }
    source.clear();
    EXPECT_EQ(::common::test_buffers_live, live_before);
}

class ContiguousDescriptors : public ::testing::TestWithParam<bool> {};

TEST_P(ContiguousDescriptors, TemporaryDescriptorsDoNotExtendPayloadLifetime) {
    const bool fragmented = GetParam();
    std::array<uint8_t, 3> first{1, 0, 2}, second{3, 0xff, 4};
    std::vector<uint8_t> expected(first.begin(), first.end());
    if (fragmented) expected.insert(expected.end(), second.begin(), second.end());
    {
        std::array<::net::const_buffer, 3> descriptors{
            ::net::buffer(first), {},
            fragmented ? ::net::buffer(second) : ::net::const_buffer{}};
        const ContiguousView view{std::span<const ::net::const_buffer>(descriptors)};
        descriptors.fill({});
        if (fragmented) {
            first.fill(0xaa);
            second.fill(0xbb);
        } else {
            EXPECT_EQ(view.Bytes().data(), first.data());
            first[1] = expected[1] = 0x80;
        }
        ASSERT_EQ(view.Bytes().size(), expected.size());
        EXPECT_TRUE(std::equal(view.Bytes().begin(), view.Bytes().end(), expected.begin()));
    }
}

INSTANTIATE_TEST_SUITE_P(ContiguousAndFragmented, ContiguousDescriptors, ::testing::Bool());

}  // namespace
