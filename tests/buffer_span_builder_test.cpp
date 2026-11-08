#include <gtest/gtest.h>

#include "common/buffer_util.hpp"
#include "common/buf/contiguous_buffer_view.hpp"
#include "common/initial_payload.hpp"

#include <array>
#include <cstring>
#include <memory_resource>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

using ContiguousView = ::buf::ContiguousBufferView;
template<class T>
concept BorrowableContiguousBytes = requires(T&& view) {
    std::forward<T>(view).Bytes();
};
static_assert(std::is_constructible_v<ContiguousView, ::buf::MultiBuffer&>);
static_assert(std::is_constructible_v<ContiguousView, const ::buf::MultiBuffer&>);
static_assert(!std::is_constructible_v<ContiguousView, ::buf::MultiBuffer&&>);
static_assert(!std::is_constructible_v<ContiguousView, const ::buf::MultiBuffer&&>);
static_assert(std::is_constructible_v<ContiguousView, std::span<const ::net::const_buffer>>);
static_assert(BorrowableContiguousBytes<ContiguousView&>);
static_assert(BorrowableContiguousBytes<const ContiguousView&>);
static_assert(!BorrowableContiguousBytes<ContiguousView&&>);
static_assert(!BorrowableContiguousBytes<const ContiguousView&&>);

template<class T>
concept BorrowableUdpInfo = requires(T&& packet) {
    ::buf::InspectUdpDatagram(std::forward<T>(packet));
};
static_assert(BorrowableUdpInfo<::buf::MultiBuffer&>);
static_assert(BorrowableUdpInfo<const ::buf::MultiBuffer&>);
static_assert(!BorrowableUdpInfo<::buf::MultiBuffer&&>);
static_assert(!BorrowableUdpInfo<const ::buf::MultiBuffer&&>);

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
concept BorrowableInitialBytes = requires(T&& payload) {
    std::forward<T>(payload).span();
};
template<class T>
concept AppendablePacket = requires(::ConstBufferSpanBuilder<2>& builder, T&& payload) {
    builder.AppendMultiBuffer(std::forward<T>(payload));
};
template<class T>
concept ExtractableInitialPayload = requires(T&& payload) {
    std::forward<T>(payload).MoveToMultiBuffer();
};
static_assert(BorrowablePrefix<::buf::MultiBuffer&>);
static_assert(BorrowablePrefix<const ::buf::MultiBuffer&>);
static_assert(!BorrowablePrefix<::buf::MultiBuffer&&>);
static_assert(!BorrowablePrefix<const ::buf::MultiBuffer&&>);
static_assert(BorrowableFront<::buf::MultiBuffer&>);
static_assert(BorrowableFront<const ::buf::MultiBuffer&>);
static_assert(!BorrowableFront<::buf::MultiBuffer&&>);
static_assert(!BorrowableFront<const ::buf::MultiBuffer&&>);
static_assert(BorrowableDescriptors<::ConstBufferSpanBuilder<2>&>);
static_assert(BorrowableDescriptors<const ::ConstBufferSpanBuilder<2>&>);
static_assert(!BorrowableDescriptors<::ConstBufferSpanBuilder<2>&&>);
static_assert(!BorrowableDescriptors<const ::ConstBufferSpanBuilder<2>&&>);
static_assert(AppendablePacket<::buf::MultiBuffer&>);
static_assert(AppendablePacket<const ::buf::MultiBuffer&>);
static_assert(!AppendablePacket<::buf::MultiBuffer&&>);
static_assert(!AppendablePacket<const ::buf::MultiBuffer&&>);
static_assert(BorrowablePrefix<::InitialPayload&>);
static_assert(BorrowablePrefix<const ::InitialPayload&>);
static_assert(!BorrowablePrefix<::InitialPayload&&>);
static_assert(!BorrowablePrefix<const ::InitialPayload&&>);
static_assert(BorrowableInitialBytes<::InitialPayload&>);
static_assert(BorrowableInitialBytes<const ::InitialPayload&>);
static_assert(!BorrowableInitialBytes<::InitialPayload&&>);
static_assert(!BorrowableInitialBytes<const ::InitialPayload&&>);
static_assert(ExtractableInitialPayload<::InitialPayload&&>);
static_assert(!ExtractableInitialPayload<::InitialPayload&>);
static_assert(!ExtractableInitialPayload<const ::InitialPayload&>);
static_assert(!ExtractableInitialPayload<const ::InitialPayload&&>);

// Retain poisoned retired blocks so stale descriptor reads fail deterministically.
class RetiringResource final : public std::pmr::memory_resource {
public:
    void RejectNextAllocation() noexcept { reject_next_ = true; }
    ~RetiringResource() override {
        for (const auto& block : retired_)
            std::pmr::new_delete_resource()->deallocate(block.pointer, block.bytes, block.alignment);
    }

private:
    struct Block { void* pointer; size_t bytes; size_t alignment; };
    bool reject_next_ = false;
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (std::exchange(reject_next_, false)) throw std::bad_alloc();
        return std::pmr::new_delete_resource()->allocate(bytes, alignment);
    }
    void do_deallocate(void* pointer, size_t bytes, size_t alignment) override {
        std::memset(pointer, 0, bytes);
        retired_.push_back({pointer, bytes, alignment});
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
    std::vector<Block> retired_;
};

class ScopedResource final {
public:
    explicit ScopedResource(std::pmr::memory_resource& resource)
        : previous_(std::pmr::set_default_resource(&resource)) {}
    ~ScopedResource() { std::pmr::set_default_resource(previous_); }
    ScopedResource(const ScopedResource&) = delete;
    ScopedResource& operator=(const ScopedResource&) = delete;
private:
    std::pmr::memory_resource* previous_;
};

std::string Flatten(std::span<const ::net::const_buffer> buffers) {
    std::string result;
    for (const auto& buffer : buffers)
        result.append(static_cast<const char*>(buffer.data()), buffer.size());
    return result;
}

TEST(BufferSpanBuilder, SelfAppendSurvivesInlineAndSpilledGrowth) {
    RetiringResource resource;
    ScopedResource scope(resource);
    const std::string text = "abc";
    ::ConstBufferSpanBuilder<2> builder;
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
    ::ConstBufferSpanBuilder<1> builder;
    builder.AppendBuffers(buffers);
    builder.AppendBuffers(buffers);
    EXPECT_EQ(Flatten(builder.Span()), "abcabc");
    for (const auto& buffer : builder.Span()) EXPECT_EQ(buffer.size(), 1);
}

TEST(BufferSpanBuilder, FailedSpillPreservesBorrowedDescriptorsAndCanRetry) {
    RetiringResource resource;
    ScopedResource scope(resource);
    const std::string text = "abc";
    for (const bool already_spilled : {false, true}) {
        SCOPED_TRACE(already_spilled);
        ::ConstBufferSpanBuilder<2> builder;
        builder.Append(::net::buffer(text.data(), 1));
        builder.Append(::net::buffer(text.data() + 1, 1));
        if (already_spilled) builder.AppendBuffers(builder.Span());
        const auto borrowed = builder.Span();
        const auto expected = Flatten(borrowed);
        resource.RejectNextAllocation();
        EXPECT_THROW(builder.AppendBuffers(borrowed), std::bad_alloc);
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
    RetiringResource resource;
    ScopedResource scope(resource);
    const std::string text = "abc";
    ::ConstBufferSpanBuilder<4> builder;
    builder.Append(::net::buffer(text.data(), 1));
    builder.Append(::net::buffer(text.data() + 1, 1));
    auto* storage = builder.Span().data();
    resource.RejectNextAllocation();
    builder.AppendBuffers(builder.Span());
    EXPECT_EQ(builder.Span().data(), storage);
    EXPECT_EQ(Flatten(builder.Span()), "abab");
    EXPECT_THROW(builder.Append(::net::buffer(text.data() + 2, 1)), std::bad_alloc);
    EXPECT_EQ(Flatten(builder.Span()), "abab");
    builder.Append(::net::buffer(text.data() + 2, 1));
    storage = builder.Span().data();
    resource.RejectNextAllocation();
    builder.AppendBuffers(builder.Span().subspan(3, 2));
    builder.AppendBuffers(builder.Span().last(1));
    EXPECT_EQ(builder.Span().data(), storage);
    EXPECT_EQ(Flatten(builder.Span()), "ababcbcc");
    EXPECT_THROW(builder.AppendBuffers(builder.Span().last(1)), std::bad_alloc);
    EXPECT_EQ(builder.Span().data(), storage);
    EXPECT_EQ(Flatten(builder.Span()), "ababcbcc");
    builder.AppendBuffers(builder.Span().last(1));
    EXPECT_EQ(Flatten(builder.Span()), "ababcbccc");
}

TEST(BufferSpanBuilder, SparseExternalAppendUsesOnlyNonemptyCapacity) {
    ::memory::AllocationDomain domain;
    ::memory::ScopedAllocationDomain lease(domain);
    const std::string text = "abcd";
    const std::array prefix{
        ::net::buffer(text.data(), 1), ::net::buffer(text.data() + 1, 1),
        ::net::buffer(text.data() + 2, 1)};
    const std::array<::net::const_buffer, 3> suffix{
        ::net::const_buffer{}, ::net::buffer(text.data() + 3, 1), {}};
    ::ConstBufferSpanBuilder<4> builder;
    builder.AppendBuffers(prefix);
    builder.AppendBuffers(suffix);
    EXPECT_EQ(Flatten(builder.Span()), "abcd");
    EXPECT_EQ(domain.OutstandingAllocations(), 0u);
    builder.AppendBuffers(suffix);
    EXPECT_EQ(Flatten(builder.Span()), "abcdd");
    EXPECT_EQ(domain.OutstandingAllocations(), 1u);
    builder.Clear();
    EXPECT_EQ(domain.OutstandingAllocations(), 0u);
}

TEST(BufferSpanBuilder, SpillUsesActiveDomainAndClearReleasesItsStorage) {
    ::ConstBufferSpanBuilder<2> builder;
    const std::string text = "abc";
    builder.Append(::net::buffer(text.data(), 1));
    builder.Append(::net::buffer(text.data() + 1, 1));
    for (int cycle = 0; cycle < 2; ++cycle) {
        ::memory::AllocationDomain domain;
        ::memory::ScopedAllocationDomain lease(domain);
        if (cycle != 0) {
            builder.Append(::net::buffer(text.data(), 1));
            builder.Append(::net::buffer(text.data() + 1, 1));
        }
        builder.Append(::net::buffer(text.data() + 2, 1));
        EXPECT_EQ(Flatten(builder.Span()), text);
        EXPECT_EQ(domain.OutstandingAllocations(), 1u);
        builder.Clear();
        EXPECT_EQ(domain.OutstandingAllocations(), 0u);
    }
}

TEST(BufferSpanBuilder, SparseMultiBufferPreservesSlicesAcrossInlineAndSpilledAppends) {
    ::memory::AllocationDomain domain;
    ::memory::ScopedAllocationDomain lease(domain);
    ::buf::MultiBuffer payload;
    const void* slice = nullptr;
    for (int index = 0; index < 3; ++index) {
        ::buf::BufferGuard block{::buf::Buffer::New()};
        ASSERT_TRUE(block);
        if (index == 1) {
            std::memcpy(block->Tail().data(), "abc", 3);
            block->Produce(3);
            block->Advance(1);
            slice = block->Bytes().data();
        }
        payload.push_back(std::move(block));
    }
    const auto payload_allocations = domain.OutstandingAllocations();
    ::ConstBufferSpanBuilder<4> builder;
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
        EXPECT_EQ(domain.OutstandingAllocations(),
            payload_allocations + static_cast<size_t>(appended >= 4));
    }
    builder.Clear();
    EXPECT_EQ(domain.OutstandingAllocations(), payload_allocations);
    payload.clear();
    EXPECT_EQ(domain.OutstandingAllocations(), 0u);
}

TEST(BufferSpanBuilder, FailedMultiBufferAppendPreservesPrefixAndCanRetry) {
    ::buf::MultiBuffer payload;
    for (const char value : {'x', 'y'}) {
        ::buf::BufferGuard block{::buf::Buffer::New()};
        ASSERT_TRUE(block);
        block->Tail()[0] = static_cast<uint8_t>(value);
        block->Produce(1);
        payload.push_back(std::move(block));
    }
    RetiringResource resource;
    ScopedResource scope(resource);
    const std::string text = "abc";
    for (const bool already_spilled : {false, true}) {
        SCOPED_TRACE(already_spilled);
        ::ConstBufferSpanBuilder<2> builder;
        builder.Append(::net::buffer(text.data(), 1));
        builder.Append(::net::buffer(text.data() + 1, 1));
        if (already_spilled) builder.Append(::net::buffer(text.data() + 2, 1));
        const auto borrowed = builder.Span();
        const auto expected = Flatten(borrowed);
        resource.RejectNextAllocation();
        EXPECT_THROW(builder.AppendMultiBuffer(payload), std::bad_alloc);
        EXPECT_EQ(builder.Span().data(), borrowed.data());
        EXPECT_EQ(Flatten(builder.Span()), expected);
        builder.AppendMultiBuffer(payload);
        EXPECT_EQ(Flatten(builder.Span()), expected + "xy");
        EXPECT_EQ(payload.byte_size(), 2u);
    }
}

TEST(ContiguousBufferView, MultiBufferBorrowAndOwnedCopyPreserveBinaryPayload) {
    ::memory::AllocationDomain domain;
    ::memory::ScopedAllocationDomain lease(domain);
    for (const bool fragmented : {false, true}) {
        SCOPED_TRACE(fragmented);
        std::array<uint8_t, 6> expected{0, 0x42, 0, 0x7f, 0x80, 0xff};
        ::buf::MultiBuffer source;
        const size_t chunk_size = fragmented ? 3 : expected.size();
        for (size_t offset = 0; offset < expected.size(); offset += chunk_size) {
            ::buf::BufferGuard block{::buf::Buffer::New()};
            ASSERT_TRUE(block);
            std::memcpy(block->Tail().data(), expected.data() + offset, chunk_size);
            block->Produce(static_cast<uint32_t>(chunk_size));
            source.push_back(std::move(block));
        }
        {
            const ContiguousView view(std::as_const(source));
            if (fragmented) {
                source.clear();
                EXPECT_EQ(domain.OutstandingAllocations(), 1);
            } else {
                EXPECT_EQ(view.Bytes().data(), source.FrontSpan().data());
                (*source.begin())->Bytes()[1] = expected[1] = 0x99;
            }
            ASSERT_EQ(view.Bytes().size(), expected.size());
            EXPECT_TRUE(std::equal(view.Bytes().begin(), view.Bytes().end(), expected.begin()));
        }
        source.clear();
        EXPECT_EQ(domain.OutstandingAllocations(), 0);
    }
}

TEST(ContiguousBufferView, TemporaryDescriptorsDoNotOwnOrExtendPayloadLifetime) {
    ::memory::AllocationDomain domain;
    ::memory::ScopedAllocationDomain lease(domain);
    for (const bool fragmented : {false, true}) {
        SCOPED_TRACE(fragmented);
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
        EXPECT_EQ(domain.OutstandingAllocations(), 0);
    }
}

} // namespace
