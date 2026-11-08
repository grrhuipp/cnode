#include <gtest/gtest.h>

#include "common/buffer_util.hpp"
#include "common/buf/contiguous_buffer_view.hpp"

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

// Retain poisoned retired blocks so stale descriptor reads fail deterministically.
class RetiringResource final : public std::pmr::memory_resource {
public:
    ~RetiringResource() override {
        for (const auto& block : retired_)
            std::pmr::new_delete_resource()->deallocate(block.pointer, block.bytes, block.alignment);
    }

private:
    struct Block { void* pointer; size_t bytes; size_t alignment; };
    void* do_allocate(size_t bytes, size_t alignment) override {
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
