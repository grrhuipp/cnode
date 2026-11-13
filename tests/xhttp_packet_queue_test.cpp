#include <gtest/gtest.h>

#include "transport/xhttp_session.hpp"
#include <algorithm>
#include <cstdlib>

namespace {

::common::MultiBuffer MakePayload(uint8_t value, size_t size) {
    ::common::MultiBuffer payload;
    while (size > 0) {
        ::common::BufferGuard buffer{::common::Buffer::New()};
        if (!buffer) {
            std::abort();
        }
        const size_t chunk = std::min<size_t>(size, ::common::Buffer::kSize);
        std::fill_n(buffer->data, chunk, value);
        buffer->Produce(static_cast<uint32_t>(chunk));
        payload.push_back(std::move(buffer));
        size -= chunk;
    }
    return payload;
}

::common::MultiBuffer MakePayload(uint8_t value) {
    return MakePayload(value, 1);
}

}  // namespace

TEST(XhttpPacketQueue, OrdersPacketsAndIgnoresDuplicateSequences) {
    ::transport::XHttpPacketQueue queue;
    ASSERT_TRUE(queue.Push(1, MakePayload(0x22)));
    ASSERT_TRUE(queue.Push(1, MakePayload(0x99)));
    ASSERT_TRUE(queue.Push(0, MakePayload(0x11)));
    auto first = queue.Pop();
    auto second = queue.Pop();
    ASSERT_EQ(first.byte_size(), 1u);
    ASSERT_EQ(second.byte_size(), 1u);
    EXPECT_EQ(first.FrontSpan()[0], 0x11);
    EXPECT_EQ(second.FrontSpan()[0], 0x22);
    EXPECT_EQ(queue.QueuedPackets(), 0u);
    EXPECT_EQ(queue.QueuedBytes(), 0u);
}

TEST(XhttpPacketQueue, RejectsPacketsBeyondCountLimit) {
    ::transport::XHttpPacketQueue queue;
    for (size_t i = 0; i < ::transport::XHttpPacketQueue::kMaxQueuedPackets; ++i)
        ASSERT_TRUE(queue.Push(i + 1, {}));
    EXPECT_FALSE(queue.Push(::transport::XHttpPacketQueue::kMaxQueuedPackets + 1, {}));
}

TEST(XhttpPacketQueue, RejectsOversizedPayload) {
    ::transport::XHttpPacketQueue queue;
    EXPECT_FALSE(queue.Push(0, MakePayload(0x55, ::transport::XHttpPacketQueue::kMaxQueuedBytes + 1)));
}

TEST(XhttpPacketQueue, PopAndClearReleaseCapacity) {
    ::transport::XHttpPacketQueue queue;
    constexpr size_t blocks = ::transport::XHttpPacketQueue::kMaxQueuedBytes / ::common::Buffer::kSize;
    for (size_t i = 0; i < blocks; ++i)
        ASSERT_TRUE(queue.Push(i, MakePayload(0x66)));
    EXPECT_FALSE(queue.Push(blocks, MakePayload(0x77)));
    EXPECT_EQ(queue.UsedCapacity(), ::transport::XHttpPacketQueue::kMaxQueuedBytes);
    auto released = queue.Pop();
    EXPECT_TRUE(queue.Push(blocks, MakePayload(0x77)));
    queue.Clear();
    EXPECT_EQ(queue.UsedCapacity(), 0u);
}

TEST(XhttpPacketQueue, ReservationsSharePayloadBudget) {
    ::transport::XHttpPacketQueue queue;
    constexpr size_t budget = ::transport::XHttpPacketQueue::kMaxQueuedBytes;
    ASSERT_TRUE(queue.Reserve(budget));
    EXPECT_FALSE(queue.Reserve(1));
    EXPECT_FALSE(queue.Push(0, MakePayload(0x88)));
    queue.Release(::common::Buffer::kSize);
    EXPECT_TRUE(queue.Push(0, MakePayload(0x88)));
    EXPECT_FALSE(queue.Reserve(1));
    queue.Clear();
    EXPECT_EQ(queue.UsedCapacity(), budget - ::common::Buffer::kSize);
    queue.Release(budget - ::common::Buffer::kSize);
    EXPECT_TRUE(queue.Reserve(budget));
    queue.Release(budget);
}

TEST(XhttpPacketQueue, UploadAdmissionRecoversReleasedSlots) {
    ::transport::XHttpPacketQueue queue;
    for (size_t i = 0; i < ::transport::XHttpPacketQueue::kMaxUploads; ++i)
        ASSERT_TRUE(queue.AcquireUpload());
    EXPECT_FALSE(queue.AcquireUpload());
    queue.ReleaseUpload();
    EXPECT_TRUE(queue.AcquireUpload());
    for (size_t i = 0; i < ::transport::XHttpPacketQueue::kMaxUploads; ++i)
        queue.ReleaseUpload();
    EXPECT_TRUE(queue.AcquireUpload());
    queue.ReleaseUpload();
}

TEST(XhttpPacketQueue, OutOfOrderPacketsLeaveRoomForMissingHead) {
    ::transport::XHttpPacketQueue queue;
    constexpr size_t blocks =
        (::transport::XHttpPacketQueue::kMaxQueuedBytes -
         ::transport::XHttpPacketQueue::kInOrderHeadroomBytes) / ::common::Buffer::kSize;
    for (size_t i = 0; i < blocks; ++i)
        ASSERT_TRUE(queue.Push(i + 1, MakePayload(0x33, ::common::Buffer::kSize)));
    EXPECT_FALSE(queue.Push(blocks + 1, MakePayload(0x33, ::common::Buffer::kSize)));
    EXPECT_TRUE(queue.Push(0, MakePayload(0x44, ::common::Buffer::kSize)));
    EXPECT_TRUE(queue.HasReady());
}
