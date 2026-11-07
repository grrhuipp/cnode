#include <gtest/gtest.h>

#include "xhttp_packet_queue.hpp"

#include <algorithm>
#include <cstdlib>

namespace {

acpp::buf::MultiBuffer MakePayload(uint8_t value, size_t size = 1) {
    acpp::buf::MultiBuffer payload;
    while (size > 0) {
        acpp::buf::BufferGuard buffer{acpp::buf::Buffer::New()};
        if (!buffer) {
            std::abort();
        }
        const size_t chunk = std::min<size_t>(size, acpp::buf::Buffer::kSize);
        std::fill_n(buffer->data, chunk, value);
        buffer->Produce(static_cast<uint32_t>(chunk));
        payload.push_back(std::move(buffer));
        size -= chunk;
    }
    return payload;
}

}  // namespace

TEST(XhttpPacketQueue, Contract) {
    acpp::detail::XHttpPacketQueue ordered;
    ASSERT_FALSE((!ordered.Push(1, MakePayload(0x22)) ||
        !ordered.Push(1, MakePayload(0x99)) ||
        !ordered.Push(0, MakePayload(0x11))));
    auto first = ordered.Pop();
    auto second = ordered.Pop();
    ASSERT_FALSE((first.size() != 1 || second.size() != 1 ||
        (*first.begin())->Bytes()[0] != 0x11 ||
        (*second.begin())->Bytes()[0] != 0x22 ||
        ordered.QueuedPackets() != 0 || ordered.QueuedBytes() != 0));

    acpp::detail::XHttpPacketQueue packet_bounded;
    for (size_t i = 0;
         i < acpp::detail::XHttpPacketQueue::kMaxQueuedPackets;
         ++i) {
        ASSERT_FALSE((!packet_bounded.Push(i + 1, {})));
    }
    ASSERT_FALSE((packet_bounded.Push(
            acpp::detail::XHttpPacketQueue::kMaxQueuedPackets + 1,
            {})));

    acpp::detail::XHttpPacketQueue byte_bounded;
    ASSERT_FALSE((byte_bounded.Push(
            0,
            MakePayload(
                0x55,
                acpp::detail::XHttpPacketQueue::kMaxQueuedBytes + 1))));
    acpp::detail::XHttpPacketQueue capacity_bounded;
    constexpr size_t blocks = acpp::detail::XHttpPacketQueue::kMaxQueuedBytes /
                              acpp::buf::Buffer::kSize;
    for (size_t i = 0; i < blocks; ++i) {
        ASSERT_FALSE((!capacity_bounded.Push(i, MakePayload(0x66))));
    }
    ASSERT_FALSE((capacity_bounded.Push(blocks, MakePayload(0x77)) ||
        capacity_bounded.UsedCapacity() != acpp::detail::XHttpPacketQueue::kMaxQueuedBytes));
    auto released = capacity_bounded.Pop();
    ASSERT_FALSE((!capacity_bounded.Push(blocks, MakePayload(0x77))));
    capacity_bounded.Clear();
    ASSERT_FALSE((capacity_bounded.UsedCapacity() != 0));

    acpp::detail::XHttpPacketQueue shared_budget;
    constexpr size_t budget = acpp::detail::XHttpPacketQueue::kMaxQueuedBytes;
    ASSERT_FALSE((!shared_budget.Reserve(budget) ||
        shared_budget.Reserve(1) ||
        shared_budget.Push(0, MakePayload(0x88))));
    shared_budget.Release(acpp::buf::Buffer::kSize);
    ASSERT_FALSE((!shared_budget.Push(0, MakePayload(0x88)) ||
        shared_budget.Reserve(1)));
    shared_budget.Clear();
    ASSERT_FALSE((shared_budget.UsedCapacity() != budget - acpp::buf::Buffer::kSize));
    shared_budget.Release(budget - acpp::buf::Buffer::kSize);
    ASSERT_FALSE((!shared_budget.Reserve(budget)));
    shared_budget.Release(budget);
    for (size_t i = 0; i < acpp::detail::XHttpPacketQueue::kMaxUploads; ++i)
        ASSERT_FALSE((!shared_budget.AcquireUpload()));
    ASSERT_FALSE((shared_budget.AcquireUpload()));
    shared_budget.ReleaseUpload();
    ASSERT_FALSE((!shared_budget.AcquireUpload()));
    for (size_t i = 0; i < acpp::detail::XHttpPacketQueue::kMaxUploads; ++i)
        shared_budget.ReleaseUpload();
    ASSERT_FALSE((!shared_budget.AcquireUpload()));
    shared_budget.ReleaseUpload();
    // Out-of-order packets (seq > next_seq_) must leave headroom so seq == next_seq_ can still be admitted.
    acpp::detail::XHttpPacketQueue ooo_headroom;
    constexpr size_t ooo_blocks =
        (acpp::detail::XHttpPacketQueue::kMaxQueuedBytes -
         acpp::detail::XHttpPacketQueue::kInOrderHeadroomBytes) /
        acpp::buf::Buffer::kSize;
    for (size_t i = 0; i < ooo_blocks; ++i) {
        ASSERT_FALSE((!ooo_headroom.Push(i + 1, MakePayload(0x33, acpp::buf::Buffer::kSize))));
    }
    ASSERT_FALSE((ooo_headroom.Push(ooo_blocks + 1, MakePayload(0x33, acpp::buf::Buffer::kSize))));
    ASSERT_FALSE((!ooo_headroom.Push(0, MakePayload(0x44, acpp::buf::Buffer::kSize))));
    ASSERT_FALSE((!ooo_headroom.HasReady()));
    { ASSERT_EQ((EXIT_SUCCESS), 0); return; }
}
