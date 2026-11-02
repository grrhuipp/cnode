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

int main() {
    acpp::detail::XHttpPacketQueue ordered;
    if (!ordered.Push(1, MakePayload(0x22)) ||
        !ordered.Push(1, MakePayload(0x99)) ||
        !ordered.Push(0, MakePayload(0x11))) {
        return 1;
    }
    auto first = ordered.Pop();
    auto second = ordered.Pop();
    if (first.size() != 1 || second.size() != 1 ||
        (*first.begin())->Bytes()[0] != 0x11 ||
        (*second.begin())->Bytes()[0] != 0x22 ||
        ordered.QueuedPackets() != 0 || ordered.QueuedBytes() != 0) {
        return 2;
    }

    acpp::detail::XHttpPacketQueue packet_bounded;
    for (size_t i = 0;
         i < acpp::detail::XHttpPacketQueue::kMaxQueuedPackets;
         ++i) {
        if (!packet_bounded.Push(i + 1, {})) {
            return 3;
        }
    }
    if (packet_bounded.Push(
            acpp::detail::XHttpPacketQueue::kMaxQueuedPackets + 1,
            {})) {
        return 4;
    }

    acpp::detail::XHttpPacketQueue byte_bounded;
    if (byte_bounded.Push(
            0,
            MakePayload(
                0x55,
                acpp::detail::XHttpPacketQueue::kMaxQueuedBytes + 1))) {
        return 5;
    }
    acpp::detail::XHttpPacketQueue capacity_bounded;
    constexpr size_t blocks = acpp::detail::XHttpPacketQueue::kMaxQueuedBytes /
                              acpp::buf::Buffer::kSize;
    for (size_t i = 0; i < blocks; ++i) {
        if (!capacity_bounded.Push(i, MakePayload(0x66))) return 6;
    }
    if (capacity_bounded.Push(blocks, MakePayload(0x77)) ||
        capacity_bounded.UsedCapacity() != acpp::detail::XHttpPacketQueue::kMaxQueuedBytes)
        return 7;
    auto released = capacity_bounded.Pop();
    if (!capacity_bounded.Push(blocks, MakePayload(0x77))) return 8;
    capacity_bounded.Clear();
    if (capacity_bounded.UsedCapacity() != 0) return 9;

    acpp::detail::XHttpPacketQueue shared_budget;
    constexpr size_t budget = acpp::detail::XHttpPacketQueue::kMaxQueuedBytes;
    if (!shared_budget.Reserve(budget) ||
        shared_budget.Reserve(1) ||
        shared_budget.Push(0, MakePayload(0x88))) return 10;
    shared_budget.Release(acpp::buf::Buffer::kSize);
    if (!shared_budget.Push(0, MakePayload(0x88)) ||
        shared_budget.Reserve(1)) return 11;
    shared_budget.Clear();
    if (shared_budget.UsedCapacity() != budget - acpp::buf::Buffer::kSize)
        return 12;
    shared_budget.Release(budget - acpp::buf::Buffer::kSize);
    if (!shared_budget.Reserve(budget)) return 13;
    shared_budget.Release(budget);
    for (size_t i = 0; i < acpp::detail::XHttpPacketQueue::kMaxUploads; ++i)
        if (!shared_budget.AcquireUpload()) return 14;
    if (shared_budget.AcquireUpload()) return 15;
    shared_budget.ReleaseUpload();
    if (!shared_budget.AcquireUpload()) return 16;
    for (size_t i = 0; i < acpp::detail::XHttpPacketQueue::kMaxUploads; ++i)
        shared_budget.ReleaseUpload();
    if (!shared_budget.AcquireUpload()) return 17;
    shared_budget.ReleaseUpload();
    return EXIT_SUCCESS;
}
