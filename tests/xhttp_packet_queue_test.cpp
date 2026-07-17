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
        payload.push_back(buffer.release());
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
        if (!packet_bounded.Push(i + 1, MakePayload(0x33))) {
            return 3;
        }
    }
    if (packet_bounded.Push(
            acpp::detail::XHttpPacketQueue::kMaxQueuedPackets + 1,
            MakePayload(0x44))) {
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
    return EXIT_SUCCESS;
}
