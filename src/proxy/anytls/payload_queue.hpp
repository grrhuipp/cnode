#pragma once

#include "acppnode/common/buf/multi_buffer.hpp"

namespace acpp::anytls {

// Both physical readers append fresh codec payload blocks to a logical byte
// queue. The owner checks its byte budget before calling this operation.
// Every interior block holds at least half a Buffer; a 65,535-byte queue thus
// owns at most 16 blocks. The queue itself remains the sole byte counter.
inline void AppendQueuedPayload(buf::MultiBuffer& queued, buf::MultiBuffer incoming) {
    constexpr size_t min_bytes = buf::Buffer::kSize / 2;
    // Reserve all metadata before modifying bytes or transferring ownership.
    // Failure releases incoming and leaves the existing queue intact.
    queued.reserve((queued.byte_size() + incoming.byte_size() + min_bytes - 1) / min_bytes);
    while (!incoming.empty()) {
        auto block = incoming.pop_front();
        if (!block || block->IsEmpty()) continue;
        auto* tail = queued.back();
        if (tail && tail->Available() != 0) {
            const size_t copied = block->Len() <= tail->Available() ? block->Len()
                : tail->Len() < min_bytes ? min_bytes - tail->Len() : 0;
            if (copied != 0) {
                std::memcpy(tail->Tail().data(), block->Bytes().data(), copied);
                tail->Produce(static_cast<uint32_t>(copied));
                queued.RecordTailProduced(copied);
                block->Advance(static_cast<uint32_t>(copied));
            }
        }
        if (!block->IsEmpty()) queued.push_back(std::move(block));
    }
}

}  // namespace acpp::anytls
