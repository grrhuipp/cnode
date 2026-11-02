#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <array>
#include <cstring>
#include <new>

namespace acpp::buf {

// A 256KiB resource budget bounds retained input, including coalesced reads.
inline constexpr size_t kPacketStreamPendingLimit = 256 * 1024;

inline void AppendPacketStreamInput(MultiBuffer& pending, MultiBuffer input) {
    if (input.byte_size() > kPacketStreamPendingLimit - pending.byte_size()) {
        throw IoSystemError(io_error::message_size, "packet stream buffer limit exceeded");
    }
    // Tiny TCP fragments share an existing tail rather than retaining one 8KB
    // allocation per byte. Whole input blocks otherwise transfer ownership.
    while (!input.empty()) {
        auto block = input.pop_front();
        if (!block || block->IsEmpty()) continue;
        auto* tail = pending.back();
        if (tail && block->Len() <= tail->Available()) {
            const size_t bytes = block->Len();
            std::memcpy(tail->Tail().data(), block->Bytes().data(), bytes);
            tail->Produce(static_cast<uint32_t>(bytes));
            pending.RecordTailProduced(bytes);
        } else {
            block->ClearUDP();
            pending.push_back(std::move(block));
        }
    }
}

class LengthPrefixedPacketBuffer final {
public:
    enum class PopResult : uint8_t { NeedMore, Packet, Invalid };

    void Append(MultiBuffer input) {
        if (failed_) {
            throw IoSystemError(io_error::invalid_argument, "failed packet stream");
        }
        try {
            AppendPacketStreamInput(pending_, std::move(input));
        } catch (...) {
            failed_ = true;
            pending_.clear();
            throw;
        }
    }

    [[nodiscard]] PopResult Pop(MultiBuffer& payload) {
        payload.clear();
        if (failed_) return PopResult::Invalid;
        if (pending_.byte_size() < 2) return PopResult::NeedMore;
        std::array<uint8_t, 2> length{};
        (void)pending_.CopyPrefixTo(length);
        const size_t bytes = (static_cast<size_t>(length[0]) << 8) | length[1];
        if (pending_.byte_size() < bytes + 2) return PopResult::NeedMore;
        (void)pending_.DropPrefixBytes(2);
        if (!pending_.MovePrefixTo(payload, bytes)) {
            failed_ = true;
            pending_.clear();
            throw std::bad_alloc();
        }
        pending_.ReleaseIfIdle();
        return PopResult::Packet;
    }

    void Finish() const {
        if (failed_ || pending_.byte_size() != 0) {
            throw IoSystemError(io_error::invalid_argument, "truncated packet stream");
        }
    }

    void Clear() noexcept {
        pending_.clear();
        pending_.ReleaseIfIdle();
        failed_ = false;
    }
    [[nodiscard]] size_t PendingBytes() const noexcept { return pending_.byte_size(); }

private:
    MultiBuffer pending_;
    bool failed_ = false;
};

}  // namespace acpp::buf
