#pragma once

#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"

#include <array>
#include <cstring>
#include <new>
#include <optional>
#include <span>

namespace buf {

// A 256KiB resource budget bounds retained input, including coalesced reads.
inline constexpr size_t kPacketStreamPendingLimit = 256 * 1024;

[[nodiscard]] inline std::optional<size_t> TrySumBufferSizes(
    std::span<const net::const_buffer> buffers,
    size_t max_size) noexcept {
    size_t total = 0;
    for (const auto& buffer : buffers) {
        if (buffer.size() > max_size - total) {
            return std::nullopt;
        }
        total += buffer.size();
    }
    return total;
}

inline void AppendCoalescedStreamInput(MultiBuffer& pending, MultiBuffer input) {
    constexpr size_t min_bytes = Buffer::kSize / 2;
    // Tiny TCP fragments share an existing tail rather than retaining one 8KB
    // allocation per byte. Whole input blocks otherwise transfer ownership.
    while (!input.empty()) {
        auto block = input.pop_front();
        if (!block || block->IsEmpty()) continue;
        auto* tail = pending.back();
        if (tail && tail->Available() < block->Len() &&
            (tail->Available() + tail->start >= block->Len() || tail->Len() < min_bytes)) {
            tail->CompactToFront();
        }
        if (tail && tail->Available() != 0) {
            const size_t copied = block->Len() <= tail->Available() ? block->Len()
                : tail->Len() < min_bytes ? min_bytes - tail->Len() : 0;
            if (copied != 0) {
                std::memcpy(tail->Tail().data(), block->Bytes().data(), copied);
                tail->Produce(static_cast<uint32_t>(copied));
                pending.RecordTailProduced(copied);
                block->Advance(static_cast<uint32_t>(copied));
            }
        }
        if (!block->IsEmpty()) {
            block->ClearUDP();
            pending.push_back(std::move(block));
        }
    }
}

inline void AppendPacketStreamInput(MultiBuffer& pending, MultiBuffer input) {
    if (pending.byte_size() > kPacketStreamPendingLimit ||
        input.byte_size() > kPacketStreamPendingLimit - pending.byte_size()) {
        throw IoSystemError(io_error::message_size, "packet stream pending buffer exceeded");
    }
    AppendCoalescedStreamInput(pending, std::move(input));
}

class LengthPrefixedPacketBuffer final {
public:
    enum class PopResult : uint8_t { NeedMore, Packet, Invalid, Finished };

    void Append(MultiBuffer input) {
        if (state_ != State::Active) {
            throw IoSystemError(io_error::invalid_argument, "inactive packet stream");
        }
        try {
            AppendPacketStreamInput(pending_, std::move(input));
        } catch (...) {
            Fail();
            throw;
        }
    }

    [[nodiscard]] PopResult Pop(MultiBuffer& payload) {
        payload.clear();
        if (state_ == State::Failed) return PopResult::Invalid;
        if (state_ == State::Finished) return PopResult::Finished;
        if (pending_.byte_size() < 2) return PopResult::NeedMore;
        std::array<uint8_t, 2> length{};
        (void)pending_.CopyPrefixTo(length);
        const size_t bytes = (static_cast<size_t>(length[0]) << 8) | length[1];
        if (pending_.byte_size() < bytes + 2) return PopResult::NeedMore;
        (void)pending_.DropPrefixBytes(2);
        if (!pending_.MovePrefixTo(payload, bytes)) {
            Fail();
            throw std::bad_alloc();
        }
        pending_.ReleaseIfIdle();
        return PopResult::Packet;
    }

    void Finish() {
        if (state_ == State::Failed || pending_.byte_size() != 0) {
            Fail();
            throw IoSystemError(io_error::invalid_argument, "truncated packet stream");
        }
        state_ = State::Finished;
    }

    void Fail() noexcept {
        pending_.clear();
        state_ = State::Failed;
    }

    void Reset() noexcept {
        pending_.clear();
        state_ = State::Active;
    }
    [[nodiscard]] bool Finished() const noexcept { return state_ == State::Finished; }
    [[nodiscard]] size_t PendingBytes() const noexcept { return pending_.byte_size(); }

private:
    enum class State : uint8_t { Active, Finished, Failed };
    MultiBuffer pending_;
    State state_ = State::Active;
};

}  // namespace buf
