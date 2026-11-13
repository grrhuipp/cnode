#pragma once

#include "common/asio_types.hpp"
#include "common/multi_buffer.hpp"
#include "common/byte_reader.hpp"

#include <new>
#include <optional>
#include <span>

namespace common {

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

// Input rejection is a framing result, not an operating-system I/O failure.
[[nodiscard]] inline bool AppendPacketStreamInput(MultiBuffer& pending, MultiBuffer input) {
    if (pending.byte_size() > kPacketStreamPendingLimit ||
        input.byte_size() > kPacketStreamPendingLimit - pending.byte_size()) {
        return false;
    }
    input.MoveTo(pending, true);
    return true;
}

class LengthPrefixedPacketBuffer final {
public:
    enum class PopResult : uint8_t { NeedMore, Packet, Invalid, Finished };

    [[nodiscard]] bool Append(MultiBuffer input) {
        if (state_ != State::Active) return false;
        try {
            if (!AppendPacketStreamInput(pending_, std::move(input))) {
                Fail();
                return false;
            }
        } catch (...) {
            Fail();
            throw;
        }
        return true;
    }

    [[nodiscard]] PopResult Pop(MultiBuffer& payload) {
        payload.clear();
        if (state_ == State::Failed) return PopResult::Invalid;
        if (state_ == State::Finished) return PopResult::Finished;
        if (pending_.byte_size() < 2) return PopResult::NeedMore;
        const auto front = pending_.FrontSpan();
        const size_t bytes = LoadU16BE(front.data());
        if (pending_.byte_size() < bytes + 2) return PopResult::NeedMore;
        (void)pending_.DropPrefixBytes(2);
        if (!pending_.MovePrefixTo(payload, bytes)) {
            Fail();
            throw std::bad_alloc();
        }
        pending_.ReleaseIfIdle();
        return PopResult::Packet;
    }

    [[nodiscard]] bool Finish() noexcept {
        if (state_ == State::Failed || pending_.byte_size() != 0) {
            Fail();
            return false;
        }
        state_ = State::Finished;
        return true;
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

}  // namespace common
