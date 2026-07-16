#pragma once

#include "acppnode/common/buf/multi_buffer.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace acpp::mux::detail {

class XudpPacketBuffer final {
public:
    enum class PopResult : uint8_t {
        NeedMore,
        Packet,
        Invalid,
    };

    void Append(buf::MultiBuffer input) {
        const size_t bytes = buf::TotalLen(input);
        input.MoveTo(pending_);
        pending_bytes_ += bytes;
    }

    [[nodiscard]] PopResult Pop(buf::MultiBuffer& payload) {
        payload.clear();
        if (pending_bytes_ < 2) {
            return PopResult::NeedMore;
        }

        std::array<uint8_t, 2> length_bytes{};
        if (pending_.CopyPrefixTo(length_bytes) != length_bytes.size()) {
            Clear();
            return PopResult::Invalid;
        }
        const size_t packet_len =
            (static_cast<size_t>(length_bytes[0]) << 8) |
            static_cast<size_t>(length_bytes[1]);
        if (pending_bytes_ < 2 + packet_len) {
            return PopResult::NeedMore;
        }
        if (pending_.DropPrefixBytes(2) != 2) {
            Clear();
            return PopResult::Invalid;
        }
        pending_bytes_ -= 2;
        if (packet_len > 0 && !pending_.MovePrefixTo(payload, packet_len)) {
            Clear();
            return PopResult::Invalid;
        }
        pending_bytes_ -= packet_len;
        return PopResult::Packet;
    }

    void Clear() noexcept {
        pending_.clear();
        pending_bytes_ = 0;
    }

    [[nodiscard]] size_t PendingBytes() const noexcept {
        return pending_bytes_;
    }

private:
    buf::MultiBuffer pending_;
    size_t pending_bytes_ = 0;
};

}  // namespace acpp::mux::detail
