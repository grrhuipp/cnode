#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"

#include <cstddef>
#include <functional>
#include <string_view>

namespace acpp::detail {

struct XHttpPacketSessionKeyRef {
    const net::io_context* owner = nullptr;
    std::string_view session_id;
};

struct XHttpPacketSessionKey {
    const net::io_context* owner = nullptr;
    memory::ThreadLocalString session_id;
};

struct XHttpPacketSessionKeyHash {
    using is_transparent = void;

    [[nodiscard]] size_t operator()(
        const XHttpPacketSessionKey& key) const noexcept {
        return (*this)(XHttpPacketSessionKeyRef{
            key.owner, std::string_view(key.session_id)});
    }

    [[nodiscard]] size_t operator()(
        XHttpPacketSessionKeyRef key) const noexcept {
        const size_t owner_hash = std::hash<const void*>{}(key.owner);
        const size_t session_hash = std::hash<std::string_view>{}(key.session_id);
        return owner_hash ^
            (session_hash + size_t{0x9e3779b9} +
             (owner_hash << 6) + (owner_hash >> 2));
    }
};

struct XHttpPacketSessionKeyEq {
    using is_transparent = void;

    [[nodiscard]] bool operator()(
        const XHttpPacketSessionKey& lhs,
        const XHttpPacketSessionKey& rhs) const noexcept {
        return lhs.owner == rhs.owner && lhs.session_id == rhs.session_id;
    }

    [[nodiscard]] bool operator()(
        const XHttpPacketSessionKey& lhs,
        XHttpPacketSessionKeyRef rhs) const noexcept {
        return lhs.owner == rhs.owner && lhs.session_id == rhs.session_id;
    }

    [[nodiscard]] bool operator()(
        XHttpPacketSessionKeyRef lhs,
        const XHttpPacketSessionKey& rhs) const noexcept {
        return lhs.owner == rhs.owner && lhs.session_id == rhs.session_id;
    }
};

}  // namespace acpp::detail
