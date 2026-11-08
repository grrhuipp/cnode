#pragma once

#include "common/allocator.hpp"

#include <cstddef>
#include <functional>
#include <string_view>

namespace detail {

struct XHttpPacketSessionKeyRef {
    std::string_view session_id;
    std::string_view session_namespace;
};

struct XHttpPacketSessionKey {
    memory::ThreadLocalString session_id;
    memory::ThreadLocalString session_namespace;
};

struct XHttpPacketSessionKeyHash {
    using is_transparent = void;

    [[nodiscard]] size_t operator()(
        const XHttpPacketSessionKey& key) const noexcept {
        return (*this)(XHttpPacketSessionKeyRef{
            std::string_view(key.session_id), std::string_view(key.session_namespace)});
    }

    [[nodiscard]] size_t operator()(
        XHttpPacketSessionKeyRef key) const noexcept {
        const size_t session_hash = std::hash<std::string_view>{}(key.session_id);
        const size_t namespace_hash = std::hash<std::string_view>{}(key.session_namespace);
        return namespace_hash ^
            (session_hash + size_t{0x9e3779b9} + (namespace_hash << 6) + (namespace_hash >> 2));
    }
};

struct XHttpPacketSessionKeyEq {
    using is_transparent = void;

    [[nodiscard]] bool operator()(
        const XHttpPacketSessionKey& lhs,
        const XHttpPacketSessionKey& rhs) const noexcept {
        return lhs.session_id == rhs.session_id &&
               lhs.session_namespace == rhs.session_namespace;
    }

    [[nodiscard]] bool operator()(
        const XHttpPacketSessionKey& lhs,
        XHttpPacketSessionKeyRef rhs) const noexcept {
        return lhs.session_id == rhs.session_id &&
               lhs.session_namespace == rhs.session_namespace;
    }

    [[nodiscard]] bool operator()(
        XHttpPacketSessionKeyRef lhs,
        const XHttpPacketSessionKey& rhs) const noexcept {
        return lhs.session_id == rhs.session_id &&
               lhs.session_namespace == rhs.session_namespace;
    }
};

}  // namespace detail
