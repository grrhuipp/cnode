#pragma once

#include <functional>
#include <string_view>


namespace common {

struct TransparentStringHash {
    using is_transparent = void;

    [[nodiscard]] size_t operator()(std::string_view value) const noexcept {
        return std::hash<std::string_view>{}(value);
    }

};

struct TransparentStringEq {
    using is_transparent = void;

    [[nodiscard]] bool operator()(std::string_view lhs,
                                  std::string_view rhs) const noexcept {
        return lhs == rhs;
    }

};

}  // namespace common

