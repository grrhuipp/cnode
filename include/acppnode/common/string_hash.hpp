#pragma once

#include <functional>
#include <string>
#include <string_view>

namespace acpp {

struct TransparentStringHash {
    using is_transparent = void;

    [[nodiscard]] size_t operator()(std::string_view value) const noexcept {
        return std::hash<std::string_view>{}(value);
    }

    [[nodiscard]] size_t operator()(const std::string& value) const noexcept {
        return (*this)(std::string_view(value));
    }
};

struct TransparentStringEq {
    using is_transparent = void;

    [[nodiscard]] bool operator()(std::string_view lhs,
                                  std::string_view rhs) const noexcept {
        return lhs == rhs;
    }

    [[nodiscard]] bool operator()(const std::string& lhs,
                                  std::string_view rhs) const noexcept {
        return std::string_view(lhs) == rhs;
    }

    [[nodiscard]] bool operator()(std::string_view lhs,
                                  const std::string& rhs) const noexcept {
        return lhs == std::string_view(rhs);
    }

    [[nodiscard]] bool operator()(const std::string& lhs,
                                  const std::string& rhs) const noexcept {
        return lhs == rhs;
    }
};

}  // namespace acpp
