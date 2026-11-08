#pragma once

#include <functional>
#include <string_view>
#include <utility>


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

template<class Map>
[[nodiscard]] auto FindOrEmplaceStringKey(Map& map, std::string_view key) {
    const auto existing = map.find(key);
    if (existing != map.end()) return std::pair{existing, false};
    using Key = typename Map::key_type;
    return map.try_emplace(Key{key});
}

