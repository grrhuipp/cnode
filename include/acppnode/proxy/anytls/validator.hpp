#pragma once

#include "acppnode/proxy/anytls/user_info.hpp"

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace acpp::anytls {

class Validator {
public:
    void ApplyUsers(std::string_view tag, const std::vector<UserInfo>& users);
    void AddUsers(std::string_view tag, const std::vector<UserInfo>& users);
    void RemoveUsers(std::string_view tag, const std::vector<UserInfo>& users);
    void ClearUsers(std::string_view tag);

    [[nodiscard]] std::optional<UserInfo> Validate(
        std::string_view tag,
        const std::array<uint8_t, 32>& password_hash) const;

    [[nodiscard]] size_t Size() const noexcept;

private:
    struct Hash {
        size_t operator()(const std::array<uint8_t, 32>& value) const noexcept;
    };

    using UserMap = std::unordered_map<std::array<uint8_t, 32>, UserInfo, Hash>;
    std::unordered_map<std::string, UserMap> users_;
};

}  // namespace acpp::anytls
