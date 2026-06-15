#pragma once

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/proxy/anytls/user_info.hpp"

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp::anytls {

class Validator {
public:
    void ApplyUsers(std::string_view tag, const std::vector<UserInfo>& users);
    void AddUsers(std::string_view tag, const std::vector<UserInfo>& users);
    void RemoveUsers(std::string_view tag, const std::vector<UserInfo>& users);
    void ClearUsers(std::string_view tag);

    [[nodiscard]] std::shared_ptr<const proxyman::inbound::UserStore::AnyTlsCredential> Validate(
        std::string_view tag,
        const std::array<uint8_t, 32>& password_hash) const;

    [[nodiscard]] size_t Size() const noexcept;

private:
};

}  // namespace acpp::anytls
