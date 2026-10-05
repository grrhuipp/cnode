#pragma once

#include "acppnode/app/proxyman/inbound/user_store.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
struct OnlineDevice;
}  // namespace acpp

namespace acpp::anytls {

class Validator {
public:
    Validator() = default;
    ~Validator() = default;

    Validator(const Validator&) = delete;
    Validator& operator=(const Validator&) = delete;
    Validator(Validator&&) noexcept = default;
    Validator& operator=(Validator&&) noexcept = default;

    [[nodiscard]] std::shared_ptr<const proxyman::inbound::UserStore::AnyTlsCredential> Validate(
        std::string_view tag,
        const std::array<uint8_t, 32>& password_hash) const;

    [[nodiscard]] size_t Size() const;
    [[nodiscard]] size_t SizeForTag(std::string_view tag) const;


};

}  // namespace acpp::anytls
