#pragma once

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
struct OnlineDevice;
}  // namespace acpp

namespace acpp::vless {

class Validator {
public:
    Validator() = default;
    ~Validator() = default;

    Validator(const Validator&) = delete;
    Validator& operator=(const Validator&) = delete;
    Validator(Validator&&) noexcept = default;
    Validator& operator=(Validator&&) noexcept = default;

    std::shared_ptr<const proxyman::inbound::UserStore::VlessCredential>
    FindUser(std::string_view tag,
             const std::array<uint8_t, 16>& uuid_bytes) const;

    size_t Size() const;
    size_t SizeForTag(std::string_view tag) const;


};

}  // namespace acpp::vless
