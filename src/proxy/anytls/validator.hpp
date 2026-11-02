#pragma once

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/sharded_user_stats.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string_view>

namespace acpp::anytls {

class Validator : public UserOnlineTracker {
public:
    using UserOnlineTracker::UserOnlineTracker;

    [[nodiscard]] std::shared_ptr<const proxyman::inbound::UserStore::AnyTlsCredential> Validate(
        std::string_view tag,
        const std::array<uint8_t, 32>& password_hash) const;
};
}  // namespace acpp::anytls
