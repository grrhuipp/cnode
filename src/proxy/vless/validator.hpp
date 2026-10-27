#pragma once

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include <array>
#include <memory>
#include <string_view>

namespace acpp::vless {

class Validator : public UserOnlineTracker {
public:
    using UserOnlineTracker::UserOnlineTracker;

    [[nodiscard]] std::shared_ptr<const proxyman::inbound::UserStore::VlessCredential>
    FindUser(std::string_view tag,
             const std::array<uint8_t, 16>& uuid_bytes) const;
};
}  // namespace acpp::vless
