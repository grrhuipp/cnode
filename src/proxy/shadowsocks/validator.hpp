#pragma once

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/sharded_user_stats.hpp"

#include <string_view>

namespace acpp::ss {

class Validator : public UserOnlineTracker {
public:
    using UserOnlineTracker::UserOnlineTracker;

    [[nodiscard]] proxyman::inbound::UserStore::ShadowsocksUsersView
    FindUsersForTag(std::string_view tag) const;
};
}  // namespace acpp::ss
