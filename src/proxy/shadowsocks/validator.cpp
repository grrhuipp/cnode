#include "validator.hpp"

namespace acpp::ss {

proxyman::inbound::UserStore::ShadowsocksUsersView
Validator::FindUsersForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::ShadowsocksUsers(tag);
}
}  // namespace acpp::ss
