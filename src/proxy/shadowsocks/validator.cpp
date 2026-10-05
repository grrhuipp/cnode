#include "validator.hpp"


namespace acpp::ss {

proxyman::inbound::UserStore::ShadowsocksUsersView
Validator::FindUsersForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::ShadowsocksUsers(tag);
}

size_t Validator::Size() const {
    return proxyman::inbound::UserStore::GetStats().shadowsocks_users;
}

size_t Validator::SizeForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::SizeForProtocolTag(
        proxyman::inbound::UserProtocol::Shadowsocks, tag);
}

}  // namespace acpp::ss
