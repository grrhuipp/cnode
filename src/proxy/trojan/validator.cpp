#include "validator.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"

namespace acpp::trojan {

std::shared_ptr<const proxyman::inbound::UserStore::TrojanCredential>
Validator::FindUser(std::string_view tag, std::string_view hash) const {
    return proxyman::inbound::UserStore::FindTrojanUser(tag, hash);
}

size_t Validator::Size() const {
    return proxyman::inbound::UserStore::GetStats().trojan_users;
}

size_t Validator::SizeForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::SizeForProtocolTag(
        proxyman::inbound::UserProtocol::Trojan, tag);
}

}  // namespace acpp::trojan
