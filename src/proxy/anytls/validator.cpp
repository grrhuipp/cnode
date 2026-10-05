#include "validator.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"

namespace acpp::anytls {

std::shared_ptr<const proxyman::inbound::UserStore::AnyTlsCredential> Validator::Validate(
    std::string_view tag,
    const std::array<uint8_t, 32>& password_hash) const {
    return proxyman::inbound::UserStore::FindAnyTlsUser(tag, password_hash);
}

size_t Validator::Size() const {
    return proxyman::inbound::UserStore::GetStats().anytls_users;
}

size_t Validator::SizeForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::SizeForProtocolTag(
        proxyman::inbound::UserProtocol::AnyTls, tag);
}

}  // namespace acpp::anytls
