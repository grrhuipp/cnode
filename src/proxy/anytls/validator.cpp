#include "validator.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"

namespace acpp::anytls {

std::shared_ptr<const proxyman::inbound::UserStore::AnyTlsCredential> Validator::Validate(
    std::string_view tag,
    const std::array<uint8_t, 32>& password_hash) const {
    return proxyman::inbound::UserStore::FindAnyTlsUser(tag, password_hash);
}
}  // namespace acpp::anytls
