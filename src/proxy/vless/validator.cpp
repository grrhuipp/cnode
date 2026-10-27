#include "validator.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"

namespace acpp::vless {

std::shared_ptr<const proxyman::inbound::UserStore::VlessCredential>
Validator::FindUser(std::string_view tag,
                    const std::array<uint8_t, 16>& uuid_bytes) const {
    return proxyman::inbound::UserStore::FindVlessUser(tag, uuid_bytes);
}
}  // namespace acpp::vless
