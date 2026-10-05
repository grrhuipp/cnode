#include "validator.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"

namespace acpp::vless {

std::shared_ptr<const proxyman::inbound::UserStore::VlessCredential>
Validator::FindUser(std::string_view tag,
                    const std::array<uint8_t, 16>& uuid_bytes) const {
    return proxyman::inbound::UserStore::FindVlessUser(tag, uuid_bytes);
}

size_t Validator::Size() const {
    return proxyman::inbound::UserStore::GetStats().vless_users;
}

size_t Validator::SizeForTag(std::string_view tag) const {
    return proxyman::inbound::UserStore::SizeForProtocolTag(
        proxyman::inbound::UserProtocol::Vless, tag);
}

}  // namespace acpp::vless
