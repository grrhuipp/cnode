#include "acppnode/proxy/anytls/validator.hpp"

#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/core/constants.hpp"

#include <openssl/evp.h>

namespace acpp::anytls {

std::array<uint8_t, 32> PasswordHash(std::string_view password) noexcept {
    std::array<uint8_t, 32> out{};
    unsigned int out_len = 0;
    EVP_Digest(password.data(), password.size(), out.data(), &out_len, EVP_sha256(), nullptr);
    return out;
}

void Validator::ApplyUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    proxyman::inbound::UserSet set;
    set.anytls_users = users;
    proxyman::inbound::UserStore::ApplyUsers(constants::protocol::kAnyTLS, tag, set);
}

void Validator::AddUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    proxyman::inbound::UserSet set;
    set.anytls_users = users;
    proxyman::inbound::UserStore::AddUsers(constants::protocol::kAnyTLS, tag, set);
}

void Validator::RemoveUsers(std::string_view tag, const std::vector<UserInfo>& users) {
    proxyman::inbound::UserSet set;
    set.anytls_users = users;
    proxyman::inbound::UserStore::RemoveUsers(constants::protocol::kAnyTLS, tag, set);
}

void Validator::ClearUsers(std::string_view tag) {
    proxyman::inbound::UserStore::ClearUsers(constants::protocol::kAnyTLS, tag);
}

std::shared_ptr<const proxyman::inbound::UserStore::AnyTlsCredential> Validator::Validate(
    std::string_view tag,
    const std::array<uint8_t, 32>& password_hash) const {
    return proxyman::inbound::UserStore::FindAnyTlsUser(tag, password_hash);
}

size_t Validator::Size() const noexcept {
    return proxyman::inbound::UserStore::GetStats().anytls_users;
}

}  // namespace acpp::anytls
