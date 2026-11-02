#include "ss_outbound_credentials.hpp"

namespace acpp::proxy::shadowsocks::outbound {

std::optional<Credentials> Credentials::Prepare(
    std::string_view method, std::string_view password) {
    const auto cipher = ss::ParseCipherMethod(method);
    if (!cipher || password.empty()) {
        return std::nullopt;
    }
    if (!ss::Is2022Cipher(*cipher)) {
        auto key = ss::DeriveKey(std::string(password), cipher->key_size);
        if (key.size != cipher->key_size) {
            return std::nullopt;
        }
        return Credentials(*cipher, key, {});
    }

    std::vector<ss::KeyBytes> chain;
    for (;;) {
        const auto separator = password.find(':');
        const auto key = ss::Decode2022Psk(password.substr(0, separator), cipher->key_size);
        if (key.size != cipher->key_size) {
            return std::nullopt;
        }
        chain.push_back(key);
        if (separator == std::string_view::npos) {
            break;
        }
        // The production TCP/UDP codecs support identity chains only for AES.
        if (!ss::Is2022AesCipher(cipher->type)) {
            return std::nullopt;
        }
        password.remove_prefix(separator + 1);
    }
    const auto master_key = chain.back();
    return Credentials(*cipher, master_key, std::move(chain));
}

}  // namespace acpp::proxy::shadowsocks::outbound
