#include "credentials.hpp"

#include <openssl/sha.h>

namespace acpp::trojan {

PasswordHash HashPassword(std::string_view password) noexcept {
    std::array<unsigned char, SHA224_DIGEST_LENGTH> digest{};
    SHA224(reinterpret_cast<const unsigned char*>(password.data()),
           password.size(), digest.data());
    constexpr std::string_view hex = "0123456789abcdef";
    PasswordHash result{};
    for (size_t i = 0; i < digest.size(); ++i) {
        result[2 * i] = hex[digest[i] >> 4];
        result[2 * i + 1] = hex[digest[i] & 0x0f];
    }
    return result;
}

}  // namespace acpp::trojan
