#pragma once

#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <string_view>

namespace anytls {

[[nodiscard]] inline std::array<uint8_t, 32> PasswordHash(std::string_view password) noexcept {
    std::array<uint8_t, 32> out{};
    unsigned int out_len = 0;
    EVP_Digest(password.data(), password.size(), out.data(), &out_len,
               EVP_sha256(), nullptr);
    return out;
}
}  // namespace anytls
