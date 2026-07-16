#pragma once

#include <openssl/ssl.h>

#include <string_view>

namespace acpp {

[[nodiscard]] bool ConfigureTlsServerIdentity(
    SSL* ssl, std::string_view identity) noexcept;

}  // namespace acpp
