#pragma once

#include <openssl/ssl.h>

#include "acppnode/transport/internet/tls_config.hpp"

#include <string_view>

namespace acpp {

[[nodiscard]] bool ConfigureTlsServerIdentity(
    SSL* ssl, std::string_view identity) noexcept;

[[nodiscard]] bool ConfigureTlsProtocolVersions(
    SSL_CTX* context,
    TlsVersion min_version,
    TlsVersion max_version) noexcept;

}  // namespace acpp
