#pragma once

#include <openssl/ssl.h>

#include "acppnode/transport/internet/tls_config.hpp"

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

[[nodiscard]] bool ConfigureTlsServerIdentity(
    SSL* ssl, std::string_view identity) noexcept;

[[nodiscard]] bool ConfigureTlsProtocolVersions(
    SSL_CTX* context,
    TlsVersion min_version,
    TlsVersion max_version) noexcept;

[[nodiscard]] bool EncodeTlsAlpnProtocols(
    std::span<const std::string> protocols,
    std::vector<unsigned char>& wire);

}  // namespace acpp
