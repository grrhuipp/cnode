#pragma once

#include <openssl/ssl.h>

#include "transport/internet/tls_config.hpp"

#include <span>
#include <string>
#include <string_view>
#include <vector>


[[nodiscard]] bool ConfigureTlsServerIdentity(
    SSL* ssl, std::string_view identity);

[[nodiscard]] bool ConfigureTlsProtocolVersions(
    SSL_CTX* context,
    TlsVersion min_version,
    TlsVersion max_version) noexcept;

[[nodiscard]] bool EncodeTlsAlpnProtocols(
    std::span<const std::string> protocols,
    std::vector<unsigned char>& wire);

// Client ALPN is a context property: configured once at load time.
[[nodiscard]] bool ConfigureTlsClientAlpn(
    SSL_CTX* context, std::span<const std::string> protocols);

// Installs the PEM certificate chain (leaf first) and its private key, the
// in-memory equivalent of SSL_CTX_use_certificate_chain_file plus
// SSL_CTX_use_PrivateKey_file. Logs the failing step.
[[nodiscard]] bool ConfigureTlsCertificatePem(
    SSL_CTX* context, const TlsPemMaterial& pem);

