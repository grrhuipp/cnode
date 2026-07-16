#include "acppnode/transport/internet/tls_stream.hpp"

#include "tls_client_context.hpp"

#include "acppnode/common/asio_types.hpp"
#include "acppnode/infra/log.hpp"

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <string>

namespace acpp {

namespace {

uint16_t ToOpenSslVersion(TlsVersion version) noexcept {
    switch (version) {
        case TlsVersion::V1_2:
            return TLS1_2_VERSION;
        case TlsVersion::V1_3:
            return TLS1_3_VERSION;
    }
    return 0;
}

}  // namespace

bool ConfigureTlsProtocolVersions(
    SSL_CTX* context,
    TlsVersion min_version,
    TlsVersion max_version) noexcept {
    const uint16_t minimum = ToOpenSslVersion(min_version);
    const uint16_t maximum = ToOpenSslVersion(max_version);
    return context && minimum != 0 && maximum != 0 && minimum <= maximum &&
        SSL_CTX_set_min_proto_version(context, minimum) == 1 &&
        SSL_CTX_set_max_proto_version(context, maximum) == 1;
}

bool EncodeTlsAlpnProtocols(
    std::span<const std::string> protocols,
    std::vector<unsigned char>& wire) {
    wire.clear();
    if (!IsValidTlsAlpn(protocols)) return false;

    std::size_t wire_size = 0;
    for (const auto& protocol : protocols) {
        wire_size += 1 + protocol.size();
    }
    wire.reserve(wire_size);
    for (const auto& protocol : protocols) {
        wire.push_back(static_cast<unsigned char>(protocol.size()));
        wire.insert(wire.end(), protocol.begin(), protocol.end());
    }
    return true;
}

bool ConfigureTlsServerIdentity(
    SSL* ssl, std::string_view identity) noexcept {
    if (!ssl || identity.empty() || identity.find('\0') != std::string_view::npos) {
        return false;
    }

    const std::string identity_text(identity);
    IoErrorCode parse_error;
    const auto address = net::ip::make_address(identity_text, parse_error);
    if (!parse_error) {
        (void)address;
        X509_VERIFY_PARAM* parameters = SSL_get0_param(ssl);
        return parameters &&
            X509_VERIFY_PARAM_set1_ip_asc(
                parameters, identity_text.c_str()) == 1;
    }

    if (SSL_set_tlsext_host_name(ssl, identity_text.c_str()) != 1) {
        return false;
    }
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    return SSL_set1_host(ssl, identity_text.c_str()) == 1;
}

std::unique_ptr<SslContext> SslContext::CreateClient(const TlsConfig& config) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        LOG_ERROR("Failed to create SSL client context");
        return nullptr;
    }

    if (!ConfigureTlsProtocolVersions(
            ctx, config.min_version, config.max_version)) {
        LOG_ERROR("Invalid TLS client protocol version policy");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    if (config.cert_file.empty() != config.key_file.empty()) {
        LOG_ERROR("TLS client certificate and private key must be configured together");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (config.HasCertificatePair()) {
        if (SSL_CTX_use_certificate_chain_file(
                ctx, config.cert_file.c_str()) <= 0) {
            LOG_ERROR("Failed to load TLS client certificate: {}",
                      config.cert_file);
            SSL_CTX_free(ctx);
            return nullptr;
        }
        if (SSL_CTX_use_PrivateKey_file(
                ctx, config.key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            LOG_ERROR("Failed to load TLS client private key: {}",
                      config.key_file);
            SSL_CTX_free(ctx);
            return nullptr;
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
            LOG_ERROR("TLS client private key does not match certificate");
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }

    if (config.allow_insecure && !config.ca_file.empty()) {
        LOG_ERROR("TLS client CA cannot be used when certificate verification is disabled");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (config.allow_insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        const int trust_loaded = config.ca_file.empty()
            ? SSL_CTX_set_default_verify_paths(ctx)
            : SSL_CTX_load_verify_locations(
                ctx, config.ca_file.c_str(), nullptr);
        if (trust_loaded != 1) {
            LOG_ERROR("Failed to load TLS client trust store: {}",
                      config.ca_file.empty() ? "system defaults"
                                             : config.ca_file);
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }

    return std::unique_ptr<SslContext>(new SslContext(ctx));
}

SslContext::~SslContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

}  // namespace acpp
