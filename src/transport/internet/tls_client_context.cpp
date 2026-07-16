#include "acppnode/transport/internet/tls_stream.hpp"

#include "tls_client_context.hpp"

#include "acppnode/common/asio_types.hpp"
#include "acppnode/infra/log.hpp"

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <string>

namespace acpp {

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

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
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

    if (config.allow_insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_default_verify_paths(ctx);
    }

    return std::unique_ptr<SslContext>(new SslContext(ctx));
}

SslContext::~SslContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

}  // namespace acpp
