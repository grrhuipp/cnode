#include "acppnode/transport/internet/tls_stream.hpp"

#include "acppnode/infra/log.hpp"

#include <openssl/ssl.h>

namespace acpp {

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
