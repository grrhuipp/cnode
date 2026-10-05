#pragma once

#include <openssl/ssl.h>

namespace acpp {

inline void ConfigureTlsBuffers(SSL_CTX* ctx) noexcept {
    if (!ctx) {
        return;
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_max_send_fragment(ctx, 8192);
}

inline void ConfigureTlsBuffers(SSL* ssl) noexcept {
    if (!ssl) {
        return;
    }
    SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);
    SSL_set_max_send_fragment(ssl, 8192);
}

}  // namespace acpp
