#pragma once

#include <openssl/ssl.h>

namespace acpp {

inline void LimitSslReadBuffer(SSL_CTX* ctx) noexcept {
    if (!ctx) {
        return;
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_default_read_buffer_len(ctx, 8192);
}

inline void LimitSslReadBuffer(SSL* ssl) noexcept {
    if (!ssl) {
        return;
    }
    SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);
    SSL_set_default_read_buffer_len(ssl, 8192);
}

}  // namespace acpp
