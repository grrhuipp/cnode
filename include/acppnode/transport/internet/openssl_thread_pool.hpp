#pragma once

#include <openssl/ssl.h>

extern "C" int cnode_release_empty_bio_pair_buffers(BIO* bio);

namespace acpp {

inline void ReleaseIdleSslBioPair(SSL* ssl) noexcept {
    if (ssl) {
        (void)cnode_release_empty_bio_pair_buffers(SSL_get_rbio(ssl));
    }
}

inline void LimitSslReadBuffer(SSL_CTX* ctx) noexcept {
    if (!ctx) {
        return;
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_default_read_buffer_len(ctx, 8192);
    SSL_CTX_set_max_send_fragment(ctx, 8192);
}

inline void LimitSslReadBuffer(SSL* ssl) noexcept {
    if (!ssl) {
        return;
    }
    SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);
    SSL_set_default_read_buffer_len(ssl, 8192);
    SSL_set_max_send_fragment(ssl, 8192);
}

}  // namespace acpp
