#pragma once

#include "transport/internet/stream_settings.hpp"

#include <memory>


class SslContext;

// ============================================================================
// TransportSecurity - shared immutable TLS / REALITY configuration
//
// Prepare once before publishing receiver settings. Each physical domain owns
// its SSL/socket independently and borrows only this immutable context. Auto-
// sign renewal publishes a new SSL_CTX snapshot off all Worker threads; active
// SSL objects retain their old snapshot through the library reference count.
// ============================================================================
class TransportSecurity {
public:
    // Throws std::invalid_argument when a configured TLS or REALITY context
    // cannot be built; the failing step is logged by the context builder.
    TransportSecurity(const StreamSettings& settings, StreamEndpointRole role);
    ~TransportSecurity();
    static void Prepare(StreamSettings& settings, StreamEndpointRole role);

    // Pinned: in-flight handshakes borrow the contexts by address.
    TransportSecurity(const TransportSecurity&) = delete;
    TransportSecurity& operator=(const TransportSecurity&) = delete;

    // Null when the settings use security "none".
    [[nodiscard]] SslContext* Context() const noexcept { return context_.get(); }

    // Null unless an outbound XHTTP stream has downloadSettings.
    [[nodiscard]] const TransportSecurity* XHttpDownload() const noexcept {
        return xhttp_download_.get();
    }

private:
    StreamEndpointRole role_ = StreamEndpointRole::Inbound;
    std::shared_ptr<SslContext> context_;
    std::shared_ptr<TransportSecurity> xhttp_download_;
};

