#pragma once

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string_view>

namespace transport::internet {

// Built from trusted configuration before accepting connections. No SNI-driven
// generation, mutable certificate cache, or request-path key rotation.
class AutoSignCertificate {
public:
    [[nodiscard]] static std::unique_ptr<AutoSignCertificate> Create(std::string_view identity);
    ~AutoSignCertificate();
    AutoSignCertificate(const AutoSignCertificate&) = delete;
    AutoSignCertificate& operator=(const AutoSignCertificate&) = delete;
    [[nodiscard]] X509* Certificate() const noexcept { return certificate_; }
    [[nodiscard]] EVP_PKEY* Key() const noexcept { return key_; }
private:
    AutoSignCertificate() = default;
    X509* certificate_ = nullptr;
    EVP_PKEY* key_ = nullptr;
};

} // namespace transport::internet

// One registration per prepared configuration, not per Worker or handshake.
// A single bounded background scheduler signs and publishes immutable contexts.
class AutoSignContextRenewal {
public:
    using Clock = std::chrono::system_clock;
    using Builder = std::function<std::shared_ptr<SSL_CTX>()>;
    static std::shared_ptr<AutoSignContextRenewal> Start(
        std::shared_ptr<SSL_CTX> initial, Builder builder);
    [[nodiscard]] std::shared_ptr<SSL_CTX> Acquire(Clock::time_point now = Clock::now()) const noexcept;
private:
    friend class AutoSignRenewalScheduler;
    struct Snapshot {
        std::shared_ptr<SSL_CTX> context;
        Clock::time_point expires;
    };
    AutoSignContextRenewal(std::shared_ptr<SSL_CTX> initial, Builder builder);
    bool Publish(std::shared_ptr<SSL_CTX> context);
    std::atomic<std::shared_ptr<const Snapshot>> current_;
    Builder builder_;
    std::atomic<Clock::time_point> next_attempt_{Clock::time_point::min()};
};
