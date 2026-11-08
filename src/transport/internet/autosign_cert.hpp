#pragma once

#include <openssl/evp.h>
#include <openssl/x509.h>
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
