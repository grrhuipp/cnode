#include "autosign_cert.hpp"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <cstdio>
#include <vector>

namespace {

std::vector<unsigned char> DerEncodeCert(X509* cert) {
    int len = i2d_X509(cert, nullptr);
    if (len <= 0) return {};

    std::vector<unsigned char> der(static_cast<size_t>(len));
    unsigned char* out = der.data();
    if (i2d_X509(cert, &out) != len) return {};
    return der;
}

std::vector<unsigned char> DerEncodePublicKey(EVP_PKEY* key) {
    int len = i2d_PUBKEY(key, nullptr);
    if (len <= 0) return {};

    std::vector<unsigned char> der(static_cast<size_t>(len));
    unsigned char* out = der.data();
    if (i2d_PUBKEY(key, &out) != len) return {};
    return der;
}

bool Require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "%s\n", message);
        return false;
    }
    return true;
}

}  // namespace

int main() {
    using acpp::transport::internet::AutoSignState;
    using acpp::transport::internet::NormalizeAutoSignCertificateName;

    if (!Require(NormalizeAutoSignCertificateName("www.example.com") ==
                     "*.example.com",
                 "subdomain must normalize to its registrable wildcard")) return 1;
    if (!Require(NormalizeAutoSignCertificateName("example.com") ==
                     "*.example.com",
                 "apex domain must not normalize to a public-suffix wildcard")) return 1;
    if (!Require(NormalizeAutoSignCertificateName("localhost") == "localhost",
                 "single-label host must remain exact")) return 1;
    if (!Require(NormalizeAutoSignCertificateName("*.example.com") ==
                     "*.example.com",
                 "existing wildcard must remain unchanged")) return 1;
    if (!Require(NormalizeAutoSignCertificateName("192.0.2.1") == "192.0.2.1",
                 "IPv4 literal must remain exact")) return 1;
    if (!Require(NormalizeAutoSignCertificateName("2001:db8::1") == "2001:db8::1",
                 "IPv6 literal must remain exact")) return 1;

    AutoSignState state;
    const auto t0 = AutoSignState::Clock::time_point{};

    auto apex = state.GetOrCreate(NormalizeAutoSignCertificateName("example.com"), t0);
    if (!Require(apex.cert != nullptr, "apex certificate must be generated")) return 1;
    if (!Require(X509_check_host(apex.cert, "example.com", 0,
                                 X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1,
                 "apex certificate SAN must cover the apex domain")) return 1;
    if (!Require(X509_check_host(apex.cert, "www.example.com", 0,
                                 X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1,
                 "apex certificate SAN must cover one-label subdomains")) return 1;

    auto ip = state.GetOrCreate(NormalizeAutoSignCertificateName("192.0.2.1"), t0);
    if (!Require(ip.cert != nullptr, "IP certificate must be generated")) return 1;
    if (!Require(X509_check_ip_asc(ip.cert, "192.0.2.1", 0) == 1,
                 "IP certificate SAN must contain the exact IP address")) return 1;

    auto first = state.GetOrCreate("*.example.com", t0);
    if (!Require(first.cert != nullptr, "first cert must be generated")) return 1;
    if (!Require(first.key != nullptr, "first key must be generated")) return 1;

    const auto first_cert = DerEncodeCert(first.cert);
    const auto first_key = DerEncodePublicKey(first.key);
    if (!Require(!first_cert.empty(), "first cert DER must encode")) return 1;
    if (!Require(!first_key.empty(), "first key DER must encode")) return 1;

    auto reused = state.GetOrCreate("*.example.com", t0 + std::chrono::seconds(299));
    if (!Require(DerEncodeCert(reused.cert) == first_cert,
                 "cert must be reused before five minutes")) return 1;
    if (!Require(DerEncodePublicKey(reused.key) == first_key,
                 "key must be reused before five minutes")) return 1;

    auto rotated = state.GetOrCreate("*.example.com", t0 + std::chrono::seconds(301));
    if (!Require(DerEncodeCert(rotated.cert) != first_cert,
                 "cert must rotate after five minutes")) return 1;
    if (!Require(DerEncodePublicKey(rotated.key) != first_key,
                 "key must rotate after five minutes")) return 1;

    return 0;
}
