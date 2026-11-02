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

    AutoSignState state;
    const auto t0 = AutoSignState::Clock::time_point{};

    auto injected_dns = state.GetOrCreate(
        "first.example,DNS:second.example", t0);
    if (!Require(injected_dns.cert != nullptr,
                 "literal DNS injection input must produce test material")) return 1;
    if (!Require(X509_check_host(injected_dns.cert, "second.example", 0,
                                 X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 0,
                 "certificate name must not inject a second DNS SAN")) return 1;

    auto injected_ip = state.GetOrCreate(
        "first.example,IP:192.0.2.55", t0);
    if (!Require(injected_ip.cert != nullptr,
                 "literal IP injection input must produce test material")) return 1;
    if (!Require(X509_check_ip_asc(injected_ip.cert, "192.0.2.55", 0) == 0,
                 "certificate name must not inject an IP SAN")) return 1;

    auto public_suffix = state.GetOrCreate("example.co.uk", t0);
    if (!Require(public_suffix.cert != nullptr,
                 "public-suffix domain certificate must be generated")) return 1;
    if (!Require(X509_check_host(public_suffix.cert, "example.co.uk", 0,
                                 X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1,
                 "certificate must cover the requested public-suffix domain")) return 1;
    if (!Require(X509_check_host(public_suffix.cert, "bank.co.uk", 0,
                                 X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 0,
                 "certificate must not cover an unrelated public-suffix sibling")) return 1;

    auto apex = state.GetOrCreate("example.com", t0);
    if (!Require(apex.cert != nullptr, "apex certificate must be generated")) return 1;
    if (!Require(X509_check_host(apex.cert, "example.com", 0,
                                 X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1,
                 "apex certificate SAN must cover the apex domain")) return 1;
    if (!Require(X509_check_host(apex.cert, "www.example.com", 0,
                                 X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 0,
                 "exact certificate SAN must not cover a subdomain")) return 1;

    auto ip = state.GetOrCreate("192.0.2.1", t0);
    if (!Require(ip.cert != nullptr, "IP certificate must be generated")) return 1;
    if (!Require(X509_check_ip_asc(ip.cert, "192.0.2.1", 0) == 1,
                 "IP certificate SAN must contain the exact IP address")) return 1;

    auto first = state.GetOrCreate("*.example.com", t0);
    if (!Require(first.cert != nullptr, "first cert must be generated")) return 1;
    if (!Require(first.key != nullptr, "first key must be generated")) return 1;
    if (!Require(X509_check_host(first.cert, "example.com", 0,
                                 X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1,
                 "explicit wildcard certificate SAN must cover its apex")) return 1;
    if (!Require(X509_check_host(first.cert, "www.example.com", 0,
                                 X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1,
                 "explicit wildcard certificate SAN must cover one-label subdomains")) return 1;

    const auto first_cert = DerEncodeCert(first.cert);
    const auto first_key = DerEncodePublicKey(first.key);
    if (!Require(!first_cert.empty(), "first cert DER must encode")) return 1;
    if (!Require(!first_key.empty(), "first key DER must encode")) return 1;

    AutoSignState isolated_state;
    auto isolated = isolated_state.GetOrCreate("*.example.com", t0);
    if (!Require(isolated.cert != nullptr && isolated.key != nullptr,
                 "isolated state material must be generated")) return 1;
    if (!Require(DerEncodePublicKey(isolated.key) != first_key,
                 "separate Worker-local states must use separate private keys")) return 1;

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
