#include "autosign_cert.hpp"

#include <openssl/evp.h>
#include <openssl/x509.h>

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
