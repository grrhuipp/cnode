#include "autosign_cert.hpp"

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <cstdio>
#include <string>

namespace {
bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}
}

int main() {
    using acpp::transport::internet::AutoSignCertificate;
    auto injected_dns = AutoSignCertificate::Create("first.example,DNS:second.example");
    if (!Require(injected_dns && X509_check_host(injected_dns->Certificate(), "second.example", 0,
                    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 0,
                 "literal identity must not inject a second DNS SAN")) return 1;
    auto injected_ip = AutoSignCertificate::Create("first.example,IP:192.0.2.55");
    if (!Require(injected_ip && X509_check_ip_asc(injected_ip->Certificate(), "192.0.2.55", 0) == 0,
                 "literal identity must not inject an IP SAN")) return 1;
    auto exact = AutoSignCertificate::Create("example.co.uk");
    if (!Require(exact && X509_check_host(exact->Certificate(), "example.co.uk", 0,
                    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1 &&
                    X509_check_host(exact->Certificate(), "bank.co.uk", 0,
                    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 0,
                 "SAN must cover only the configured identity")) return 1;
    auto ip = AutoSignCertificate::Create("192.0.2.1");
    if (!Require(ip && X509_check_ip_asc(ip->Certificate(), "192.0.2.1", 0) == 1,
                 "IP identity must use an IP SAN")) return 1;
    auto wildcard = AutoSignCertificate::Create("*.example.com");
    if (!Require(wildcard && X509_check_host(wildcard->Certificate(), "example.com", 0,
                    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1 &&
                    X509_check_host(wildcard->Certificate(), "www.example.com", 0,
                    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1,
                 "explicit wildcard covers its apex and one-label children")) return 1;
    const std::string long_name = std::string(63, 'a') + "." + std::string(63, 'b') + ".example.com";
    auto long_cert = AutoSignCertificate::Create(long_name);
    if (!Require(long_cert && X509_check_host(long_cert->Certificate(), long_name.c_str(), 0,
                    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1,
                 "DNS SAN beyond CN's 64-byte limit must be supported")) return 1;
    auto root_dot = AutoSignCertificate::Create("example.com.");
    if (!Require(root_dot && X509_check_host(root_dot->Certificate(), "example.com", 0,
                    X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr) == 1,
                 "configured DNS root dot must normalize for SAN")) return 1;
    if (!Require(!AutoSignCertificate::Create(std::string_view("a\0b", 3)),
                 "embedded NUL must not truncate a configured identity")) return 1;

    // SSL_CTX takes references; credentials remain valid after the temporary
    // startup builder dies. Each SSL has its own state and shares only context.
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!Require(ctx && SSL_CTX_use_certificate(ctx, long_cert->Certificate()) == 1 &&
                    SSL_CTX_use_PrivateKey(ctx, long_cert->Key()) == 1,
                 "startup material must install into SSL_CTX")) return 1;
    long_cert.reset();
    SSL* first = SSL_new(ctx);
    SSL* second = SSL_new(ctx);
    const bool retained = first && second && SSL_get_certificate(first) && SSL_get_certificate(second);
    SSL_free(first);
    SSL_free(second);
    SSL_CTX_free(ctx);
    if (!Require(retained, "independent SSL connections must retain shared certificate material")) return 1;
    return 0;
}
