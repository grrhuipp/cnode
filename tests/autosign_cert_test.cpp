#include <gtest/gtest.h>

#include "transport/tls_context.hpp"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <memory>
#include <string>

namespace {
using ::transport::AutoSignCertificate;

TEST(AutosignCert, LiteralIdentityCannotInjectDnsSan) {
    auto certificate = AutoSignCertificate::Create("first.example,DNS:second.example");
    ASSERT_NE(certificate, nullptr);
    EXPECT_EQ(X509_check_host(certificate->Certificate(), "second.example", 14,
                             X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr), 0);
}

TEST(AutosignCert, LiteralIdentityCannotInjectIpSan) {
    auto certificate = AutoSignCertificate::Create("first.example,IP:192.0.2.55");
    ASSERT_NE(certificate, nullptr);
    EXPECT_EQ(X509_check_ip_asc(certificate->Certificate(), "192.0.2.55", 0), 0);
}

TEST(AutosignCert, DnsSanDoesNotAuthorizeSiblingDomain) {
    auto certificate = AutoSignCertificate::Create("example.co.uk");
    ASSERT_NE(certificate, nullptr);
    EXPECT_EQ(X509_check_host(certificate->Certificate(), "example.co.uk", 13,
                             X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr), 1);
    EXPECT_EQ(X509_check_host(certificate->Certificate(), "bank.co.uk", 10,
                             X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr), 0);
}

TEST(AutosignCert, IpIdentityUsesIpSan) {
    auto certificate = AutoSignCertificate::Create("192.0.2.1");
    ASSERT_NE(certificate, nullptr);
    EXPECT_EQ(X509_check_ip_asc(certificate->Certificate(), "192.0.2.1", 0), 1);
}

TEST(AutosignCert, ExplicitWildcardCoversApexAndChild) {
    auto certificate = AutoSignCertificate::Create("*.example.com");
    ASSERT_NE(certificate, nullptr);
    EXPECT_EQ(X509_check_host(certificate->Certificate(), "example.com", 11,
                             X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr), 1);
    EXPECT_EQ(X509_check_host(certificate->Certificate(), "www.example.com", 15,
                             X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr), 1);
}

TEST(AutosignCert, DnsSanCanExceedCommonNameLengthLimit) {
    const std::string name = std::string(63, 'a') + "." + std::string(63, 'b') + ".example.com";
    auto certificate = AutoSignCertificate::Create(name);
    ASSERT_NE(certificate, nullptr);
    EXPECT_EQ(X509_check_host(certificate->Certificate(), name.c_str(), name.size(),
                             X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr), 1);
}

TEST(AutosignCert, DnsRootDotNormalizesForSan) {
    auto certificate = AutoSignCertificate::Create("example.com.");
    ASSERT_NE(certificate, nullptr);
    EXPECT_EQ(X509_check_host(certificate->Certificate(), "example.com", 11,
                             X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, nullptr), 1);
}

TEST(AutosignCert, RejectsEmbeddedNullIdentity) {
    EXPECT_EQ(AutoSignCertificate::Create(std::string_view("a\0b", 3)), nullptr);
}

TEST(AutosignCert, ConnectionsRetainCredentialsAfterBuilderIsDestroyed) {
    auto certificate = AutoSignCertificate::Create("retained.example");
    ASSERT_NE(certificate, nullptr);
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    ASSERT_NE(context, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate(context.get(), certificate->Certificate()), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(context.get(), certificate->Key()), 1);
    certificate.reset();
    std::unique_ptr<SSL, decltype(&SSL_free)> first(SSL_new(context.get()), SSL_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> second(SSL_new(context.get()), SSL_free);
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    EXPECT_NE(SSL_get_certificate(first.get()), nullptr);
    EXPECT_NE(SSL_get_certificate(second.get()), nullptr);
}
}  // namespace
