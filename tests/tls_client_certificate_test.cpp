#include <gtest/gtest.h>

#include "transport/internet/tls_stream.hpp"
#include "autosign_cert.hpp"
#include "tls_client_context.hpp"

#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

class CertificateFiles {
public:
    CertificateFiles() {
        const auto nonce = std::chrono::steady_clock::now()
            .time_since_epoch().count();
        const auto base = std::filesystem::temp_directory_path() /
            ("cnode_tls_client_" + std::to_string(nonce));
        cert = base;
        cert += ".pem";
        key = base;
        key += ".key";
    }

    ~CertificateFiles() {
        std::error_code ignored;
        std::filesystem::remove(cert, ignored);
        std::filesystem::remove(key, ignored);
    }

    std::filesystem::path cert;
    std::filesystem::path key;
};

bool WriteCertificateFiles(const CertificateFiles& files,
                           X509* certificate,
                           EVP_PKEY* private_key) {
    BIO* cert_file = BIO_new_file(files.cert.string().c_str(), "w");
    if (!cert_file) return false;
    const bool cert_written = PEM_write_bio_X509(cert_file, certificate) == 1;
    BIO_free(cert_file);
    if (!cert_written) return false;

    BIO* key_file = BIO_new_file(files.key.string().c_str(), "w");
    if (!key_file) return false;
    const bool key_written =
        PEM_write_bio_PrivateKey(key_file, private_key, nullptr, nullptr, 0,
                                 nullptr, nullptr) == 1;
    BIO_free(key_file);
    return key_written;
}

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

bool VerifyCertificate(X509* certificate, const X509_VERIFY_PARAM* parameters) {
    X509_STORE* store = X509_STORE_new();
    X509_STORE_CTX* store_context = X509_STORE_CTX_new();
    if (!store || !store_context ||
        X509_STORE_add_cert(store, certificate) != 1 ||
        X509_STORE_CTX_init(store_context, store, certificate, nullptr) != 1 ||
        X509_VERIFY_PARAM_set1(
            X509_STORE_CTX_get0_param(store_context), parameters) != 1) {
        if (store_context) X509_STORE_CTX_free(store_context);
        if (store) X509_STORE_free(store);
        return false;
    }
    const bool verified = X509_verify_cert(store_context) == 1;
    X509_STORE_CTX_free(store_context);
    X509_STORE_free(store);
    return verified;
}

bool VerifyCertificateWithContextStore(X509* certificate, SSL_CTX* context) {
    X509_STORE_CTX* store_context = X509_STORE_CTX_new();
    if (!store_context ||
        X509_STORE_CTX_init(
            store_context, SSL_CTX_get_cert_store(context),
            certificate, nullptr) != 1) {
        if (store_context) X509_STORE_CTX_free(store_context);
        return false;
    }
    const bool verified = X509_verify_cert(store_context) == 1;
    X509_STORE_CTX_free(store_context);
    return verified;
}

bool ReplaceCommonName(X509* certificate,
                       EVP_PKEY* private_key,
                       const char* common_name) {
    X509_NAME* name = X509_NAME_new();
    if (!name) return false;
    const bool updated =
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(common_name),
            -1, -1, 0) == 1 &&
        X509_set_subject_name(certificate, name) == 1 &&
        X509_set_issuer_name(certificate, name) == 1;
    X509_NAME_free(name);
    return updated && X509_sign(certificate, private_key, EVP_sha256()) > 0;
}

}  // namespace

TEST(TlsClientCertificate, Contract) {
    auto material = ::transport::internet::AutoSignCertificate::Create("client.example");
    CertificateFiles files;
    ASSERT_FALSE((!Require(material != nullptr,
                 "client certificate material must be generated") ||
        !Require(WriteCertificateFiles(files, material->Certificate(), material->Key()),
                 "client certificate files must be written")));

    ::TlsConfig config;
    config.cert_file = files.cert.string();
    config.key_file = files.key.string();
    config.allow_insecure = true;
    ::LoadTlsPemMaterial(config);

    auto context = ::SslContext::CreateClient(config);
    ASSERT_FALSE((!Require(context != nullptr, "client context must be created")));
    ASSERT_FALSE((!Require(SSL_CTX_get0_certificate(context->Native()) != nullptr,
                 "client context must expose the configured certificate")));
    ASSERT_FALSE((!Require(SSL_CTX_get0_privatekey(context->Native()) != nullptr,
                 "client context must expose the configured private key")));
    ASSERT_FALSE((!Require(SSL_CTX_check_private_key(context->Native()) == 1,
                 "client certificate and private key must match")));

    ::TlsConfig private_ca_config;
    private_ca_config.ca_file = files.cert.string();
    ::LoadTlsPemMaterial(private_ca_config);
    auto private_ca_context = ::SslContext::CreateClient(private_ca_config);
    ASSERT_FALSE((!Require(private_ca_context != nullptr,
                 "client context with private CA must be created")));
    ASSERT_FALSE((!Require(VerifyCertificateWithContextStore(
                     material->Certificate(), private_ca_context->Native()),
                 "configured private CA must be present in the client trust store")));

    // Like SSL_CTX_use_certificate_chain_file, only a clean end of input may
    // follow the leaf: a malformed later block fails the whole chain.
    auto malformed_chain = std::make_shared<::TlsPemMaterial>();
    malformed_chain->certificate_chain = config.pem->certificate_chain +
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    malformed_chain->private_key = config.pem->private_key;
    ::TlsConfig malformed_chain_config = config;
    malformed_chain_config.pem = std::move(malformed_chain);
    ASSERT_FALSE((!Require(::SslContext::CreateClient(malformed_chain_config) == nullptr,
                 "a malformed PEM block after the leaf certificate must be rejected")));

    ::TlsConfig unreadable_config;
    unreadable_config.ca_file = files.cert.string() + ".missing";
    bool unreadable_rejected = false;
    try {
        ::LoadTlsPemMaterial(unreadable_config);
    } catch (const std::invalid_argument&) {
        unreadable_rejected = true;
    }
    ASSERT_FALSE((!Require(unreadable_rejected && !unreadable_config.pem,
                 "an unreadable TLS file must be rejected while loading configuration")));

    ::TlsConfig tls13_config;
    tls13_config.allow_insecure = true;
    tls13_config.min_version = ::TlsVersion::V1_3;
    tls13_config.max_version = ::TlsVersion::V1_3;
    auto tls13_context = ::SslContext::CreateClient(tls13_config);
    ASSERT_FALSE((!Require(tls13_context != nullptr,
                 "TLS 1.3-only client context must be created")));
    ASSERT_FALSE((!Require(
            SSL_CTX_get_min_proto_version(tls13_context->Native()) ==
                TLS1_3_VERSION &&
            SSL_CTX_get_max_proto_version(tls13_context->Native()) ==
                TLS1_3_VERSION,
            "TLS 1.3-only policy must reach the client SSL context")));

    using namespace std::string_view_literals;
    for (const auto identity : {"127.0.0.1:9"sv, "[::1]"sv, "bad..example"sv,
                               "fe80::1%invalid"sv, "127.0.0.1\0ignored"sv}) {
        SSL* client = SSL_new(context->Native());
        const bool rejected = client && !::ConfigureTlsServerIdentity(client, identity);
        SSL_free(client);
        ASSERT_FALSE((!Require(rejected, "invalid TLS identity must be rejected before SNI or SAN setup")));
    }
    for (const auto identity : {"2001:db8::1", "fe80::1%3", "::ffff:192.0.2.1"}) {
        SSL* client = SSL_new(context->Native());
        const bool configured = client && ::ConfigureTlsServerIdentity(client, identity) &&
            SSL_get_servername(client, TLSEXT_NAMETYPE_host_name) == nullptr;
        SSL_free(client);
        ASSERT_FALSE((!Require(configured, "IPv6 TLS identity must use IP SAN bytes without SNI")));
    }

    auto ip_material = ::transport::internet::AutoSignCertificate::Create("192.0.2.1");
    SSL* ip_client = SSL_new(context->Native());
    if (!Require(ip_material != nullptr &&
                     ip_client != nullptr,
                 "IP identity test material must be created")) {
        if (ip_client) SSL_free(ip_client);
        FAIL() << "IP identity test material must be created";
    }
    if (!Require(ReplaceCommonName(
                     ip_material->Certificate(), ip_material->Key(), "unrelated.example"),
                 "IP identity certificate common name must be replaced")) {
        SSL_free(ip_client);
        FAIL() << "IP identity certificate common name must be replaced";
    }
    if (!Require(::ConfigureTlsServerIdentity(ip_client, "192.0.2.1"),
                 "IP server identity must be configured")) {
        SSL_free(ip_client);
        FAIL() << "IP server identity must be configured";
    }
    if (!Require(SSL_get_servername(
                     ip_client, TLSEXT_NAMETYPE_host_name) == nullptr,
                 "IP server identity must not be sent as SNI")) {
        SSL_free(ip_client);
        FAIL() << "IP server identity must not be sent as SNI";
    }
    const bool ip_verified = VerifyCertificate(
        ip_material->Certificate(), SSL_get0_param(ip_client));
    SSL_free(ip_client);
    ASSERT_FALSE((!Require(ip_verified,
                 "IP SAN certificate must verify for its configured identity")));

    SSL* wrong_ip_client = SSL_new(context->Native());
    if (!Require(wrong_ip_client != nullptr &&
                     ::ConfigureTlsServerIdentity(
                         wrong_ip_client, "192.0.2.2"),
                 "wrong IP identity must be configured for rejection test")) {
        if (wrong_ip_client) SSL_free(wrong_ip_client);
        FAIL() << "wrong IP identity must be configured for rejection test";
    }
    const bool wrong_ip_verified = VerifyCertificate(
        ip_material->Certificate(), SSL_get0_param(wrong_ip_client));
    SSL_free(wrong_ip_client);
    ASSERT_FALSE((!Require(!wrong_ip_verified,
                 "IP SAN certificate must reject a different IP identity")));

    SSL* dns_client = SSL_new(context->Native());
    if (!Require(dns_client != nullptr &&
                     ::ConfigureTlsServerIdentity(
                         dns_client, "client.example"),
                 "DNS server identity must be configured")) {
        if (dns_client) SSL_free(dns_client);
        FAIL() << "DNS server identity must be configured";
    }
    const char* configured_sni = SSL_get_servername(
        dns_client, TLSEXT_NAMETYPE_host_name);
    const bool dns_verified = VerifyCertificate(
        material->Certificate(), SSL_get0_param(dns_client));
    if (!Require(configured_sni != nullptr &&
                     std::string_view(configured_sni) == "client.example",
                 "DNS server identity must be sent as SNI")) {
        SSL_free(dns_client);
        FAIL() << "DNS server identity must be sent as SNI";
    }
    SSL_free(dns_client);
    ASSERT_FALSE((!Require(dns_verified,
                 "DNS SAN certificate must verify for its configured identity")));
    // FQDN with trailing root dot must strip the dot for SNI (RFC 6066) and X.509 SAN host verification.
    SSL* fqdn_client = SSL_new(context->Native());
    if (!Require(fqdn_client != nullptr &&
                     ::ConfigureTlsServerIdentity(fqdn_client, "client.example."),
                 "FQDN server identity with trailing dot must be configured")) {
        if (fqdn_client) SSL_free(fqdn_client);
        FAIL() << "FQDN server identity with trailing dot must be configured";
    }
    const char* fqdn_sni = SSL_get_servername(fqdn_client, TLSEXT_NAMETYPE_host_name);
    const bool fqdn_verified = VerifyCertificate(
        material->Certificate(), SSL_get0_param(fqdn_client));
    if (!Require(fqdn_sni != nullptr && std::string_view(fqdn_sni) == "client.example",
                 "FQDN trailing root dot must be stripped from SNI")) {
        SSL_free(fqdn_client);
        FAIL() << "FQDN trailing root dot must be stripped from SNI";
    }
    SSL_free(fqdn_client);
    ASSERT_FALSE((!Require(fqdn_verified,
                 "FQDN with trailing root dot must verify against certificate SAN")));

    std::vector<unsigned char> alpn_wire;
    const std::vector<std::string> valid_alpn = {"h2", "http/1.1"};
    const std::vector<unsigned char> expected_alpn_wire = {
        2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    ASSERT_FALSE((!Require(::EncodeTlsAlpnProtocols(valid_alpn, alpn_wire) &&
                     alpn_wire == expected_alpn_wire,
                 "valid ALPN protocols must have canonical wire encoding")));
    const std::vector<std::string> empty_alpn = {""};
    ASSERT_FALSE((!Require(!::EncodeTlsAlpnProtocols(empty_alpn, alpn_wire),
                 "empty ALPN protocol must be rejected")));
    const std::vector<std::string> overlong_alpn = {std::string(256, 'a')};
    ASSERT_FALSE((!Require(!::EncodeTlsAlpnProtocols(overlong_alpn, alpn_wire),
                 "overlong ALPN protocol must be rejected")));
    const std::vector<std::string> duplicate_alpn = {"h2", "h2"};
    ASSERT_FALSE((!Require(!::EncodeTlsAlpnProtocols(duplicate_alpn, alpn_wire),
                 "duplicate ALPN protocol must be rejected")));
}
