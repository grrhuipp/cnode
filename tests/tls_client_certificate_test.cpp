#include "acppnode/transport/internet/tls_stream.hpp"
#include "autosign_cert.hpp"
#include "tls_client_context.hpp"

#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
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

int main() {
    acpp::transport::internet::AutoSignState certificates;
    auto material = certificates.GetOrCreate("client.example");
    CertificateFiles files;
    if (!Require(material.cert && material.key,
                 "client certificate material must be generated") ||
        !Require(WriteCertificateFiles(files, material.cert, material.key),
                 "client certificate files must be written")) {
        return 1;
    }

    acpp::TlsConfig config;
    config.cert_file = files.cert.string();
    config.key_file = files.key.string();
    config.allow_insecure = true;

    auto context = acpp::SslContext::CreateClient(config);
    if (!Require(context != nullptr, "client context must be created")) return 2;
    if (!Require(SSL_CTX_get0_certificate(context->Native()) != nullptr,
                 "client context must expose the configured certificate")) {
        return 3;
    }
    if (!Require(SSL_CTX_get0_privatekey(context->Native()) != nullptr,
                 "client context must expose the configured private key")) {
        return 4;
    }
    if (!Require(SSL_CTX_check_private_key(context->Native()) == 1,
                 "client certificate and private key must match")) {
        return 5;
    }

    acpp::TlsConfig private_ca_config;
    private_ca_config.ca_file = files.cert.string();
    auto private_ca_context = acpp::SslContext::CreateClient(private_ca_config);
    if (!Require(private_ca_context != nullptr,
                 "client context with private CA must be created")) {
        return 6;
    }
    if (!Require(VerifyCertificateWithContextStore(
                     material.cert, private_ca_context->Native()),
                 "configured private CA must be present in the client trust store")) {
        return 7;
    }

    acpp::TlsConfig tls13_config;
    tls13_config.allow_insecure = true;
    tls13_config.min_version = acpp::TlsVersion::V1_3;
    tls13_config.max_version = acpp::TlsVersion::V1_3;
    auto tls13_context = acpp::SslContext::CreateClient(tls13_config);
    if (!Require(tls13_context != nullptr,
                 "TLS 1.3-only client context must be created")) {
        return 8;
    }
    if (!Require(
            SSL_CTX_get_min_proto_version(tls13_context->Native()) ==
                TLS1_3_VERSION &&
            SSL_CTX_get_max_proto_version(tls13_context->Native()) ==
                TLS1_3_VERSION,
            "TLS 1.3-only policy must reach the client SSL context")) {
        return 9;
    }

    auto ip_material = certificates.GetOrCreate("192.0.2.1");
    SSL* ip_client = SSL_new(context->Native());
    if (!Require(ip_material.cert != nullptr && ip_material.key != nullptr &&
                     ip_client != nullptr,
                 "IP identity test material must be created")) {
        if (ip_client) SSL_free(ip_client);
        return 10;
    }
    if (!Require(ReplaceCommonName(
                     ip_material.cert, ip_material.key, "unrelated.example"),
                 "IP identity certificate common name must be replaced")) {
        SSL_free(ip_client);
        return 11;
    }
    if (!Require(acpp::ConfigureTlsServerIdentity(ip_client, "192.0.2.1"),
                 "IP server identity must be configured")) {
        SSL_free(ip_client);
        return 12;
    }
    if (!Require(SSL_get_servername(
                     ip_client, TLSEXT_NAMETYPE_host_name) == nullptr,
                 "IP server identity must not be sent as SNI")) {
        SSL_free(ip_client);
        return 13;
    }
    const bool ip_verified = VerifyCertificate(
        ip_material.cert, SSL_get0_param(ip_client));
    SSL_free(ip_client);
    if (!Require(ip_verified,
                 "IP SAN certificate must verify for its configured identity")) {
        return 14;
    }

    SSL* wrong_ip_client = SSL_new(context->Native());
    if (!Require(wrong_ip_client != nullptr &&
                     acpp::ConfigureTlsServerIdentity(
                         wrong_ip_client, "192.0.2.2"),
                 "wrong IP identity must be configured for rejection test")) {
        if (wrong_ip_client) SSL_free(wrong_ip_client);
        return 15;
    }
    const bool wrong_ip_verified = VerifyCertificate(
        ip_material.cert, SSL_get0_param(wrong_ip_client));
    SSL_free(wrong_ip_client);
    if (!Require(!wrong_ip_verified,
                 "IP SAN certificate must reject a different IP identity")) {
        return 16;
    }

    SSL* dns_client = SSL_new(context->Native());
    if (!Require(dns_client != nullptr &&
                     acpp::ConfigureTlsServerIdentity(
                         dns_client, "client.example"),
                 "DNS server identity must be configured")) {
        if (dns_client) SSL_free(dns_client);
        return 17;
    }
    const char* configured_sni = SSL_get_servername(
        dns_client, TLSEXT_NAMETYPE_host_name);
    const bool dns_verified = VerifyCertificate(
        material.cert, SSL_get0_param(dns_client));
    if (!Require(configured_sni != nullptr &&
                     std::string_view(configured_sni) == "client.example",
                 "DNS server identity must be sent as SNI")) {
        SSL_free(dns_client);
        return 18;
    }
    SSL_free(dns_client);
    if (!Require(dns_verified,
                 "DNS SAN certificate must verify for its configured identity")) {
        return 19;
    }

    std::vector<unsigned char> alpn_wire;
    const std::vector<std::string> valid_alpn = {"h2", "http/1.1"};
    const std::vector<unsigned char> expected_alpn_wire = {
        2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    if (!Require(acpp::EncodeTlsAlpnProtocols(valid_alpn, alpn_wire) &&
                     alpn_wire == expected_alpn_wire,
                 "valid ALPN protocols must have canonical wire encoding")) {
        return 20;
    }
    const std::vector<std::string> empty_alpn = {""};
    if (!Require(!acpp::EncodeTlsAlpnProtocols(empty_alpn, alpn_wire),
                 "empty ALPN protocol must be rejected")) {
        return 21;
    }
    const std::vector<std::string> overlong_alpn = {std::string(256, 'a')};
    if (!Require(!acpp::EncodeTlsAlpnProtocols(overlong_alpn, alpn_wire),
                 "overlong ALPN protocol must be rejected")) {
        return 22;
    }
    const std::vector<std::string> duplicate_alpn = {"h2", "h2"};
    if (!Require(!acpp::EncodeTlsAlpnProtocols(duplicate_alpn, alpn_wire),
                 "duplicate ALPN protocol must be rejected")) {
        return 23;
    }
    return 0;
}
