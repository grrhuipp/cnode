#include "acppnode/transport/internet/tls_stream.hpp"
#include "autosign_cert.hpp"

#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>

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
    return 0;
}
