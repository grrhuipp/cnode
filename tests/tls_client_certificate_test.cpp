#include <gtest/gtest.h>

#include "transport/internet/tls_stream.hpp"
#include "transport/internet/tls_context.hpp"

#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <string_view>

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

class ClientCertificateFiles : public testing::Test {
protected:
    void SetUp() override {
        material = ::transport::internet::AutoSignCertificate::Create("client.example");
        ASSERT_NE(material, nullptr);
        ASSERT_TRUE(WriteCertificateFiles(files, material->Certificate(), material->Key()));
        config.cert_file = files.cert.string();
        config.key_file = files.key.string();
        config.allow_insecure = true;
        ::LoadTlsPemMaterial(config);
    }
    decltype(::transport::internet::AutoSignCertificate::Create("")) material;
    CertificateFiles files;
    ::TlsConfig config;
};

TEST_F(ClientCertificateFiles, LoadsMatchingClientCredentials) {
    auto context = ::SslContext::CreateClient(config);
    ASSERT_NE(context, nullptr);
    EXPECT_NE(SSL_CTX_get0_certificate(context->Native()), nullptr);
    EXPECT_NE(SSL_CTX_get0_privatekey(context->Native()), nullptr);
    EXPECT_EQ(SSL_CTX_check_private_key(context->Native()), 1);
}

TEST_F(ClientCertificateFiles, PrivateCaCanVerifyConfiguredCertificate) {
    ::TlsConfig ca_config;
    ca_config.ca_file = files.cert.string();
    ::LoadTlsPemMaterial(ca_config);
    auto context = ::SslContext::CreateClient(ca_config);
    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(VerifyCertificateWithContextStore(material->Certificate(), context->Native()));
}

TEST_F(ClientCertificateFiles, RejectsMalformedPemAfterLeafCertificate) {
    auto malformed = std::make_shared<::TlsPemMaterial>();
    malformed->certificate_chain = config.pem->certificate_chain +
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    malformed->private_key = config.pem->private_key;
    config.pem = std::move(malformed);
    EXPECT_EQ(::SslContext::CreateClient(config), nullptr);
}

TEST_F(ClientCertificateFiles, RejectsUnreadableCaWithoutPublishingPartialMaterial) {
    ::TlsConfig unreadable;
    unreadable.ca_file = files.cert.string() + ".missing";
    EXPECT_THROW(::LoadTlsPemMaterial(unreadable), std::invalid_argument);
    EXPECT_FALSE(unreadable.pem);
}

TEST(TlsClientCertificate, EnforcesExplicitTls13OnlyPolicy) {
    ::TlsConfig config;
    config.allow_insecure = true;
    config.min_version = ::TlsVersion::V1_3;
    config.max_version = ::TlsVersion::V1_3;
    auto context = ::SslContext::CreateClient(config);
    ASSERT_NE(context, nullptr);
    EXPECT_EQ(SSL_CTX_get_min_proto_version(context->Native()), TLS1_3_VERSION);
    EXPECT_EQ(SSL_CTX_get_max_proto_version(context->Native()), TLS1_3_VERSION);
}

class TlsIdentityTest : public testing::Test {
protected:
    void SetUp() override {
        ::TlsConfig config;
        config.allow_insecure = true;
        context = ::SslContext::CreateClient(config);
        ASSERT_NE(context, nullptr);
        client.reset(SSL_new(context->Native()));
        ASSERT_NE(client, nullptr);
    }
    decltype(::SslContext::CreateClient(::TlsConfig{})) context;
    bssl::UniquePtr<SSL> client;
};

class InvalidTlsIdentity : public TlsIdentityTest, public testing::WithParamInterface<std::string_view> {};
TEST_P(InvalidTlsIdentity, RejectsInvalidIdentityBeforeConfiguringSniOrSan) {
    EXPECT_FALSE(::ConfigureTlsServerIdentity(client.get(), GetParam()));
}
using namespace std::string_view_literals;
INSTANTIATE_TEST_SUITE_P(Identities, InvalidTlsIdentity, testing::Values(
    "127.0.0.1:9"sv, "[::1]"sv, "bad..example"sv, "fe80::1%invalid"sv, "127.0.0.1\0ignored"sv));

class Ipv6TlsIdentity : public TlsIdentityTest, public testing::WithParamInterface<const char*> {};
TEST_P(Ipv6TlsIdentity, ConfiguresIpVerificationWithoutSendingSni) {
    ASSERT_TRUE(::ConfigureTlsServerIdentity(client.get(), GetParam()));
    EXPECT_EQ(SSL_get_servername(client.get(), TLSEXT_NAMETYPE_host_name), nullptr);
}
INSTANTIATE_TEST_SUITE_P(Addresses, Ipv6TlsIdentity,
                        testing::Values("2001:db8::1", "fe80::1%3", "::ffff:192.0.2.1"));

class IpSanVerification : public TlsIdentityTest, public testing::WithParamInterface<bool> {};
TEST_P(IpSanVerification, VerifiesOnlyMatchingIpSanWithoutCommonNameFallback) {
    auto material = ::transport::internet::AutoSignCertificate::Create("192.0.2.1");
    ASSERT_NE(material, nullptr);
    ASSERT_TRUE(ReplaceCommonName(material->Certificate(), material->Key(), "unrelated.example"));
    ASSERT_TRUE(::ConfigureTlsServerIdentity(client.get(), GetParam() ? "192.0.2.1" : "192.0.2.2"));
    EXPECT_EQ(SSL_get_servername(client.get(), TLSEXT_NAMETYPE_host_name), nullptr);
    EXPECT_EQ(VerifyCertificate(material->Certificate(), SSL_get0_param(client.get())), GetParam());
}
INSTANTIATE_TEST_SUITE_P(MatchingAddress, IpSanVerification, testing::Bool());

class DnsSanVerification : public TlsIdentityTest, public testing::WithParamInterface<const char*> {};
TEST_P(DnsSanVerification, NormalizesRootDotForSniAndCertificateVerification) {
    auto material = ::transport::internet::AutoSignCertificate::Create("client.example");
    ASSERT_NE(material, nullptr);
    ASSERT_TRUE(::ConfigureTlsServerIdentity(client.get(), GetParam()));
    const auto* sni = SSL_get_servername(client.get(), TLSEXT_NAMETYPE_host_name);
    ASSERT_NE(sni, nullptr);
    EXPECT_STREQ(sni, "client.example");
    EXPECT_TRUE(VerifyCertificate(material->Certificate(), SSL_get0_param(client.get())));
}
INSTANTIATE_TEST_SUITE_P(HostNames, DnsSanVerification, testing::Values("client.example", "client.example."));

TEST(TlsClientCertificate, EncodesAlpnAsLengthPrefixedProtocolNames) {
    std::vector<unsigned char> wire;
    ASSERT_TRUE(::EncodeTlsAlpnProtocols(std::vector<std::string>{"h2", "http/1.1"}, wire));
    EXPECT_EQ(wire, (std::vector<unsigned char>{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}));
}

class InvalidTlsAlpn : public testing::TestWithParam<std::vector<std::string>> {};
TEST_P(InvalidTlsAlpn, RejectsEmptyOverlongOrDuplicateProtocolNames) {
    std::vector<unsigned char> wire;
    EXPECT_FALSE(::EncodeTlsAlpnProtocols(GetParam(), wire));
}
INSTANTIATE_TEST_SUITE_P(Protocols, InvalidTlsAlpn, testing::Values(
    std::vector<std::string>{""}, std::vector<std::string>{std::string(256, 'a')},
    std::vector<std::string>{"h2", "h2"}));

TEST_F(ClientCertificateFiles, QuicServerRestrictsTlsToVersion13) {
    config.min_version = ::TlsVersion::V1_2;
    config.max_version = ::TlsVersion::V1_3;
    auto context = ::SslContext::CreateQuicServer(config, std::vector<std::string>{"h3"});
    ASSERT_NE(context, nullptr);
    EXPECT_EQ(SSL_CTX_get_min_proto_version(context->Native()), TLS1_3_VERSION);
    EXPECT_EQ(SSL_CTX_get_max_proto_version(context->Native()), TLS1_3_VERSION);
}

enum class InvalidQuicPolicy { Tls12Only, UnknownVersion, MissingAlpn, EmptyAlpn };
class QuicRejectedPolicy : public ClientCertificateFiles, public testing::WithParamInterface<InvalidQuicPolicy> {};
TEST_P(QuicRejectedPolicy, RejectsUnsupportedVersionOrAlpnPolicy) {
    config.min_version = ::TlsVersion::V1_2;
    config.max_version = ::TlsVersion::V1_3;
    std::vector<std::string> alpn{"h3"};
    switch (GetParam()) {
        case InvalidQuicPolicy::Tls12Only: config.max_version = ::TlsVersion::V1_2; break;
        case InvalidQuicPolicy::UnknownVersion: config.min_version = static_cast<::TlsVersion>(255); break;
        case InvalidQuicPolicy::MissingAlpn: alpn.clear(); break;
        case InvalidQuicPolicy::EmptyAlpn: alpn = {""}; break;
    }
    EXPECT_EQ(::SslContext::CreateQuicServer(config, alpn), nullptr);
}
INSTANTIATE_TEST_SUITE_P(Policies, QuicRejectedPolicy, testing::Values(
    InvalidQuicPolicy::Tls12Only, InvalidQuicPolicy::UnknownVersion,
    InvalidQuicPolicy::MissingAlpn, InvalidQuicPolicy::EmptyAlpn));

class QuicAlpnHandshake : public ClientCertificateFiles, public testing::WithParamInterface<bool> {};
TEST_P(QuicAlpnHandshake, NegotiatesOnlyACommonConfiguredProtocol) {
    auto context = ::SslContext::CreateQuicServer(config, std::vector<std::string>{"h3"});
    ASSERT_NE(context, nullptr);
    ::TlsConfig client_config;
    client_config.allow_insecure = true;
    client_config.alpn = GetParam()
        ? std::vector<std::string>{"unrelated", "h3"} : std::vector<std::string>{"unrelated"};
    auto client_context = ::SslContext::CreateClient(client_config);
    ASSERT_NE(client_context, nullptr);
    bssl::UniquePtr<SSL> client(SSL_new(client_context->Native()));
    bssl::UniquePtr<SSL> server(SSL_new(context->Native()));
    ASSERT_NE(client, nullptr);
    ASSERT_NE(server, nullptr);
    BIO* client_bio = nullptr;
    BIO* server_bio = nullptr;
    ASSERT_EQ(BIO_new_bio_pair(&client_bio, 0, &server_bio, 0), 1);
    SSL_set_bio(client.get(), client_bio, client_bio);
    SSL_set_bio(server.get(), server_bio, server_bio);
    SSL_set_connect_state(client.get());
    SSL_set_accept_state(server.get());
    bool failed = false;
    for (size_t round = 0; round < 16 && !failed &&
         (!SSL_is_init_finished(client.get()) || !SSL_is_init_finished(server.get())); ++round) {
        for (SSL* ssl : {client.get(), server.get()}) {
            const int result = SSL_do_handshake(ssl);
            if (result == 1) continue;
            const int error = SSL_get_error(ssl, result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                failed = true;
                break;
            }
        }
    }
    EXPECT_EQ(failed, !GetParam());
    if (GetParam()) {
        ASSERT_TRUE(SSL_is_init_finished(client.get()));
        ASSERT_TRUE(SSL_is_init_finished(server.get()));
        const uint8_t* selected = nullptr;
        unsigned int size = 0;
        SSL_get0_alpn_selected(client.get(), &selected, &size);
        ASSERT_NE(selected, nullptr);
        EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(selected), size), "h3");
    }
}
INSTANTIATE_TEST_SUITE_P(CommonProtocol, QuicAlpnHandshake, testing::Bool());
}  // namespace
