#include "transport/internet/tls_stream.hpp"
#include "common/domain_name.hpp"
#include "common/ip_address.hpp"

#include "tls_client_context.hpp"

#include "common/asio_types.hpp"
#include "infra/log.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <array>
#include <cstring>
#include <memory>
#include <string>


namespace {

uint16_t ToOpenSslVersion(TlsVersion version) noexcept {
    switch (version) {
        case TlsVersion::V1_2:
            return TLS1_2_VERSION;
        case TlsVersion::V1_3:
            return TLS1_3_VERSION;
    }
    return 0;
}

[[nodiscard]] bssl::UniquePtr<BIO> PemReader(const std::string& pem) {
    return bssl::UniquePtr<BIO>(BIO_new_mem_buf(
        pem.data(), static_cast<ossl_ssize_t>(pem.size())));
}

int RejectEncryptedPemPassword(char*, int, int, void*) noexcept {
    return -1;
}

// PEM readers report the end of input as PEM_R_NO_START_LINE; anything else
// is a malformed block. Clears the queue so no stale error reaches later
// SSL_get_error calls on this thread.
[[nodiscard]] bool ConsumePemEndOfInput() noexcept {
    const uint32_t error = ERR_peek_last_error();
    ERR_clear_error();
    return ERR_GET_LIB(error) == ERR_LIB_PEM &&
        ERR_GET_REASON(error) == PEM_R_NO_START_LINE;
}

// In-memory SSL_CTX_load_verify_locations: like X509_load_cert_crl_file it
// reads every PEM_X509_INFO block (including TRUSTED CERTIFICATE and CRLs);
// a bundle without any certificate or CRL is rejected.
[[nodiscard]] bool ConfigureTlsTrustedCaPem(SSL_CTX* context, const std::string& pem) {
    ERR_clear_error();
    auto reader = PemReader(pem);
    X509_STORE* store = SSL_CTX_get_cert_store(context);
    if (!reader || !store) {
        ERR_clear_error();
        return false;
    }
    struct InfoStackFree {
        void operator()(STACK_OF(X509_INFO)* infos) const noexcept {
            sk_X509_INFO_pop_free(infos, X509_INFO_free);
        }
    };
    std::unique_ptr<STACK_OF(X509_INFO), InfoStackFree> infos(
        PEM_X509_INFO_read_bio(reader.get(), nullptr, &RejectEncryptedPemPassword, nullptr));
    if (!infos) {
        ERR_clear_error();
        return false;
    }
    size_t loaded = 0;
    for (size_t i = 0; i < sk_X509_INFO_num(infos.get()); ++i) {
        const X509_INFO* info = sk_X509_INFO_value(infos.get(), i);
        if (info->x509) {
            if (X509_STORE_add_cert(store, info->x509) != 1) {
                const uint32_t err = ERR_peek_last_error();
                if (ERR_GET_LIB(err) == ERR_LIB_X509 &&
                    ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                    ERR_clear_error();
                    ++loaded;
                } else {
                    ERR_clear_error();
                    return false;
                }
            } else {
                ++loaded;
            }
        }
        if (info->crl) {
            if (X509_STORE_add_crl(store, info->crl) != 1) {
                ERR_clear_error();
                return false;
            }
            ++loaded;
        }
    }
    ERR_clear_error();
    return loaded != 0;
}

}  // namespace

bool ConfigureTlsCertificatePem(SSL_CTX* context, const TlsPemMaterial& pem) {
    ERR_clear_error();
    auto chain = PemReader(pem.certificate_chain);
    if (!chain) {
        ERR_clear_error();
        return false;
    }
    bssl::UniquePtr<X509> leaf(
        PEM_read_bio_X509_AUX(chain.get(), nullptr, &RejectEncryptedPemPassword, nullptr));
    if (!leaf || SSL_CTX_use_certificate(context, leaf.get()) != 1) {
        ERR_clear_error();
        LOG_ERROR("TLS certificate file does not start with a valid PEM certificate");
        return false;
    }
    while (bssl::UniquePtr<X509> intermediate{
               PEM_read_bio_X509(chain.get(), nullptr, &RejectEncryptedPemPassword, nullptr)}) {
        if (SSL_CTX_add1_chain_cert(context, intermediate.get()) != 1) {
            ERR_clear_error();
            LOG_ERROR("failed to install TLS certificate chain");
            return false;
        }
    }
    if (!ConsumePemEndOfInput()) {
        LOG_ERROR("TLS certificate file contains a malformed PEM block");
        return false;
    }

    auto key_reader = PemReader(pem.private_key);
    bssl::UniquePtr<EVP_PKEY> key(key_reader
        ? PEM_read_bio_PrivateKey(key_reader.get(), nullptr, &RejectEncryptedPemPassword, nullptr)
        : nullptr);
    if (!key || SSL_CTX_use_PrivateKey(context, key.get()) != 1) {
        ERR_clear_error();
        LOG_ERROR("TLS private key file does not contain a valid PEM private key");
        return false;
    }
    if (SSL_CTX_check_private_key(context) != 1) {
        ERR_clear_error();
        LOG_ERROR("TLS private key does not match certificate");
        return false;
    }
    ERR_clear_error();
    return true;
}

bool ConfigureTlsProtocolVersions(
    SSL_CTX* context,
    TlsVersion min_version,
    TlsVersion max_version) noexcept {
    const uint16_t minimum = ToOpenSslVersion(min_version);
    const uint16_t maximum = ToOpenSslVersion(max_version);
    return context && minimum != 0 && maximum != 0 && minimum <= maximum &&
        SSL_CTX_set_min_proto_version(context, minimum) == 1 &&
        SSL_CTX_set_max_proto_version(context, maximum) == 1;
}

bool EncodeTlsAlpnProtocols(
    std::span<const std::string> protocols,
    std::vector<unsigned char>& wire) {
    wire.clear();
    if (!IsValidTlsAlpn(protocols)) return false;

    std::size_t wire_size = 0;
    for (const auto& protocol : protocols) {
        wire_size += 1 + protocol.size();
    }
    wire.reserve(wire_size);
    for (const auto& protocol : protocols) {
        wire.push_back(static_cast<unsigned char>(protocol.size()));
        wire.insert(wire.end(), protocol.begin(), protocol.end());
    }
    return true;
}

bool ConfigureTlsClientAlpn(
    SSL_CTX* context, std::span<const std::string> protocols) {
    std::vector<unsigned char> wire;
    // SSL_new copies the context list, so no handshake encodes it again.
    return EncodeTlsAlpnProtocols(protocols, wire) &&
        (wire.empty() || SSL_CTX_set_alpn_protos(context, wire.data(), wire.size()) == 0);
}

bool ConfigureTlsServerIdentity(
    SSL* ssl, std::string_view identity) {
    if (!ssl || identity.empty() || identity.find('\0') != std::string_view::npos) {
        return false;
    }

    if (const auto address = iputil::ParseLiteral(identity)) {
        X509_VERIFY_PARAM* parameters = SSL_get0_param(ssl);
        if (!parameters) return false;
        if (address->is_v4()) {
            const auto bytes = address->to_v4().to_bytes();
            return X509_VERIFY_PARAM_set1_ip(parameters, bytes.data(), bytes.size()) == 1;
        }
        const auto bytes = address->to_v6().to_bytes();
        return X509_VERIFY_PARAM_set1_ip(parameters, bytes.data(), bytes.size()) == 1;
    }
    if (!domain::IsValidDnsHostname(identity, domain::TrailingDotPolicy::Allow)) return false;
    identity = domain::WithoutTrailingRootDot(identity);
    std::array<char, 256> identity_text{};
    if (identity.size() >= identity_text.size()) return false;
    std::memcpy(identity_text.data(), identity.data(), identity.size());

    if (SSL_set_tlsext_host_name(ssl, identity_text.data()) != 1) {
        return false;
    }
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    return SSL_set1_host(ssl, identity_text.data()) == 1;
}

std::unique_ptr<SslContext> SslContext::CreateClient(const TlsConfig& config) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        LOG_ERROR("failed to create TLS client context");
        return nullptr;
    }

    if (!ConfigureTlsProtocolVersions(
            ctx, config.min_version, config.max_version)) {
        LOG_ERROR("invalid TLS client protocol version policy");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (!ConfigureTlsClientAlpn(ctx, config.alpn)) {
        LOG_ERROR("invalid TLS client ALPN policy");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (config.cert_file.empty() != config.key_file.empty()) {
        LOG_ERROR("TLS client certificate and private key must be configured together");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if ((config.HasCertificatePair() || !config.ca_file.empty()) && !config.pem) {
        LOG_ERROR("TLS client files were not loaded with the configuration");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (config.HasCertificatePair() &&
        !ConfigureTlsCertificatePem(ctx, *config.pem)) {
        LOG_ERROR("failed to load TLS client certificate from {}", config.cert_file);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (config.allow_insecure && !config.ca_file.empty()) {
        LOG_ERROR("TLS client CA cannot be used when certificate verification is disabled");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (config.allow_insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        const bool trust_loaded = config.ca_file.empty()
            ? SSL_CTX_set_default_verify_paths(ctx) == 1
            : ConfigureTlsTrustedCaPem(ctx, config.pem->trusted_ca);
        if (!trust_loaded) {
            LOG_ERROR("failed to load TLS client trust store from {}",
                      config.ca_file.empty() ? "system defaults"
                                             : config.ca_file);
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }

    return std::unique_ptr<SslContext>(new SslContext(ctx));
}

SslContext::SslContext(SSL_CTX* ctx, std::unique_ptr<ContextState> context_state)
    : ctx_(ctx) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> guard(ctx, SSL_CTX_free);
    static const int index = SSL_CTX_get_ex_new_index(
        0, nullptr, nullptr, nullptr,
        [](void*, void* ptr, CRYPTO_EX_DATA*, int, long, void*) {
            delete static_cast<SharedState*>(ptr);
        });
    auto state = std::make_unique<SharedState>();
    state->context = std::move(context_state);
    if (index < 0 || SSL_CTX_set_ex_data(ctx_, index, state.get()) != 1)
        throw std::bad_alloc();
    shared_state_ = state.release();
    native_owner_ = std::shared_ptr<SSL_CTX>(guard.release(), SSL_CTX_free);
}

SslContext::~SslContext() = default;

