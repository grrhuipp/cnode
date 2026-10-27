#include "reality_tls.hpp"
#include "reality_key_share.hpp"
#include "acppnode/transport/internet/reality_client_version.hpp"
#include "acppnode/transport/internet/reality_key.hpp"
#include "acppnode/transport/internet/reality_server_name.hpp"
#include "acppnode/transport/internet/reality_short_id.hpp"
#include "acppnode/transport/internet/tls_server_name.hpp"

#include "acppnode/transport/internet/tls_stream.hpp"
#include "acppnode/transport/internet/openssl_thread_pool.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/unsafe.hpp"

#include <openssl/aead.h>
#include <openssl/asn1.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace acpp {

namespace {

// ============================================================================
// REALITY 服务端：在 TLS ClientHello 阶段完成 REALITY 认证并动态签发证书
// ============================================================================

constexpr size_t kRealityX25519KeySize = 32;
constexpr size_t kRealityRandomSize = 32;
constexpr size_t kRealitySessionIdSize = 32;
constexpr size_t kRealityPlainAuthSize = 16;
constexpr size_t kRealityShortIdSize = transport::internet::kRealityShortIdSize;
constexpr size_t kRealityAesGcmNonceSize = 12;

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept {
        EVP_PKEY_free(key);
    }
};

struct X509Deleter {
    void operator()(X509* cert) const noexcept {
        X509_free(cert);
    }
};

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* ctx) const noexcept {
        EVP_MD_CTX_free(ctx);
    }
};

struct Asn1ObjectDeleter {
    void operator()(ASN1_OBJECT* obj) const noexcept {
        ASN1_OBJECT_free(obj);
    }
};

struct Asn1OctetStringDeleter {
    void operator()(ASN1_OCTET_STRING* str) const noexcept {
        ASN1_OCTET_STRING_free(str);
    }
};

struct X509ExtensionDeleter {
    void operator()(X509_EXTENSION* ext) const noexcept {
        X509_EXTENSION_free(ext);
    }
};

using UniqueEvpPkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using UniqueEvpMdCtx = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using UniqueX509 = std::unique_ptr<X509, X509Deleter>;
using UniqueAsn1Object = std::unique_ptr<ASN1_OBJECT, Asn1ObjectDeleter>;
using UniqueAsn1OctetString = std::unique_ptr<ASN1_OCTET_STRING, Asn1OctetStringDeleter>;
using UniqueX509Extension = std::unique_ptr<X509_EXTENSION, X509ExtensionDeleter>;

struct RealityServerState final : SslContext::ContextState {
    std::array<uint8_t, kRealityX25519KeySize> private_key{};
    std::vector<std::string> server_names;
    std::vector<transport::internet::RealityShortId> short_ids;
    std::optional<transport::internet::RealityClientVersion> min_client_version;
    std::optional<transport::internet::RealityClientVersion> max_client_version;
    uint64_t max_time_diff_ms = 0;
    UniqueEvpPkey ed25519_key;
    std::array<uint8_t, 32> ed25519_public{};
    UniqueEvpPkey mldsa65_key;
};

struct RealityServerConnState {
    std::array<uint8_t, 32> auth_key{};
    std::vector<uint8_t> client_hello_raw;
    bool authenticated = false;
};

void FreeRealityServerConnState(void* /*parent*/,
                                void* ptr,
                                CRYPTO_EX_DATA* /*ad*/,
                                int /*index*/,
                                long /*argl*/,
                                void* /*argp*/) {
    delete static_cast<RealityServerConnState*>(ptr);
}

[[nodiscard]] int RealityStateExIndex() {
    static const int index = SSL_CTX_get_ex_new_index(
        0, nullptr, nullptr, nullptr, nullptr);
    return index;
}

[[nodiscard]] int RealityConnStateExIndex() {
    static const int index = SSL_get_ex_new_index(
        0, nullptr, nullptr, nullptr, FreeRealityServerConnState);
    return index;
}

enum class RealitySniParseResult {
    Missing,
    Present,
    Invalid,
};

[[nodiscard]] RealitySniParseResult ParseRealitySni(
    const SSL_CLIENT_HELLO& hello,
    std::string_view& out) noexcept {
    const uint8_t* ext = nullptr;
    size_t ext_len = 0;
    if (SSL_early_callback_ctx_extension_get(
            &hello,
            TLSEXT_TYPE_server_name,
            &ext,
            &ext_len) != 1) {
        return RealitySniParseResult::Missing;
    }
    if (!ext) {
        return RealitySniParseResult::Invalid;
    }
    auto parsed = transport::internet::ParseTlsServerNameExtension(
        std::span<const uint8_t>(ext, ext_len));
    if (!parsed) {
        return RealitySniParseResult::Invalid;
    }
    out = *parsed;
    return RealitySniParseResult::Present;
}

[[nodiscard]] std::optional<std::array<uint8_t, kRealityX25519KeySize>>
ParseRealityPeerPublicKey(const SSL_CLIENT_HELLO& hello) noexcept {
    const uint8_t* ext = nullptr;
    size_t ext_len = 0;
    if (SSL_early_callback_ctx_extension_get(
            &hello,
            TLSEXT_TYPE_key_share,
            &ext,
            &ext_len) != 1 ||
        !ext) {
        return std::nullopt;
    }
    auto parsed = transport::internet::ParseRealityClientKeyShareExtension(
        std::span<const uint8_t>(ext, ext_len));
    if (!parsed) return std::nullopt;
    return *parsed;
}

[[nodiscard]] std::vector<uint8_t> BuildRealityClientHelloAad(
    const SSL_CLIENT_HELLO& hello) {
    std::vector<uint8_t> aad;
    const bool has_handshake_header =
        hello.client_hello_len >= 4 &&
        hello.client_hello[0] == 0x01 &&
        (static_cast<size_t>(hello.client_hello[1]) << 16 |
         static_cast<size_t>(hello.client_hello[2]) << 8 |
         static_cast<size_t>(hello.client_hello[3])) ==
            hello.client_hello_len - 4;
    if (has_handshake_header) {
        aad.assign(hello.client_hello,
                   hello.client_hello + hello.client_hello_len);
    } else {
        aad.resize(4 + hello.client_hello_len);
        aad[0] = 0x01;
        aad[1] = static_cast<uint8_t>((hello.client_hello_len >> 16) & 0xff);
        aad[2] = static_cast<uint8_t>((hello.client_hello_len >> 8) & 0xff);
        aad[3] = static_cast<uint8_t>(hello.client_hello_len & 0xff);
        std::copy_n(hello.client_hello, hello.client_hello_len, aad.data() + 4);
    }

    std::optional<size_t> aad_session_offset;
    if (hello.session_id &&
        hello.session_id >= hello.client_hello &&
        hello.session_id + hello.session_id_len <=
            hello.client_hello + hello.client_hello_len) {
        const size_t session_offset =
            static_cast<size_t>(hello.session_id - hello.client_hello);
        aad_session_offset = session_offset + (has_handshake_header ? 0 : 4);
    } else {
        const size_t body_start = has_handshake_header ? 4 : 0;
        const size_t session_len_offset = body_start + 2 + kRealityRandomSize;
        if (aad.size() >= session_len_offset + 1) {
            const size_t session_len = aad[session_len_offset];
            const size_t session_offset = session_len_offset + 1;
            if (session_len == hello.session_id_len &&
                aad.size() >= session_offset + session_len) {
                aad_session_offset = session_offset;
            }
        }
    }

    if (aad_session_offset &&
        aad.size() >= *aad_session_offset + hello.session_id_len) {
        std::fill_n(
            aad.data() + *aad_session_offset,
            hello.session_id_len,
            uint8_t{0});
    }
    return aad;
}

[[nodiscard]] std::optional<std::array<uint8_t, 32>> DeriveRealityAuthKey(
    std::span<const uint8_t> shared,
    std::span<const uint8_t, 20> random_salt) noexcept;

[[nodiscard]] std::optional<std::array<uint8_t, 32>> ComputeRealityAuthKey(
    const RealityServerState& state,
    std::span<const uint8_t, kRealityX25519KeySize> peer_public,
    std::span<const uint8_t, 20> random_salt) noexcept {
    std::array<uint8_t, kRealityX25519KeySize> shared{};
    if (X25519(shared.data(), state.private_key.data(), peer_public.data()) != 1) {
        return std::nullopt;
    }

    return DeriveRealityAuthKey(
        std::span<const uint8_t, kRealityX25519KeySize>(
            shared.data(), shared.size()),
        random_salt);
}

[[nodiscard]] std::optional<std::array<uint8_t, 32>> DeriveRealityAuthKey(
    std::span<const uint8_t> shared,
    std::span<const uint8_t, 20> random_salt) noexcept {
    std::array<uint8_t, 32> auth_key{};
    static constexpr std::string_view kRealityInfo = "REALITY";
    if (HKDF(auth_key.data(),
             auth_key.size(),
             EVP_sha256(),
             shared.data(),
             shared.size(),
             random_salt.data(),
             random_salt.size(),
             unsafe::ptr_cast<const uint8_t>(kRealityInfo.data()),
             kRealityInfo.size()) != 1) {
        return std::nullopt;
    }
    return auth_key;
}

[[nodiscard]] std::optional<std::array<uint8_t, kRealityPlainAuthSize>>
OpenRealitySessionId(
    std::span<const uint8_t, 32> auth_key,
    std::span<const uint8_t, kRealityAesGcmNonceSize> nonce,
    std::span<const uint8_t, kRealitySessionIdSize> ciphertext,
    std::span<const uint8_t> aad) noexcept {
    EVP_AEAD_CTX aead;
    EVP_AEAD_CTX_zero(&aead);
    if (EVP_AEAD_CTX_init(&aead,
                          EVP_aead_aes_256_gcm(),
                          auth_key.data(),
                          auth_key.size(),
                          EVP_AEAD_DEFAULT_TAG_LENGTH,
                          nullptr) != 1) {
        return std::nullopt;
    }

    std::array<uint8_t, kRealityPlainAuthSize> plain{};
    size_t plain_len = 0;
    const int ok = EVP_AEAD_CTX_open(&aead,
                                     plain.data(),
                                     &plain_len,
                                     plain.size(),
                                     nonce.data(),
                                     nonce.size(),
                                     ciphertext.data(),
                                     ciphertext.size(),
                                     aad.data(),
                                     aad.size());
    EVP_AEAD_CTX_cleanup(&aead);
    if (ok != 1 || plain_len != plain.size()) {
        return std::nullopt;
    }
    return plain;
}

[[nodiscard]] std::optional<std::array<uint8_t, kRealitySessionIdSize>>
SealRealitySessionId(
    std::span<const uint8_t, 32> auth_key,
    std::span<const uint8_t, kRealityAesGcmNonceSize> nonce,
    std::span<const uint8_t, kRealityPlainAuthSize> plain,
    std::span<const uint8_t> aad) noexcept {
    EVP_AEAD_CTX aead;
    EVP_AEAD_CTX_zero(&aead);
    if (EVP_AEAD_CTX_init(&aead,
                          EVP_aead_aes_256_gcm(),
                          auth_key.data(),
                          auth_key.size(),
                          EVP_AEAD_DEFAULT_TAG_LENGTH,
                          nullptr) != 1) {
        return std::nullopt;
    }

    std::array<uint8_t, kRealitySessionIdSize> out{};
    size_t out_len = 0;
    const int ok = EVP_AEAD_CTX_seal(&aead,
                                     out.data(),
                                     &out_len,
                                     out.size(),
                                     nonce.data(),
                                     nonce.size(),
                                     plain.data(),
                                     plain.size(),
                                     aad.data(),
                                     aad.size());
    EVP_AEAD_CTX_cleanup(&aead);
    if (ok != 1 || out_len != out.size()) {
        return std::nullopt;
    }
    return out;
}

[[nodiscard]] std::array<uint8_t, kRealityPlainAuthSize>
BuildRealityClientAuthPlain(
    std::span<const uint8_t, kRealityShortIdSize> short_id) noexcept {
    std::array<uint8_t, kRealityPlainAuthSize> plain{};
    plain[0] = 1;
    plain[1] = 0;
    plain[2] = 0;
    plain[3] = 0;

    const auto now = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    plain[4] = static_cast<uint8_t>((now >> 24) & 0xff);
    plain[5] = static_cast<uint8_t>((now >> 16) & 0xff);
    plain[6] = static_cast<uint8_t>((now >> 8) & 0xff);
    plain[7] = static_cast<uint8_t>(now & 0xff);
    std::copy(short_id.begin(), short_id.end(), plain.begin() + 8);
    return plain;
}

[[nodiscard]] std::unique_ptr<RealityClientState> BuildRealityClientState(
    const RealityConfig& config) {
    if (!config.public_key) {
        LOG_ERROR("REALITY client publicKey is empty");
        return nullptr;
    }
    auto state = std::make_unique<RealityClientState>();
    state->server_public = *config.public_key;
    state->short_id = config.short_id;
    state->server_name = config.server_name;
    state->spider_x = config.spider_x;
    state->mldsa65_verify = config.mldsa65_verify;
    return state;
}

void RealityClientMsgCallback(int is_write,
                              int /*version*/,
                              int content_type,
                              const void* buf,
                              size_t len,
                              SSL* /*ssl*/,
                              void* arg) {
    if (content_type != SSL3_RT_HANDSHAKE || !buf || len < 4 || !arg) {
        return;
    }
    auto* state = static_cast<RealityClientState*>(arg);
    const auto* bytes = static_cast<const uint8_t*>(buf);
    if (is_write && bytes[0] == SSL3_MT_CLIENT_HELLO) {
        state->client_hello_raw.assign(bytes, bytes + len);
    } else if (!is_write && bytes[0] == SSL3_MT_SERVER_HELLO) {
        state->server_hello_raw.assign(bytes, bytes + len);
    }
}
int RealityClientHelloCallback(SSL* /*ssl*/,
                               const uint8_t* shared_secret,
                               size_t shared_secret_len,
                               const uint8_t* client_random,
                               size_t client_random_len,
                               const uint8_t* client_hello,
                               size_t client_hello_len,
                               uint8_t* out_session_id,
                               size_t out_session_id_len,
                               void* arg) {
    auto* state = static_cast<RealityClientState*>(arg);
    if (!state ||
        !shared_secret ||
        shared_secret_len != kRealityX25519KeySize ||
        !client_random ||
        client_random_len != kRealityRandomSize ||
        !client_hello ||
        client_hello_len == 0 ||
        !out_session_id ||
        out_session_id_len != kRealitySessionIdSize) {
        return 0;
    }

    auto auth_key = DeriveRealityAuthKey(
        std::span<const uint8_t>(shared_secret, shared_secret_len),
        std::span<const uint8_t, 20>(client_random, 20));
    if (!auth_key) {
        return 0;
    }

    const auto plain = BuildRealityClientAuthPlain(
        std::span<const uint8_t, kRealityShortIdSize>(
            state->short_id.data(), state->short_id.size()));
    auto encrypted = SealRealitySessionId(
        std::span<const uint8_t, 32>(auth_key->data(), auth_key->size()),
        std::span<const uint8_t, kRealityAesGcmNonceSize>(
            client_random + 20, kRealityAesGcmNonceSize),
        std::span<const uint8_t, kRealityPlainAuthSize>(
            plain.data(), plain.size()),
        std::span<const uint8_t>(client_hello, client_hello_len));
    if (!encrypted) {
        return 0;
    }

    state->auth_key = *auth_key;
    state->auth_key_ready = true;
    std::copy(encrypted->begin(), encrypted->end(), out_session_id);
    return 1;
}

[[nodiscard]] bool VerifyRealityPeerCertificate(
    SSL* ssl,
    const RealityClientState& state) {
    if (!ssl || !state.auth_key_ready) {
        return false;
    }

    UniqueX509 cert(SSL_get_peer_certificate(ssl));
    if (!cert) {
        LOG_NET_DEBUG("REALITY client verification failed: missing peer certificate");
        return false;
    }

    EVP_PKEY* pubkey = X509_get0_pubkey(cert.get());
    if (!pubkey || EVP_PKEY_id(pubkey) != EVP_PKEY_ED25519) {
        LOG_NET_DEBUG("REALITY client verification failed: peer key is not Ed25519");
        return false;
    }

    std::array<uint8_t, 32> peer_public{};
    size_t peer_public_len = peer_public.size();
    if (EVP_PKEY_get_raw_public_key(
            pubkey,
            peer_public.data(),
            &peer_public_len) != 1 ||
        peer_public_len != peer_public.size()) {
        LOG_NET_DEBUG("REALITY client verification failed: peer public key export failed");
        return false;
    }

    const ASN1_BIT_STRING* sig = nullptr;
    const X509_ALGOR* sig_alg = nullptr;
    X509_get0_signature(&sig, &sig_alg, cert.get());
    (void)sig_alg;
    if (!sig ||
        ASN1_STRING_length(sig) != 64 ||
        !ASN1_STRING_get0_data(sig)) {
        LOG_NET_DEBUG("REALITY client verification failed: certificate signature invalid");
        return false;
    }

    std::array<uint8_t, 64> expected{};
    unsigned int expected_len = 0;
    if (!HMAC(EVP_sha512(),
              state.auth_key.data(),
              static_cast<int>(state.auth_key.size()),
              peer_public.data(),
              peer_public.size(),
              expected.data(),
              &expected_len) ||
        expected_len != expected.size()) {
        LOG_NET_DEBUG("REALITY client verification failed: signature hmac failed");
        return false;
    }

    const uint8_t* signature = ASN1_STRING_get0_data(sig);
    if (!std::equal(expected.begin(), expected.end(), signature)) {
        LOG_NET_DEBUG("REALITY client verification failed: signature mismatch");
        return false;
    }

    if (state.mldsa65_verify) {
        if (X509_get_ext_count(cert.get()) <= 0 ||
            state.client_hello_raw.empty() ||
            state.server_hello_raw.empty()) {
            LOG_NET_DEBUG("REALITY client verification failed: missing ML-DSA-65 extension or transcript");
            return false;
        }
        X509_EXTENSION* ext = X509_get_ext(cert.get(), 0);
        const ASN1_OCTET_STRING* ext_data =
            ext ? X509_EXTENSION_get_data(ext) : nullptr;
        if (!ext_data ||
            static_cast<size_t>(ASN1_STRING_length(ext_data)) !=
                transport::internet::kRealityMldsa65SignatureSize ||
            !ASN1_STRING_get0_data(ext_data)) {
            LOG_NET_DEBUG("REALITY client verification failed: invalid ML-DSA-65 extension");
            return false;
        }

        HMAC_CTX hmac_ctx;
        HMAC_CTX_init(&hmac_ctx);
        std::array<uint8_t, 64> mldsa_msg{};
        unsigned int mldsa_msg_len = 0;
        const bool hmac_ok =
            HMAC_Init_ex(&hmac_ctx,
                         state.auth_key.data(),
                         state.auth_key.size(),
                         EVP_sha512(),
                         nullptr) == 1 &&
            HMAC_Update(&hmac_ctx, peer_public.data(), peer_public.size()) == 1 &&
            HMAC_Update(&hmac_ctx,
                        state.client_hello_raw.data(),
                        state.client_hello_raw.size()) == 1 &&
            HMAC_Update(&hmac_ctx,
                        state.server_hello_raw.data(),
                        state.server_hello_raw.size()) == 1 &&
            HMAC_Final(&hmac_ctx, mldsa_msg.data(), &mldsa_msg_len) == 1 &&
            mldsa_msg_len == mldsa_msg.size();
        HMAC_CTX_cleanup(&hmac_ctx);
        if (!hmac_ok) {
            return false;
        }

        UniqueEvpPkey verify_key(EVP_PKEY_pqdsa_new_raw_public_key(
            NID_MLDSA65,
            state.mldsa65_verify->data(),
            state.mldsa65_verify->size()));
        UniqueEvpMdCtx md_ctx(EVP_MD_CTX_new());
        if (!verify_key ||
            !md_ctx ||
            EVP_DigestVerifyInit(
                md_ctx.get(), nullptr, nullptr, nullptr, verify_key.get()) != 1 ||
            EVP_DigestVerify(
                md_ctx.get(),
                ASN1_STRING_get0_data(ext_data),
                static_cast<size_t>(ASN1_STRING_length(ext_data)),
                mldsa_msg.data(),
                mldsa_msg.size()) != 1) {
            LOG_NET_DEBUG("REALITY client verification failed: ML-DSA-65 signature invalid");
            return false;
        }
    }

    LOG_NET_DEBUG("REALITY client verification ok");
    return true;
}

[[nodiscard]] bool IsRealityClientTimeAllowed(uint32_t client_unix_seconds,
                                              uint64_t max_diff_ms) noexcept {
    if (max_diff_ms == 0) {
        return true;
    }
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const int64_t client_ms =
        static_cast<int64_t>(client_unix_seconds) * int64_t{1000};
    const uint64_t diff = now_ms >= client_ms
        ? static_cast<uint64_t>(now_ms - client_ms)
        : static_cast<uint64_t>(client_ms - now_ms);
    return diff <= max_diff_ms;
}

[[nodiscard]] bool IsRealityClientAuthAllowed(
    const RealityServerState& state,
    std::span<const uint8_t, kRealityPlainAuthSize> plain) noexcept {
    const std::array<uint8_t, 4> client_ver{
        plain[0], plain[1], plain[2], plain[3]};
    const uint32_t client_ver_value =
        transport::internet::RealityClientVersionValue(client_ver);
    if (state.min_client_version &&
        client_ver_value < transport::internet::RealityClientVersionValue(
            *state.min_client_version)) {
        return false;
    }
    if (state.max_client_version &&
        client_ver_value > transport::internet::RealityClientVersionValue(
            *state.max_client_version)) {
        return false;
    }

    const uint32_t client_time =
        (static_cast<uint32_t>(plain[4]) << 24) |
        (static_cast<uint32_t>(plain[5]) << 16) |
        (static_cast<uint32_t>(plain[6]) << 8) |
        static_cast<uint32_t>(plain[7]);
    if (!IsRealityClientTimeAllowed(client_time, state.max_time_diff_ms)) {
        return false;
    }

    transport::internet::RealityShortId short_id{};
    std::copy_n(plain.data() + 8, short_id.size(), short_id.begin());
    return std::find(state.short_ids.begin(), state.short_ids.end(), short_id) !=
           state.short_ids.end();
}

[[nodiscard]] UniqueX509 BuildRealityCertificate(
    RealityServerState& state,
    std::span<const uint8_t, 32> auth_key,
    std::span<const uint8_t> mldsa65_signature = {}) {
    UniqueX509 cert(X509_new());
    if (!cert) {
        return {};
    }

    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 0);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 365 * 24 * 60 * 60);
    X509_set_pubkey(cert.get(), state.ed25519_key.get());
    X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get()));

    if (!mldsa65_signature.empty()) {
        static constexpr uint8_t kOidZero[] = {0x00};
        UniqueAsn1Object oid(ASN1_OBJECT_create(
            NID_undef, kOidZero, sizeof(kOidZero), nullptr, nullptr));
        UniqueAsn1OctetString value(ASN1_OCTET_STRING_new());
        if (!oid ||
            !value ||
            ASN1_OCTET_STRING_set(
                value.get(),
                mldsa65_signature.data(),
                static_cast<int>(mldsa65_signature.size())) != 1) {
            return {};
        }
        UniqueX509Extension ext(X509_EXTENSION_create_by_OBJ(
            nullptr, oid.get(), 0, value.get()));
        if (!ext || X509_add_ext(cert.get(), ext.get(), 0) != 1) {
            return {};
        }
    }

    if (X509_sign(cert.get(), state.ed25519_key.get(), nullptr) <= 0) {
        return {};
    }

    std::array<uint8_t, 64> signature{};
    unsigned int signature_len = 0;
    if (!HMAC(EVP_sha512(),
              auth_key.data(),
              static_cast<int>(auth_key.size()),
              state.ed25519_public.data(),
              state.ed25519_public.size(),
              signature.data(),
              &signature_len) ||
        signature_len != signature.size()) {
        return {};
    }
    if (X509_set1_signature_value(
            cert.get(), signature.data(), signature.size()) != 1) {
        return {};
    }
    return cert;
}

void RealityServerMsgCallback(int is_write,
                              int /*version*/,
                              int content_type,
                              const void* buf,
                              size_t len,
                              SSL* ssl,
                              void* /*arg*/) {
    if (!is_write || content_type != SSL3_RT_HANDSHAKE || !buf || len < 4 || !ssl) {
        return;
    }
    const auto* bytes = static_cast<const uint8_t*>(buf);
    if (bytes[0] != SSL3_MT_SERVER_HELLO) {
        return;
    }
    auto* ssl_ctx = SSL_get_SSL_CTX(ssl);
    auto* state = ssl_ctx
        ? static_cast<RealityServerState*>(
              SSL_CTX_get_ex_data(ssl_ctx, RealityStateExIndex()))
        : nullptr;
    auto* conn_state = static_cast<RealityServerConnState*>(
        SSL_get_ex_data(ssl, RealityConnStateExIndex()));
    if (!state || !state->mldsa65_key || !conn_state || !conn_state->authenticated) {
        return;
    }

    HMAC_CTX hmac_ctx;
    HMAC_CTX_init(&hmac_ctx);
    std::array<uint8_t, 64> mldsa_msg{};
    unsigned int mldsa_msg_len = 0;
    const bool hmac_ok =
        HMAC_Init_ex(&hmac_ctx,
                     conn_state->auth_key.data(),
                     conn_state->auth_key.size(),
                     EVP_sha512(),
                     nullptr) == 1 &&
        HMAC_Update(&hmac_ctx,
                    state->ed25519_public.data(),
                    state->ed25519_public.size()) == 1 &&
        HMAC_Update(&hmac_ctx,
                    conn_state->client_hello_raw.data(),
                    conn_state->client_hello_raw.size()) == 1 &&
        HMAC_Update(&hmac_ctx, bytes, len) == 1 &&
        HMAC_Final(&hmac_ctx, mldsa_msg.data(), &mldsa_msg_len) == 1 &&
        mldsa_msg_len == mldsa_msg.size();
    HMAC_CTX_cleanup(&hmac_ctx);
    if (!hmac_ok) {
        return;
    }

    std::array<uint8_t, transport::internet::kRealityMldsa65SignatureSize> mldsa_sig{};
    size_t sig_len = mldsa_sig.size();
    UniqueEvpMdCtx md_ctx(EVP_MD_CTX_new());
    if (!md_ctx ||
        EVP_DigestSignInit(
            md_ctx.get(), nullptr, nullptr, nullptr, state->mldsa65_key.get()) != 1 ||
        EVP_DigestSign(
            md_ctx.get(),
            mldsa_sig.data(),
            &sig_len,
            mldsa_msg.data(),
            mldsa_msg.size()) != 1 ||
        sig_len != mldsa_sig.size()) {
        return;
    }

    auto cert = BuildRealityCertificate(*state, conn_state->auth_key, mldsa_sig);
    if (cert) {
        (void)SSL_use_certificate(ssl, cert.get());
    }
}

[[nodiscard]] ssl_select_cert_result_t RealitySelectCertificateCallback(
    const SSL_CLIENT_HELLO* hello) {
    auto fail = [](std::string_view reason) {
        LOG_NET_DEBUG("REALITY server handshake reject: {}", reason);
        return ssl_select_cert_error;
    };

    if (!hello || !hello->ssl || !hello->client_hello ||
        hello->client_hello_len > 0x00ffffff ||
        hello->random_len != kRealityRandomSize ||
        hello->session_id_len != kRealitySessionIdSize) {
        return fail("invalid client hello shape");
    }

    auto* ssl_ctx = SSL_get_SSL_CTX(hello->ssl);
    auto* state = static_cast<RealityServerState*>(
        SSL_CTX_get_ex_data(ssl_ctx, RealityStateExIndex()));
    if (!state) {
        return fail("missing server state");
    }

    std::string_view sni;
    const RealitySniParseResult sni_result = ParseRealitySni(*hello, sni);
    if (sni_result == RealitySniParseResult::Invalid ||
        !transport::internet::IsRealityServerNameAllowed(
            state->server_names,
            sni_result == RealitySniParseResult::Missing
                ? std::string_view{}
                : sni)) {
        return fail("server name not allowed");
    }

    auto peer_public = ParseRealityPeerPublicKey(*hello);
    if (!peer_public) {
        return fail("missing x25519 key share");
    }

    auto auth_key = ComputeRealityAuthKey(
        *state,
        std::span<const uint8_t, kRealityX25519KeySize>(
            peer_public->data(), peer_public->size()),
        std::span<const uint8_t, 20>(hello->random, 20));
    if (!auth_key) {
        return fail("auth key derivation failed");
    }

    auto aad = BuildRealityClientHelloAad(*hello);
    auto plain = OpenRealitySessionId(
        std::span<const uint8_t, 32>(auth_key->data(), auth_key->size()),
        std::span<const uint8_t, kRealityAesGcmNonceSize>(
            hello->random + 20, kRealityAesGcmNonceSize),
        std::span<const uint8_t, kRealitySessionIdSize>(
            hello->session_id, hello->session_id_len),
        aad);
    if (!plain) {
        return fail("session id decrypt failed");
    }
    if (!IsRealityClientAuthAllowed(
            *state,
            std::span<const uint8_t, kRealityPlainAuthSize>(
                plain->data(), plain->size()))) {
        return fail("client auth fields rejected");
    }

    if (state->mldsa65_key) {
        auto conn_state = std::make_unique<RealityServerConnState>();
        conn_state->auth_key = *auth_key;
        conn_state->authenticated = true;
        const bool has_handshake_header =
            hello->client_hello_len >= 4 &&
            hello->client_hello[0] == 0x01 &&
            (static_cast<size_t>(hello->client_hello[1]) << 16 |
             static_cast<size_t>(hello->client_hello[2]) << 8 |
             static_cast<size_t>(hello->client_hello[3])) ==
                hello->client_hello_len - 4;
        if (has_handshake_header) {
            conn_state->client_hello_raw.assign(
                hello->client_hello,
                hello->client_hello + hello->client_hello_len);
        } else {
            conn_state->client_hello_raw.resize(4 + hello->client_hello_len);
            conn_state->client_hello_raw[0] = 0x01;
            conn_state->client_hello_raw[1] =
                static_cast<uint8_t>((hello->client_hello_len >> 16) & 0xff);
            conn_state->client_hello_raw[2] =
                static_cast<uint8_t>((hello->client_hello_len >> 8) & 0xff);
            conn_state->client_hello_raw[3] =
                static_cast<uint8_t>(hello->client_hello_len & 0xff);
            std::copy_n(hello->client_hello,
                        hello->client_hello_len,
                        conn_state->client_hello_raw.data() + 4);
        }
        if (SSL_set_ex_data(
                hello->ssl, RealityConnStateExIndex(), conn_state.get()) != 1) {
            return fail("failed to store REALITY connection state");
        }
        (void)conn_state.release();
    }

    auto cert = BuildRealityCertificate(
        *state,
        std::span<const uint8_t, 32>(auth_key->data(), auth_key->size()));
    if (!cert ||
        SSL_use_certificate(hello->ssl, cert.get()) != 1 ||
        SSL_use_PrivateKey(hello->ssl, state->ed25519_key.get()) != 1) {
        return fail("certificate install failed");
    }

    LOG_NET_DEBUG("REALITY server handshake authenticated");
    return ssl_select_cert_success;
}

[[nodiscard]] std::unique_ptr<RealityServerState> BuildRealityServerState(
    const RealityConfig& config) {
    if (!config.private_key) {
        LOG_ERROR("REALITY server privateKey is empty");
        return {};
    }
    if (config.server_names.empty()) {
        LOG_ERROR("REALITY serverNames is empty");
        return {};
    }
    if (config.short_ids.empty()) {
        LOG_ERROR("REALITY shortIds is empty");
        return {};
    }

    auto state = std::make_unique<RealityServerState>();
    state->private_key = *config.private_key;
    state->server_names = config.server_names;
    state->max_time_diff_ms = config.max_time_diff;
    state->min_client_version = config.min_client_version;
    state->max_client_version = config.max_client_version;
    state->short_ids = config.short_ids;

    if (config.mldsa65_seed) {
        state->mldsa65_key.reset(EVP_PKEY_pqdsa_new_raw_private_key(
            NID_MLDSA65,
            config.mldsa65_seed->data(),
            config.mldsa65_seed->size()));
        if (!state->mldsa65_key) {
            LOG_ERROR("REALITY ML-DSA-65 key generation from seed failed");
            return {};
        }
    }

    std::array<uint8_t, 32> seed{};
    if (RAND_bytes(seed.data(), static_cast<int>(seed.size())) != 1) {
        LOG_ERROR("REALITY Ed25519 seed generation failed");
        return {};
    }
    state->ed25519_key.reset(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519,
        nullptr,
        seed.data(),
        seed.size()));
    if (!state->ed25519_key) {
        LOG_ERROR("REALITY Ed25519 key generation failed");
        return {};
    }

    size_t public_len = state->ed25519_public.size();
    if (EVP_PKEY_get_raw_public_key(
            state->ed25519_key.get(),
            state->ed25519_public.data(),
            &public_len) != 1 ||
        public_len != state->ed25519_public.size()) {
        LOG_ERROR("REALITY Ed25519 public key export failed");
        return {};
    }

    return state;
}

void ConfigureRealityClientFingerprint(SSL_CTX* ctx,
                                       std::string_view fingerprint) {
    if (fingerprint == "firefox") {
        SSL_CTX_set_grease_enabled(ctx, 0);
        SSL_CTX_set_permute_extensions(ctx, 0);
        (void)SSL_CTX_set_strict_cipher_list(
            ctx,
            "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:"
            "AES128-SHA:AES256-SHA");
        return;
    }
    if (fingerprint == "safari" || fingerprint == "ios") {
        SSL_CTX_set_grease_enabled(ctx, 1);
        SSL_CTX_set_permute_extensions(ctx, 0);
        (void)SSL_CTX_set_strict_cipher_list(
            ctx,
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:"
            "AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA:AES128-SHA");
        return;
    }
    if (fingerprint == "360" || fingerprint == "qq") {
        SSL_CTX_set_grease_enabled(ctx, 1);
        SSL_CTX_set_permute_extensions(ctx, 0);
    } else {
        // chrome, edge, android, random, randomized, auto, or default
        SSL_CTX_set_grease_enabled(ctx, 1);
        SSL_CTX_set_permute_extensions(ctx, 1);
    }
    (void)SSL_CTX_set_strict_cipher_list(
        ctx,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:"
        "ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:"
        "AES128-SHA:AES256-SHA");
}

}  // namespace

std::unique_ptr<SslContext> SslContext::CreateServerReality(
    const RealityConfig& reality,
    const TlsConfig& tls_config) {
    auto state = BuildRealityServerState(reality);
    if (!state) {
        return nullptr;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        LOG_ERROR("Failed to create REALITY SSL server context");
        return nullptr;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    LimitSslReadBuffer(ctx);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_reality_ignore_peer_signature_algorithm_prefs(ctx, 1);

    if (SSL_CTX_set_ex_data(ctx, RealityStateExIndex(), state.get()) != 1) {
        LOG_ERROR("Failed to attach REALITY server state");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_select_certificate_cb(ctx, RealitySelectCertificateCallback);
    if (state->mldsa65_key) {
        SSL_CTX_set_msg_callback(ctx, RealityServerMsgCallback);
    }

    auto out = std::unique_ptr<SslContext>(
        new SslContext(ctx, std::move(state)));
    if (!out->ConfigureServerAlpn(tls_config.alpn)) {
        LOG_ERROR("Invalid REALITY server ALPN policy");
        return nullptr;
    }
    LOG_INFO("REALITY server context enabled (serverNames={}, shortIds={})",
             reality.server_names.size(),
             reality.short_ids.size());
    return out;
}

std::unique_ptr<SslContext> SslContext::CreateClientReality(
    const RealityConfig& reality,
    const TlsConfig& tls_config) {
    if (!reality.IsClient()) {
        LOG_ERROR("REALITY client publicKey is empty");
        return nullptr;
    }

    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        LOG_ERROR("Failed to create REALITY SSL client context");
        return nullptr;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    LimitSslReadBuffer(ctx);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    ConfigureRealityClientFingerprint(ctx, reality.fingerprint);

    (void)tls_config;
    return std::unique_ptr<SslContext>(new SslContext(ctx));
}

bool TlsStream::SetRealityClient(const RealityConfig& reality) {
    SSL* ssl = NativeSsl();
    if (is_server_ || !ssl) {
        return false;
    }

    auto state = BuildRealityClientState(reality);
    if (!state) {
        return false;
    }

    if (SSL_set1_reality_peer_public_key(
            ssl,
            state->server_public.data(),
            state->server_public.size()) != 1) {
        LOG_ERROR("REALITY client peer public key install failed");
        return false;
    }

    const char* groups = "X25519MLKEM768:X25519:P-256:P-384";
    const char* sigalgs =
        "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:"
        "ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:"
        "rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
    if (reality.fingerprint == "firefox") {
        groups = "X25519MLKEM768:X25519:P-256:P-384:P-521";
        sigalgs =
            "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:"
            "ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:"
            "rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:"
            "rsa_pkcs1_sha512";
    } else if (reality.fingerprint == "safari" || reality.fingerprint == "ios") {
        groups = "X25519MLKEM768:X25519:P-256:P-384:P-521";
        sigalgs =
            "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:"
            "ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:"
            "rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha384:"
            "rsa_pkcs1_sha512:rsa_pkcs1_sha1";
    } else if (reality.fingerprint == "random" || reality.fingerprint == "randomized") {
        groups = "X25519MLKEM768:X25519:P-256:P-384:P-521";
    }
    if (SSL_set1_groups_list(ssl, groups) != 1) {
        LOG_ERROR("REALITY client failed to configure key share groups");
        return false;
    }
    if (SSL_set1_sigalgs_list(ssl, sigalgs) != 1) {
        LOG_ERROR("REALITY client failed to configure signature algorithms");
        return false;
    }

    SSL_set_msg_callback(ssl, RealityClientMsgCallback);
    SSL_set_msg_callback_arg(ssl, state.get());
    SSL_set_reality_client_hello_cb(
        ssl,
        RealityClientHelloCallback,
        state.get());
    reality_client_state_ = std::move(state);
    return true;
}

bool VerifyRealityClientHandshake(
    SSL* ssl,
    const RealityClientState& state) {
    return VerifyRealityPeerCertificate(ssl, state);
}

bool VerifyRealityClientHelloRecord(
    std::span<const uint8_t> record,
    const RealityConfig& config,
    std::string* out_sni) {
    if (!config.private_key || config.server_names.empty() ||
        config.short_ids.empty()) {
        return false;
    }
    // TLS record header (5B) + Handshake header (4B) + Version (2B) +
    // Random (32B) + SessionIdLen (1B) + SessionId (32B)
    if (record.size() < 5 + 4 + 2 + 32 + 1 + 32 || record[0] != 0x16) {
        return false;
    }
    const size_t record_len =
        (static_cast<size_t>(record[3]) << 8) | record[4];
    if (record.size() < 5 + record_len || record_len < 4 + 2 + 32 + 1 + 32) {
        return false;
    }

    const auto handshake = record.subspan(5, record_len);
    if (handshake[0] != 0x01) {
        return false;
    }
    const size_t hello_len =
        (static_cast<size_t>(handshake[1]) << 16) |
        (static_cast<size_t>(handshake[2]) << 8) |
        handshake[3];
    if (hello_len + 4 != handshake.size()) {
        return false;
    }

    const auto body = handshake.subspan(4);
    const auto random = body.subspan(2, kRealityRandomSize);
    const size_t session_id_len = body[34];
    if (session_id_len != kRealitySessionIdSize || body.size() < 35 + session_id_len + 2) {
        return false;
    }
    const auto session_id = body.subspan(35, kRealitySessionIdSize);
    size_t pos = 35 + kRealitySessionIdSize;

    const size_t cipher_suites_len =
        (static_cast<size_t>(body[pos]) << 8) | body[pos + 1];
    pos += 2;
    if (cipher_suites_len == 0 || (cipher_suites_len & 1u) != 0 ||
        pos + cipher_suites_len + 1 > body.size()) {
        return false;
    }
    pos += cipher_suites_len;

    const size_t comp_methods_len = body[pos++];
    if (comp_methods_len == 0 || pos + comp_methods_len + 2 > body.size()) {
        return false;
    }
    pos += comp_methods_len;

    const size_t extensions_len =
        (static_cast<size_t>(body[pos]) << 8) | body[pos + 1];
    pos += 2;
    if (pos + extensions_len != body.size()) {
        return false;
    }

    std::string_view sni;
    bool has_sni = false;
    bool sni_invalid = false;
    std::optional<std::array<uint8_t, kRealityX25519KeySize>> peer_public;
    bool supports_tls13 = false;

    size_t ext_pos = pos;
    while (ext_pos < body.size()) {
        if (ext_pos + 4 > body.size()) {
            return false;
        }
        const uint16_t ext_type =
            static_cast<uint16_t>((body[ext_pos] << 8) | body[ext_pos + 1]);
        const size_t ext_len =
            (static_cast<size_t>(body[ext_pos + 2]) << 8) | body[ext_pos + 3];
        ext_pos += 4;
        if (ext_pos + ext_len > body.size()) {
            return false;
        }
        const auto ext_data = body.subspan(ext_pos, ext_len);
        ext_pos += ext_len;

        if (ext_type == TLSEXT_TYPE_server_name) {
            auto parsed_sni = transport::internet::ParseTlsServerNameExtension(ext_data);
            if (!parsed_sni) {
                sni_invalid = true;
            } else {
                has_sni = true;
                sni = *parsed_sni;
            }
        } else if (ext_type == TLSEXT_TYPE_key_share) {
            if (auto parsed_ks =
                    transport::internet::ParseRealityClientKeyShareExtension(ext_data)) {
                peer_public = *parsed_ks;
            }
        } else if (ext_type == TLSEXT_TYPE_supported_versions) {
            if (ext_data.size() >= 1 &&
                static_cast<size_t>(ext_data[0]) + 1 == ext_data.size() &&
                (ext_data[0] & 1u) == 0) {
                for (size_t i = 1; i + 1 < ext_data.size(); i += 2) {
                    const uint16_t ver =
                        static_cast<uint16_t>((ext_data[i] << 8) | ext_data[i + 1]);
                    if (ver == TLS1_3_VERSION) {
                        supports_tls13 = true;
                    }
                }
            }
        }
    }

    if (sni_invalid || !supports_tls13 || !peer_public) {
        return false;
    }
    if (!transport::internet::IsRealityServerNameAllowed(
            config.server_names, has_sni ? sni : std::string_view{})) {
        return false;
    }
    if (out_sni && has_sni) {
        out_sni->assign(sni);
    }

    std::array<uint8_t, kRealityX25519KeySize> shared{};
    if (X25519(shared.data(), config.private_key->data(), peer_public->data()) != 1) {
        return false;
    }
    auto auth_key = DeriveRealityAuthKey(
        shared,
        std::span<const uint8_t, 20>(random.data(), 20));
    if (!auth_key) {
        return false;
    }

    std::vector<uint8_t> aad(handshake.begin(), handshake.end());
    std::fill_n(aad.data() + 4 + 35, kRealitySessionIdSize, uint8_t{0});
    auto plain = OpenRealitySessionId(
        *auth_key,
        std::span<const uint8_t, kRealityAesGcmNonceSize>(
            random.data() + 20, kRealityAesGcmNonceSize),
        std::span<const uint8_t, kRealitySessionIdSize>(
            session_id.data(), session_id.size()),
        aad);
    if (!plain) {
        return false;
    }

    RealityServerState temp_state;
    temp_state.min_client_version = config.min_client_version;
    temp_state.max_client_version = config.max_client_version;
    temp_state.max_time_diff_ms = config.max_time_diff;
    temp_state.short_ids = config.short_ids;
    return IsRealityClientAuthAllowed(temp_state, *plain);
}
}  // namespace acpp
