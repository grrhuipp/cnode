#include "transport/internet/reality_tls.hpp"
#include "transport/internet/tls_context.hpp"
#include "transport/internet/tls_stream.hpp"
#include "transport/internet/stream_settings.hpp"
#include "transport/internet/tls_server_name.hpp"
#include "common/ascii.hpp"
#include "common/binary_text_codec.hpp"
#include "common/byte_reader.hpp"
#include "common/scoped_cleanse.hpp"
#include "common/unsafe.hpp"
#include "infra/log.hpp"
#include <openssl/aead.h>
#include <openssl/asn1.h>
#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/mldsa.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace transport::internet {

void RealityClientHelloReader::Append(std::span<const uint8_t> bytes) {
    if (bytes.empty() || bytes.size() > ReadSize()) {
        status_ = Status::Invalid;
        return;
    }
    wire_.insert(wire_.end(), bytes.begin(), bytes.end());
    if (header_size_ < header_.size()) {
        std::copy(bytes.begin(), bytes.end(), header_.begin() + header_size_);
        header_size_ += bytes.size();
        if ((header_size_ >= 1 && header_[0] != 22) ||
            (header_size_ >= 2 && header_[1] != 3)) {
            status_ = Status::Invalid;
            return;
        }
        if (header_size_ != header_.size()) return;
        remaining_ = common::LoadU16BE(header_.data() + 3);
        if (remaining_ == 0 || remaining_ > 16384) {
            status_ = Status::Invalid;
        }
        return;
    }
    remaining_ -= bytes.size();
    if (hello_.size() < 4) {
        const size_t header_bytes = std::min(bytes.size(), 4 - hello_.size());
        hello_.insert(hello_.end(), bytes.begin(), bytes.begin() + header_bytes);
        bytes = bytes.subspan(header_bytes);
        if (hello_[0] != 1) {
            status_ = Status::Invalid;
            return;
        }
        if (hello_.size() == 4) {
            hello_size_ = 4 + common::LoadU24BE(hello_.data() + 1);
            if (hello_size_ < 4 + 2 + 32 + 1 + 32 + 2 + 2 + 1 + 1 + 2 || hello_size_ > kMaxHelloSize) {
                status_ = Status::Invalid;
                return;
            }
        }
    }
    if (hello_size_) {
        if (bytes.size() + remaining_ > hello_size_ - hello_.size()) {
            status_ = Status::Invalid;
            return;
        }
        hello_.insert(hello_.end(), bytes.begin(), bytes.end());
    }
    if (remaining_ == 0) {
        if (hello_size_ && hello_.size() == hello_size_) status_ = Status::Complete;
        else header_size_ = 0;
    }
}

}  // namespace transport::internet

namespace transport::internet {
namespace {

template <std::size_t N>
tl::expected<std::array<uint8_t, N>, RealityKeyError>
DecodeFixedBase64Url(std::string_view value) noexcept {
    constexpr std::size_t kEncodedSize = (N * 8 + 5) / 6;
    static_assert(common::Base64UrlDecodedSize(kEncodedSize) == N);
    std::array<uint8_t, N> decoded{};
    if (value.size() != kEncodedSize) {
        return tl::unexpected(RealityKeyError::InvalidFormat);
    }
    const auto result = common::DecodeBase64Url(value, decoded);
    if (!result || result->nonzero_pad_bits) {
        OPENSSL_cleanse(decoded.data(), decoded.size());
        return tl::unexpected(RealityKeyError::InvalidFormat);
    }
    return decoded;
}

}  // namespace

tl::expected<RealityKey, RealityKeyError>
ParseRealityKey(std::string_view value) noexcept {
    return DecodeFixedBase64Url<kRealityKeySize>(value);
}

tl::expected<RealityKey, RealityKeyError>
ParseRealityMldsa65Seed(std::string_view value) noexcept {
    auto seed = ParseRealityKey(value);
    if (!seed) {
        return tl::unexpected(seed.error());
    }
    MLDSA65_private_key key;
    const int valid = MLDSA65_private_key_from_seed(&key, seed->data(), seed->size());
    OPENSSL_cleanse(&key, sizeof(key));
    if (valid != 1) {
        OPENSSL_cleanse(seed->data(), seed->size());
        ERR_clear_error();
        return tl::unexpected(RealityKeyError::InvalidFormat);
    }
    return *seed;
}

tl::expected<RealityMldsa65PublicKey, RealityKeyError>
ParseRealityMldsa65PublicKey(std::string_view value) noexcept {
    auto pub = DecodeFixedBase64Url<kRealityMldsa65PublicKeySize>(value);
    if (!pub) {
        return tl::unexpected(pub.error());
    }
    MLDSA65_public_key key;
    CBS encoded;
    CBS_init(&encoded, pub->data(), pub->size());
    if (MLDSA65_parse_public_key(&key, &encoded) != 1) {
        ERR_clear_error();
        return tl::unexpected(RealityKeyError::InvalidFormat);
    }
    return *pub;
}

std::optional<std::string>
NormalizeRealityFingerprint(std::string_view value) {
    const std::string normalized = common::LowerAscii(std::string(value));
    if (normalized.empty() ||
        normalized == "chrome" ||
        normalized == "firefox" ||
        normalized == "safari" ||
        normalized == "ios" ||
        normalized == "android" ||
        normalized == "edge" ||
        normalized == "360" ||
        normalized == "qq" ||
        normalized == "random" ||
        normalized == "randomized" ||
        normalized == "auto") {
        return normalized;
    }
    return std::nullopt;
}

}  // namespace transport::internet

namespace transport::internet {

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
constexpr std::array<uint8_t, 32> kTls13HelloRetryRequestRandom{{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}};

struct Mldsa65PrivateKeyDeleter {
    void operator()(MLDSA65_private_key* key) const noexcept {
        OPENSSL_cleanse(key, sizeof(*key));
        delete key;
    }
};
using UniqueMldsa65PrivateKey =
    std::unique_ptr<MLDSA65_private_key, Mldsa65PrivateKeyDeleter>;

struct RealityServerState final {
    ~RealityServerState() {
        OPENSSL_cleanse(private_key.data(), private_key.size());
        for (auto& id : short_ids) OPENSSL_cleanse(id.data(), id.size());
    }
    std::array<uint8_t, kRealityX25519KeySize> private_key{};
    std::vector<std::string> server_names;
    std::vector<transport::internet::RealityShortId> short_ids;
    std::optional<transport::internet::RealityClientVersion> min_client_version;
    std::optional<transport::internet::RealityClientVersion> max_client_version;
    uint64_t max_time_diff_ms = 0;
    bssl::UniquePtr<EVP_PKEY> ed25519_key;
    std::array<uint8_t, 32> ed25519_public{};
    UniqueMldsa65PrivateKey mldsa65_key;
    std::vector<uint8_t> certificate_template;
};

struct RealityClientContextState final {
    MLDSA65_public_key mldsa65_verify_key;
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
        0, nullptr, nullptr, nullptr,
        [](void*, void* ptr, CRYPTO_EX_DATA*, int, long, void*) {
            delete static_cast<RealityServerState*>(ptr);
        });
    return index;
}
[[nodiscard]] int RealityClientContextStateExIndex() {
    static const int index = SSL_CTX_get_ex_new_index(
        0, nullptr, nullptr, nullptr,
        [](void*, void* ptr, CRYPTO_EX_DATA*, int, long, void*) {
            delete static_cast<RealityClientContextState*>(ptr);
        });
    return index;
}


[[nodiscard]] int RealityConnStateExIndex() {
    static const int index = SSL_get_ex_new_index(
        0, nullptr, nullptr, nullptr, FreeRealityServerConnState);
    return index;
}


// RFC 8446 §4.4.1: transcript messages include the 4-byte handshake header,
// which the early callback may omit from |client_hello|.
[[nodiscard]] bool HasHandshakeHeader(const SSL_CLIENT_HELLO& hello) noexcept {
    return hello.client_hello_len >= 4 &&
        hello.client_hello[0] == SSL3_MT_CLIENT_HELLO &&
        common::LoadU24BE(hello.client_hello + 1) == hello.client_hello_len - 4;
}

[[nodiscard]] memory::ByteVector FramedClientHello(const SSL_CLIENT_HELLO& hello) {
    memory::ByteVector framed;
    if (HasHandshakeHeader(hello)) {
        framed.assign(hello.client_hello,
                      hello.client_hello + hello.client_hello_len);
        return framed;
    }
    framed.resize(4 + hello.client_hello_len);
    framed[0] = SSL3_MT_CLIENT_HELLO;
    common::StoreU24BE(framed.data() + 1, static_cast<uint32_t>(hello.client_hello_len));
    std::copy_n(hello.client_hello, hello.client_hello_len, framed.data() + 4);
    return framed;
}


[[nodiscard]] std::optional<std::array<uint8_t, 32>> DeriveRealityAuthKey(
    std::span<const uint8_t> shared,
    std::span<const uint8_t, 20> random_salt) noexcept;

[[nodiscard]] std::optional<std::array<uint8_t, 32>> ComputeRealityAuthKey(
    const RealityServerState& state,
    std::span<const uint8_t, kRealityX25519KeySize> peer_public,
    std::span<const uint8_t, 20> random_salt) noexcept {
    std::array<uint8_t, kRealityX25519KeySize> shared{};
    const common::ScopedCleanse wipe_shared{shared};
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
    const common::ScopedCleanse wipe_auth{auth_key};
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

template <typename Op>
[[nodiscard]] bool WithRealitySessionIdAead(
    std::span<const uint8_t, 32> auth_key, Op&& op) noexcept {
    EVP_AEAD_CTX aead;
    EVP_AEAD_CTX_zero(&aead);
    struct CleanseAead {
        EVP_AEAD_CTX& ctx;
        ~CleanseAead() noexcept {
            EVP_AEAD_CTX_cleanup(&ctx);
            OPENSSL_cleanse(&ctx, sizeof(ctx));
        }
    } cleanse_aead{aead};
    return EVP_AEAD_CTX_init(&aead,
                             EVP_aead_aes_256_gcm(),
                             auth_key.data(),
                             auth_key.size(),
                             EVP_AEAD_DEFAULT_TAG_LENGTH,
                             nullptr) == 1 &&
           op(aead);
}

[[nodiscard]] std::optional<std::array<uint8_t, kRealityPlainAuthSize>>
OpenRealitySessionId(
    std::span<const uint8_t, 32> auth_key,
    std::span<const uint8_t, kRealityAesGcmNonceSize> nonce,
    std::span<const uint8_t, kRealitySessionIdSize> ciphertext,
    std::span<const uint8_t> aad) noexcept {
    std::array<uint8_t, kRealityPlainAuthSize> plain{};
    const common::ScopedCleanse wipe_plain{plain};
    size_t plain_len = 0;
    if (!WithRealitySessionIdAead(auth_key, [&](EVP_AEAD_CTX& aead) noexcept {
            return EVP_AEAD_CTX_open(&aead,
                                     plain.data(),
                                     &plain_len,
                                     plain.size(),
                                     nonce.data(),
                                     nonce.size(),
                                     ciphertext.data(),
                                     ciphertext.size(),
                                     aad.data(),
                                     aad.size()) == 1 &&
                   plain_len == plain.size();
        })) {
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
    std::array<uint8_t, kRealitySessionIdSize> out{};
    size_t out_len = 0;
    if (!WithRealitySessionIdAead(auth_key, [&](EVP_AEAD_CTX& aead) noexcept {
            return EVP_AEAD_CTX_seal(&aead,
                                     out.data(),
                                     &out_len,
                                     out.size(),
                                     nonce.data(),
                                     nonce.size(),
                                     plain.data(),
                                     plain.size(),
                                     aad.data(),
                                     aad.size()) == 1 &&
                   out_len == out.size();
        })) {
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
    common::StoreU32BE(plain.data() + 4, now);
    std::copy(short_id.begin(), short_id.end(), plain.begin() + 8);
    return plain;
}

[[nodiscard]] std::unique_ptr<RealityClientState> BuildRealityClientState(
    const RealityConfig& config,
    const MLDSA65_public_key* mldsa65_verify_key) {
    if (!config.public_key) {
        LOG_ERROR("REALITY client public key is missing");
        return nullptr;
    }
    auto state = std::make_unique<RealityClientState>();
    state->short_id = config.short_id;
    state->spider_x.assign(config.spider_x.data(), config.spider_x.size());
    state->mldsa65_verify_key = mldsa65_verify_key;
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
        if (state->client_hello_raw.empty()) {
            state->client_hello_raw.assign(bytes, bytes + len);
        }
    } else if (!is_write && bytes[0] == SSL3_MT_SERVER_HELLO) {
        if (len >= 4 + 2 + kTls13HelloRetryRequestRandom.size() &&
            std::equal(kTls13HelloRetryRequestRandom.begin(),
                       kTls13HelloRetryRequestRandom.end(),
                       bytes + 6)) {
            return;
        }
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
    const common::ScopedCleanse wipe_auth{*auth_key};

    auto plain = BuildRealityClientAuthPlain(
        std::span<const uint8_t, kRealityShortIdSize>(
            state->short_id.data(), state->short_id.size()));
    const common::ScopedCleanse wipe_plain{plain};
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


[[nodiscard]] bool ComputeRealityTranscriptHmac(
    std::span<const uint8_t, 32> auth_key,
    std::span<const uint8_t, 32> ed25519_public,
    std::span<const uint8_t> client_hello,
    std::span<const uint8_t> server_hello,
    std::span<uint8_t, 64> out) noexcept {
    HMAC_CTX hmac_ctx;
    HMAC_CTX_init(&hmac_ctx);
    struct CleanseHmac {
        HMAC_CTX& ctx;
        ~CleanseHmac() noexcept {
            HMAC_CTX_cleanup(&ctx);
            OPENSSL_cleanse(&ctx, sizeof(ctx));
        }
    } cleanse_hmac{hmac_ctx};
    unsigned int out_len = 0;
    return HMAC_Init_ex(&hmac_ctx,
                        auth_key.data(),
                        auth_key.size(),
                        EVP_sha512(),
                        nullptr) == 1 &&
           HMAC_Update(&hmac_ctx,
                       ed25519_public.data(),
                       ed25519_public.size()) == 1 &&
           HMAC_Update(&hmac_ctx,
                       client_hello.data(),
                       client_hello.size()) == 1 &&
           HMAC_Update(&hmac_ctx,
                       server_hello.data(),
                       server_hello.size()) == 1 &&
           HMAC_Final(&hmac_ctx, out.data(), &out_len) == 1 &&
           out_len == out.size();
}

// REALITY 服务端证书只携带 Ed25519 公钥，用于派生签名位置上的 HMAC。
[[nodiscard]] std::optional<std::array<uint8_t, 32>> ExportRealityPeerPublicKey(X509* cert) {
    EVP_PKEY* pubkey = X509_get0_pubkey(cert);
    if (!pubkey || EVP_PKEY_id(pubkey) != EVP_PKEY_ED25519) {
        LOG_NET_DEBUG("REALITY client verification failed > peer key is not Ed25519");
        return std::nullopt;
    }

    std::array<uint8_t, 32> peer_public{};
    size_t peer_public_len = peer_public.size();
    if (EVP_PKEY_get_raw_public_key(
            pubkey,
            peer_public.data(),
            &peer_public_len) != 1 ||
        peer_public_len != peer_public.size()) {
        LOG_NET_DEBUG("REALITY client verification failed > peer public key export failed");
        return std::nullopt;
    }
    return peer_public;
}

// The X.509 signature slot carries HMAC-SHA512(authKey, peer Ed25519 key).
[[nodiscard]] bool VerifyRealityCertificateHmac(
    X509* cert,
    std::span<const uint8_t, 32> auth_key,
    std::span<const uint8_t, 32> peer_public) {
    const ASN1_BIT_STRING* sig = nullptr;
    const X509_ALGOR* sig_alg = nullptr;
    X509_get0_signature(&sig, &sig_alg, cert);
    (void)sig_alg;
    if (!sig ||
        ASN1_STRING_length(sig) != 64 ||
        !ASN1_STRING_get0_data(sig)) {
        LOG_NET_DEBUG("REALITY client verification failed > invalid certificate signature");
        return false;
    }

    std::array<uint8_t, 64> expected{};
    const common::ScopedCleanse wipe_expected{expected};
    unsigned int expected_len = 0;
    if (!HMAC(EVP_sha512(),
              auth_key.data(),
              static_cast<int>(auth_key.size()),
              peer_public.data(),
              peer_public.size(),
              expected.data(),
              &expected_len) ||
        expected_len != expected.size()) {
        LOG_NET_DEBUG("REALITY client verification failed > signature HMAC failed");
        return false;
    }

    // HMAC verification: compare in constant time.
    const uint8_t* signature = ASN1_STRING_get0_data(sig);
    if (CRYPTO_memcmp(expected.data(), signature, expected.size()) != 0) {
        LOG_NET_DEBUG("REALITY client verification failed > signature mismatch");
        return false;
    }
    return true;
}

// The first certificate extension carries an ML-DSA-65 signature over the
// transcript HMAC, binding the certificate to this ClientHello/ServerHello.
[[nodiscard]] bool VerifyRealityMldsa65Extension(
    X509* cert,
    const RealityClientState& state,
    std::span<const uint8_t, 32> peer_public) {
    if (X509_get_ext_count(cert) <= 0 ||
        state.client_hello_raw.empty() ||
        state.server_hello_raw.empty()) {
        LOG_NET_DEBUG("REALITY client verification failed > missing ML-DSA-65 extension or transcript");
        return false;
    }
    X509_EXTENSION* ext = X509_get_ext(cert, 0);
    const ASN1_OCTET_STRING* ext_data =
        ext ? X509_EXTENSION_get_data(ext) : nullptr;
    if (!ext_data ||
        static_cast<size_t>(ASN1_STRING_length(ext_data)) !=
            transport::internet::kRealityMldsa65SignatureSize ||
        !ASN1_STRING_get0_data(ext_data)) {
        LOG_NET_DEBUG("REALITY client verification failed > invalid ML-DSA-65 extension");
        return false;
    }

    std::array<uint8_t, 64> mldsa_msg{};
    const common::ScopedCleanse wipe_mldsa_msg{mldsa_msg};
    if (!ComputeRealityTranscriptHmac(
            state.auth_key,
            peer_public,
            state.client_hello_raw,
            state.server_hello_raw,
            mldsa_msg)) {
        return false;
    }

    if (MLDSA65_verify(
            state.mldsa65_verify_key,
            ASN1_STRING_get0_data(ext_data),
            static_cast<size_t>(ASN1_STRING_length(ext_data)),
            mldsa_msg.data(), mldsa_msg.size(), nullptr, 0) != 1) {
        LOG_NET_DEBUG("REALITY client verification failed > invalid ML-DSA-65 signature");
        return false;
    }
    return true;
}

}  // namespace

bool VerifyRealityClientHandshake(
    SSL* ssl,
    const RealityClientState& state) {
    if (!ssl || !state.auth_key_ready) {
        return false;
    }

    bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl));
    if (!cert) {
        LOG_NET_DEBUG("REALITY client verification failed > missing peer certificate");
        return false;
    }

    const auto peer_public = ExportRealityPeerPublicKey(cert.get());
    if (!peer_public ||
        !VerifyRealityCertificateHmac(cert.get(), state.auth_key, *peer_public)) {
        return false;
    }
    if (state.mldsa65_verify_key &&
        !VerifyRealityMldsa65Extension(cert.get(), state, *peer_public)) {
        return false;
    }

    LOG_NET_DEBUG("REALITY client verification completed");
    return true;
}

namespace {

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

    const uint32_t client_time = common::LoadU32BE(plain.data() + 4);
    if (!IsRealityClientTimeAllowed(client_time, state.max_time_diff_ms)) {
        return false;
    }

    // Short IDs are the shared client credential: scan all of them in
    // constant time per entry instead of stopping at the first match.
    bool matched = false;
    for (const auto& candidate : state.short_ids) {
        matched |= CRYPTO_memcmp(
            candidate.data(), plain.data() + 8, candidate.size()) == 0;
    }
    return matched;
}

[[nodiscard]] bssl::UniquePtr<X509> BuildRealityCertificate(
    const RealityServerState& state,
    std::span<const uint8_t, 32> auth_key,
    std::span<const uint8_t> mldsa65_signature = {}) {
    // REALITY replaces the X.509 signature with HMAC(authKey, publicKey).
    // Only that HMAC (and optional transcript-bound ML-DSA) is per-session;
    // the ordinary Ed25519 certificate signature is prepared once at startup.
    const uint8_t* encoded = state.certificate_template.data();
    bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &encoded, state.certificate_template.size()));
    if (!cert) return {};

    if (!mldsa65_signature.empty()) {
        static constexpr uint8_t kOidZero[] = {0x00};
        bssl::UniquePtr<ASN1_OBJECT> oid(ASN1_OBJECT_create(
            NID_undef, kOidZero, sizeof(kOidZero), nullptr, nullptr));
        bssl::UniquePtr<ASN1_OCTET_STRING> value(ASN1_OCTET_STRING_new());
        if (!oid ||
            !value ||
            ASN1_OCTET_STRING_set(
                value.get(),
                mldsa65_signature.data(),
                static_cast<int>(mldsa65_signature.size())) != 1) {
            return {};
        }
        bssl::UniquePtr<X509_EXTENSION> ext(X509_EXTENSION_create_by_OBJ(
            nullptr, oid.get(), 0, value.get()));
        if (!ext || X509_add_ext(cert.get(), ext.get(), 0) != 1) {
            return {};
        }
    }

    if (!mldsa65_signature.empty() && i2d_re_X509_tbs(cert.get(), nullptr) <= 0) {
        return {};
    }

    std::array<uint8_t, 64> signature{};
    const common::ScopedCleanse wipe_signature{signature};
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
    if (len >= 4 + 2 + kTls13HelloRetryRequestRandom.size() &&
        std::equal(kTls13HelloRetryRequestRandom.begin(),
                   kTls13HelloRetryRequestRandom.end(),
                   bytes + 6)) {
        return;
    }
    auto* ssl_ctx = SSL_get_SSL_CTX(ssl);
    auto* state = ssl_ctx
        ? static_cast<RealityServerState*>(
              SSL_CTX_get_ex_data(ssl_ctx, RealityStateExIndex()))
        : nullptr;
    if (!state || !state->mldsa65_key) {
        return;
    }
    struct ConnStateCleanup {
        SSL* ssl;
        ~ConnStateCleanup() noexcept {
            ClearRealityServerConnState(ssl);
        }
    } cleanup{ssl};

    auto* conn_state = static_cast<RealityServerConnState*>(
        SSL_get_ex_data(ssl, RealityConnStateExIndex()));
    if (!conn_state) {
        SSL_certs_clear(ssl);
        return;
    }

    std::array<uint8_t, 64> mldsa_msg{};
    const common::ScopedCleanse wipe_mldsa_msg{mldsa_msg};
    if (!ComputeRealityTranscriptHmac(
            conn_state->auth_key,
            state->ed25519_public,
            conn_state->client_hello_raw,
            std::span<const uint8_t>(bytes, len),
            mldsa_msg)) {
        SSL_certs_clear(ssl);
        return;
    }

    std::array<uint8_t, transport::internet::kRealityMldsa65SignatureSize> mldsa_sig{};
    static_assert(mldsa_sig.size() == MLDSA65_SIGNATURE_BYTES);
    if (MLDSA65_sign(mldsa_sig.data(), state->mldsa65_key.get(),
                     mldsa_msg.data(), mldsa_msg.size(), nullptr, 0) != 1) {
        SSL_certs_clear(ssl);
        return;
    }

    auto cert = BuildRealityCertificate(*state, conn_state->auth_key, mldsa_sig);
    if (!cert || SSL_use_certificate(ssl, cert.get()) != 1) {
        SSL_certs_clear(ssl);
    }
}

// RFC 8446 §4.2.1 supported_versions body; null when malformed.
[[nodiscard]] std::optional<bool> OffersTls13(std::span<const uint8_t> ext_data) noexcept {
    common::ByteReader versions_outer(ext_data);
    const uint8_t versions_len = versions_outer.ReadU8();
    const auto versions_bytes = versions_outer.ReadBytes(versions_len);
    if (!versions_outer.Ok() || !versions_outer.Empty() ||
        versions_len == 0 || (versions_len & 1u) != 0) {
        return std::nullopt;
    }
    bool supports_tls13 = false;
    common::ByteReader versions(versions_bytes);
    while (!versions.Empty()) {
        if (versions.ReadU16BE() == TLS1_3_VERSION) {
            supports_tls13 = true;
        }
    }
    return supports_tls13;
}

// REALITY 认证所需的 ClientHello 扩展；server_name 借用握手缓冲。
struct RealityClientHelloExtensions {
    std::optional<std::string_view> server_name;
    std::array<uint8_t, kRealityX25519KeySize> peer_public{};
};

// 每种相关扩展至多出现一次，且必须提供 TLS 1.3 与可用的 X25519 key_share。
[[nodiscard]] std::optional<RealityClientHelloExtensions> ParseRealityClientHelloExtensions(
    std::span<const uint8_t> extensions_bytes) noexcept {
    RealityClientHelloExtensions parsed;
    bool has_key_share = false;
    bool has_supported_versions = false;
    bool supports_tls13 = false;

    common::ByteReader extensions(extensions_bytes);
    while (!extensions.Empty()) {
        const uint16_t ext_type = extensions.ReadU16BE();
        const auto ext_data = extensions.ReadBytes(extensions.ReadU16BE());
        if (!extensions.Ok()) {
            return std::nullopt;
        }

        if (ext_type == TLSEXT_TYPE_server_name) {
            if (parsed.server_name) {
                return std::nullopt;
            }
            auto parsed_sni = transport::internet::ParseTlsServerNameExtension(ext_data);
            if (!parsed_sni) {
                return std::nullopt;
            }
            parsed.server_name = *parsed_sni;
        } else if (ext_type == TLSEXT_TYPE_key_share) {
            if (has_key_share) {
                return std::nullopt;
            }
            has_key_share = true;
            auto parsed_ks =
                transport::internet::ParseRealityClientKeyShareExtension(ext_data);
            if (!parsed_ks) {
                return std::nullopt;
            }
            parsed.peer_public = *parsed_ks;
        } else if (ext_type == TLSEXT_TYPE_supported_versions) {
            if (has_supported_versions) {
                return std::nullopt;
            }
            has_supported_versions = true;
            const auto offers_tls13 = OffersTls13(ext_data);
            if (!offers_tls13) {
                return std::nullopt;
            }
            supports_tls13 = *offers_tls13;
        }
    }

    if (!supports_tls13 || !has_key_share) {
        return std::nullopt;
    }
    return parsed;
}

[[nodiscard]] std::unique_ptr<RealityServerConnState>
VerifyRealityClientHelloHandshake(
    memory::ByteVector handshake,
    const RealityServerState& state) {
    // This is the reassembled handshake, including its four-byte header.
    common::ByteReader reader(handshake);
    const uint8_t msg_type = reader.ReadU8();
    const uint32_t hello_len = reader.ReadU24BE();
    if (!reader.Ok() || msg_type != SSL3_MT_CLIENT_HELLO ||
        hello_len != reader.Remaining()) {
        return nullptr;
    }
    (void)reader.ReadU16BE();
    const auto random = reader.ReadBytes(kRealityRandomSize);
    if (reader.ReadU8() != kRealitySessionIdSize ||
        !reader.Skip(kRealitySessionIdSize)) {
        return nullptr;
    }
    const uint16_t cipher_suites_len = reader.ReadU16BE();
    if (cipher_suites_len == 0 || (cipher_suites_len & 1u) != 0 ||
        !reader.Skip(cipher_suites_len)) {
        return nullptr;
    }
    const uint8_t comp_methods_len = reader.ReadU8();
    if (comp_methods_len == 0 || !reader.Skip(comp_methods_len)) {
        return nullptr;
    }
    const auto extensions_bytes = reader.ReadBytes(reader.ReadU16BE());
    if (!reader.Ok() || !reader.Empty()) {
        return nullptr;
    }

    const auto extensions = ParseRealityClientHelloExtensions(extensions_bytes);
    if (!extensions) {
        return nullptr;
    }
    if (!transport::internet::IsRealityServerNameAllowed(
            state.server_names, extensions->server_name.value_or(std::string_view{}))) {
        return nullptr;
    }

    auto auth_key = ComputeRealityAuthKey(
        state,
        extensions->peer_public,
        std::span<const uint8_t, 20>(random.data(), 20));
    if (!auth_key) {
        return nullptr;
    }
    const common::ScopedCleanse wipe_auth{*auth_key};

    std::array<uint8_t, kRealitySessionIdSize> session_id{};
    std::copy_n(handshake.data() + 4 + 35, kRealitySessionIdSize, session_id.data());
    std::fill_n(handshake.data() + 4 + 35, kRealitySessionIdSize, uint8_t{0});
    auto plain = OpenRealitySessionId(
        *auth_key,
        std::span<const uint8_t, kRealityAesGcmNonceSize>(
            random.data() + 20, kRealityAesGcmNonceSize),
        session_id,
        handshake);
    if (!plain) return nullptr;
    const common::ScopedCleanse wipe_plain{*plain};
    if (!IsRealityClientAuthAllowed(state, *plain)) return nullptr;

    auto conn_state = std::make_unique<RealityServerConnState>();
    conn_state->auth_key = *auth_key;
    if (state.mldsa65_key) {
        std::copy(session_id.begin(), session_id.end(), handshake.data() + 4 + 35);
        conn_state->client_hello_raw = std::move(handshake);
    }
    return conn_state;
}

[[nodiscard]] ssl_select_cert_result_t RealitySelectCertificateCallback(
    const SSL_CLIENT_HELLO* hello) {
    auto fail = [](std::string_view reason) {
        LOG_NET_DEBUG("REALITY server handshake rejected > {}", reason);
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

    auto* conn_state = static_cast<RealityServerConnState*>(
        SSL_get_ex_data(hello->ssl, RealityConnStateExIndex()));
    std::unique_ptr<RealityServerConnState> verified;
    if (!conn_state) {
        verified = VerifyRealityClientHelloHandshake(
            FramedClientHello(*hello), *state);
        if (!verified) {
            return fail("client hello verification failed");
        }
        conn_state = verified.get();
        if (state->mldsa65_key) {
            if (SSL_set_ex_data(
                    hello->ssl, RealityConnStateExIndex(), verified.get()) != 1) {
                return fail("failed to store REALITY connection state");
            }
            (void)verified.release();
        }
    }

    auto cert = BuildRealityCertificate(
        *state,
        std::span<const uint8_t, 32>(
            conn_state->auth_key.data(),
            conn_state->auth_key.size()));
    if (!cert) {
        return fail("ephemeral Ed25519 certificate build failed");
    }
    if (SSL_use_certificate(hello->ssl, cert.get()) != 1 ||
        SSL_use_PrivateKey(hello->ssl, state->ed25519_key.get()) != 1) {
        return fail("failed to install REALITY certificate on SSL connection");
    }
    if (!state->mldsa65_key) {
        ClearRealityServerConnState(hello->ssl);
    }
    LOG_NET_DEBUG("REALITY server handshake authenticated");
    return ssl_select_cert_success;
}

[[nodiscard]] std::unique_ptr<RealityServerState> BuildRealityServerState(
    const RealityConfig& config) {
    if (!config.private_key) {
        LOG_ERROR("REALITY server private key is missing");
        return {};
    }
    if (config.server_names.empty()) {
        LOG_ERROR("REALITY server name list is empty");
        return {};
    }
    if (config.short_ids.empty()) {
        LOG_ERROR("REALITY short ID list is empty");
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
        state->mldsa65_key.reset(new MLDSA65_private_key);
        if (MLDSA65_private_key_from_seed(
                state->mldsa65_key.get(), config.mldsa65_seed->data(),
                config.mldsa65_seed->size()) != 1) {
            LOG_ERROR("REALITY ML-DSA-65 key generation from seed failed");
            return {};
        }
    }

    std::array<uint8_t, 32> seed{};
    const common::ScopedCleanse wipe_seed{seed};
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

    bssl::UniquePtr<X509> certificate(X509_new());
    if (!certificate ||
        X509_set_version(certificate.get(), 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 0) != 1 ||
        !X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0) ||
        !X509_gmtime_adj(X509_get_notAfter(certificate.get()), 365 * 24 * 60 * 60) ||
        X509_set_pubkey(certificate.get(), state->ed25519_key.get()) != 1 ||
        X509_set_issuer_name(certificate.get(), X509_get_subject_name(certificate.get())) != 1 ||
        X509_sign(certificate.get(), state->ed25519_key.get(), nullptr) <= 0) {
        LOG_ERROR("REALITY certificate template creation failed");
        return {};
    }
    const int encoded_size = i2d_X509(certificate.get(), nullptr);
    if (encoded_size <= 0) return {};
    state->certificate_template.resize(static_cast<size_t>(encoded_size));
    auto* encoded = state->certificate_template.data();
    if (i2d_X509(certificate.get(), &encoded) != encoded_size) return {};

    return state;
}

[[nodiscard]] bool ConfigureRealityClientFingerprint(SSL_CTX* ctx,
                                                    std::string_view fingerprint) {
    uint16_t tls13_ciphers[] = {
        SSL_CIPHER_AES_128_GCM_SHA256,
        SSL_CIPHER_AES_256_GCM_SHA384,
        SSL_CIPHER_CHACHA20_POLY1305_SHA256,
    };
    if (fingerprint == "firefox") {
        std::swap(tls13_ciphers[1], tls13_ciphers[2]);
    }
    if (SSL_CTX_set1_tls13_ciphers(ctx, tls13_ciphers, nullptr,
                                  std::size(tls13_ciphers)) != 1) {
        return false;
    }
    if (fingerprint == "firefox") {
        SSL_CTX_set_grease_enabled(ctx, 0);
        SSL_CTX_set_permute_extensions(ctx, 0);
        return SSL_CTX_set_strict_cipher_list(
            ctx,
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:"
            "AES128-SHA:AES256-SHA") == 1;
    }
    if (fingerprint == "safari" || fingerprint == "ios") {
        SSL_CTX_set_grease_enabled(ctx, 1);
        SSL_CTX_set_permute_extensions(ctx, 0);
        return SSL_CTX_set_strict_cipher_list(
            ctx,
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:"
            "AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA:AES128-SHA") == 1;
    }
    if (fingerprint == "360" || fingerprint == "qq") {
        SSL_CTX_set_grease_enabled(ctx, 1);
        SSL_CTX_set_permute_extensions(ctx, 0);
    } else {
        // chrome, edge, android, random, randomized, auto, or default
        SSL_CTX_set_grease_enabled(ctx, 1);
        SSL_CTX_set_permute_extensions(ctx, 1);
    }
    return SSL_CTX_set_strict_cipher_list(
        ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:"
        "ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:"
        "AES128-SHA:AES256-SHA") == 1;
}

// Groups and signature algorithms are part of the fingerprint: parse them once
// into the context; SSL_new copies both lists into every connection.
[[nodiscard]] bool ConfigureRealityClientKeyExchange(SSL_CTX* ctx,
                                                     std::string_view fingerprint) {
    const char* groups = "X25519MLKEM768:X25519:P-256:P-384";
    static constexpr uint16_t chrome_sigalgs[] = {
        SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256,
        SSL_SIGN_RSA_PKCS1_SHA256, SSL_SIGN_ECDSA_SECP384R1_SHA384,
        SSL_SIGN_RSA_PSS_RSAE_SHA384, SSL_SIGN_RSA_PKCS1_SHA384,
        SSL_SIGN_RSA_PSS_RSAE_SHA512, SSL_SIGN_RSA_PKCS1_SHA512,
    };
    static constexpr uint16_t firefox_sigalgs[] = {
        SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_ECDSA_SECP384R1_SHA384,
        SSL_SIGN_ECDSA_SECP521R1_SHA512, SSL_SIGN_RSA_PSS_RSAE_SHA256,
        SSL_SIGN_RSA_PSS_RSAE_SHA384, SSL_SIGN_RSA_PSS_RSAE_SHA512,
        SSL_SIGN_RSA_PKCS1_SHA256, SSL_SIGN_RSA_PKCS1_SHA384,
        SSL_SIGN_RSA_PKCS1_SHA512,
    };
    static constexpr uint16_t safari_sigalgs[] = {
        SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256,
        SSL_SIGN_RSA_PKCS1_SHA256, SSL_SIGN_ECDSA_SECP384R1_SHA384,
        SSL_SIGN_ECDSA_SECP521R1_SHA512, SSL_SIGN_RSA_PSS_RSAE_SHA384,
        SSL_SIGN_RSA_PSS_RSAE_SHA512, SSL_SIGN_RSA_PKCS1_SHA384,
        SSL_SIGN_RSA_PKCS1_SHA512, SSL_SIGN_RSA_PKCS1_SHA1,
    };
    std::span<const uint16_t> sigalgs = chrome_sigalgs;
    if (fingerprint == "firefox") {
        groups = "X25519MLKEM768:X25519:P-256:P-384:P-521";
        sigalgs = firefox_sigalgs;
    } else if (fingerprint == "safari" || fingerprint == "ios") {
        groups = "X25519MLKEM768:X25519:P-256:P-384:P-521";
        sigalgs = safari_sigalgs;
    } else if (fingerprint == "random" || fingerprint == "randomized") {
        groups = "X25519MLKEM768:X25519:P-256:P-384:P-521";
    }
    if (SSL_CTX_set1_groups_list(ctx, groups) != 1) {
        LOG_ERROR("REALITY client failed to configure key share groups");
        return false;
    }
    if (SSL_CTX_set_signing_algorithm_prefs(ctx, sigalgs.data(), sigalgs.size()) != 1 ||
        SSL_CTX_set_verify_algorithm_prefs(ctx, sigalgs.data(), sigalgs.size()) != 1) {
        LOG_ERROR("REALITY client failed to configure signature algorithms");
        return false;
    }
    return true;
}

}  // namespace

std::unique_ptr<SslContext> SslContext::CreateServerReality(
    const RealityConfig& reality,
    const TlsConfig& tls_config) {
    auto state = BuildRealityServerState(reality);
    if (!state) {
        return nullptr;
    }

    bssl::UniquePtr<SSL_CTX> owner(SSL_CTX_new(TLS_server_method()));
    SSL_CTX* ctx = owner.get();
    if (!ctx) {
        LOG_ERROR("failed to create REALITY server TLS context");
        return nullptr;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_reality_ignore_peer_signature_algorithm_prefs(ctx, 1);

    const int state_index = RealityStateExIndex();
    if (state_index < 0 ||
        SSL_CTX_set_ex_data(ctx, state_index, state.get()) != 1) {
        LOG_ERROR("failed to attach REALITY server state");
        return nullptr;
    }
    auto* raw_state = state.release();
    SSL_CTX_set_select_certificate_cb(ctx, RealitySelectCertificateCallback);
    if (raw_state->mldsa65_key) {
        SSL_CTX_set_msg_callback(ctx, RealityServerMsgCallback);
    }

    if (!ConfigureTlsServerAlpn(ctx, tls_config.alpn)) {
        LOG_ERROR("invalid REALITY server ALPN policy");
        return nullptr;
    }
    LOG_INFO("REALITY server context enabled (serverNames={}, shortIds={})",
             reality.server_names.size(),
             reality.short_ids.size());
    return std::unique_ptr<SslContext>(new SslContext(std::move(owner)));
}

std::unique_ptr<SslContext> SslContext::CreateClientReality(
    const RealityConfig& reality,
    const TlsConfig& tls_config) {
    if (!reality.IsClient()) {
        LOG_ERROR("REALITY client public key is missing");
        return nullptr;
    }

    const SSL_METHOD* method = TLS_client_method();
    bssl::UniquePtr<SSL_CTX> owner(SSL_CTX_new(method));
    SSL_CTX* ctx = owner.get();
    if (!ctx) {
        LOG_ERROR("failed to create REALITY client TLS context");
        return nullptr;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    if (!ConfigureRealityClientFingerprint(ctx, reality.fingerprint) ||
        !ConfigureRealityClientKeyExchange(ctx, reality.fingerprint)) {
        return nullptr;
    }
    if (!ConfigureTlsClientAlpn(ctx, tls_config.alpn)) {
        LOG_ERROR("invalid REALITY client ALPN policy");
        return nullptr;
    }

    if (reality.mldsa65_verify) {
        auto state = std::make_unique<RealityClientContextState>();
        CBS encoded;
        CBS_init(&encoded, reality.mldsa65_verify->data(),
                 reality.mldsa65_verify->size());
        if (MLDSA65_parse_public_key(&state->mldsa65_verify_key, &encoded) != 1) {
            LOG_ERROR("REALITY client ML-DSA-65 public key initialization failed");
            return nullptr;
        }
        const int state_index = RealityClientContextStateExIndex();
        if (state_index < 0 ||
            SSL_CTX_set_ex_data(ctx, state_index, state.get()) != 1) {
            LOG_ERROR("failed to attach REALITY client state to TLS context");
            return nullptr;
        }
        (void)state.release();
    }

    return std::unique_ptr<SslContext>(new SslContext(std::move(owner)));
}

bool TlsStream::SetRealityClient(const RealityConfig& reality) {
    SSL* ssl = NativeSsl();
    if (is_server_) {
        return false;
    }

    SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(ssl);
    const auto* ctx_state = ssl_ctx
        ? static_cast<const RealityClientContextState*>(
              SSL_CTX_get_ex_data(ssl_ctx, RealityClientContextStateExIndex()))
        : nullptr;
    const MLDSA65_public_key* verify_key =
        ctx_state ? &ctx_state->mldsa65_verify_key : nullptr;
    if (reality.mldsa65_verify && !verify_key) {
        LOG_ERROR("REALITY client missing prebuilt ML-DSA-65 verification key");
        return false;
    }

    auto state = BuildRealityClientState(reality, verify_key);
    if (!state) {
        return false;
    }

    if (SSL_set1_reality_peer_public_key(
            ssl,
            reality.public_key->data(),
            reality.public_key->size()) != 1) {
        LOG_ERROR("REALITY client peer public key install failed");
        return false;
    }

    if (state->mldsa65_verify_key) {
        SSL_set_msg_callback(ssl, RealityClientMsgCallback);
        SSL_set_msg_callback_arg(ssl, state.get());
    }
    SSL_set_reality_client_hello_cb(
        ssl,
        RealityClientHelloCallback,
        state.get());
    reality_client_state_ = std::move(state);
    return true;
}

std::unique_ptr<RealityServerConnState> VerifyRealityClientHello(
    memory::ByteVector handshake,
    const SslContext& ctx) {
    const SSL_CTX* ssl_ctx = ctx.Native();
    const auto* state = ssl_ctx
        ? static_cast<const RealityServerState*>(
              SSL_CTX_get_ex_data(ssl_ctx, RealityStateExIndex()))
        : nullptr;
    if (!state) {
        return nullptr;
    }
    return VerifyRealityClientHelloHandshake(std::move(handshake), *state);
}

bool TlsStream::SetRealityServerPreverified(
    std::unique_ptr<RealityServerConnState> state) noexcept {
    SSL* ssl = NativeSsl();
    if (!state) {
        return false;
    }
    if (SSL_set_ex_data(ssl, RealityConnStateExIndex(), state.get()) != 1) {
        return false;
    }
    (void)state.release();
    return true;
}

void ClearRealityClientState(
    SSL* ssl,
    std::unique_ptr<RealityClientState>& state) noexcept {
    if (!state) {
        return;
    }
    if (ssl) {
        SSL_set_msg_callback(ssl, nullptr);
        SSL_set_msg_callback_arg(ssl, nullptr);
        SSL_set_reality_client_hello_cb(ssl, nullptr, nullptr);
    }
    state.reset();
}

void ClearRealityServerConnState(SSL* ssl) noexcept {
    if (!ssl) {
        return;
    }
    const int idx = RealityConnStateExIndex();
    auto* state = static_cast<RealityServerConnState*>(SSL_get_ex_data(ssl, idx));
    if (state) {
        (void)SSL_set_ex_data(ssl, idx, nullptr);
        delete state;
    }
}

}  // namespace transport::internet
