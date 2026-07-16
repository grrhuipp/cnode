#include "reality_tls.hpp"

#include "acppnode/transport/internet/tls_stream.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"

#include <openssl/aead.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
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
constexpr size_t kRealityShortIdSize = 8;
constexpr size_t kRealityAesGcmNonceSize = 12;
constexpr uint16_t kTlsGroupX25519 = 29;
constexpr uint16_t kTlsGroupX25519MlKem768 = 0x11ec;

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

using UniqueEvpPkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using UniqueX509 = std::unique_ptr<X509, X509Deleter>;

struct RealityServerState {
    std::array<uint8_t, kRealityX25519KeySize> private_key{};
    std::vector<std::string> server_names;
    std::vector<std::array<uint8_t, kRealityShortIdSize>> short_ids;
    std::optional<std::array<uint8_t, 4>> min_client_ver;
    std::optional<std::array<uint8_t, 4>> max_client_ver;
    uint64_t max_time_diff_ms = 0;
    UniqueEvpPkey ed25519_key;
    std::array<uint8_t, 32> ed25519_public{};
};

[[nodiscard]] int RealityStateExIndex() {
    static const int index = SSL_CTX_get_ex_new_index(
        0, nullptr, nullptr, nullptr, nullptr);
    return index;
}

[[nodiscard]] int Base64RawUrlValue(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

[[nodiscard]] std::optional<std::vector<uint8_t>> DecodeBase64RawUrl(
    std::string_view value) {
    if (value.empty() ||
        value.find('=') != std::string_view::npos ||
        value.size() % 4 == 1) {
        return std::nullopt;
    }

    std::vector<uint8_t> out;
    out.reserve(value.size() * 3 / 4);
    uint32_t bits = 0;
    int bit_count = 0;
    for (char c : value) {
        const int v = Base64RawUrlValue(c);
        if (v < 0) {
            return std::nullopt;
        }
        bits = (bits << 6) | static_cast<uint32_t>(v);
        bit_count += 6;
        if (bit_count >= 8) {
            bit_count -= 8;
            out.push_back(static_cast<uint8_t>((bits >> bit_count) & 0xff));
        }
    }
    return out;
}

[[nodiscard]] int HexValue(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

[[nodiscard]] std::optional<std::array<uint8_t, kRealityShortIdSize>>
DecodeRealityShortId(std::string_view value) noexcept {
    if (value.size() % 2 != 0 ||
        value.size() / 2 > kRealityShortIdSize) {
        return std::nullopt;
    }

    std::array<uint8_t, kRealityShortIdSize> out{};
    for (size_t i = 0; i < value.size(); i += 2) {
        const int hi = HexValue(value[i]);
        const int lo = HexValue(value[i + 1]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out[i / 2] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

[[nodiscard]] std::optional<std::array<uint8_t, 4>>
ParseRealityClientVersion(std::string_view value) noexcept {
    if (value.empty()) {
        return std::nullopt;
    }

    std::array<uint8_t, 4> version{};
    size_t part = 0;
    size_t start = 0;
    while (start <= value.size() && part < 3) {
        const size_t dot = value.find('.', start);
        const size_t end = dot == std::string_view::npos ? value.size() : dot;
        if (end == start) {
            return std::nullopt;
        }
        uint32_t parsed = 0;
        for (char ch : value.substr(start, end - start)) {
            if (ch < '0' || ch > '9') {
                return std::nullopt;
            }
            parsed = parsed * 10u + static_cast<uint32_t>(ch - '0');
            if (parsed > 255u) {
                return std::nullopt;
            }
        }
        version[part++] = static_cast<uint8_t>(parsed);
        if (dot == std::string_view::npos) {
            break;
        }
        start = dot + 1;
    }
    if (start < value.size() && part >= 3) {
        return std::nullopt;
    }
    return version;
}

[[nodiscard]] uint32_t RealityVersionValue(
    std::span<const uint8_t, 4> version) noexcept {
    return (static_cast<uint32_t>(version[0]) << 24) |
           (static_cast<uint32_t>(version[1]) << 16) |
           (static_cast<uint32_t>(version[2]) << 8) |
           static_cast<uint32_t>(version[3]);
}

[[nodiscard]] uint16_t ReadBigEndianU16(const uint8_t* data) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) |
                                 static_cast<uint16_t>(data[1]));
}

[[nodiscard]] bool ParseRealitySni(
    const SSL_CLIENT_HELLO& hello,
    std::string_view& out) noexcept {
    const uint8_t* ext = nullptr;
    size_t ext_len = 0;
    if (SSL_early_callback_ctx_extension_get(
            &hello,
            TLSEXT_TYPE_server_name,
            &ext,
            &ext_len) != 1 ||
        !ext ||
        ext_len < 2) {
        return false;
    }

    const uint16_t list_len = ReadBigEndianU16(ext);
    if (static_cast<size_t>(list_len) + 2 > ext_len) {
        return false;
    }

    size_t pos = 2;
    const size_t end = 2 + static_cast<size_t>(list_len);
    while (pos + 3 <= end) {
        const uint8_t name_type = ext[pos++];
        const uint16_t name_len = ReadBigEndianU16(ext + pos);
        pos += 2;
        if (pos + name_len > end) {
            return false;
        }
        if (name_type == 0) {
            out = std::string_view(
                unsafe::ptr_cast<const char>(ext + pos),
                name_len);
            return !out.empty();
        }
        pos += name_len;
    }
    return false;
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
        !ext ||
        ext_len < 2) {
        return std::nullopt;
    }

    const uint16_t list_len = ReadBigEndianU16(ext);
    if (static_cast<size_t>(list_len) + 2 > ext_len) {
        return std::nullopt;
    }

    std::optional<std::array<uint8_t, kRealityX25519KeySize>> mlkem_x25519;
    size_t pos = 2;
    const size_t end = 2 + static_cast<size_t>(list_len);
    while (pos + 4 <= end) {
        const uint16_t group = ReadBigEndianU16(ext + pos);
        pos += 2;
        const uint16_t key_len = ReadBigEndianU16(ext + pos);
        pos += 2;
        if (pos + key_len > end) {
            return std::nullopt;
        }

        const uint8_t* key = ext + pos;
        if (group == kTlsGroupX25519 && key_len == kRealityX25519KeySize) {
            std::array<uint8_t, kRealityX25519KeySize> out{};
            std::copy_n(key, out.size(), out.begin());
            return out;
        }
        if (group == kTlsGroupX25519MlKem768 &&
            key_len >= kRealityX25519KeySize) {
            std::array<uint8_t, kRealityX25519KeySize> out{};
            std::copy_n(
                key + key_len - kRealityX25519KeySize,
                out.size(),
                out.begin());
            mlkem_x25519 = out;
        }
        pos += key_len;
    }
    return mlkem_x25519;
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

struct RealityClientState {
    std::array<uint8_t, kRealityX25519KeySize> server_public{};
    std::array<uint8_t, kRealityShortIdSize> short_id{};
    std::array<uint8_t, 32> auth_key{};
    bool auth_key_ready = false;
};

[[nodiscard]] std::shared_ptr<RealityClientState> BuildRealityClientState(
    const RealityConfig& config) {
    auto key = DecodeBase64RawUrl(config.public_key);
    if (!key || key->size() != kRealityX25519KeySize) {
        LOG_ERROR("REALITY client publicKey is invalid");
        return {};
    }
    auto short_id = DecodeRealityShortId(config.short_id);
    if (!short_id) {
        LOG_ERROR("REALITY client shortId '{}' is invalid", config.short_id);
        return {};
    }

    auto state = std::make_shared<RealityClientState>();
    std::copy_n(key->data(), state->server_public.size(), state->server_public.begin());
    state->short_id = *short_id;
    return state;
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
        LOG_ACCESS_DEBUG("REALITY client verification failed: missing peer certificate");
        return false;
    }

    EVP_PKEY* pubkey = X509_get0_pubkey(cert.get());
    if (!pubkey || EVP_PKEY_id(pubkey) != EVP_PKEY_ED25519) {
        LOG_ACCESS_DEBUG("REALITY client verification failed: peer key is not Ed25519");
        return false;
    }

    std::array<uint8_t, 32> peer_public{};
    size_t peer_public_len = peer_public.size();
    if (EVP_PKEY_get_raw_public_key(
            pubkey,
            peer_public.data(),
            &peer_public_len) != 1 ||
        peer_public_len != peer_public.size()) {
        LOG_ACCESS_DEBUG("REALITY client verification failed: peer public key export failed");
        return false;
    }

    const ASN1_BIT_STRING* sig = nullptr;
    const X509_ALGOR* sig_alg = nullptr;
    X509_get0_signature(&sig, &sig_alg, cert.get());
    (void)sig_alg;
    if (!sig ||
        ASN1_STRING_length(sig) != 64 ||
        !ASN1_STRING_get0_data(sig)) {
        LOG_ACCESS_DEBUG("REALITY client verification failed: certificate signature invalid");
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
        LOG_ACCESS_DEBUG("REALITY client verification failed: signature hmac failed");
        return false;
    }

    const uint8_t* signature = ASN1_STRING_get0_data(sig);
    if (!std::equal(expected.begin(), expected.end(), signature)) {
        LOG_ACCESS_DEBUG("REALITY client verification failed: signature mismatch");
        return false;
    }

    LOG_ACCESS_DEBUG("REALITY client verification ok");
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
    const uint32_t client_ver_value = RealityVersionValue(client_ver);
    if (state.min_client_ver &&
        client_ver_value < RealityVersionValue(*state.min_client_ver)) {
        return false;
    }
    if (state.max_client_ver &&
        client_ver_value > RealityVersionValue(*state.max_client_ver)) {
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

    std::array<uint8_t, kRealityShortIdSize> short_id{};
    std::copy_n(plain.data() + 8, short_id.size(), short_id.begin());
    return std::find(state.short_ids.begin(), state.short_ids.end(), short_id) !=
           state.short_ids.end();
}

[[nodiscard]] UniqueX509 BuildRealityCertificate(
    RealityServerState& state,
    std::span<const uint8_t, 32> auth_key) {
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

[[nodiscard]] ssl_select_cert_result_t RealitySelectCertificateCallback(
    const SSL_CLIENT_HELLO* hello) {
    auto fail = [](std::string_view reason) {
        LOG_ACCESS_DEBUG("REALITY server handshake reject: {}", reason);
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
    if (!ParseRealitySni(*hello, sni) ||
        std::find(state->server_names.begin(),
                  state->server_names.end(),
                  sni) == state->server_names.end()) {
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

    auto cert = BuildRealityCertificate(
        *state,
        std::span<const uint8_t, 32>(auth_key->data(), auth_key->size()));
    if (!cert ||
        SSL_use_certificate(hello->ssl, cert.get()) != 1 ||
        SSL_use_PrivateKey(hello->ssl, state->ed25519_key.get()) != 1) {
        return fail("certificate install failed");
    }

    LOG_ACCESS_DEBUG("REALITY server handshake authenticated");
    return ssl_select_cert_success;
}

[[nodiscard]] std::shared_ptr<RealityServerState> BuildRealityServerState(
    const RealityConfig& config) {
    auto key = DecodeBase64RawUrl(config.private_key);
    if (!key || key->size() != kRealityX25519KeySize) {
        LOG_ERROR("REALITY server privateKey is invalid");
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

    auto state = std::make_shared<RealityServerState>();
    std::copy_n(key->data(), state->private_key.size(), state->private_key.begin());
    state->server_names = config.server_names;
    state->max_time_diff_ms = config.max_time_diff;
    state->min_client_ver = ParseRealityClientVersion(config.min_client_ver);
    state->max_client_ver = ParseRealityClientVersion(config.max_client_ver);

    for (const auto& short_id_text : config.short_ids) {
        auto short_id = DecodeRealityShortId(short_id_text);
        if (!short_id) {
            LOG_ERROR("REALITY shortId '{}' is invalid", short_id_text);
            return {};
        }
        state->short_ids.push_back(*short_id);
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
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_reality_ignore_peer_signature_algorithm_prefs(ctx, 1);

    if (SSL_CTX_set_ex_data(ctx, RealityStateExIndex(), state.get()) != 1) {
        LOG_ERROR("Failed to attach REALITY server state");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_select_certificate_cb(ctx, RealitySelectCertificateCallback);

    auto out = std::unique_ptr<SslContext>(
        new SslContext(ctx, std::static_pointer_cast<void>(state)));
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
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

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

    if (SSL_set1_groups_list(ssl, "X25519") != 1) {
        LOG_ERROR("REALITY client failed to force X25519 key share");
        return false;
    }
    if (SSL_set1_sigalgs_list(ssl, "ed25519") != 1) {
        LOG_ERROR("REALITY client failed to advertise Ed25519");
        return false;
    }

    SSL_set_reality_client_hello_cb(
        ssl,
        RealityClientHelloCallback,
        state.get());
    app_state_ = std::static_pointer_cast<void>(state);
    return true;
}

bool VerifyRealityClientHandshake(
    SSL* ssl,
    const std::shared_ptr<void>& app_state) {
    auto state = std::static_pointer_cast<RealityClientState>(app_state);
    return state && VerifyRealityPeerCertificate(ssl, *state);
}

}  // namespace acpp
