#include "acppnode/transport/internet/tls_stream.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛
#include <openssl/aead.h>
#include <openssl/curve25519.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>
#include <algorithm>
#include <chrono>
#include <limits>
#include <mutex>
#include <optional>
#include <span>
#include <unordered_map>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

namespace acpp {

// ============================================================================
// SslContext 实现
// ============================================================================

namespace {

int SelectServerAlpnCallback(
    SSL* ssl,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* /*arg*/) {
    auto* ctx = static_cast<SslContext*>(
        SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
    if (!ctx) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    const auto& configured = ctx->ServerAlpnWire();
    if (configured.empty()) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    unsigned char* selected = nullptr;
    const int rc = SSL_select_next_proto(
        &selected,
        outlen,
        configured.data(),
        static_cast<unsigned int>(configured.size()),
        in,
        inlen);
    if (rc != OPENSSL_NPN_NEGOTIATED || !selected || *outlen == 0) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    *out = selected;
    return SSL_TLSEXT_ERR_OK;
}

}  // namespace

std::unique_ptr<SslContext> SslContext::CreateServer(const TlsConfig& config) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        LOG_ERROR("Failed to create SSL server context");
        return nullptr;
    }

    // 设置 TLS 版本
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    // 加载证书
    if (SSL_CTX_use_certificate_chain_file(ctx, config.cert_file.c_str()) <= 0) {
        LOG_ERROR("Failed to load certificate: {}", config.cert_file);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // 加载私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, config.key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("Failed to load private key: {}", config.key_file);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // 验证私钥与证书匹配
    if (!SSL_CTX_check_private_key(ctx)) {
        LOG_ERROR("Private key does not match certificate");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    auto out = std::unique_ptr<SslContext>(new SslContext(ctx));
    out->ConfigureServerAlpn(config.alpn);
    return out;
}

// ============================================================================
// 自动签名：根据 SNI 动态生成自签证书
// ============================================================================

namespace {

[[noreturn]] void ThrowTlsWriteError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

[[noreturn]] void ThrowTlsReadError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

bool IsBenignServerHandshakeError(unsigned long err_code) {
    if (err_code == 0) return false;
    const auto reason = ERR_GET_REASON(err_code);
#ifdef SSL_R_WRONG_VERSION_NUMBER
    if (reason == SSL_R_WRONG_VERSION_NUMBER) return true;
#endif
#ifdef SSL_R_HTTP_REQUEST
    if (reason == SSL_R_HTTP_REQUEST) return true;
#endif
    return false;
}

struct AutoSignState {
    EVP_PKEY* pkey = nullptr;
    std::mutex mu;
    std::unordered_map<std::string, X509*> cert_cache;
    long next_serial = 1;

    ~AutoSignState() {
        for (auto& [_, cert] : cert_cache) X509_free(cert);
        if (pkey) EVP_PKEY_free(pkey);
    }

    bool EnsureKey() {
        std::lock_guard lock(mu);
        if (pkey) {
            return true;
        }

        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        EVP_PKEY* generated = nullptr;
        if (!pctx ||
            EVP_PKEY_keygen_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
            EVP_PKEY_keygen(pctx, &generated) <= 0) {
            if (pctx) EVP_PKEY_CTX_free(pctx);
            if (generated) EVP_PKEY_free(generated);
            return false;
        }
        EVP_PKEY_CTX_free(pctx);
        pkey = generated;
        return true;
    }

    // 为指定域名生成或获取缓存的证书
    X509* GetOrCreate(const std::string& cn) {
        std::lock_guard lock(mu);
        if (auto it = cert_cache.find(cn); it != cert_cache.end())
            return it->second;

        X509* x509 = X509_new();
        if (!x509) return nullptr;

        X509_set_version(x509, 2);

        // Cache-local serial; GetOrCreate is already serialized by mu.
        ASN1_INTEGER_set(X509_get_serialNumber(x509), next_serial++);

        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);

        X509_set_pubkey(x509, pkey);

        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
        X509_set_issuer_name(x509, name);

        // SAN 扩展：泛域名 + 裸域名（如 *.example.com, example.com）
        X509V3_CTX v3ctx;
        X509V3_set_ctx_nodb(&v3ctx);
        X509V3_set_ctx(&v3ctx, x509, x509, nullptr, nullptr, 0);
        std::string san_val = "DNS:" + cn;
        // 泛域名时额外加裸域名
        if (cn.size() > 2 && cn[0] == '*' && cn[1] == '.') {
            san_val += ",DNS:" + cn.substr(2);
        }
        X509_EXTENSION* san_ext = X509V3_EXT_nconf_nid(
            nullptr, &v3ctx, NID_subject_alt_name,
            const_cast<char*>(san_val.c_str()));
        if (san_ext) {
            X509_add_ext(x509, san_ext, -1);
            X509_EXTENSION_free(san_ext);
        }

        if (!X509_sign(x509, pkey, EVP_sha256())) {
            X509_free(x509);
            return nullptr;
        }

        cert_cache[cn] = x509;
        LOG_DEBUG("自签证书已生成: {}", cn);
        return x509;
    }
};

AutoSignState& GetAutoSignState() {
    static AutoSignState state;
    return state;
}

// 从 SNI 提取泛域名：www.example.com → *.example.com
// 裸域名 example.com → *.example.com
// 单标签 localhost → localhost（不做通配）
std::string ToWildcard(std::string_view sni) {
    auto dot = sni.find('.');
    if (dot == std::string_view::npos) return std::string(sni);  // localhost 等
    // *.example.com
    return "*" + std::string(sni.substr(dot));
}

std::string ResolveAutoSignDefaultName(const TlsConfig& config) {
    if (config.server_name.empty()) {
        return "localhost";
    }
    return ToWildcard(config.server_name);
}

// SNI 回调：根据客户端请求的域名切换泛域名证书
int AutoSignSniCallback(SSL* ssl, int* /*ad*/, void* /*arg*/) {
    const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    std::string wildcard = sni ? ToWildcard(sni) : "localhost";

    auto& state = GetAutoSignState();
    thread_local AutoSignState* last_state = nullptr;
    thread_local std::string last_wildcard;
    thread_local X509* last_cert = nullptr;

    X509* cert = nullptr;
    if (last_state == &state && last_cert && last_wildcard == wildcard) {
        cert = last_cert;
    } else {
        cert = state.GetOrCreate(wildcard);
        if (cert) {
            last_state = &state;
            last_wildcard = std::move(wildcard);
            last_cert = cert;
        }
    }
    if (!cert) return SSL_TLSEXT_ERR_ALERT_FATAL;

    SSL_use_certificate(ssl, cert);
    SSL_use_PrivateKey(ssl, state.pkey);
    return SSL_TLSEXT_ERR_OK;
}

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

std::unique_ptr<SslContext> SslContext::CreateServerAutoSign(const TlsConfig& config) {
    auto& state = GetAutoSignState();

    // 只在首次调用时生成 EC P-256 密钥
    if (!state.EnsureKey()) {
        LOG_ERROR("EC P-256 密钥生成失败");
        return nullptr;
    }

    // 默认证书优先使用配置的 server_name，避免无 SNI 时退回 localhost。
    const std::string default_name = ResolveAutoSignDefaultName(config);
    X509* default_cert = state.GetOrCreate(default_name);
    if (!default_cert) {
        LOG_ERROR("默认自签证书生成失败");
        return nullptr;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return nullptr;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    SSL_CTX_use_certificate(ctx, default_cert);
    SSL_CTX_use_PrivateKey(ctx, state.pkey);

    // 注册 SNI 回调，按需切换证书
    SSL_CTX_set_tlsext_servername_callback(ctx, AutoSignSniCallback);

    LOG_INFO("TLS 自动签名模式已启用（按 SNI 动态生成证书，默认域名={}）",
             default_name);
    auto out = std::unique_ptr<SslContext>(new SslContext(ctx));
    out->ConfigureServerAlpn(config.alpn);
    return out;
}

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
    out->ConfigureServerAlpn(tls_config.alpn);
    LOG_INFO("REALITY server context enabled (serverNames={}, shortIds={})",
             reality.server_names.size(),
             reality.short_ids.size());
    return out;
}

std::unique_ptr<SslContext> SslContext::CreateClient(const TlsConfig& config) {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        LOG_ERROR("Failed to create SSL client context");
        return nullptr;
    }

    // 设置 TLS 版本
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    if (config.allow_insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_default_verify_paths(ctx);
    }

    return std::unique_ptr<SslContext>(new SslContext(ctx));
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

void SslContext::ConfigureServerAlpn(const std::vector<std::string>& protocols) {
    server_alpn_wire_.clear();
    for (const auto& proto : protocols) {
        if (proto.empty() || proto.size() > 255) {
            continue;
        }
        server_alpn_wire_.push_back(static_cast<unsigned char>(proto.size()));
        server_alpn_wire_.insert(
            server_alpn_wire_.end(),
            proto.begin(),
            proto.end());
    }

    if (!server_alpn_wire_.empty()) {
        SSL_CTX_set_app_data(ctx_, this);
        SSL_CTX_set_alpn_select_cb(ctx_, SelectServerAlpnCallback, nullptr);
    }
}

SslContext::~SslContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

// ============================================================================
// TlsStream 实现
// ============================================================================

TlsStream::TlsStream(std::unique_ptr<TcpStream> inner, SSL_CTX* ctx, bool is_server)
    : inner_(std::move(*inner))
    , is_server_(is_server) {

    ssl_ = SSL_new(ctx);
    if (!ssl_) {
        throw std::runtime_error("Failed to create SSL object");
    }
    SSL_set_mode(ssl_, SSL_MODE_RELEASE_BUFFERS);

    // 创建内存 BIO 对
    read_bio_ = BIO_new(BIO_s_mem());
    write_bio_ = BIO_new(BIO_s_mem());

    if (!read_bio_ || !write_bio_) {
        if (read_bio_) BIO_free(read_bio_);
        if (write_bio_) BIO_free(write_bio_);
        SSL_free(ssl_);
        throw std::runtime_error("Failed to create BIO objects");
    }

    // 设置非阻塞模式
    BIO_set_nbio(read_bio_, 1);
    BIO_set_nbio(write_bio_, 1);

    SSL_set_bio(ssl_, read_bio_, write_bio_);
    memory::OnTlsStreamNew();

    if (is_server_) {
        SSL_set_accept_state(ssl_);
    } else {
        SSL_set_connect_state(ssl_);
    }
}

TlsStream::~TlsStream() {
    if (ssl_) {
        memory::OnTlsStreamFree();
        SSL_free(ssl_);  // 这会自动释放关联的 BIO
    }
}

TlsStream::TlsStream(TlsStream&& other) noexcept
    : inner_(std::move(other.inner_))
    , ssl_(other.ssl_)
    , read_bio_(other.read_bio_)
    , write_bio_(other.write_bio_)
    , is_server_(other.is_server_)
    , handshake_done_(other.handshake_done_)
    , shutdown_initiated_(other.shutdown_initiated_)
    , app_state_(std::move(other.app_state_)) {
    other.ssl_ = nullptr;
    other.read_bio_ = nullptr;
    other.write_bio_ = nullptr;
    other.shutdown_initiated_ = true;  // 防止被移动的对象再调用 shutdown
}

TlsStream& TlsStream::operator=(TlsStream&& other) noexcept {
    if (this != &other) {
        if (ssl_) {
            memory::OnTlsStreamFree();
            SSL_free(ssl_);
        }
        inner_ = std::move(other.inner_);
        ssl_ = other.ssl_;
        read_bio_ = other.read_bio_;
        write_bio_ = other.write_bio_;
        is_server_ = other.is_server_;
        handshake_done_ = other.handshake_done_;
        shutdown_initiated_ = other.shutdown_initiated_;
        app_state_ = std::move(other.app_state_);
        other.ssl_ = nullptr;
        other.read_bio_ = nullptr;
        other.write_bio_ = nullptr;
        other.shutdown_initiated_ = true;  // 防止被移动的对象再调用 shutdown
    }
    return *this;
}

void TlsStream::SetServerName(const std::string& name) {
    if (!is_server_ && ssl_) {
        SSL_set_tlsext_host_name(ssl_, name.c_str());
    }
}

void TlsStream::SetAlpn(const std::vector<std::string>& protocols) {
    if (protocols.empty() || !ssl_) return;

    // 构建 ALPN 格式：长度前缀 + 协议名
    std::vector<unsigned char> alpn;
    for (const auto& proto : protocols) {
        alpn.push_back(static_cast<unsigned char>(proto.size()));
        alpn.insert(alpn.end(), proto.begin(), proto.end());
    }

    SSL_set_alpn_protos(ssl_, alpn.data(), static_cast<unsigned int>(alpn.size()));
}

bool TlsStream::SetRealityClient(const RealityConfig& reality) {
    if (is_server_ || !ssl_) {
        return false;
    }

    auto state = BuildRealityClientState(reality);
    if (!state) {
        return false;
    }

    if (SSL_set1_reality_peer_public_key(
            ssl_,
            state->server_public.data(),
            state->server_public.size()) != 1) {
        LOG_ERROR("REALITY client peer public key install failed");
        return false;
    }

    if (SSL_set1_groups_list(ssl_, "X25519") != 1) {
        LOG_ERROR("REALITY client failed to force X25519 key share");
        return false;
    }
    if (SSL_set1_sigalgs_list(ssl_, "ed25519") != 1) {
        LOG_ERROR("REALITY client failed to advertise Ed25519");
        return false;
    }

    SSL_set_reality_client_hello_cb(
        ssl_,
        RealityClientHelloCallback,
        state.get());
    app_state_ = std::static_pointer_cast<void>(state);
    return true;
}

net::awaitable<bool> TlsStream::Handshake() {
    if (handshake_done_) {
        co_return true;
    }

    std::array<uint8_t, kTlsIoBufferSize> read_buffer{};

    while (true) {
        int ret = SSL_do_handshake(ssl_);

        if (ret == 1) {
            if (app_state_) {
                auto state = std::static_pointer_cast<RealityClientState>(app_state_);
                if (state && !VerifyRealityPeerCertificate(ssl_, *state)) {
                    co_return false;
                }
            }
            handshake_done_ = true;
            co_return true;
        }

        int err = SSL_get_error(ssl_, ret);

        if (err == SSL_ERROR_WANT_READ) {
            // 先发送待发数据
            if (!co_await FlushWriteBio()) {
                co_return false;
            }

            // 从底层读取数据
            auto n = co_await inner_.AsyncRead(net::buffer(read_buffer));
            if (n == 0) {
                LOG_ACCESS_DEBUG("TLS handshake: connection closed during read");
                co_return false;
            }

            // 写入 read_bio
            BIO_write(read_bio_, read_buffer.data(), static_cast<int>(n));
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (!co_await FlushWriteBio()) {
                co_return false;
            }
        } else {
            const unsigned long err_code = ERR_get_error();
            char buf[256];
            ERR_error_string_n(err_code, buf, sizeof(buf));
            if (is_server_ && IsBenignServerHandshakeError(err_code)) {
                LOG_ACCESS_DEBUG("TLS handshake ignored (non-TLS traffic on TLS port): {}", buf);
            } else {
                LOG_CONN_FAIL("TLS handshake error: {}", buf);
            }
            co_return false;
        }
    }
}

net::awaitable<bool> TlsStream::FlushWriteBio() {
    try {
        int pending = static_cast<int>(BIO_pending(write_bio_));
        if (pending <= 0) {
            co_return true;
        }

        if (static_cast<size_t>(pending) <= kTlsIoBufferSize) {
            alignas(64) std::array<uint8_t, kTlsIoBufferSize> buf{};
            while (pending > 0) {
                const int to_read = static_cast<int>(
                    std::min<size_t>(static_cast<size_t>(pending), buf.size()));
                int read = BIO_read(write_bio_, buf.data(), to_read);
                if (read > 0) {
                    size_t written = co_await inner_.AsyncWrite(net::buffer(buf.data(), read));
                    if (written != static_cast<size_t>(read)) {
                        co_return false;
                    }
                    pending = static_cast<int>(BIO_pending(write_bio_));
                    continue;
                }
                if (read < 0 && BIO_should_retry(write_bio_)) {
                    co_return true;
                }
                co_return false;
            }
            co_return true;
        }

        buf::MultiBuffer mb;
        mb.reserve((static_cast<size_t>(pending) + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
        while (true) {
            pending = static_cast<int>(BIO_pending(write_bio_));
            if (pending <= 0) {
                break;
            }

            buf::BufferGuard out{buf::Buffer::New()};
            if (!out) {
                co_return false;
            }
            const int to_read = static_cast<int>(std::min<size_t>(
                static_cast<size_t>(pending),
                static_cast<size_t>(out->Available())));
            int read = BIO_read(write_bio_, out->Tail().data(), to_read);
            if (read > 0) {
                out->Produce(static_cast<uint32_t>(read));
                mb.push_back(out.release());
                continue;
            }
            if (read < 0 && BIO_should_retry(write_bio_)) {
                break;
            }
            co_return false;
        }

        if (!mb.empty()) {
            co_await inner_.WriteMultiBuffer(std::move(mb));
        }
        co_return true;
    } catch (...) {
        co_return false;
    }
}

std::string TlsStream::NegotiatedAlpn() const {
    if (!ssl_) return "";

    const unsigned char* data = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ssl_, &data, &len);

    if (data && len > 0) {
        // ISSUE-02-02: 使用 unsafe::ptr_cast 替代 reinterpret_cast
        return std::string(unsafe::ptr_cast<const char>(data), len);
    }
    return "";
}

std::string TlsStream::ReceivedSni() const {
    if (!ssl_ || !is_server_) return "";

    const char* name = SSL_get_servername(ssl_, TLSEXT_NAMETYPE_host_name);
    return name ? name : "";
}

net::awaitable<std::size_t> TlsStream::AsyncRead(net::mutable_buffer buf) {
    if (!handshake_done_) {
        if (!co_await Handshake()) {
            ThrowTlsReadError("TLS handshake failed during read");
        }
    }

    std::array<uint8_t, kTlsIoBufferSize> read_buffer{};

    while (true) {
        int ret = SSL_read(ssl_, buf.data(), static_cast<int>(buf.size()));

        if (ret > 0) {
            co_return static_cast<std::size_t>(ret);
        }

        int err = SSL_get_error(ssl_, ret);

        if (err == SSL_ERROR_ZERO_RETURN) {
            co_return 0;  // Clean shutdown
        }

        if (err == SSL_ERROR_WANT_READ) {
            // 先刷新写缓冲
            if (!co_await FlushWriteBio()) {
                ThrowTlsReadError("TLS flush write BIO failed");
            }

            // 从底层读取
            auto n = co_await inner_.AsyncRead(net::buffer(read_buffer));
            if (n == 0) {
                ThrowTlsReadError("TLS peer closed without close_notify");
            }
            BIO_write(read_bio_, read_buffer.data(), static_cast<int>(n));
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (!co_await FlushWriteBio()) {
                ThrowTlsReadError("TLS flush write BIO failed");
            }
        } else {
            ThrowTlsReadError("TLS read failed");
        }
    }
}

net::awaitable<buf::MultiBuffer> TlsStream::ReadMultiBuffer() {
    if (!handshake_done_) {
        if (!co_await Handshake()) {
            ThrowTlsReadError("TLS handshake failed during read");
        }
    }

    std::array<uint8_t, kTlsIoBufferSize> read_buffer{};

    while (true) {
        if (SSL_pending(ssl_) <= 0 && BIO_pending(read_bio_) <= 0) {
            bool need_encrypted_read = true;
            std::array<uint8_t, 1> probe{};
            const int peek = SSL_peek(ssl_, probe.data(), static_cast<int>(probe.size()));
            if (peek > 0) {
                // Application data is already decryptable; fall through and
                // read it into a relay Buffer without consuming the probe byte.
                need_encrypted_read = false;
            } else {
                const int peek_err = SSL_get_error(ssl_, peek);
                if (peek_err == SSL_ERROR_ZERO_RETURN) {
                    co_return buf::MultiBuffer{};
                }
                if (peek_err == SSL_ERROR_WANT_WRITE) {
                    if (!co_await FlushWriteBio()) {
                        ThrowTlsReadError("TLS flush write BIO failed");
                    }
                    continue;
                }
                if (peek_err != SSL_ERROR_WANT_READ) {
                    ThrowTlsReadError("TLS read failed");
                }
            }

            if (need_encrypted_read) {
                if (!co_await FlushWriteBio()) {
                    ThrowTlsReadError("TLS flush write BIO failed");
                }

                auto n = co_await inner_.AsyncRead(net::buffer(read_buffer));
                if (n == 0) {
                    ThrowTlsReadError("TLS peer closed without close_notify");
                }

                const int written = BIO_write(
                    read_bio_,
                    read_buffer.data(),
                    static_cast<int>(std::min<std::size_t>(
                        n,
                        static_cast<std::size_t>(std::numeric_limits<int>::max()))));
                if (written <= 0 || static_cast<std::size_t>(written) != n) {
                    ThrowTlsReadError("TLS read BIO write failed");
                }
            }
        }

        bool want_read = false;
        bool want_write = false;
        {
            buf::BufferGuard out{buf::Buffer::New()};
            if (!out) {
                co_return buf::MultiBuffer{};
            }

            int ret = SSL_read(ssl_, out->Tail().data(), static_cast<int>(out->Available()));
            if (ret > 0) {
                out->Produce(static_cast<uint32_t>(ret));
                co_return buf::MultiBuffer{out.release()};
            }

            int err = SSL_get_error(ssl_, ret);
            if (err == SSL_ERROR_ZERO_RETURN) {
                co_return buf::MultiBuffer{};
            }

            if (err == SSL_ERROR_WANT_READ) {
                want_read = true;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                want_write = true;
            } else {
                ThrowTlsReadError("TLS read failed");
            }
        }

        if (want_write) {
            if (!co_await FlushWriteBio()) {
                ThrowTlsReadError("TLS flush write BIO failed");
            }
            continue;
        }

        if (want_read) {
            if (!co_await FlushWriteBio()) {
                ThrowTlsReadError("TLS flush write BIO failed");
            }

            auto n = co_await inner_.AsyncRead(net::buffer(read_buffer));
            if (n == 0) {
                ThrowTlsReadError("TLS peer closed without close_notify");
            }

            const int written = BIO_write(
                read_bio_,
                read_buffer.data(),
                static_cast<int>(std::min<std::size_t>(
                    n,
                    static_cast<std::size_t>(std::numeric_limits<int>::max()))));
            if (written <= 0 || static_cast<std::size_t>(written) != n) {
                ThrowTlsReadError("TLS read BIO write failed");
            }
            continue;
        }
    }
}

net::awaitable<std::size_t> TlsStream::AsyncWrite(net::const_buffer buf) {
    if (!handshake_done_) {
        if (!co_await Handshake()) {
            ThrowTlsWriteError("TLS handshake failed during write");
        }
    }

    size_t total_written = 0;
    const uint8_t* data = static_cast<const uint8_t*>(buf.data());
    size_t remaining = buf.size();
    std::array<uint8_t, kTlsIoBufferSize> read_buffer{};

    while (remaining > 0) {
        const auto to_write = static_cast<int>(
            std::min<std::size_t>(remaining, kTlsIoBufferSize));
        int ret = SSL_write(ssl_, data + total_written, to_write);

        if (ret > 0) {
            total_written += ret;
            remaining -= ret;

            // 刷新写缓冲
            if (!co_await FlushWriteBio()) {
                ThrowTlsWriteError("TLS flush write BIO failed");
            }
        } else {
            int err = SSL_get_error(ssl_, ret);
            if (err == SSL_ERROR_WANT_WRITE) {
                if (!co_await FlushWriteBio()) {
                    ThrowTlsWriteError("TLS flush write BIO failed");
                }
            } else if (err == SSL_ERROR_WANT_READ) {
                auto n = co_await inner_.AsyncRead(net::buffer(read_buffer));
                if (n > 0) {
                    BIO_write(read_bio_, read_buffer.data(), static_cast<int>(n));
                } else {
                    ThrowTlsWriteError("TLS write peer closed while waiting for read");
                }
            } else {
                ThrowTlsWriteError("TLS write failed");
            }
        }
    }

    if (total_written != buf.size()) {
        ThrowTlsWriteError("TLS partial write");
    }

    co_return total_written;
}

net::awaitable<void> TlsStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    if (!handshake_done_) {
        if (!co_await Handshake()) {
            ThrowTlsWriteError("TLS handshake failed during write");
        }
    }

    if (buffers.empty()) {
        co_return;
    }

    std::array<uint8_t, kTlsIoBufferSize> read_buffer{};

    for (const auto& buffer : buffers) {
        if (buffer.size() == 0) {
            continue;
        }

        const uint8_t* data = static_cast<const uint8_t*>(buffer.data());
        size_t remaining = buffer.size();

        while (remaining > 0) {
            const auto to_write = static_cast<int>(
                std::min<std::size_t>(remaining, kTlsIoBufferSize));
            int ret = SSL_write(ssl_, data, to_write);

            if (ret > 0) {
                data += ret;
                remaining -= static_cast<size_t>(ret);
                if (static_cast<size_t>(BIO_pending(write_bio_)) >= kTlsIoBufferSize * 8) {
                    if (!co_await FlushWriteBio()) {
                        ThrowTlsWriteError("TLS flush write BIO failed");
                    }
                }
                continue;
            }

            int err = SSL_get_error(ssl_, ret);
            if (err == SSL_ERROR_WANT_WRITE) {
                if (!co_await FlushWriteBio()) {
                    ThrowTlsWriteError("TLS flush write BIO failed");
                }
            } else if (err == SSL_ERROR_WANT_READ) {
                auto n = co_await inner_.AsyncRead(net::buffer(read_buffer));
                if (n > 0) {
                    BIO_write(read_bio_, read_buffer.data(), static_cast<int>(n));
                } else {
                    ThrowTlsWriteError("TLS write peer closed while waiting for read");
                }
            } else {
                ThrowTlsWriteError("TLS write failed");
            }
        }
    }

    if (!co_await FlushWriteBio()) {
        ThrowTlsWriteError("TLS flush write BIO failed");
    }
    co_return;
}

net::awaitable<void> TlsStream::WriteMultiBuffer(buf::MultiBuffer mb) {
    if (!handshake_done_) {
        if (!co_await Handshake()) {
            ThrowTlsWriteError("TLS handshake failed during write");
        }
    }

    if (mb.empty()) {
        co_return;
    }

    std::array<uint8_t, kTlsIoBufferSize> read_buffer{};

    for (const auto* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }

        auto bytes = buffer->Bytes();
        const uint8_t* data = bytes.data();
        size_t remaining = bytes.size();

        while (remaining > 0) {
            const auto to_write = static_cast<int>(
                std::min<std::size_t>(remaining, kTlsIoBufferSize));
            int ret = SSL_write(ssl_, data, to_write);

            if (ret > 0) {
                data += ret;
                remaining -= static_cast<size_t>(ret);
                if (static_cast<size_t>(BIO_pending(write_bio_)) >= kTlsIoBufferSize * 8) {
                    if (!co_await FlushWriteBio()) {
                        ThrowTlsWriteError("TLS flush write BIO failed");
                    }
                }
                continue;
            }

            int err = SSL_get_error(ssl_, ret);
            if (err == SSL_ERROR_WANT_WRITE) {
                if (!co_await FlushWriteBio()) {
                    ThrowTlsWriteError("TLS flush write BIO failed");
                }
            } else if (err == SSL_ERROR_WANT_READ) {
                auto n = co_await inner_.AsyncRead(net::buffer(read_buffer));
                if (n > 0) {
                    BIO_write(read_bio_, read_buffer.data(), static_cast<int>(n));
                } else {
                    ThrowTlsWriteError("TLS write peer closed while waiting for read");
                }
            } else {
                ThrowTlsWriteError("TLS write failed");
            }
        }
    }

    if (!co_await FlushWriteBio()) {
        ThrowTlsWriteError("TLS flush write BIO failed");
    }
    co_return;
}

void TlsStream::ShutdownRead() {
    inner_.ShutdownRead();
}

void TlsStream::ShutdownWrite() {
    if (ssl_ && handshake_done_ && !shutdown_initiated_) {
        shutdown_initiated_ = true;
        SSL_shutdown(ssl_);

        // 分块 flush close_notify，避免每连接为大 pending BIO 再做 heap 分配。
        int fd = inner_.NativeHandle();
        if (fd >= 0) {
            alignas(64) std::array<uint8_t, kTlsIoBufferSize> buf{};
            while (true) {
                auto pending = static_cast<int>(BIO_pending(write_bio_));
                if (pending <= 0) break;

                int chunk = std::min<int>(pending, static_cast<int>(buf.size()));
                int read = BIO_read(write_bio_, buf.data(), chunk);
                if (read <= 0) break;

                int sent_total = 0;
                while (sent_total < read) {
                    int sent = ::send(
                        fd,
                        unsafe::ptr_cast<const char>(buf.data()) + sent_total,
                        read - sent_total,
                        MSG_NOSIGNAL);
                    if (sent <= 0) {
                        break;
                    }
                    sent_total += sent;
                }

                if (sent_total < read) {
                    break;
                }
            }
        }
    }
    inner_.ShutdownWrite();
}

net::awaitable<void> TlsStream::AsyncShutdownWrite() {
    // ISSUE-01-04: TLS 层 AsyncShutdownWrite 发送 close_notify
    // 根据 RFC 5246/8446，优雅关闭需要发送 close_notify alert
    if (ssl_ && handshake_done_ && !shutdown_initiated_) {
        shutdown_initiated_ = true;
        LOG_ACCESS_DEBUG("TLS: sending close_notify");
        int ret = SSL_shutdown(ssl_);
        if (ret == 0) {
            // 第一次 SSL_shutdown 返回 0 表示 close_notify 已发送
            // 但尚未收到对端的 close_notify
            LOG_ACCESS_DEBUG("TLS: close_notify sent, waiting for peer");
        } else if (ret == 1) {
            LOG_ACCESS_DEBUG("TLS: bidirectional shutdown complete");
        }
        co_await FlushWriteBio();
    }
    co_await inner_.AsyncShutdownWrite();
}

void TlsStream::Close() {
    if (ssl_ && !shutdown_initiated_) {
        shutdown_initiated_ = true;
        SSL_shutdown(ssl_);
    }
    inner_.Close();
}

void TlsStream::CloseAbortive() {
    shutdown_initiated_ = true;
    inner_.SetAbortiveClose(true);
    inner_.Close();
}

void TlsStream::Cancel() noexcept {
    inner_.Cancel();
}

int TlsStream::NativeHandle() const {
    return inner_.NativeHandle();
}

bool TlsStream::IsOpen() const {
    return inner_.IsOpen() && ssl_ != nullptr;
}

// ============================================================================
// 工厂函数实现
// ============================================================================

net::awaitable<std::unique_ptr<TlsStream>> WrapTlsServer(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx) {

    auto stream = std::make_unique<TlsStream>(std::move(inner), ctx.Native(), true);

    if (!co_await stream->Handshake()) {
        co_return nullptr;
    }

    co_return stream;
}

net::awaitable<std::unique_ptr<TlsStream>> WrapTlsClient(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx,
    const std::string& server_name,
    const std::vector<std::string>& alpn) {

    auto stream = std::make_unique<TlsStream>(std::move(inner), ctx.Native(), false);

    if (!server_name.empty()) {
        stream->SetServerName(server_name);
    }
    if (!alpn.empty()) {
        stream->SetAlpn(alpn);
    }

    if (!co_await stream->Handshake()) {
        co_return nullptr;
    }

    co_return stream;
}

net::awaitable<std::unique_ptr<TlsStream>> WrapRealityClient(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx,
    const RealityConfig& reality,
    const std::string& server_name,
    const std::vector<std::string>& alpn) {

    auto stream = std::make_unique<TlsStream>(std::move(inner), ctx.Native(), false);

    if (!server_name.empty()) {
        stream->SetServerName(server_name);
    }
    if (!alpn.empty()) {
        stream->SetAlpn(alpn);
    }
    if (!stream->SetRealityClient(reality)) {
        co_return nullptr;
    }

    if (!co_await stream->Handshake()) {
        co_return nullptr;
    }

    co_return stream;
}

net::awaitable<DialResult> ConnectTls(
    net::io_context& io_context,
    const tcp::endpoint& endpoint,
    SslContext& ctx,
    const std::string& server_name,
    const std::vector<std::string>& alpn,
    std::chrono::seconds timeout) {

    // 先建立 TCP 连接
    auto tcp_result = co_await TcpStream::Connect(io_context, endpoint, timeout);
    if (!tcp_result.Ok()) {
        co_return tcp_result;
    }

    auto* tcp_raw = tcp_result.stream
        ? dynamic_cast<TcpStream*>(tcp_result.stream.get())
        : nullptr;
    if (!tcp_raw) {
        co_return DialResult::Fail(
            ErrorCode::INVALID_ARGUMENT,
            "TLS upgrade requires TcpStream as base transport");
    }
    tcp_result.stream.release();
    auto tcp = std::unique_ptr<TcpStream>(tcp_raw);
    auto tls_stream = co_await WrapTlsClient(
        std::move(tcp), ctx, server_name, alpn);

    if (!tls_stream) {
        co_return DialResult::Fail(ErrorCode::TLS_HANDSHAKE_FAILED, "TLS handshake failed");
    }

    co_return DialResult::Success(std::move(tls_stream));
}

}  // namespace acpp
