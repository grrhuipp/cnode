#include "acppnode/protocol/shadowsocks/shadowsocks_protocol.hpp"
#include "acppnode/infra/log.hpp"

#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace acpp::ss {

// ============================================================================
// ParseCipherMethod
// ============================================================================
std::optional<SsCipherInfo> ParseCipherMethod(std::string_view method) {
    // 转小写比较
    std::string lower(method);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (lower == "aes-128-gcm") {
        return SsCipherInfo{SsCipherType::AES_128_GCM, 16, 16};
    }
    if (lower == "aes-256-gcm") {
        return SsCipherInfo{SsCipherType::AES_256_GCM, 32, 32};
    }
    if (lower == "chacha20-ietf-poly1305" || lower == "chacha20-poly1305") {
        return SsCipherInfo{SsCipherType::CHACHA20_POLY1305, 32, 32};
    }
    return std::nullopt;
}

// ============================================================================
// DeriveKey — EVP_BytesToKey + MD5
// ============================================================================
std::vector<uint8_t> DeriveKey(const std::string& password, size_t key_size) {
    std::vector<uint8_t> key;
    key.reserve(key_size + 16);

    uint8_t prev[16];
    size_t prev_len = 0;
    const auto* pw = reinterpret_cast<const uint8_t*>(password.data());
    const size_t pw_len = password.size();

    // 复用 EVP_MD_CTX，避免循环内反复 new/free
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    while (key.size() < key_size) {
        // D_i = MD5(D_{i-1} || password)
        EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
        if (prev_len > 0) {
            EVP_DigestUpdate(ctx, prev, prev_len);
        }
        EVP_DigestUpdate(ctx, pw, pw_len);

        unsigned int len = 16;
        EVP_DigestFinal_ex(ctx, prev, &len);
        prev_len = 16;

        key.insert(key.end(), prev, prev + 16);
    }

    EVP_MD_CTX_free(ctx);

    key.resize(key_size);
    return key;
}

// ============================================================================
// DeriveSubkey — HKDF-SHA1("ss-subkey")
// ============================================================================
bool DeriveSubkey(const uint8_t* key, size_t key_size,
                  const uint8_t* salt, size_t salt_size,
                  uint8_t* out_subkey) {
    const char* info = "ss-subkey";
    return HKDF(out_subkey, key_size, EVP_sha1(),
                key, key_size,
                salt, salt_size,
                reinterpret_cast<const uint8_t*>(info), std::strlen(info)) == 1;
}

// ============================================================================
// MakeNonce
// ============================================================================
std::array<uint8_t, 12> MakeNonce(uint64_t counter) {
    std::array<uint8_t, 12> nonce{};
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(i)] = static_cast<uint8_t>(counter >> (8 * i));
    }
    return nonce;
}

// ============================================================================
// SsAeadCipher
// ============================================================================
SsAeadCipher::SsAeadCipher(SsCipherType type, const uint8_t* key, size_t key_size)
    : type_(type)
    , key_(key, key + key_size) {
    ctx_ = EVP_CIPHER_CTX_new();
}

SsAeadCipher::~SsAeadCipher() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
        ctx_ = nullptr;
    }
}

static const EVP_CIPHER* GetCipher(SsCipherType type) noexcept {
    switch (type) {
        case SsCipherType::AES_128_GCM:       return EVP_aes_128_gcm();
        case SsCipherType::AES_256_GCM:       return EVP_aes_256_gcm();
        case SsCipherType::CHACHA20_POLY1305:  return EVP_chacha20_poly1305();
    }
    return nullptr;
}

bool SsAeadCipher::Encrypt(const uint8_t* nonce,
                            const uint8_t* plaintext, size_t plaintext_len,
                            uint8_t* output) noexcept {
    if (!ctx_) return false;

    const EVP_CIPHER* cipher = GetCipher(type_);
    if (!cipher) return false;

    EVP_CIPHER_CTX_reset(ctx_);

    int out_len = 0;

    if (EVP_EncryptInit_ex(ctx_, cipher, nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) return false;
    if (EVP_EncryptInit_ex(ctx_, nullptr, nullptr, key_.data(), nonce) != 1) return false;

    if (EVP_EncryptUpdate(ctx_, output, &out_len,
                          plaintext, static_cast<int>(plaintext_len)) != 1) return false;

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx_, output + out_len, &final_len) != 1) return false;

    // 写入 GCM/Poly1305 tag
    if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_GET_TAG, 16,
                             output + plaintext_len) != 1) return false;

    return true;
}

bool SsAeadCipher::Decrypt(const uint8_t* nonce,
                            const uint8_t* ciphertext, size_t ciphertext_len,
                            uint8_t* output) noexcept {
    if (!ctx_ || ciphertext_len < 16) return false;

    const EVP_CIPHER* cipher = GetCipher(type_);
    if (!cipher) return false;

    EVP_CIPHER_CTX_reset(ctx_);

    const size_t data_len = ciphertext_len - 16;
    const uint8_t* tag_ptr = ciphertext + data_len;

    int out_len = 0;

    if (EVP_DecryptInit_ex(ctx_, cipher, nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) return false;
    if (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key_.data(), nonce) != 1) return false;

    if (EVP_DecryptUpdate(ctx_, output, &out_len,
                          ciphertext, static_cast<int>(data_len)) != 1) return false;

    // 设置 tag
    if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_TAG, 16,
                             const_cast<uint8_t*>(tag_ptr)) != 1) return false;

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx_, output + out_len, &final_len) != 1) return false;

    return true;
}

// ============================================================================
// SsUserManager
// ============================================================================

void SsUserManager::UpdateSharedUsersForTag(const std::string& tag,
                                            std::vector<SsUserInfo>&& users) {
    SharedStore().UpdateTag(tag, std::move(users));
}

void SsUserManager::UpdateUsersForTag(const std::string& /*tag*/,
                                      const std::vector<SsUserInfo>& /*users*/) {
    // Worker 通过 SharedStore 读取，无需本地副本
}

std::vector<SsUserInfo> SsUserManager::GetUsersForTag(const std::string& tag) const {
    auto snapshot = SharedStore().GetSnapshot();
    auto tag_users = snapshot->GetTagUsers(tag);
    if (!tag_users) return {};

    std::vector<SsUserInfo> result;
    result.reserve(tag_users->size());
    for (const auto& [key, user] : *tag_users)
        result.push_back(*user);
    return result;
}

std::optional<SsUserInfo> SsUserManager::FindUserById(const std::string& tag,
                                                       int64_t user_id) const {
    auto snapshot = SharedStore().GetSnapshot();
    auto tag_users = snapshot->GetTagUsers(tag);
    if (!tag_users) return std::nullopt;
    for (const auto& [key, user] : *tag_users)
        if (user->user_id == user_id) return *user;
    return std::nullopt;
}

size_t SsUserManager::Size() const {
    return SharedStore().Size();
}

// ============================================================================
// ParseSocks5Address
// ============================================================================
std::optional<SsAddress> ParseSocks5Address(const uint8_t* data, size_t len) {
    if (len < 1) return std::nullopt;

    SsAddress result;
    size_t idx = 0;

    const uint8_t atyp = data[idx++];

    if (atyp == 0x01) {
        // IPv4: 4 bytes addr + 2 bytes port
        if (idx + 4 + 2 > len) return std::nullopt;
        char ipbuf[16];
        std::snprintf(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u",
                      data[idx], data[idx+1], data[idx+2], data[idx+3]);
        idx += 4;
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx+1]);
        idx += 2;
        result.target = TargetAddress(std::string(ipbuf), port);

    } else if (atyp == 0x03) {
        // Domain: 1 byte length + domain + 2 bytes port
        if (idx + 1 > len) return std::nullopt;
        const size_t name_len = data[idx++];
        if (idx + name_len + 2 > len) return std::nullopt;
        std::string domain(reinterpret_cast<const char*>(data + idx), name_len);
        idx += name_len;
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx+1]);
        idx += 2;
        result.target = TargetAddress(domain, port);

    } else if (atyp == 0x04) {
        // IPv6: 16 bytes addr + 2 bytes port
        if (idx + 16 + 2 > len) return std::nullopt;
        char ipbuf[64];
        std::snprintf(ipbuf, sizeof(ipbuf),
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                      data[idx+0],  data[idx+1],  data[idx+2],  data[idx+3],
                      data[idx+4],  data[idx+5],  data[idx+6],  data[idx+7],
                      data[idx+8],  data[idx+9],  data[idx+10], data[idx+11],
                      data[idx+12], data[idx+13], data[idx+14], data[idx+15]);
        idx += 16;
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx+1]);
        idx += 2;
        result.target = TargetAddress(std::string(ipbuf), port);

    } else {
        return std::nullopt;  // 未知 ATYP
    }

    result.consumed = idx;
    return result;
}

// ============================================================================
// EncodeSocks5Address
// ============================================================================
std::vector<uint8_t> EncodeSocks5Address(const TargetAddress& addr) {
    std::vector<uint8_t> buf;

    if (addr.type == AddressType::IPv4 || addr.type == AddressType::IPv6) {
        boost::system::error_code ec;
        auto ip = net::ip::make_address(addr.host, ec);
        if (!ec && ip.is_v4()) {
            buf.push_back(0x01);
            auto bytes = ip.to_v4().to_bytes();
            buf.insert(buf.end(), bytes.begin(), bytes.end());
        } else if (!ec && ip.is_v6()) {
            buf.push_back(0x04);
            auto bytes = ip.to_v6().to_bytes();
            buf.insert(buf.end(), bytes.begin(), bytes.end());
        } else {
            // 解析失败，回退到域名编码
            goto domain_encode;
        }
    } else {
    domain_encode:
        buf.push_back(0x03);
        const auto& host = addr.host;
        if (host.size() > 255) {
            return {};
        }
        buf.push_back(static_cast<uint8_t>(host.size()));
        buf.insert(buf.end(), host.begin(), host.end());
    }

    // 端口（大端序）
    buf.push_back(static_cast<uint8_t>(addr.port >> 8));
    buf.push_back(static_cast<uint8_t>(addr.port & 0xFF));

    return buf;
}

}  // namespace acpp::ss
