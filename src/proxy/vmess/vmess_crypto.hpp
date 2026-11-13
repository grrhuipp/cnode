#pragma once
#include "proxy/vmess/security.hpp"
// vmess_crypto.hpp — VMess 协议类型与密码学原语
//
// 职责：协议常量/枚举/请求结构体、底层加密函数、密钥派生（KDF）、哈希、AuthID 生成。
// 底层 OpenSSL 失败属于系统故障，统一以异常上报，不返回未初始化输出。
// ============================================================================

#include "app/proxyman/user_store.hpp"
#include "proxy/aead.hpp"
#include "common/hash.hpp"
#include "common/multi_buffer.hpp"
#include "common/target_address.hpp"
#include <openssl/mem.h>
#include <openssl/aes.h>
#include <openssl/ossl_typ.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
namespace proxy {


constexpr uint8_t VERSION             = 1;
constexpr size_t  GCM_TAG_SIZE        = 16;
constexpr size_t  MAX_CHUNK_SIZE      = 16 * 1024;  // 16KB
constexpr int64_t TIMESTAMP_TOLERANCE = 60;         // ±60秒，防重放攻击

enum class VmessCommand : uint8_t {
    TCP = 1,
    UDP = 2,
    Mux = 3,  // XUDP/Mux 模式，每个包有地址头
};

struct VmessOption {
    static constexpr uint8_t CHUNK_STREAM         = 0x01;
    static constexpr uint8_t CHUNK_MASKING        = 0x04;
    static constexpr uint8_t GLOBAL_PADDING       = 0x08;
    static constexpr uint8_t AUTHENTICATED_LENGTH = 0x10;
};

struct KDFSalt {
    static constexpr const char* AUTH_ID_ENCRYPTION_KEY                = "AES Auth ID Encryption";
    // 响应头
    static constexpr const char* AEAD_RESP_HEADER_LEN_KEY              = "AEAD Resp Header Len Key";
    static constexpr const char* AEAD_RESP_HEADER_LEN_IV               = "AEAD Resp Header Len IV";
    static constexpr const char* AEAD_RESP_HEADER_PAYLOAD_KEY          = "AEAD Resp Header Key";
    static constexpr const char* AEAD_RESP_HEADER_PAYLOAD_IV           = "AEAD Resp Header IV";
    // 请求头（客户端使用）
    static constexpr const char* VMESS_AEAD_KDF                        = "VMess AEAD KDF";
    static constexpr const char* VMESS_HEADER_PAYLOAD_AEAD_KEY         = "VMess Header AEAD Key";
    static constexpr const char* VMESS_HEADER_PAYLOAD_AEAD_IV          = "VMess Header AEAD Nonce";
    static constexpr const char* VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY  = "VMess Header AEAD Key_Length";
    static constexpr const char* VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV   = "VMess Header AEAD Nonce_Length";
};

struct VMessRequest {
    std::array<uint8_t, 16> body_iv{};
    std::array<uint8_t, 16> body_key{};
    uint8_t response_header = 0;
    uint8_t options         = 0;
    VmessSecurity security  = VmessSecurity::AES_128_GCM;
    VmessCommand  command   = VmessCommand::TCP;
    common::TargetAddress target;
    std::optional<common::ForwardedMetadata> forwarded;

    std::shared_ptr<const app::UserStore::VmessCredential> user;
    ~VMessRequest() noexcept {
        OPENSSL_cleanse(body_iv.data(), body_iv.size());
        OPENSSL_cleanse(body_key.data(), body_key.size());
    }
};

struct VmessUserAccount {
    std::array<uint8_t, 16> uuid_bytes{};
    std::array<uint8_t, 16> cmd_key{};
    std::array<uint8_t, 16> auth_key{};

    ~VmessUserAccount() noexcept {
        OPENSSL_cleanse(uuid_bytes.data(), uuid_bytes.size());
        OPENSSL_cleanse(cmd_key.data(), cmd_key.size());
        OPENSSL_cleanse(auth_key.data(), auth_key.size());
    }
    static std::optional<VmessUserAccount> FromUUID(std::string_view uuid_str);
    static VmessUserAccount FromUuidBytes(const std::array<uint8_t, 16>& uuid);
};

// ============================================================================
// 哈希函数
// ============================================================================

std::array<uint8_t, 16> MD5Hash(const uint8_t* data, size_t len);
std::array<uint8_t, 32> SHA256Hash(const uint8_t* data, size_t len);

// ============================================================================
// VMess AEAD KDF（嵌套 HMAC-SHA256）
// ============================================================================

void KDF(const uint8_t* key, size_t key_len,
         std::span<const std::string_view> path,
         uint8_t* out, size_t out_len);

// KDF16 — 返回 16 字节派生密钥
std::array<uint8_t, 16> KDF16(const uint8_t* key, size_t key_len,
                               std::span<const std::string_view> path);

// AES-128-GCM 头部密钥与 nonce
struct HeaderAeadKey {
    std::array<uint8_t, 16> key{};
    std::array<uint8_t, 12> nonce{};
    ~HeaderAeadKey() noexcept {
        OPENSSL_cleanse(key.data(), key.size());
        OPENSSL_cleanse(nonce.data(), nonce.size());
    }
};

// 请求头：由 cmd_key、AuthID 与 8 字节连接 nonce 派生
HeaderAeadKey RequestHeaderLengthKey(std::span<const uint8_t, 16> cmd_key,
                                     std::span<const uint8_t, 16> auth_id,
                                     std::span<const uint8_t, 8> connection_nonce);
HeaderAeadKey RequestHeaderPayloadKey(std::span<const uint8_t, 16> cmd_key,
                                      std::span<const uint8_t, 16> auth_id,
                                      std::span<const uint8_t, 8> connection_nonce);

// 响应头：由响应 body key/IV 派生
HeaderAeadKey ResponseHeaderLengthKey(std::span<const uint8_t, 16> response_key,
                                      std::span<const uint8_t, 16> response_iv);
HeaderAeadKey ResponseHeaderPayloadKey(std::span<const uint8_t, 16> response_key,
                                       std::span<const uint8_t, 16> response_iv);

// ============================================================================
// 校验和
// ============================================================================

uint32_t CRC32(const uint8_t* data, size_t len);

// ============================================================================
// AuthID 生成（客户端使用）
// ============================================================================

// AES-128 encrypt schedule of an account's AuthID key, expanded once when the
// outbound account is prepared; requests only borrow it.
[[nodiscard]] AES_KEY ExpandAuthIDEncryptKey(const std::array<uint8_t, 16>& auth_key);
void GenerateAuthID(const AES_KEY& auth_id_key, int64_t timestamp, uint8_t* out_auth_id);

// ============================================================================
// VMessCipher — 单方向 AEAD per-chunk 加密/解密器
//
// 支持：AES-128-GCM、ChaCha20-Poly1305；NONE/ZERO 原样复制。
// 每次 Encrypt/Decrypt 递增内部计数器（16-bit，嵌入 nonce）；一个实例只用于一个方向。
// 其他 Security 值构造即抛出，不进入数据路径。
// ============================================================================
class VMessCipher {
public:
    VMessCipher(VmessSecurity security, const uint8_t* key, const uint8_t* iv);
    ~VMessCipher() noexcept {
        OPENSSL_cleanse(iv_.data(), iv_.size());
    }

    VMessCipher(const VMessCipher&)            = delete;
    VMessCipher& operator=(const VMessCipher&) = delete;
    VMessCipher(VMessCipher&& other) noexcept = default;
    VMessCipher& operator=(VMessCipher&& other) noexcept = default;

    // AEAD tag 大小（GCM_TAG_SIZE = 16）
    size_t Overhead() const;

    // 加密一个数据块（返回密文长度，包含 tag）
    // ciphertext 必须有 len + Overhead() 字节空间
    ssize_t Encrypt(const uint8_t* plaintext, size_t len, uint8_t* ciphertext);

    // 解密一个数据块（输入包含 tag）
    // plaintext 必须有 len - Overhead() 字节空间
    ssize_t Decrypt(const uint8_t* ciphertext, size_t len, uint8_t* plaintext);

private:
    void BuildNonce(uint16_t count, uint8_t* nonce);

    VmessSecurity security_;
    std::array<uint8_t, 16> iv_;
    uint16_t count_ = 0;

    proxy::AeadContext aead_;
};

// ============================================================================
// ShakeMask — chunk 长度掩码生成器
//
// 使用 SHAKE128 生成伪随机掩码序列，避免流量分析。
// 缓冲恰为 SHAKE128 rate（168B，84 个 mask），每次 Refill 正好一次 Keccak 置换；
// squeeze 可分段拼接，掩码字节流与缓冲大小无关。懒加载，不常驻大缓冲。
// ============================================================================
class ShakeMask {
public:
    explicit ShakeMask(const uint8_t* nonce);
    ~ShakeMask();

    ShakeMask(const ShakeMask&)            = delete;
    ShakeMask& operator=(const ShakeMask&) = delete;
    ShakeMask(ShakeMask&& other) noexcept;
    ShakeMask& operator=(ShakeMask&& other) noexcept;

    // 获取下一个 mask（从 SHAKE128 XOF 流式读取，永不重复）
    uint16_t NextMask();

private:
    static constexpr size_t kBufferSize = 168;  // SHAKE128 rate；偶数保证 mask 不跨缓冲

    EVP_MD_CTX* ctx_ = nullptr;
    uint8_t buffer_[kBufferSize];
    size_t                         offset_      = kBufferSize;  // 初始为满，触发首次 Refill

    void Refill();
};

}  // namespace proxy
