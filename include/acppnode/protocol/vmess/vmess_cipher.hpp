#pragma once

// ============================================================================
// vmess_cipher.hpp — VMess AEAD 加密器与 chunk 编解码
//
// 职责：
//   - VMessCipher：单方向 AEAD per-chunk 加密/解密器
//   - ShakeMask：chunk 长度掩码生成器（SHAKE128）
//   - VMessServerStream：服务端 chunk 编解码器（响应头 + 分块加解密）
// ============================================================================

#include "acppnode/protocol/vmess/vmess_crypto.hpp"
#include "acppnode/protocol/vmess/vmess_request.hpp"

#include <array>
#include <memory>
#include <optional>
#include <cstdint>

namespace acpp {
namespace vmess {

// ============================================================================
// VMessCipher — 单方向 AEAD per-chunk 加密/解密器
//
// 支持：AES-128-GCM、ChaCha20-Poly1305
// 每次 Encrypt/Decrypt 递增内部计数器（16-bit，嵌入 nonce）。
// ============================================================================
class VMessCipher {
public:
    VMessCipher(Security security, const uint8_t* key, const uint8_t* iv);
    ~VMessCipher();

    VMessCipher(const VMessCipher&)            = delete;
    VMessCipher& operator=(const VMessCipher&) = delete;

    // AEAD tag 大小（GCM_TAG_SIZE = 16）
    size_t Overhead() const;

    // 加密一个数据块（返回密文长度，包含 tag）
    // ciphertext 必须有 len + Overhead() 字节空间
    ssize_t Encrypt(const uint8_t* plaintext, size_t len, uint8_t* ciphertext);

    // 解密一个数据块（输入包含 tag）
    // plaintext 必须有 len - Overhead() 字节空间
    ssize_t Decrypt(const uint8_t* ciphertext, size_t len, uint8_t* plaintext);

    void ResetCount() { count_ = 0; }

private:
    void BuildNonce(uint16_t count, uint8_t* nonce);

    // ChaCha20-Poly1305 需要 32 字节密钥，从 16 字节扩展：
    //   key32[0:16] = MD5(key16), key32[16:32] = MD5(key32[0:16])
    static void GenerateChaCha20Key(const uint8_t* key16, uint8_t* key32);

    Security security_;
    std::array<uint8_t, 16> key_;
    std::array<uint8_t, 32> key32_;   // ChaCha20 扩展密钥
    std::array<uint8_t, 16> iv_;
    uint16_t count_ = 0;

    void* enc_ctx_          = nullptr;  // EVP_CIPHER_CTX*，加密上下文
    void* dec_ctx_          = nullptr;  // EVP_CIPHER_CTX*，解密上下文
    bool  ctx_initialized_  = false;
};

// ============================================================================
// ShakeMask — chunk 长度掩码生成器
//
// 使用 SHAKE128 生成伪随机掩码序列，避免流量分析。
// 优化：4KB 固定缓冲区（覆盖 2048 个 chunk），懒加载，循环使用。
// ============================================================================
class ShakeMask {
public:
    explicit ShakeMask(const uint8_t* nonce);
    ~ShakeMask();

    ShakeMask(const ShakeMask&)            = delete;
    ShakeMask& operator=(const ShakeMask&) = delete;

    // 获取下一个 mask（从 SHAKE128 XOF 流式读取，永不重复）
    uint16_t NextMask();

private:
    static constexpr size_t kBufferSize = 4096;  // 批量 squeeze 大小

    void* ctx_ = nullptr;  // EVP_MD_CTX*
    alignas(64) uint8_t            buffer_[kBufferSize];
    size_t                         offset_      = kBufferSize;  // 初始为满，触发首次 Refill

    void Refill();
};

// ============================================================================
// VMessServerStream — 服务端 chunk 编解码器
//
// 职责：
//   - 生成 VMess 响应头（一次性，发送给客户端）
//   - 解密来自客户端的 chunk（含可选 masking）
//   - 加密发往客户端的 chunk（含可选 masking）
//
// 注意：此类是纯 codec，不持有底层 socket。I/O 由 VMessServerAsyncStream 负责。
// ============================================================================
class VMessServerStream {
public:
    explicit VMessServerStream(const VMessRequest& request);
    ~VMessServerStream();

    // 生成响应头（首次写数据前调用）
    memory::ByteVector GenerateResponseHeader();

    // 解密一个客户端 chunk（返回明文，consumed 为消耗的字节数）
    std::optional<memory::ByteVector> DecryptChunk(
        const uint8_t* data, size_t len, size_t& consumed);

    // 加密一个响应 chunk
    memory::ByteVector EncryptChunk(const uint8_t* data, size_t len);

    bool ResponseSent() const { return response_sent_; }

private:
    VMessRequest request_;

    std::array<uint8_t, 16> request_key_;
    std::array<uint8_t, 16> request_iv_;
    std::array<uint8_t, 16> response_key_;
    std::array<uint8_t, 16> response_iv_;

    std::unique_ptr<VMessCipher>  read_cipher_;
    std::unique_ptr<VMessCipher>  write_cipher_;
    std::unique_ptr<ShakeMask>    read_mask_;
    std::unique_ptr<ShakeMask>    write_mask_;

    bool response_sent_  = false;
    bool global_padding_ = false;
};

}  // namespace vmess
}  // namespace acpp
