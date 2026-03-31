#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/common/protocol_data.hpp"
#include "acppnode/common/sharded_user_stats.hpp"
#include "acppnode/app/shared_user_store.hpp"

#include <openssl/evp.h>

#include <array>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace acpp::ss {

// ============================================================================
// 密码类型
// ============================================================================
enum class SsCipherType : uint8_t {
    AES_128_GCM        = 0,
    AES_256_GCM        = 1,
    CHACHA20_POLY1305  = 2,
};

struct SsCipherInfo {
    SsCipherType type;
    size_t key_size;   // bytes（主密钥长度 == 子密钥长度 == salt 长度）
    size_t salt_size;  // bytes
    static constexpr size_t tag_size = 16;
};

// 根据方法名获取密码参数（不区分大小写）
// 支持: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305
[[nodiscard]] std::optional<SsCipherInfo> ParseCipherMethod(std::string_view method);

// ============================================================================
// 密钥派生
// ============================================================================

// 从密码派生主密钥（EVP_BytesToKey + MD5，Shadowsocks 标准）
[[nodiscard]] std::vector<uint8_t> DeriveKey(const std::string& password, size_t key_size);

// 从主密钥 + 随机 salt 派生子密钥（HKDF-SHA1，ss-subkey）
[[nodiscard]] bool DeriveSubkey(const uint8_t* key, size_t key_size,
                                const uint8_t* salt, size_t salt_size,
                                uint8_t* out_subkey);  // out_subkey 大小 == key_size

// ============================================================================
// AEAD 加解密
// ============================================================================

// 12 字节 nonce（96-bit，小端计数器从 0 开始）
[[nodiscard]] std::array<uint8_t, 12> MakeNonce(uint64_t counter);

// SsAeadCipher — 每次 Encrypt/Decrypt 后在调用方自增 nonce 计数器
class SsAeadCipher {
public:
    SsAeadCipher(SsCipherType type, const uint8_t* key, size_t key_size);
    ~SsAeadCipher();

    SsAeadCipher(const SsAeadCipher&)            = delete;
    SsAeadCipher& operator=(const SsAeadCipher&) = delete;

    // 加密：output 大小须 >= plaintext_len + 16（ciphertext + tag）
    [[nodiscard]] bool Encrypt(const uint8_t* nonce,
                               const uint8_t* plaintext, size_t plaintext_len,
                               uint8_t* output) noexcept;

    // 解密：ciphertext_len 包含 16 字节 tag；output 大小须 >= ciphertext_len - 16
    [[nodiscard]] bool Decrypt(const uint8_t* nonce,
                               const uint8_t* ciphertext, size_t ciphertext_len,
                               uint8_t* output) noexcept;

    [[nodiscard]] SsCipherType Type() const noexcept { return type_; }
    [[nodiscard]] std::span<const uint8_t> Key() const noexcept { return key_; }

    static constexpr size_t kTagSize = 16;

private:
    SsCipherType type_;
    std::vector<uint8_t> key_;
    EVP_CIPHER_CTX*      ctx_ = nullptr;
};

// ========================================================================
// SsAeadStreamDecryptor
//
// 用于 ReadMultiBuffer 的流式 AEAD 解密器：
//   - 先对长度字段做一次 one-shot 解密
//   - 再按 Buffer 片段调用 EVP_DecryptUpdate/Final
//   - 避免先落入线性 ByteVector，再二次拷贝到 pool Buffer
// ========================================================================
class SsAeadStreamDecryptor {
public:
    explicit SsAeadStreamDecryptor(const SsAeadCipher& cipher);
    ~SsAeadStreamDecryptor();

    SsAeadStreamDecryptor(const SsAeadStreamDecryptor&)            = delete;
    SsAeadStreamDecryptor& operator=(const SsAeadStreamDecryptor&) = delete;

    bool Init(const uint8_t* nonce) noexcept;
    bool Update(const uint8_t* ciphertext, size_t ciphertext_len,
                uint8_t* output, int* out_len) noexcept;
    bool Final(const uint8_t* tag) noexcept;

private:
    SsCipherType         type_;
    std::vector<uint8_t> key_;
    EVP_CIPHER_CTX*      ctx_ = nullptr;
};

// ============================================================================
// 用户信息
// ============================================================================
struct SsUserInfo {
    std::string          password;      // 明文密码（来自面板 uuid）
    std::string          email;
    int64_t              user_id    = 0;
    uint64_t             speed_limit = 0;   // bytes/s，0 = 不限速
    std::vector<uint8_t> derived_key;       // 预计算主密钥（DeriveKey 结果）
    SsCipherType         cipher_type = SsCipherType::AES_256_GCM;
    size_t               key_size   = 32;
    size_t               salt_size  = 32;

    // SharedUserStore<T> 要求的 key 提取方法（password 唯一标识用户）
    std::string_view key() const { return password; }
};

// ============================================================================
// 用户管理器（SharedUserStore<SsUserInfo> RCU 模式）
//
// 在线追踪委托 ShardedUserStats<8>（SS 用户量小，8 分片足够）
// ============================================================================
class SsUserManager {
public:
    SsUserManager() = default;
    using Snapshot = SharedUserStore<SsUserInfo>::Snapshot;
    using SnapshotPtr = SharedUserStore<SsUserInfo>::SnapshotPtr;
    using UserRawList = typename Snapshot::UserRawList;

    // 全局共享存储（RCU，所有 Worker 共享同一份数据）
    static SharedUserStore<SsUserInfo>& SharedStore() {
        static SharedUserStore<SsUserInfo> store;
        return store;
    }

    [[nodiscard]] SnapshotPtr GetSnapshot() const {
        return SharedStore().GetSnapshot();
    }

    // 增量更新指定 tag 的用户列表（无空窗期，RCU）
    void UpdateUsersForTag(const std::string& tag,
                           const std::vector<SsUserInfo>& users);

    // 静态方法：更新全局共享存储
    static void UpdateSharedUsersForTag(const std::string& tag,
                                        std::vector<SsUserInfo>&& users);

    // 获取指定 tag 的所有用户（用于握手验证，快照只读）
    [[nodiscard]] std::vector<SsUserInfo> GetUsersForTag(const std::string& tag) const;

    // 按 tag + user_id 查找用户（遍历，SS 用户量小）
    [[nodiscard]] std::optional<SsUserInfo> FindUserById(const std::string& tag,
                                                         int64_t user_id) const;

    [[nodiscard]] size_t Size() const;

    // ── 在线追踪 ─────────────────────────────────────────────────────────────

    void OnUserConnected(const std::string& tag, int64_t user_id) {
        stats_.OnUserConnected(tag, static_cast<uint64_t>(user_id));
    }

    void OnUserDisconnected(const std::string& tag, int64_t user_id) {
        stats_.OnUserDisconnected(tag, static_cast<uint64_t>(user_id));
    }

    void OnUserDisconnected(const std::string& tag, uint64_t user_id) {
        stats_.OnUserDisconnected(tag, user_id);
    }

    [[nodiscard]] std::vector<int64_t> GetOnlineUserIds(const std::string& tag) const {
        return stats_.GetOnlineUserIds(tag);
    }

private:
    ShardedUserStats<8> stats_;
};

// ============================================================================
// SOCKS5 目标地址解析（SS AEAD 首 chunk 内容）
// ============================================================================
struct SsAddress {
    TargetAddress target;
    size_t        consumed = 0;  // 已消耗的字节数
};

// 从字节流解析 SOCKS5 目标地址
// ATYP=0x01: IPv4(4) + PORT(2)
// ATYP=0x03: len(1) + name + PORT(2)
[[nodiscard]] std::optional<SsAddress> ParseSocks5Address(const uint8_t* data, size_t len);

// 编码 SOCKS5 目标地址（用于出站握手）
[[nodiscard]] std::vector<uint8_t> EncodeSocks5Address(const TargetAddress& addr);

// ============================================================================
// 协议状态（ParseStream → WrapStream 通过 ctx.protocol_data 传递）
// ============================================================================
struct SsProtocolData : public IProtocolData {
    SsCipherType         cipher_type  = SsCipherType::AES_256_GCM;
    size_t               key_size     = 32;
    size_t               salt_size    = 32;
    std::vector<uint8_t> master_key;       // 用户主密钥（用于派生写子密钥）
    std::vector<uint8_t> read_subkey;      // 读子密钥（来自客户端 salt）
    uint64_t             read_nonce   = 0; // 当前读 nonce（ParseStream 结束后的值）
};

// SS AEAD 最大 chunk payload 大小（2^14 - 1 = 16383 bytes）
static constexpr size_t kMaxChunkPayload = 0x3FFF;

}  // namespace acpp::ss
