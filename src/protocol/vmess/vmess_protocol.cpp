#include "acppnode/protocol/vmess/vmess_protocol.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/byte_reader.hpp"  // ISSUE-02-03: 安全协议解析
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛

// OpenSSL headers
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>  // ERR_clear_error

#include <zlib.h>
#include <cstring>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <unordered_set>

namespace acpp {
namespace vmess {

// ============================================================================
// OpenSSL 错误队列自动清理（安全加固）
// 
// 问题：OpenSSL 错误队列如果不清理，会影响后续操作
// 解决：使用 RAII 在失败时自动清理错误队列
// ============================================================================
class SslErrorGuard {
public:
    SslErrorGuard() : success_(false) {}
    ~SslErrorGuard() {
        if (!success_) {
            ERR_clear_error();
        }
    }
    void MarkSuccess() { success_ = true; }
private:
    bool success_;
};

// ============================================================================
// CachedAESKey 实现
// ============================================================================

void CachedAESKey::InitDecryptKey(const uint8_t* k) {
    std::memcpy(key, k, 16);
}

void CachedAESKey::ECBDecrypt(const uint8_t* ciphertext, uint8_t* plaintext) const {
    AES128ECBDecrypt(key, ciphertext, plaintext);
}

// VMess 魔法字符串
static const char* VMESS_MAGIC = "c48619fe-8f02-49e0-b9e9-edf763e17e21";
static constexpr size_t kVmessMagicLen = 36;

// ============================================================================
// 工具函数实现
// ============================================================================

std::optional<std::array<uint8_t, 16>> ParseUUID(const std::string& uuid_str) {
    std::array<uint8_t, 16> result;
    
    // 移除连字符
    std::string clean;
    clean.reserve(32);
    for (char c : uuid_str) {
        if (c != '-') {
            clean += c;
        }
    }
    
    if (clean.size() != 32) {
        return std::nullopt;
    }
    
    // 解析十六进制
    for (size_t i = 0; i < 16; ++i) {
        char buf[3] = {clean[i * 2], clean[i * 2 + 1], '\0'};
        char* end;
        long val = strtol(buf, &end, 16);
        if (*end != '\0') {
            return std::nullopt;
        }
        result[i] = static_cast<uint8_t>(val);
    }
    
    return result;
}

std::array<uint8_t, 16> MD5Hash(const uint8_t* data, size_t len) {
    std::array<uint8_t, 16> result;
    unsigned int md_len = 16;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, result.data(), &md_len);
    EVP_MD_CTX_free(ctx);
    return result;
}

std::array<uint8_t, 32> SHA256Hash(const uint8_t* data, size_t len) {
    std::array<uint8_t, 32> result;
    SHA256(data, len, result.data());
    return result;
}

std::array<uint8_t, 16> HMAC_MD5(const uint8_t* key, size_t key_len,
                                  const uint8_t* data, size_t data_len) {
    std::array<uint8_t, 16> result;
    unsigned int out_len = 16;
    HMAC(EVP_md5(), key, static_cast<int>(key_len), data, data_len, result.data(), &out_len);
    return result;
}

// HMAC-SHA256
static void HMAC_SHA256_Impl(const void* key, int key_len,
                              const uint8_t* data, size_t data_len, 
                              uint8_t* out) {
    unsigned int out_len = 32;
    HMAC(EVP_sha256(), key, key_len, data, data_len, out, &out_len);
}

// VMess KDF 递归实现 (嵌套 HMAC-SHA256)
// 注意：递归时 data_len 会增长，需要足够大的缓冲区
static void vmess_kdf_recursive(
    const uint8_t* data, size_t data_len,
    std::span<const std::string_view> path,
    size_t depth,
    uint8_t* out) {
    
    static const char* kKdfSalt = "VMess AEAD KDF";

    if (depth == 0) {
        // 基础情况：HMAC-SHA256 with key = "VMess AEAD KDF"
        HMAC_SHA256_Impl(kKdfSalt, static_cast<int>(strlen(kKdfSalt)), data, data_len, out);
        return;
    }
    
    // 递归情况：HMAC(inner_hash_func, path[depth-1], data)
    const std::string_view key = path[depth - 1];
    
    // 准备 HMAC 密钥 (pad 到 64 字节) - 栈分配
    alignas(16) uint8_t k_padded[64] = {0};
    
    if (key.size() <= 64) {
        memcpy(k_padded, key.data(), key.size());
    } else {
        // ISSUE-02-02: 使用 unsafe::ptr_cast 替代 reinterpret_cast
        vmess_kdf_recursive(unsafe::ptr_cast<const uint8_t>(key.data()), 
                           key.size(), path, depth - 1, k_padded);
    }
    
    // ipad = k_padded XOR 0x36, opad = k_padded XOR 0x5c
    alignas(16) uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k_padded[i] ^ 0x36;
        opad[i] = k_padded[i] ^ 0x5c;
    }
    
    // inner = H(ipad || data)
    // 递归时 data_len 增长：depth=3 时最大约 80，depth=2 约 144，depth=1 约 208
    // 使用 512 字节缓冲区确保安全
    alignas(16) uint8_t inner_input[512];
    if (64 + data_len > sizeof(inner_input)) {
        // 极端情况回退到堆分配
        memory::ByteVector inner_vec(64 + data_len);
        memcpy(inner_vec.data(), ipad, 64);
        memcpy(inner_vec.data() + 64, data, data_len);
        
        uint8_t inner_hash[32];
        vmess_kdf_recursive(inner_vec.data(), 64 + data_len, path, depth - 1, inner_hash);
        
        alignas(16) uint8_t outer_input[96];
        memcpy(outer_input, opad, 64);
        memcpy(outer_input + 64, inner_hash, 32);
        vmess_kdf_recursive(outer_input, 96, path, depth - 1, out);
        return;
    }
    
    memcpy(inner_input, ipad, 64);
    memcpy(inner_input + 64, data, data_len);
    
    uint8_t inner_hash[32];
    vmess_kdf_recursive(inner_input, 64 + data_len, path, depth - 1, inner_hash);
    
    // outer = H(opad || inner)
    alignas(16) uint8_t outer_input[96];  // 64 + 32
    memcpy(outer_input, opad, 64);
    memcpy(outer_input + 64, inner_hash, 32);
    vmess_kdf_recursive(outer_input, 96, path, depth - 1, out);
}

void KDF(const uint8_t* key, size_t key_len,
         std::span<const std::string_view> path,
         uint8_t* out, size_t out_len) {
    uint8_t result[32];
    vmess_kdf_recursive(key, key_len, path, path.size(), result);
    memcpy(out, result, std::min(out_len, size_t(32)));
}

std::array<uint8_t, 16> KDF16(const uint8_t* key, size_t key_len,
                               std::span<const std::string_view> path) {
    std::array<uint8_t, 16> result;
    KDF(key, key_len, path, result.data(), 16);
    return result;
}

// OpenSSL 实现
std::optional<memory::ByteVector> AES128GCMDecrypt(
    const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* ciphertext, size_t len,
    const uint8_t* aad, size_t aad_len) {
    
    if (len < GCM_TAG_SIZE) return std::nullopt;
    
    SslErrorGuard ssl_guard;  // 安全加固：失败时自动清理错误队列
    
    size_t data_len = len - GCM_TAG_SIZE;
    memory::ByteVector plaintext(data_len);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;
    
    int out_len = 0, final_len = 0;
    bool ok = false;
    
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce_len), nullptr) != 1) break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
        
        if (aad && aad_len > 0) {
            if (EVP_DecryptUpdate(ctx, nullptr, &out_len, aad, static_cast<int>(aad_len)) != 1) break;
        }
        
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext, static_cast<int>(data_len)) != 1) break;
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_SIZE, 
                               const_cast<uint8_t*>(ciphertext + data_len)) != 1) break;
        
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) != 1) break;
        
        ok = true;
    } while (0);
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (!ok) return std::nullopt;
    
    ssl_guard.MarkSuccess();  // 成功，不需要清理错误队列
    plaintext.resize(out_len + final_len);
    return plaintext;
}

memory::ByteVector AES128GCMEncrypt(
    const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* plaintext, size_t len,
    const uint8_t* aad, size_t aad_len) {
    
    memory::ByteVector ciphertext(len + GCM_TAG_SIZE);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};
    
    int out_len = 0, final_len = 0;
    bool ok = false;
    
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce_len), nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
        
        if (aad && aad_len > 0) {
            if (EVP_EncryptUpdate(ctx, nullptr, &out_len, aad, static_cast<int>(aad_len)) != 1) break;
        }
        
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext, static_cast<int>(len)) != 1) break;
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len) != 1) break;
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_SIZE, ciphertext.data() + out_len + final_len) != 1) break;
        
        ok = true;
    } while (0);
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (!ok) return {};
    ciphertext.resize(out_len + final_len + GCM_TAG_SIZE);
    return ciphertext;
}

void AES128ECBEncrypt(const uint8_t* key, const uint8_t* plaintext, uint8_t* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int out_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, 16);
    EVP_CIPHER_CTX_free(ctx);
}

// AES-128-GCM 加密 (带输出参数版本)
bool AES128GCMEncrypt(
    const uint8_t* key, const uint8_t* nonce,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t len,
    uint8_t* ciphertext, uint8_t* tag) {
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    int out_len = 0, final_len = 0;
    bool ok = false;
    
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1) break;
        
        if (aad && aad_len > 0) {
            if (EVP_EncryptUpdate(ctx, nullptr, &out_len, aad, static_cast<int>(aad_len)) != 1) break;
        }
        
        if (EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, static_cast<int>(len)) != 1) break;
        if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_SIZE, tag) != 1) break;
        
        ok = true;
    } while (0);
    
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

void AES128ECBDecrypt(const uint8_t* key, const uint8_t* ciphertext, uint8_t* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int out_len = 0;
    EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, 16);
    EVP_CIPHER_CTX_free(ctx);
}

uint32_t CRC32(const uint8_t* data, size_t len) {
    return crc32(0L, data, static_cast<uInt>(len));
}

uint32_t FNV1a32(const uint8_t* data, size_t len) {
    uint32_t hash = 0x811c9dc5;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    return hash;
}

void RandomBytes(uint8_t* buf, size_t len) {
    RAND_bytes(buf, static_cast<int>(len));
}

// 生成 AuthID: AES-128-ECB(auth_key, timestamp || random || crc32)
void GenerateAuthID(const uint8_t* auth_key, int64_t timestamp, uint8_t* out_auth_id) {
    uint8_t plaintext[16];
    
    // 时间戳 (8 bytes, big-endian)
    for (int i = 7; i >= 0; i--) {
        plaintext[7 - i] = static_cast<uint8_t>(timestamp >> (i * 8));
    }
    
    // 随机数 (4 bytes)
    RAND_bytes(plaintext + 8, 4);
    
    // CRC32 of first 12 bytes
    uint32_t crc = CRC32(plaintext, 12);
    plaintext[12] = static_cast<uint8_t>(crc >> 24);
    plaintext[13] = static_cast<uint8_t>(crc >> 16);
    plaintext[14] = static_cast<uint8_t>(crc >> 8);
    plaintext[15] = static_cast<uint8_t>(crc);
    
    // AES-128-ECB 加密
    AES128ECBEncrypt(auth_key, plaintext, out_auth_id);
}

// ============================================================================
// SHAKE128 实现
// ============================================================================
// OpenSSL 3.0+ EVP 实现
void SHAKE128(const uint8_t* input, size_t input_len,
              uint8_t* output, size_t output_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    const EVP_MD* md = EVP_shake128();
    if (!md) {
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    if (EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, input, input_len) == 1) {
        EVP_DigestFinalXOF(ctx, output, output_len);
    }
    
    EVP_MD_CTX_free(ctx);
}

// ============================================================================
// VMessUser 实现
// ============================================================================

std::optional<VMessUser> VMessUser::FromUUID(const std::string& uuid_str,
                                              int64_t user_id,
                                              const std::string& email,
                                              uint64_t speed_limit) {
    auto uuid_bytes = ParseUUID(uuid_str);
    if (!uuid_bytes) {
        return std::nullopt;
    }
    
    VMessUser user;
    user.uuid = uuid_str;
    user.uuid_bytes = *uuid_bytes;
    user.user_id = user_id;
    user.email = email;
    user.speed_limit = speed_limit;
    
    // 计算 CMD Key = MD5(UUID + MAGIC)
    std::array<uint8_t, 16 + kVmessMagicLen> key_material{};
    std::memcpy(key_material.data(), user.uuid_bytes.data(), user.uuid_bytes.size());
    std::memcpy(key_material.data() + user.uuid_bytes.size(), VMESS_MAGIC, kVmessMagicLen);
    user.cmd_key = MD5Hash(key_material.data(), key_material.size());
    
    // 计算 Auth Key = KDF16(cmd_key, "AES Auth ID Encryption")
    const std::array<std::string_view, 1> auth_key_path{
        KDFSalt::AUTH_ID_ENCRYPTION_KEY
    };
    user.auth_key = KDF16(user.cmd_key.data(), 16, auth_key_path);
    
    // 预计算 AES 解密密钥（避免每次 FindByAuthID 都调用 AES_set_decrypt_key）
    user.cached_auth_aes_key.InitDecryptKey(user.auth_key.data());
    
    return user;
}

// ============================================================================
// VMessUserManager 实现
// ============================================================================

// 静态方法：更新全局共享存储
void VMessUserManager::UpdateSharedUsersForTag(const std::string& tag, std::vector<VMessUser>&& users) {
    VMessUserManager::SharedStore().UpdateTag(tag, std::move(users));
}

void VMessUserManager::UpdateUsersForTag(const std::string& tag, const std::vector<VMessUser>& users) {
    if (use_shared_store_) {
        // 共享存储模式：只清空热点缓存，用户数据由 SharedStore 管理
        // 注意：实际更新应通过 UpdateSharedUsersForTag 静态方法进行（只调用一次）
        hot_cache_.lock.Lock();
        hot_cache_.Clear();
        hot_cache_.lock.Unlock();
        return;
    }
    
    // 本地存储模式（旧行为）
    // Per-worker: no lock needed
    
    // 获取或创建该 tag 的用户 map
    auto& tag_users = users_by_tag_[tag];
    tag_users.reserve(users.size());
    
    // 构建新用户集合
    std::unordered_set<std::string> new_uuids;
    new_uuids.reserve(users.size());
    for (const auto& user : users) {
        new_uuids.insert(user.uuid);
    }
    
    // 删除不在新列表中的用户
    for (auto it = tag_users.begin(); it != tag_users.end(); ) {
        if (new_uuids.find(it->first) == new_uuids.end()) {
            it = tag_users.erase(it);
        } else {
            ++it;
        }
    }
    
    // 添加或更新用户
    for (const auto& user : users) {
        tag_users[user.uuid] = user;
    }
    
    // 清空热点缓存（用户指针可能已失效）
    hot_cache_.lock.Lock();
    hot_cache_.Clear();
    hot_cache_.lock.Unlock();
}

void VMessUserManager::ClearTag(const std::string& tag) {
    if (use_shared_store_) {
        VMessUserManager::SharedStore().ClearTag(tag);
    } else {
        users_by_tag_.erase(tag);
    }
    
    // 清空热点缓存
    hot_cache_.lock.Lock();
    hot_cache_.Clear();
    hot_cache_.lock.Unlock();
}

void VMessUserManager::Clear() {
    if (use_shared_store_) {
        VMessUserManager::SharedStore().Clear();
    } else {
        users_by_tag_.clear();
    }
    
    // 清空热点缓存
    hot_cache_.lock.Lock();
    hot_cache_.Clear();
    hot_cache_.lock.Unlock();
}

size_t VMessUserManager::Size() const {
    if (use_shared_store_) {
        return VMessUserManager::SharedStore().Size();
    }
    
    size_t total = 0;
    for (const auto& [tag, users] : users_by_tag_) {
        total += users.size();
    }
    return total;
}

size_t VMessUserManager::SizeForTag(const std::string& tag) const {
    if (use_shared_store_) {
        return VMessUserManager::SharedStore().SizeForTag(tag);
    }
    
    auto it = users_by_tag_.find(tag);
    if (it != users_by_tag_.end()) {
        return it->second.size();
    }
    return 0;
}

const VMessUser* VMessUserManager::FindByAuthID(const uint8_t* auth_id, int64_t& out_timestamp) const {
    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // 内部验证函数：尝试用指定用户解密 AuthID
    auto tryUser = [&](const VMessUser& user) -> bool {
        std::array<uint8_t, 16> plaintext;
        user.cached_auth_aes_key.ECBDecrypt(auth_id, plaintext.data());
        
        // 提取时间戳
        int64_t timestamp = 0;
        for (int i = 0; i < 8; i++) {
            timestamp = (timestamp << 8) | plaintext[i];
        }
        
        // 检查时间戳范围
        if (timestamp > now + TIMESTAMP_TOLERANCE || timestamp < now - TIMESTAMP_TOLERANCE) {
            return false;
        }
        
        // 验证 CRC32
        uint32_t crc = CRC32(plaintext.data(), 12);
        uint32_t expected_crc = (static_cast<uint32_t>(plaintext[12]) << 24) |
                                (static_cast<uint32_t>(plaintext[13]) << 16) |
                                (static_cast<uint32_t>(plaintext[14]) << 8) |
                                plaintext[15];
        
        if (crc == expected_crc) {
            out_timestamp = timestamp;
            return true;
        }
        return false;
    };
    
    // ========================================================================
    // 定期清理热点缓存（每 60 秒）
    // ========================================================================
    int64_t last_cleanup = last_hot_cache_cleanup_.load(std::memory_order_relaxed);
    if (now - last_cleanup > 60 && 
        last_hot_cache_cleanup_.compare_exchange_weak(last_cleanup, now)) {
        hot_cache_.lock.Lock();
        hot_cache_.Cleanup(now);
        hot_cache_.lock.Unlock();
    }
    
    // ========================================================================
    // 第一阶段：查找热点缓存（按活跃度排序，最近活跃的优先）
    // 优化：先复制用户指针列表，释放锁后再验证
    // ========================================================================
    {
        constexpr int64_t hot_cache_window = 300;  // 5 分钟窗口

        // 收集有效的热点用户（在锁内，快速操作）
        // 同时复制 snapshot 引用，防止锁释放后对应用户对象失效
        using CandidateEntry = std::pair<const VMessUser*, HotUserCache::SnapshotRef>;
        std::vector<CandidateEntry> candidates;
        candidates.reserve(32);

        hot_cache_.lock.Lock();
        for (const auto* user : hot_cache_.active_order) {
            auto it = hot_cache_.entries.find(user);
            if (it != hot_cache_.entries.end() &&
                it->second.timestamp + hot_cache_window >= now) {
                candidates.emplace_back(user, it->second.owner);
            }
        }
        hot_cache_.lock.Unlock();

        // 在锁外验证（AES 解密是耗时操作），snapshot shared_ptr 保证对象存活
        for (const auto& [user, owner] : candidates) {
            (void)owner;
            if (tryUser(*user)) {
                // 命中！更新时间戳
                hot_cache_.lock.Lock();
                hot_cache_.UpdateTime(user, now);
                hot_cache_.lock.Unlock();
                return user;
            }
        }
    }

    // ========================================================================
    // 第二阶段：遍历所有用户
    // ========================================================================
    if (use_shared_store_) {
        // 共享存储模式：从 SharedStore 读取
        auto snapshot = VMessUserManager::SharedStore().GetSnapshot();
        auto global_users = snapshot->GetGlobalUserList();
        if (global_users) {
            for (const auto* user : *global_users) {
                if (tryUser(*user)) {
                    // 找到！添加到热点缓存（传入 snapshot 保持用户对象存活）
                    hot_cache_.lock.Lock();
                    hot_cache_.Touch(user, now, snapshot);
                    hot_cache_.lock.Unlock();
                    return user;
                }
            }
        }
    } else {
        // 本地存储模式
        for (const auto& [tag, users] : users_by_tag_) {
            for (const auto& [uuid, user] : users) {
                if (tryUser(user)) {
                    // 找到！添加到热点缓存
                    hot_cache_.lock.Lock();
                    hot_cache_.Touch(&user, now);
                    hot_cache_.lock.Unlock();
                    return &user;
                }
            }
        }
    }
    
    return nullptr;
}

std::vector<const VMessUser*> VMessUserManager::GetAllUsers() const {
    std::vector<const VMessUser*> result;
    
    if (use_shared_store_) {
        auto snapshot = VMessUserManager::SharedStore().GetSnapshot();
        auto global_users = snapshot->GetGlobalUserList();
        if (global_users) {
            result.reserve(global_users->size());
            result.insert(result.end(), global_users->begin(), global_users->end());
        }
    } else {
        result.reserve(Size());
        for (const auto& [tag, users] : users_by_tag_) {
            for (const auto& [uuid, user] : users) {
                result.push_back(&user);
            }
        }
    }
    return result;
}

// ============================================================================
// FindByAuthIDForTag - 优化版：只搜索指定 tag 的用户
// 预期减少 80-90% 的搜索量（当有多个入站时）
// ============================================================================
const VMessUser* VMessUserManager::FindByAuthIDForTag(
    const std::string& tag,
    const uint8_t* auth_id, 
    int64_t& out_timestamp) const {
    
    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // 内部验证函数（与 FindByAuthID 相同）
    auto tryUser = [&](const VMessUser& user) -> bool {
        std::array<uint8_t, 16> plaintext;
        user.cached_auth_aes_key.ECBDecrypt(auth_id, plaintext.data());
        
        // 提取时间戳
        int64_t timestamp = 0;
        for (int i = 0; i < 8; i++) {
            timestamp = (timestamp << 8) | plaintext[i];
        }
        
        // 检查时间戳范围
        if (timestamp > now + TIMESTAMP_TOLERANCE || timestamp < now - TIMESTAMP_TOLERANCE) {
            return false;
        }
        
        // 验证 CRC32
        uint32_t crc = CRC32(plaintext.data(), 12);
        uint32_t expected_crc = (static_cast<uint32_t>(plaintext[12]) << 24) |
                                (static_cast<uint32_t>(plaintext[13]) << 16) |
                                (static_cast<uint32_t>(plaintext[14]) << 8) |
                                plaintext[15];
        
        if (crc == expected_crc) {
            out_timestamp = timestamp;
            return true;
        }
        return false;
    };
    
    // ========================================================================
    // 第一阶段：检查热点缓存（全局的，因为用户可能跨入站活跃）
    // ========================================================================
    {
        constexpr int64_t hot_cache_window = 300;  // 5 分钟窗口

        // 同时复制 snapshot 引用，防止锁释放后对应用户对象失效
        using CandidateEntry = std::pair<const VMessUser*, HotUserCache::SnapshotRef>;
        std::vector<CandidateEntry> candidates;
        candidates.reserve(32);

        hot_cache_.lock.Lock();
        for (const auto* user : hot_cache_.active_order) {
            auto it = hot_cache_.entries.find(user);
            if (it != hot_cache_.entries.end() &&
                it->second.timestamp + hot_cache_window >= now) {
                candidates.emplace_back(user, it->second.owner);
            }
        }
        hot_cache_.lock.Unlock();

        for (const auto& [user, owner] : candidates) {
            (void)owner;
            if (tryUser(*user)) {
                hot_cache_.lock.Lock();
                hot_cache_.UpdateTime(user, now);
                hot_cache_.lock.Unlock();
                return user;
            }
        }
    }

    // ========================================================================
    // 第二阶段：只遍历指定 tag 的用户（关键优化点！）
    // ========================================================================
    if (use_shared_store_) {
        // 共享存储模式：从 SharedStore 读取指定 tag 的用户
        auto snapshot = VMessUserManager::SharedStore().GetSnapshot();
        auto tag_users = snapshot->GetTagUserList(tag);
        if (!tag_users) {
            return nullptr;  // 该 tag 没有用户
        }

        for (const auto* user : *tag_users) {
            if (tryUser(*user)) {
                // 找到！添加到热点缓存（传入 snapshot 保持用户对象存活）
                hot_cache_.lock.Lock();
                hot_cache_.Touch(user, now, snapshot);
                hot_cache_.lock.Unlock();
                return user;
            }
        }
    } else {
        // 本地存储模式
        auto tag_it = users_by_tag_.find(tag);
        if (tag_it == users_by_tag_.end()) {
            return nullptr;  // 该 tag 没有用户
        }
        
        for (const auto& [uuid, user] : tag_it->second) {
            if (tryUser(user)) {
                // 找到！添加到热点缓存
                hot_cache_.lock.Lock();
                hot_cache_.Touch(&user, now);
                hot_cache_.lock.Unlock();
                return &user;
            }
        }
    }
    
    return nullptr;
}

// ============================================================================
// VMessParser 实现
// ============================================================================

VMessParser::VMessParser(const VMessUserManager& user_manager)
    : user_manager_(user_manager), tag_() {
}

VMessParser::VMessParser(const VMessUserManager& user_manager, const std::string& tag)
    : user_manager_(user_manager), tag_(tag) {
}

std::pair<std::optional<VMessRequest>, size_t>
VMessParser::ParseRequest(const uint8_t* data, size_t len) {
    // VMess AEAD 请求格式：
    // AuthID (16) + LengthEncrypted (2+16) + ConnectionNonce (8) + HeaderEncrypted (N+16)
    
    if (len < 16 + 18 + 8) {  // 最小长度
        LOG_ACCESS_DEBUG("VMess: data too short, len={}", len);
        return {std::nullopt, 0};
    }
    
    // 提取 AuthID (16 bytes)
    const uint8_t* auth_id = data;
    
    // 查找用户 - 根据是否指定 tag 选择查找方式
    int64_t timestamp;
    const VMessUser* user;
    
    if (tag_.empty()) {
        // 兼容模式：搜索所有用户
        user = user_manager_.FindByAuthID(auth_id, timestamp);
    } else {
        // 优化模式：只搜索指定 tag 的用户
        user = user_manager_.FindByAuthIDForTag(tag_, auth_id, timestamp);
    }
    
    if (!user) {
        LOG_ACCESS_DEBUG("VMess: user not found by auth_id (tag={}, users={})", 
                  tag_.empty() ? "all" : tag_, user_manager_.Size());
        return {std::nullopt, 0};
    }
    
    LOG_ACCESS_DEBUG("VMess: found user {} by auth_id", user->email);
    
    // 读取 connectionNonce (8 bytes after AuthID + encrypted length)
    const uint8_t* connection_nonce = data + 16 + 18;
    
    // 解析请求头
    VMessRequest request;
    size_t consumed = 0;
    
    if (!ParseRequestHeader(data + 16, len - 16, user, auth_id, connection_nonce,
                           request, consumed)) {
        LOG_ACCESS_DEBUG("VMess: failed to parse request header");
        return {std::nullopt, 0};
    }
    
    request.user = user;
    
    return {request, 16 + consumed};
}

bool VMessParser::ParseRequestHeader(const uint8_t* data, size_t len,
                                     const VMessUser* user,
                                     const uint8_t* auth_id,
                                     const uint8_t* connection_nonce,
                                     VMessRequest& request,
                                     size_t& consumed) {
    // 格式: LengthEncrypted (18) + ConnectionNonce (8) + HeaderEncrypted (N+16)
    
    if (len < 18 + 8) {
        return false;
    }
    
    const uint8_t* len_enc = data;
    connection_nonce = data + 18;
    
    // 派生长度加密密钥
    // ISSUE-02-02: 使用 unsafe::ptr_cast 替代 reinterpret_cast
    std::string auth_id_str(unsafe::ptr_cast<const char>(auth_id), 16);
    std::string nonce_str(unsafe::ptr_cast<const char>(connection_nonce), 8);
    
    const std::array<std::string_view, 3> len_key_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
        auth_id_str,
        nonce_str
    };
    auto len_key = KDF16(user->cmd_key.data(), 16, len_key_path);
    
    std::array<uint8_t, 12> len_iv;
    const std::array<std::string_view, 3> len_iv_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
        auth_id_str,
        nonce_str
    };
    KDF(user->cmd_key.data(), 16, len_iv_path, len_iv.data(), 12);
    
    // 解密长度 (AAD = auth_id)
    auto len_dec = AES128GCMDecrypt(len_key.data(), len_iv.data(), 12,
                                     len_enc, 18, auth_id, 16);
    
    if (!len_dec || len_dec->size() != 2) {
        LOG_ACCESS_DEBUG("VMess: header length decrypt failed");
        return false;
    }
    
    uint16_t header_len = (static_cast<uint16_t>((*len_dec)[0]) << 8) | (*len_dec)[1];
    LOG_ACCESS_DEBUG("VMess: header length = {}", header_len);
    
    // 检查是否有足够数据
    size_t needed = 18 + 8 + static_cast<size_t>(header_len) + 16;
    if (len < needed) {
        LOG_ACCESS_DEBUG("VMess: not enough data for header, need {}, have {}", needed, len);
        return false;
    }
    
    // 读取加密的请求头
    const uint8_t* header_enc = data + 18 + 8;
    
    // 派生请求头加密密钥
    const std::array<std::string_view, 3> header_key_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_AEAD_KEY,
        auth_id_str,
        nonce_str
    };
    auto header_key = KDF16(user->cmd_key.data(), 16, header_key_path);
    
    std::array<uint8_t, 12> header_iv;
    const std::array<std::string_view, 3> header_iv_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_AEAD_IV,
        auth_id_str,
        nonce_str
    };
    KDF(user->cmd_key.data(), 16, header_iv_path, header_iv.data(), 12);
    
    // 解密请求头 (AAD = auth_id)
    auto header_dec = AES128GCMDecrypt(header_key.data(), header_iv.data(), 12,
                                        header_enc, header_len + 16, auth_id, 16);
    
    if (!header_dec) {
        LOG_ACCESS_DEBUG("VMess: header decrypt failed");
        return false;
    }
    
    // 解析解密后的请求头
    if (!ParseDecryptedHeader(header_dec->data(), header_dec->size(), request)) {
        LOG_ACCESS_DEBUG("VMess: parse decrypted header failed");
        return false;
    }
    
    consumed = 18 + 8 + header_len + 16;
    return true;
}

bool VMessParser::ParseDecryptedHeader(const uint8_t* data, size_t len, VMessRequest& request) {
    // VMess 请求头格式：
    // 1 byte: version
    // 16 bytes: body IV
    // 16 bytes: body key
    // 1 byte: response_header
    // 1 byte: options
    // 1 byte: (padding_len << 4) | security
    // 1 byte: reserved (0)
    // 1 byte: command
    // 2 bytes: port (big endian)
    // 1 byte: address type
    // N bytes: address
    // (padding)
    // 4 bytes: checksum (fnv1a)
    
    if (len < 41) {  // 最小长度
        return false;
    }
    
    // ISSUE-02-03: 使用 ByteReader 进行安全协议解析
    ByteReader reader(data, len);
    
    // Version
    request.version = reader.ReadU8();
    if (!reader.Ok() || request.version != VERSION) {
        LOG_ACCESS_DEBUG("VMess: unsupported version {}", request.version);
        return false;
    }
    
    // Body IV (16 bytes)
    auto iv_span = reader.ReadBytes(16);
    if (!reader.Ok()) return false;
    std::memcpy(request.body_iv.data(), iv_span.data(), 16);
    
    // Body Key (16 bytes)
    auto key_span = reader.ReadBytes(16);
    if (!reader.Ok()) return false;
    std::memcpy(request.body_key.data(), key_span.data(), 16);
    
    // Response header
    request.response_header = reader.ReadU8();
    
    // Options
    request.options = reader.ReadU8();
    
    // Padding len + Security
    uint8_t ps = reader.ReadU8();
    request.padding_len = (ps >> 4) & 0x0F;
    request.security = static_cast<Security>(ps & 0x0F);
    
    // Reserved (skip)
    reader.Skip(1);
    
    // Command
    request.command = static_cast<Command>(reader.ReadU8());
    
    // Port (big endian)
    uint16_t port = reader.ReadU16BE();
    
    // Address type
    uint8_t addr_type = reader.ReadU8();
    if (!reader.Ok()) return false;
    
    std::string host;
    
    switch (addr_type) {
        case 1: {  // IPv4
            auto ipv4_span = reader.ReadBytes(4);
            if (!reader.Ok()) return false;
            char buf[INET_ADDRSTRLEN];
            snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                     ipv4_span[0], ipv4_span[1], ipv4_span[2], ipv4_span[3]);
            host = buf;
            break;
        }
        case 2: {  // Domain
            uint8_t domain_len = reader.ReadU8();
            if (!reader.Ok()) return false;
            host = reader.ReadString(domain_len);
            if (!reader.Ok()) return false;
            break;
        }
        case 3: {  // IPv6
            auto ipv6_span = reader.ReadBytes(16);
            if (!reader.Ok()) return false;
            char buf[INET6_ADDRSTRLEN];
            snprintf(buf, sizeof(buf),
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     ipv6_span[0], ipv6_span[1], ipv6_span[2], ipv6_span[3],
                     ipv6_span[4], ipv6_span[5], ipv6_span[6], ipv6_span[7],
                     ipv6_span[8], ipv6_span[9], ipv6_span[10], ipv6_span[11],
                     ipv6_span[12], ipv6_span[13], ipv6_span[14], ipv6_span[15]);
            host = buf;
            break;
        }
        default:
            LOG_ACCESS_DEBUG("VMess: unsupported address type {}", addr_type);
            return false;
    }
    
    request.target = TargetAddress(host, port);
    
    // 跳过 padding
    reader.Skip(request.padding_len);
    if (!reader.Ok()) return false;
    
    // 验证 FNV1a checksum
    // 注意：FNV1a 需要对原始数据计算，使用 reader.Position() 获取当前位置
    size_t pos = reader.Position();
    if (pos + 4 > len) return false;
    
    uint32_t expected_fnv = FNV1a32(data, pos);
    uint32_t actual_fnv = reader.ReadU32BE();
    
    if (!reader.Ok() || expected_fnv != actual_fnv) {
        LOG_ACCESS_DEBUG("VMess: FNV1a checksum mismatch");
        return false;
    }
    
    return true;
}

// ============================================================================
// VMessCipher 实现
// ============================================================================

// OpenSSL 实现（使用 EVP_CIPHER API）
// 优化：预分配 EVP_CIPHER_CTX，避免每次加解密都分配/释放
VMessCipher::VMessCipher(Security security, const uint8_t* key, const uint8_t* iv)
    : security_(security), count_(0), enc_ctx_(nullptr), dec_ctx_(nullptr), ctx_initialized_(false) {
    std::memcpy(key_.data(), key, 16);
    std::memcpy(iv_.data(), iv, 16);
    
    if (security_ == Security::AES_128_GCM || security_ == Security::CHACHA20_POLY1305) {
        if (security_ == Security::CHACHA20_POLY1305) {
            GenerateChaCha20Key(key_.data(), key32_.data());
        }
        
        // 预分配加密和解密上下文（直接成员指针，无额外堆分配）
        enc_ctx_ = EVP_CIPHER_CTX_new();
        dec_ctx_ = EVP_CIPHER_CTX_new();

        ctx_initialized_ = (enc_ctx_ != nullptr && dec_ctx_ != nullptr);
    }
}

VMessCipher::~VMessCipher() {
    if (enc_ctx_) EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(enc_ctx_));
    if (dec_ctx_) EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(dec_ctx_));
}

ssize_t VMessCipher::Encrypt(const uint8_t* plaintext, size_t len, uint8_t* ciphertext) {
    if (security_ == Security::NONE || security_ == Security::ZERO) {
        if (len > 0 && plaintext) memcpy(ciphertext, plaintext, len);
        return static_cast<ssize_t>(len);
    }
    
    if (!ctx_initialized_) return -1;

    uint8_t nonce[12];
    BuildNonce(count_++, nonce);

    EVP_CIPHER_CTX* ctx = static_cast<EVP_CIPHER_CTX*>(enc_ctx_);

    // 重置上下文以便复用
    EVP_CIPHER_CTX_reset(ctx);
    
    const EVP_CIPHER* cipher;
    const uint8_t* actual_key;
    
    if (security_ == Security::CHACHA20_POLY1305) {
        cipher = EVP_chacha20_poly1305();
        actual_key = key32_.data();
    } else {
        cipher = EVP_aes_128_gcm();
        actual_key = key_.data();
    }
    
    int out_len = 0;
    int final_len = 0;
    
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        return -1;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        return -1;
    }
    
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, actual_key, nonce) != 1) {
        return -1;
    }
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, static_cast<int>(len)) != 1) {
        return -1;
    }
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) != 1) {
        return -1;
    }
    
    out_len += final_len;
    
    // 获取 tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_SIZE, ciphertext + out_len) != 1) {
        return -1;
    }
    
    return static_cast<ssize_t>(out_len + GCM_TAG_SIZE);
}

ssize_t VMessCipher::Decrypt(const uint8_t* ciphertext, size_t len, uint8_t* plaintext) {
    if (security_ == Security::NONE || security_ == Security::ZERO) {
        memcpy(plaintext, ciphertext, len);
        return static_cast<ssize_t>(len);
    }
    
    if (len < GCM_TAG_SIZE) return -1;
    if (!ctx_initialized_) return -1;

    uint8_t nonce[12];
    BuildNonce(count_++, nonce);

    EVP_CIPHER_CTX* ctx = static_cast<EVP_CIPHER_CTX*>(dec_ctx_);

    // 重置上下文以便复用
    EVP_CIPHER_CTX_reset(ctx);
    
    const EVP_CIPHER* cipher;
    const uint8_t* actual_key;
    
    if (security_ == Security::CHACHA20_POLY1305) {
        cipher = EVP_chacha20_poly1305();
        actual_key = key32_.data();
    } else {
        cipher = EVP_aes_128_gcm();
        actual_key = key_.data();
    }
    
    size_t ciphertext_len = len - GCM_TAG_SIZE;
    int out_len = 0;
    int final_len = 0;
    
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        return -1;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        return -1;
    }
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, actual_key, nonce) != 1) {
        return -1;
    }
    
    if (EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, static_cast<int>(ciphertext_len)) != 1) {
        return -1;
    }
    
    // 设置 tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_SIZE, 
                           const_cast<uint8_t*>(ciphertext + ciphertext_len)) != 1) {
        return -1;
    }
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) != 1) {
        return -1;  // Tag 验证失败
    }
    
    return static_cast<ssize_t>(out_len + final_len);
}

size_t VMessCipher::Overhead() const {
    switch (security_) {
        case Security::AES_128_GCM:
        case Security::CHACHA20_POLY1305:
            return GCM_TAG_SIZE;
        default:
            return 0;
    }
}

// ChaCha20-Poly1305 需要 32 字节密钥，从 16 字节扩展
void VMessCipher::GenerateChaCha20Key(const uint8_t* key16, uint8_t* key32) {
    // 使用 EVP API 避免废弃警告
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    unsigned int md_len = 16;
    
    EVP_DigestInit_ex(md_ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(md_ctx, key16, 16);
    EVP_DigestFinal_ex(md_ctx, key32, &md_len);
    
    EVP_DigestInit_ex(md_ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(md_ctx, key32, 16);
    EVP_DigestFinal_ex(md_ctx, key32 + 16, &md_len);
    
    EVP_MD_CTX_free(md_ctx);
}

void VMessCipher::BuildNonce(uint16_t count, uint8_t* nonce) {
    // Nonce = Count(2 bytes, big-endian) || IV[2:12]
    nonce[0] = (count >> 8) & 0xFF;
    nonce[1] = count & 0xFF;
    memcpy(nonce + 2, iv_.data() + 2, 10);
}

// ============================================================================
// ShakeMask 实现 - 优化版：固定 4KB 数组
// ============================================================================

ShakeMask::ShakeMask(const uint8_t* nonce) {
    // 初始化 SHAKE128 XOF 上下文，写入 nonce 作为输入
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        const EVP_MD* md = EVP_shake128();
        if (md && EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
            EVP_DigestUpdate(ctx, nonce, 16) == 1) {
            ctx_ = ctx;
        } else {
            EVP_MD_CTX_free(ctx);
        }
    }
}

ShakeMask::~ShakeMask() {
    if (ctx_) {
        EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(ctx_));
    }
}

void ShakeMask::Refill() {
    // 从 SHAKE128 XOF 流式输出新的 4KB 数据（对齐 Xray 的 shake.Read() 语义）
    // EVP_DigestSqueeze 可多次调用，每次输出新数据，永不重复
    if (ctx_) {
        EVP_DigestSqueeze(static_cast<EVP_MD_CTX*>(ctx_), buffer_, kBufferSize);
    } else {
        memset(buffer_, 0, kBufferSize);
    }
    offset_ = 0;
}

uint16_t ShakeMask::NextMask() {
    if (offset_ + 2 > kBufferSize) {
        Refill();
    }

    // Big-endian（对齐 Xray 的 binary.BigEndian.Uint16）
    uint16_t result = (static_cast<uint16_t>(buffer_[offset_]) << 8) |
                      static_cast<uint16_t>(buffer_[offset_ + 1]);
    offset_ += 2;
    return result;
}

// ============================================================================
// VMessServerStream 实现
// ============================================================================

VMessServerStream::VMessServerStream(const VMessRequest& request)
    : request_(request) {
    
    // 使用请求中的 body_key 和 body_iv
    memcpy(request_key_.data(), request_.body_key.data(), 16);
    memcpy(request_iv_.data(), request_.body_iv.data(), 16);
    
    // 响应密钥/IV 派生: SHA256(request_key/iv)[0:16]
    auto resp_key_hash = SHA256Hash(request_key_.data(), 16);
    auto resp_iv_hash = SHA256Hash(request_iv_.data(), 16);
    
    memcpy(response_key_.data(), resp_key_hash.data(), 16);
    memcpy(response_iv_.data(), resp_iv_hash.data(), 16);
    
    // 服务端：读用 request，写用 response
    read_cipher_ = std::make_unique<VMessCipher>(request_.security, 
                                                   request_key_.data(), request_iv_.data());
    write_cipher_ = std::make_unique<VMessCipher>(request_.security,
                                                    response_key_.data(), response_iv_.data());
    
    global_padding_ = request_.HasGlobalPadding();
    
    // 初始化 masking
    if (request_.HasChunkMasking()) {
        read_mask_ = std::make_unique<ShakeMask>(request_.body_iv.data());
        write_mask_ = std::make_unique<ShakeMask>(response_iv_.data());
    }
}

VMessServerStream::~VMessServerStream() = default;

memory::ByteVector VMessServerStream::GenerateResponseHeader() {
    if (response_sent_) {
        return {};
    }
    response_sent_ = true;
    
    // 响应头：[response_header][option][command][command_len]
    uint8_t resp_data[4] = {
        request_.response_header,
        request_.options,
        0,  // command
        0   // command_len
    };
    
    // 加密响应头长度
    uint8_t len_data[2] = {0, 4};  // 长度 = 4
    
    const std::array<std::string_view, 1> resp_len_key_path{
        KDFSalt::AEAD_RESP_HEADER_LEN_KEY
    };
    auto len_key = KDF16(response_key_.data(), 16, resp_len_key_path);
    std::array<uint8_t, 12> len_iv;
    const std::array<std::string_view, 1> resp_len_iv_path{
        KDFSalt::AEAD_RESP_HEADER_LEN_IV
    };
    KDF(response_iv_.data(), 16, resp_len_iv_path, len_iv.data(), 12);
    
    auto len_enc = AES128GCMEncrypt(len_key.data(), len_iv.data(), 12,
                                     len_data, 2, nullptr, 0);
    
    // 加密响应头内容
    const std::array<std::string_view, 1> resp_header_key_path{
        KDFSalt::AEAD_RESP_HEADER_PAYLOAD_KEY
    };
    auto header_key = KDF16(response_key_.data(), 16, resp_header_key_path);
    std::array<uint8_t, 12> header_iv;
    const std::array<std::string_view, 1> resp_header_iv_path{
        KDFSalt::AEAD_RESP_HEADER_PAYLOAD_IV
    };
    KDF(response_iv_.data(), 16, resp_header_iv_path, header_iv.data(), 12);
    
    auto header_enc = AES128GCMEncrypt(header_key.data(), header_iv.data(), 12,
                                        resp_data, 4, nullptr, 0);
    
    if (len_enc.size() != 18 || header_enc.size() != 20) {
        return {};
    }

    // 组合
    memory::ByteVector result(38);
    std::memcpy(result.data(), len_enc.data(), len_enc.size());
    std::memcpy(result.data() + len_enc.size(), header_enc.data(), header_enc.size());
    
    return result;
}

std::optional<memory::ByteVector> VMessServerStream::DecryptChunk(
    const uint8_t* data, size_t len, size_t& consumed) {
    
    consumed = 0;
    
    if (request_.security == Security::NONE || request_.security == Security::ZERO) {
        consumed = len;
        return memory::ByteVector(data, data + len);
    }
    
    // AEAD chunk 格式: [2 bytes length] + [encrypted data + 16 bytes tag]
    if (len < 2) return std::nullopt;
    
    // 读取长度
    uint16_t chunk_len = (static_cast<uint16_t>(data[0]) << 8) | data[1];
    
    // 应用 masking
    if (read_mask_) {
        chunk_len ^= read_mask_->NextMask();
    }
    
    // 安全加固：chunk 大小限制 (16KB 最大)
    if (chunk_len > MAX_CHUNK_SIZE) {
        LOG_ACCESS_WARN("VMess: suspicious large chunk size: {}", chunk_len);
        return std::nullopt;
    }
    
    // 检查数据是否足够
    size_t expected_len = 2 + chunk_len + GCM_TAG_SIZE;
    if (len < expected_len) {
        return std::nullopt;  // 数据不足
    }
    
    // 解密
    memory::ByteVector plaintext(chunk_len);
    ssize_t decrypted_len = read_cipher_->Decrypt(data + 2, chunk_len + GCM_TAG_SIZE,
                                                   plaintext.data());
    
    if (decrypted_len < 0) {
        return std::nullopt;
    }
    
    plaintext.resize(decrypted_len);
    consumed = expected_len;
    
    return plaintext;
}

memory::ByteVector VMessServerStream::EncryptChunk(const uint8_t* data, size_t len) {
    if (request_.security == Security::NONE || request_.security == Security::ZERO) {
        memory::ByteVector result(2 + len);
        result[0] = (len >> 8) & 0xFF;
        result[1] = len & 0xFF;
        memcpy(result.data() + 2, data, len);
        return result;
    }
    
    // 加密数据
    memory::ByteVector ciphertext(len + GCM_TAG_SIZE);
    ssize_t encrypted_len = write_cipher_->Encrypt(data, len, ciphertext.data());
    
    if (encrypted_len < 0) {
        return {};
    }
    
    // 添加长度前缀
    uint16_t chunk_len = static_cast<uint16_t>(len);
    
    // 应用 masking
    if (write_mask_) {
        chunk_len ^= write_mask_->NextMask();
    }
    
    memory::ByteVector result(2 + static_cast<size_t>(encrypted_len));
    result[0] = static_cast<uint8_t>((chunk_len >> 8) & 0xFF);
    result[1] = static_cast<uint8_t>(chunk_len & 0xFF);
    std::memcpy(result.data() + 2, ciphertext.data(), static_cast<size_t>(encrypted_len));
    
    return result;
}

}  // namespace vmess
}  // namespace acpp
