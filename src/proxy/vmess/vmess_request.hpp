#pragma once

// ============================================================================
// vmess_request.hpp — VMess 协议常量、枚举与请求结构体
//
// 职责：定义 VMess 协议帧格式所需的全部协议级类型。
// 不包含加密实现、用户管理或解析逻辑。
// ============================================================================

#include "acppnode/common.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "types.hpp"
#include <array>
#include <cstdint>
#include <memory>

namespace acpp {
namespace vmess {

// ============================================================================
// 协议常量
// ============================================================================

constexpr uint8_t VERSION           = 1;
constexpr size_t  GCM_TAG_SIZE      = 16;
constexpr size_t  GCM_NONCE_SIZE    = 12;
constexpr size_t  MAX_CHUNK_SIZE    = 16 * 1024;  // 16KB
constexpr int64_t TIMESTAMP_TOLERANCE = 60;        // ±60秒，防重放攻击

// ============================================================================
// 枚举：命令类型
// ============================================================================

enum class Command : uint8_t {
    TCP = 1,
    UDP = 2,
    Mux = 3,  // XUDP/Mux 模式，每个包有地址头
    MUX = 3   // 别名
};

// ============================================================================
// 枚举：地址类型
// ============================================================================

enum class AddressType : uint8_t {
    IPv4   = 1,
    Domain = 2
};

// ============================================================================
// 选项标志（Option 字节的位掩码）
// ============================================================================

namespace Option {
    constexpr uint8_t CHUNK_STREAM        = 0x01;
    constexpr uint8_t CONNECTION_REUSE    = 0x02;
    constexpr uint8_t CHUNK_MASKING       = 0x04;
    constexpr uint8_t GLOBAL_PADDING      = 0x08;
    constexpr uint8_t AUTHENTICATED_LENGTH = 0x10;
}

// ============================================================================
// KDF Salt 常量（用于 AEAD 密钥派生路径）
// ============================================================================

namespace KDFSalt {
    constexpr const char* AUTH_ID_ENCRYPTION_KEY        = "AES Auth ID Encryption";
    // 响应头
    constexpr const char* AEAD_RESP_HEADER_LEN_KEY      = "AEAD Resp Header Len Key";
    constexpr const char* AEAD_RESP_HEADER_LEN_IV       = "AEAD Resp Header Len IV";
    constexpr const char* AEAD_RESP_HEADER_PAYLOAD_KEY  = "AEAD Resp Header Key";
    constexpr const char* AEAD_RESP_HEADER_PAYLOAD_IV   = "AEAD Resp Header IV";
    // 请求头（客户端使用）
    constexpr const char* VMESS_AEAD_KDF                        = "VMess AEAD KDF";
    constexpr const char* VMESS_HEADER_PAYLOAD_AEAD_KEY         = "VMess Header AEAD Key";
    constexpr const char* VMESS_HEADER_PAYLOAD_AEAD_IV          = "VMess Header AEAD Nonce";
    constexpr const char* VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY  = "VMess Header AEAD Key_Length";
    constexpr const char* VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV   = "VMess Header AEAD Nonce_Length";
}

// ============================================================================
// 握手失败原因
// ============================================================================

enum class VMessHandshakeFailReason {
    NONE,              // 无错误
    TIMEOUT,           // 超时
    CONNECTION_CLOSED, // 连接关闭
    IP_BLOCKED,        // IP 被屏蔽
    AUTH_FAILED,       // 认证失败
    UNKNOWN_ERROR,     // 未知错误
};

// ============================================================================
// VMess 请求头（Process 解析后填充，VMess Link 读取）
// ============================================================================

struct VMessRequest {
    VMessRequest() = default;
    ~VMessRequest() noexcept = default;

    VMessRequest(const VMessRequest& other)
        : version(other.version)
        , body_iv(other.body_iv)
        , body_key(other.body_key)
        , response_header(other.response_header)
        , options(other.options)
        , padding_len(other.padding_len)
        , security(other.security)
        , command(other.command)
        , target(other.target)
        , user_ref(other.user_ref)
        , user(user_ref ? user_ref.get() : other.user) {
        if (other.HasPendingData()) {
            SetPendingData(other.PendingDataSpan());
        }
    }

    VMessRequest& operator=(const VMessRequest& other) {
        if (this == &other) {
            return *this;
        }
        version = other.version;
        body_iv = other.body_iv;
        body_key = other.body_key;
        response_header = other.response_header;
        options = other.options;
        padding_len = other.padding_len;
        security = other.security;
        command = other.command;
        target = other.target;
        user_ref = other.user_ref;
        user = user_ref ? user_ref.get() : other.user;
        if (other.HasPendingData()) {
            SetPendingData(other.PendingDataSpan());
        } else {
            ClearPendingData();
        }
        return *this;
    }

    VMessRequest(VMessRequest&& other) noexcept
        : version(other.version)
        , body_iv(other.body_iv)
        , body_key(other.body_key)
        , response_header(other.response_header)
        , options(other.options)
        , padding_len(other.padding_len)
        , security(other.security)
        , command(other.command)
        , target(std::move(other.target))
        , user_ref(std::move(other.user_ref))
        , user(user_ref ? user_ref.get() : other.user)
        , pending_buffer_(std::move(other.pending_buffer_))
        , pending_offset_(other.pending_offset_)
        , pending_size_(other.pending_size_) {
        other.pending_offset_ = 0;
        other.pending_size_ = 0;
        other.user = nullptr;
    }

    VMessRequest& operator=(VMessRequest&& other) noexcept {
        if (this == &other) {
            return *this;
        }
        version = other.version;
        body_iv = other.body_iv;
        body_key = other.body_key;
        response_header = other.response_header;
        options = other.options;
        padding_len = other.padding_len;
        security = other.security;
        command = other.command;
        target = std::move(other.target);
        user_ref = std::move(other.user_ref);
        user = user_ref ? user_ref.get() : other.user;
        pending_buffer_ = std::move(other.pending_buffer_);
        pending_offset_ = other.pending_offset_;
        pending_size_ = other.pending_size_;
        other.pending_offset_ = 0;
        other.pending_size_ = 0;
        other.user = nullptr;
        return *this;
    }

    uint8_t version = VERSION;
    std::array<uint8_t, 16> body_iv;
    std::array<uint8_t, 16> body_key;
    uint8_t response_header = 0;
    uint8_t options         = 0;
    uint8_t padding_len     = 0;
    Security security       = Security::AES_128_GCM;
    Command  command        = Command::TCP;
    TargetAddress target;

    std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential> user_ref;
    const proxyman::inbound::UserStore::VmessCredential* user = nullptr;

    void SetUser(
        std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential> account) noexcept {
        user_ref = std::move(account);
        user = user_ref.get();
    }

    [[nodiscard]] bool HasPendingData() const noexcept {
        return pending_buffer_ && pending_size_ > 0;
    }

    [[nodiscard]] size_t PendingDataSize() const noexcept {
        return HasPendingData() ? pending_size_ : 0;
    }

    [[nodiscard]] std::span<const uint8_t> PendingDataSpan() const noexcept {
        if (!HasPendingData()) {
            return {};
        }
        return {pending_buffer_->data + pending_offset_, pending_size_};
    }

    void SetPendingData(std::span<const uint8_t> data) {
        if (data.empty()) {
            ClearPendingData();
            return;
        }
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            throw std::bad_alloc();
        }
        const size_t len = std::min(data.size(), static_cast<size_t>(buffer->Available()));
        std::memcpy(buffer->Tail().data(), data.data(), len);
        buffer->Produce(static_cast<uint32_t>(len));
        pending_buffer_ = std::move(buffer);
        pending_offset_ = 0;
        pending_size_ = len;
    }

    void SetPendingBuffer(buf::BufferGuard buffer, size_t offset, size_t size) noexcept {
        if (!buffer || size == 0) {
            ClearPendingData();
            return;
        }
        const size_t clamped_offset = std::min(offset, static_cast<size_t>(buffer->end));
        const size_t available = static_cast<size_t>(buffer->end) - clamped_offset;
        pending_buffer_ = std::move(buffer);
        pending_offset_ = clamped_offset;
        pending_size_ = std::min(size, available);
        if (pending_size_ == 0) {
            ClearPendingData();
        }
    }

    void ConsumePendingData(size_t bytes) noexcept {
        if (!HasPendingData()) {
            return;
        }
        const size_t consumed = std::min(bytes, pending_size_);
        pending_offset_ += consumed;
        pending_size_ -= consumed;
        if (pending_size_ == 0) {
            ClearPendingData();
        }
    }

    void ClearPendingData() noexcept {
        pending_buffer_ = buf::BufferGuard{};
        pending_offset_ = 0;
        pending_size_ = 0;
    }

    bool HasChunkMasking()       const { return (options & Option::CHUNK_MASKING)       != 0; }
    bool HasAuthenticatedLength() const { return (options & Option::AUTHENTICATED_LENGTH) != 0; }
    bool HasGlobalPadding()      const { return (options & Option::GLOBAL_PADDING)       != 0; }

private:
    // 握手后的预读数据（加密的数据块），从握手 Buffer 转移所有权。
    buf::BufferGuard pending_buffer_;
    size_t pending_offset_ = 0;
    size_t pending_size_ = 0;
};

}  // namespace vmess
}  // namespace acpp
