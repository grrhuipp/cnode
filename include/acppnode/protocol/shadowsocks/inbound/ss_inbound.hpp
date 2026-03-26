#pragma once

#include "acppnode/handlers/inbound_handler.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/protocol/shadowsocks/shadowsocks_protocol.hpp"
#include "acppnode/transport/delegating_stream.hpp"

#include <array>
#include <atomic>
#include <memory>

namespace acpp {

// ============================================================================
// SsInboundHandler
//
// 职责：解析 SS AEAD 握手头（salt + 首 chunk），完成多用户匹配 + 地址解析。
// 传输层（TLS/WS）由 SessionHandler 处理，与本类无关。
// ============================================================================
class SsInboundHandler final : public InboundHandlerBase {
public:
    SsInboundHandler(ss::SsUserManager& user_manager,
                     StatsShard& stats,
                     ConnectionLimiterPtr limiter,
                     std::string cipher_method);

    // 解析首包：读 salt + 首 chunk，尝试所有用户密钥，解析 SOCKS5 地址
    cobalt::task<std::expected<ParsedAction, ErrorCode>> ParseStream(
        AsyncStream& stream, SessionContext& ctx) override;

    // 用读子密钥状态 + master_key 包装成 SsServerAsyncStream
    cobalt::task<InboundWrapResult> WrapStream(
        std::unique_ptr<AsyncStream> stream, SessionContext& ctx) override;

private:
    ss::SsUserManager&  user_manager_;
    std::string         cipher_method_;
    ss::SsCipherInfo    cipher_info_;
    // 上次匹配成功的用户索引，用于优先尝试（大概率命中同一活跃用户）
    mutable std::atomic<size_t> last_matched_index_{0};
};

// ============================================================================
// SsServerAsyncStream — SS AEAD 服务端双向加密流
//
// 读（客户端 → 服务器）：用 read_cipher_ 解密
// 写（服务器 → 客户端）：按需生成 server salt，派生 write_cipher_ 加密
//
// 继承自 DelegatingAsyncStream，只覆写 AsyncRead/AsyncWrite。
// ============================================================================
class SsServerAsyncStream final : public DelegatingAsyncStream {
public:
    SsServerAsyncStream(std::unique_ptr<AsyncStream> inner,
                        ss::SsCipherType cipher_type,
                        size_t key_size,
                        size_t salt_size,
                        std::span<const uint8_t> master_key,
                        std::span<const uint8_t> read_subkey,
                        uint64_t read_nonce);

    ~SsServerAsyncStream() noexcept override = default;

    SsServerAsyncStream(const SsServerAsyncStream&)            = delete;
    SsServerAsyncStream& operator=(const SsServerAsyncStream&) = delete;

    cobalt::task<size_t> AsyncRead(net::mutable_buffer buf) override;
    cobalt::task<size_t> AsyncWrite(net::const_buffer buf) override;

    // 批量写入：将多个 Buffer 加密后合并为单次 inner_ 写入，
    // 将每个 chunk 的 2 次 WriteFull（长度+payload）× N 降为 1 次
    cobalt::task<void> WriteMultiBuffer(MultiBuffer mb) override;

private:
    static constexpr size_t kLenHeaderSize = 2 + ss::SsAeadCipher::kTagSize;  // 18
    static constexpr size_t kEncryptedChunkSize =
        ss::kMaxChunkPayload + ss::SsAeadCipher::kTagSize;

    // 从 inner_ 读满 len 字节到 buf
    cobalt::task<bool> ReadFull(uint8_t* buf, size_t len);
    // 向 inner_ 写完 len 字节
    cobalt::task<bool> WriteFull(const uint8_t* buf, size_t len);
    // 解密下一个 SS chunk，追加到 read_buf_
    cobalt::task<bool> ReadNextChunk();
    // 初始化写端（生成 server salt，派生写子密钥，发送 salt）
    cobalt::task<bool> InitWriteCipher();

    // ── 读端 ────────────────────────────────────────────────────────────────
    ss::SsAeadCipher        read_cipher_;
    uint64_t                read_nonce_ = 0;
    memory::ByteVector      read_buf_;      // 已解密但未消耗的数据
    size_t                  read_buf_offset_ = 0;
    std::array<uint8_t, kEncryptedChunkSize> read_chunk_buf_{};

    // ── 写端 ────────────────────────────────────────────────────────────────
    ss::SsCipherType         cipher_type_;
    size_t                   key_size_;
    size_t                   salt_size_;
    memory::ByteVector       master_key_;
    std::unique_ptr<ss::SsAeadCipher> write_cipher_;   // 懒初始化
    uint64_t                 write_nonce_ = 0;
    bool                     write_init_  = false;
    // 前 kLenHeaderSize 字节用于 enc_len，后续用于加密载荷，支持单次 WriteFull
    std::array<uint8_t, kLenHeaderSize + kEncryptedChunkSize> write_chunk_buf_{};

    // WriteMultiBuffer 批量输出缓冲（持久化避免反复分配）
    memory::ByteVector write_batch_buf_;
};

// ============================================================================
// 工厂函数
// ============================================================================
[[nodiscard]] std::unique_ptr<IInboundHandler> CreateSsInboundHandler(
    ss::SsUserManager& user_manager,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    std::string cipher_method);

}  // namespace acpp
