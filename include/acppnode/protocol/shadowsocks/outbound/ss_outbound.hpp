#pragma once

#include "acppnode/protocol/outbound.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/handlers/outbound_handler.hpp"
#include "acppnode/protocol/shadowsocks/shadowsocks_protocol.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace acpp {

class IDnsService;

// ============================================================================
// SS Outbound 配置
// ============================================================================
struct SsOutboundConfig {
    std::string            tag;
    std::string            address;
    uint16_t               port    = 8388;
    std::string            password;
    std::string            method  = std::string(constants::protocol::kAes256Gcm);
    StreamSettings         stream_settings;
    std::chrono::seconds   timeout{10};
};

// ============================================================================
// SsClientAsyncStream — SS AEAD 客户端双向加密流
//
// 写（客户端 → 服务器）：首次写时生成 client salt，发送握手头（salt + 地址 chunk）
// 读（服务器 → 客户端）：首次读时接收 server salt，派生读子密钥
// ============================================================================
class SsClientAsyncStream final : public AsyncStream {
public:
    SsClientAsyncStream(std::unique_ptr<AsyncStream> inner,
                        ss::SsCipherType cipher_type,
                        size_t key_size,
                        size_t salt_size,
                        std::span<const uint8_t> master_key,
                        TargetAddress target);

    ~SsClientAsyncStream() noexcept override = default;

    SsClientAsyncStream(const SsClientAsyncStream&)            = delete;
    SsClientAsyncStream& operator=(const SsClientAsyncStream&) = delete;

    cobalt::task<MultiBuffer> ReadMultiBuffer() override;
    cobalt::task<void> WriteMultiBuffer(MultiBuffer mb) override;
    cobalt::task<size_t> AsyncRead(net::mutable_buffer buf) override;
    cobalt::task<size_t> AsyncWrite(net::const_buffer buf) override;

    void ShutdownRead() override  { inner_->ShutdownRead(); }
    void ShutdownWrite() override { inner_->ShutdownWrite(); }
    cobalt::task<void> AsyncShutdownWrite() override {
        co_await inner_->AsyncShutdownWrite();
    }
    void Close() override  { inner_->Close(); }
    void Cancel() noexcept override { inner_->Cancel(); }

    [[nodiscard]] int NativeHandle() const override { return inner_->NativeHandle(); }
    [[nodiscard]] net::any_io_executor GetExecutor() const override {
        return inner_->GetExecutor();
    }
    [[nodiscard]] bool IsOpen() const override { return inner_->IsOpen(); }

    TcpStream* GetBaseTcpStream() override { return inner_->GetBaseTcpStream(); }
    const TcpStream* GetBaseTcpStream() const override { return inner_->GetBaseTcpStream(); }

private:
    cobalt::task<bool> EnsureReadCipherInitialized();

    // enc_len header (2 + kTagSize) + 加密载荷 (payload + kTagSize)
    static constexpr size_t kLenHeaderSize = 2 + ss::SsAeadCipher::kTagSize;  // 18
    static constexpr size_t kEncryptedChunkSize =
        ss::kMaxChunkPayload + ss::SsAeadCipher::kTagSize;

    cobalt::task<bool> ReadFull(uint8_t* buf, size_t len);
    cobalt::task<bool> WriteFull(const uint8_t* buf, size_t len);
    cobalt::task<bool> ReadNextChunk();
    cobalt::task<bool> SendHandshake(const MultiBuffer& mb, size_t& consumed_prefix);
    // 首次写：发送 [client_salt][enc_len][len_tag][enc_addr_payload][payload_tag]
    cobalt::task<bool> SendHandshake(const uint8_t* data, size_t data_len);
    // 普通 chunk 写入（握手后）
    cobalt::task<bool> WriteChunk(const uint8_t* data, size_t data_len);

    std::unique_ptr<AsyncStream> inner_;
    TargetAddress                target_;

    // ── 写端 ────────────────────────────────────────────────────────────────
    ss::SsCipherType         cipher_type_;
    size_t                   key_size_;
    size_t                   salt_size_;
    memory::ByteVector       master_key_;
    std::unique_ptr<ss::SsAeadCipher> write_cipher_;
    uint64_t                 write_nonce_    = 0;
    bool                     handshake_sent_ = false;
    // 前 kLenHeaderSize 字节用于 enc_len，后续用于加密载荷，支持单次 WriteFull
    std::array<uint8_t, kLenHeaderSize + kEncryptedChunkSize> write_chunk_buf_{};

    // ── 读端 ────────────────────────────────────────────────────────────────
    std::unique_ptr<ss::SsAeadCipher> read_cipher_;
    uint64_t                 read_nonce_     = 0;
    bool                     read_init_      = false;
    memory::ByteVector       read_buf_;
    size_t                   read_buf_offset_ = 0;
    std::array<uint8_t, kEncryptedChunkSize> read_chunk_buf_{};
};

// ============================================================================
// SsOutboundHandler — 协议层握手（WrapStream 返回 SsClientAsyncStream）
// ============================================================================
class SsOutboundHandler final : public IOutboundHandler {
public:
    SsOutboundHandler(ss::SsCipherType cipher_type,
                      size_t key_size,
                      size_t salt_size,
                      std::span<const uint8_t> master_key);

    // Handshake: noop（握手在 WrapStream 内 SsClientAsyncStream 首次写完成）
    cobalt::task<OutboundHandshakeResult> Handshake(
        AsyncStream& stream,
        const SessionContext& ctx,
        std::span<const uint8_t> initial_payload) override {
        (void)stream; (void)ctx; (void)initial_payload;
        co_return {};
    }

    // WrapStream: 返回 SsClientAsyncStream
    cobalt::task<OutboundWrapResult> WrapStream(
        std::unique_ptr<AsyncStream> stream,
        const SessionContext& ctx) override;

private:
    ss::SsCipherType     cipher_type_;
    size_t               key_size_;
    size_t               salt_size_;
    memory::ByteVector master_key_;
};

// ============================================================================
// SsOutbound — 出站实现（只负责传输层：TCP）
// ============================================================================
class SsOutbound final : public IOutbound {
public:
    SsOutbound(net::any_io_executor executor,
               const SsOutboundConfig& config,
               IDnsService* dns_service);

    ~SsOutbound() noexcept override = default;

    cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
        ResolveTransportTarget(SessionContext& ctx) override;

    [[nodiscard]] std::string Tag() const override { return config_.tag; }
    [[nodiscard]] IOutboundHandler* GetOutboundHandler() override {
        return handler_.get();
    }

private:
    SsOutboundConfig                config_;
    IDnsService*                    dns_service_;
    ss::SsCipherInfo                cipher_info_;
    memory::ByteVector              master_key_;
    StreamSettings                  stream_settings_;
    std::unique_ptr<SsOutboundHandler> handler_;
};

// ============================================================================
// 工厂函数
// ============================================================================
[[nodiscard]] std::unique_ptr<IOutbound> CreateSsOutbound(
    net::any_io_executor executor,
    const SsOutboundConfig& config,
    IDnsService* dns_service);

}  // namespace acpp
