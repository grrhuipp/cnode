#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/protocol/outbound.hpp"
#include "acppnode/protocol/vmess/vmess_protocol.hpp"
#include "acppnode/dns/dns_service.hpp"
#include "acppnode/handlers/outbound_handler.hpp"

namespace acpp {

// ============================================================================
// VMess Outbound 配置
// ============================================================================
struct VMessOutboundConfig {
    std::string tag;
    std::string address;           // 服务器地址
    uint16_t port = 443;           // 服务器端口
    std::string uuid;              // 用户 UUID
    vmess::Security security = vmess::Security::AES_128_GCM;
    
    // 可选配置
    int alter_id = 0;              // AlterID (现代客户端通常为 0)
    
    // 传输层配置（JSON 格式保持不变）
    StreamSettings stream_settings;

    // 传输层拨号/握手超时
    std::chrono::seconds timeout{defaults::kDialTimeout};
};

// ============================================================================
// VMess Outbound 协议处理器（三层架构协议层）
//
// Handshake = noop（握手写入在 WrapStream 中完成）
// WrapStream = 创建 VMessClientAsyncStream 并发送 AEAD 请求头
// ============================================================================
class VMessOutboundHandler final : public IOutboundHandler {
public:
    VMessOutboundHandler(const vmess::VMessUser& user, vmess::Security security)
        : user_(user), security_(security) {}

    cobalt::task<OutboundHandshakeResult> Handshake(
        AsyncStream& stream,
        const SessionContext& ctx,
        std::span<const uint8_t> initial_payload) override {
        (void)stream;
        (void)ctx;
        (void)initial_payload;
        co_return {};  // VMess 握手在 WrapStream 中完成
    }

    cobalt::task<OutboundWrapResult> WrapStream(
        std::unique_ptr<AsyncStream> stream,
        const SessionContext& ctx) override;

private:
    vmess::VMessUser user_;
    vmess::Security security_;
};

// ============================================================================
// VMess Outbound（传输层：TCP + 可选 WS）
// ============================================================================
class VMessOutbound final : public IOutbound {
public:
    VMessOutbound(net::any_io_executor executor,
                  const VMessOutboundConfig& config,
                  IDnsService* dns_service = nullptr);

    // IOutbound 接口
    // 仅返回传输目标，由 TransportDialer 统一执行 TCP/TLS/WS 构建
    cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
        ResolveTransportTarget(SessionContext& ctx) override;
    std::string Tag() const override { return config_.tag; }
    IOutboundHandler* GetOutboundHandler() override { return handler_.get(); }

private:
    VMessOutboundConfig config_;
    std::optional<vmess::VMessUser> user_;
    IDnsService* dns_service_ = nullptr;
    std::unique_ptr<VMessOutboundHandler> handler_;
};

// ============================================================================
// VMess Client Stream (客户端加密流)
// ============================================================================
namespace vmess {

class VMessClientAsyncStream final : public AsyncStream {
public:
    VMessClientAsyncStream(std::unique_ptr<AsyncStream> inner,
                           const VMessUser& user,
                           const TargetAddress& target,
                           Security security,
                           uint64_t conn_id);
    
    ~VMessClientAsyncStream() override = default;
    
    // AsyncStream 接口
    cobalt::task<MultiBuffer> ReadMultiBuffer() override { return AsyncStream::ReadMultiBuffer(); }
    cobalt::task<size_t> AsyncRead(net::mutable_buffer buffer) override;
    cobalt::task<size_t> AsyncWrite(net::const_buffer buffer) override;
    cobalt::task<void> WriteMultiBuffer(MultiBuffer mb) override;
    void Close() override { inner_->Close(); }
    void ShutdownWrite() override;
    cobalt::task<void> AsyncShutdownWrite() override;
    void Cancel() noexcept override;
    int NativeHandle() const override { return inner_->NativeHandle(); }
    net::any_io_executor GetExecutor() const override { return inner_->GetExecutor(); }
    bool IsOpen() const override { return inner_->IsOpen() && !read_eof_; }

    TcpStream* GetBaseTcpStream() override { return inner_->GetBaseTcpStream(); }
    const TcpStream* GetBaseTcpStream() const override { return inner_->GetBaseTcpStream(); }
    
    // 发送握手（在第一次写入前调用）
    cobalt::task<OutboundHandshakeResult> SendHandshake();

private:
    static constexpr size_t MAX_CHUNK_SIZE = 16 * 1024;
    
    cobalt::task<bool> ReadFull(uint8_t* buf, size_t len);
    cobalt::task<bool> WriteFull(const uint8_t* buf, size_t len);
    cobalt::task<bool> ReadResponseHeader();
    
    // 零拷贝版本：直接读入调用者 buffer
    // 返回: >0 读取字节数, 0 EOF, -1 错误
    cobalt::task<ssize_t> ReadChunkInto(uint8_t* buf, size_t max_len);
    
    cobalt::task<bool> WriteChunk(const uint8_t* data, size_t len);
    
    std::unique_ptr<AsyncStream> inner_;
    VMessUser user_;  // 复制而非引用
    TargetAddress target_;
    Security security_;

    // 握手状态
    bool handshake_sent_ = false;
    bool response_received_ = false;
    bool write_eof_sent_ = false;
    
    // 密钥
    std::array<uint8_t, 16> body_key_;     // 原始 body key (用于握手)
    std::array<uint8_t, 16> body_iv_;      // 原始 body iv (用于握手和 write_mask)
    std::array<uint8_t, 16> request_key_;
    std::array<uint8_t, 16> request_iv_;
    std::array<uint8_t, 16> response_key_;
    std::array<uint8_t, 16> response_iv_;
    uint8_t response_header_ = 0;
    uint8_t options_ = 0;
    
    // 加密器
    std::unique_ptr<VMessCipher> read_cipher_;   // 读用 response 密钥
    std::unique_ptr<VMessCipher> write_cipher_;  // 写用 request 密钥
    
    // Mask
    std::unique_ptr<ShakeMask> read_mask_;
    std::unique_ptr<ShakeMask> write_mask_;
    bool global_padding_ = false;
    
    // ========================================================================
    // 内存优化：固定缓冲区 + 环形读缓冲
    // 
    // 原设计：
    //   - ReadChunk() 返回 std::vector（每次分配）
    //   - read_buffer_ 使用 std::deque（频繁分配 chunk）
    //
    // 优化后：
    //   - 固定 18KB 缓冲区用于加密/解密
    //   - 环形缓冲区存储未消费数据
    //   - 写输出使用独立缓冲区，避免读写冲突
    // ========================================================================
    static constexpr size_t CRYPTO_BUF_SIZE = MAX_CHUNK_SIZE + 128;
    alignas(64) uint8_t crypto_buf_[CRYPTO_BUF_SIZE];       // 读解密缓冲
    alignas(64) uint8_t write_output_buf_[CRYPTO_BUF_SIZE]; // 写输出缓冲
    
    // 读缓冲（简化版环形缓冲）
    memory::ByteVector read_buffer_;
    size_t read_buffer_offset_ = 0;
    bool read_eof_ = false;
};

}  // namespace vmess

// 创建 VMess 出站
std::unique_ptr<IOutbound> CreateVMessOutbound(
    net::any_io_executor executor,
    const VMessOutboundConfig& config,
    IDnsService* dns_service = nullptr);

}  // namespace acpp
