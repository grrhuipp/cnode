#pragma once

#include "acppnode/protocol/vmess/vmess_cipher.hpp"
#include "acppnode/transport/delegating_stream.hpp"
#include "acppnode/infra/log.hpp"

#include <memory>
#include <vector>

namespace acpp {
namespace vmess {

// VMess 服务端加密流
// 继承自 DelegatingAsyncStream，只覆写 AsyncRead/AsyncWrite 实现 AEAD 帧协议，
// 以及 AsyncShutdownWrite 发送 VMess EOF marker。其余操作全部转发给 inner_。
class VMessServerAsyncStream final : public DelegatingAsyncStream {
public:
    // 支持 move 语义，避免 pending_data 复制
    VMessServerAsyncStream(std::unique_ptr<AsyncStream> inner,
                           VMessRequest&& request);

    ~VMessServerAsyncStream() override = default;

    cobalt::task<size_t> AsyncRead(net::mutable_buffer buffer) override;
    cobalt::task<size_t> AsyncWrite(net::const_buffer buffer) override;

    // 批量写入：将多个 Buffer 加密后合并为单次 inner_ 写入，
    // 将 relay 热路径的 N 次 syscall 降为 1 次
    cobalt::task<void> WriteMultiBuffer(MultiBuffer mb) override;

    // 发送 VMess EOF marker，然后不关闭底层 socket（半关闭语义）
    cobalt::task<void> AsyncShutdownWrite() override;

    // 发送响应头（必须在第一次写数据前调用）
    cobalt::task<bool> SendResponseHeader();

private:
    void EnsureReadBuffers();
    void EnsureWriteBuffers();

    // 零拷贝版本：直接读取到指定 buffer
    // 返回: >0 实际读取字节数, 0 EOF, -1 错误
    cobalt::task<ssize_t> ReadChunkInto(uint8_t* buf, size_t max_len);

    // 写入一个 VMess 数据块
    cobalt::task<bool> WriteChunk(const uint8_t* data, size_t len);

    // 发送 EOF marker
    cobalt::task<bool> SendEOFMarker();

    // 读取指定长度的数据
    cobalt::task<bool> ReadFull(uint8_t* buf, size_t len);

    // 写入数据
    cobalt::task<bool> WriteFull(const uint8_t* buf, size_t len);

private:
    // 请求信息
    VMessRequest request_;
    Security security_;
    uint8_t option_;
    
    // 密钥
    std::array<uint8_t, 16> request_key_;
    std::array<uint8_t, 16> request_iv_;
    std::array<uint8_t, 16> response_key_;
    std::array<uint8_t, 16> response_iv_;
    
    // 加密器
    std::unique_ptr<VMessCipher> read_cipher_;
    std::unique_ptr<VMessCipher> write_cipher_;
    
    // Mask 生成器
    std::unique_ptr<ShakeMask> read_mask_;
    std::unique_ptr<ShakeMask> write_mask_;
    
    // 状态
    bool response_header_sent_ = false;
    bool read_eof_ = false;
    bool write_eof_sent_ = false;
    bool global_padding_ = false;
    
    // 读缓冲区（用于暂存未消费的解密数据）
    std::vector<uint8_t> read_buffer_;
    size_t read_buffer_offset_ = 0;
    
    // ========================================================================
    // 读写独立缓冲区
    //
    // relay 中读和写通过 cobalt::gather 并发执行，协程在 co_await 处交替，
    // 读写方向会同时访问缓冲区，因此必须使用独立缓冲区。
    // ========================================================================
    static constexpr size_t BUF_SIZE = MAX_CHUNK_SIZE + 128;
    std::vector<uint8_t> read_crypto_buf_;       // 读方向：按需分配，避免每连接预留 2*16KB
    std::vector<uint8_t> read_spare_buf_;        // 读方向：fallback 解密目标
    std::vector<uint8_t> write_crypto_buf_;      // 写方向：Encrypt 输出
    std::vector<uint8_t> write_output_buf_;      // 写方向：[header + encrypted + padding]
    
    uint32_t read_chunk_count_ = 0;
    uint32_t write_chunk_count_ = 0;
    
    // WriteMultiBuffer 批量输出缓冲（持久化避免反复分配，典型 ~66KB）
    std::vector<uint8_t> write_batch_buf_;

    // 预读数据缓冲区（握手时读取的多余数据）
    std::vector<uint8_t> pending_data_;
    size_t pending_offset_ = 0;
};

}  // namespace vmess
}  // namespace acpp
