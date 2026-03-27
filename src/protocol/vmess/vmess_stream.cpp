#include "acppnode/protocol/vmess/vmess_stream.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/infra/log.hpp"
#include <openssl/rand.h>

namespace acpp {
namespace vmess {

namespace {
constexpr size_t kStreamFlushBufferCount = 8;
constexpr size_t kStreamFlushBytes = Buffer::kSize * kStreamFlushBufferCount;

[[noreturn]] void ThrowVMessWriteError(const char* what) {
    throw boost::system::system_error(boost::asio::error::connection_reset, what);
}

}  // namespace

void VMessServerAsyncStream::EnsureReadBuffers() {
    if (read_crypto_buf_.size() != BUF_SIZE) {
        read_crypto_buf_.resize(BUF_SIZE);
        read_spare_buf_.resize(BUF_SIZE);
    }
}

void VMessServerAsyncStream::EnsureWriteBuffers() {
    if (write_crypto_buf_.size() != BUF_SIZE) {
        write_crypto_buf_.resize(BUF_SIZE);
        write_output_buf_.resize(BUF_SIZE + 2);
    }
}

VMessServerAsyncStream::VMessServerAsyncStream(
    std::unique_ptr<AsyncStream> inner,
    VMessRequest&& request)
    : DelegatingAsyncStream(std::move(inner))
    , request_(std::move(request))
    , security_(request_.security)
    , option_(request_.options) {

    // AEAD 模式：直接使用 body_key 和 body_iv
    std::memcpy(request_key_.data(), request_.body_key.data(), 16);
    std::memcpy(request_iv_.data(), request_.body_iv.data(), 16);

    // 响应密钥/IV 派生
    // 参考 v2ray-core/proxy/vmess/encoding/server.go:
    //   BodyKey := sha256.Sum256(s.requestBodyKey[:])
    //   copy(s.responseBodyKey[:], BodyKey[:16])
    //   BodyIV := sha256.Sum256(s.requestBodyIV[:])
    //   copy(s.responseBodyIV[:], BodyIV[:16])
    auto resp_key_hash = SHA256Sum(request_key_.data(), 16);
    auto resp_iv_hash = SHA256Sum(request_iv_.data(), 16);

    std::memcpy(response_key_.data(), resp_key_hash.data(), 16);
    std::memcpy(response_iv_.data(), resp_iv_hash.data(), 16);

    // 服务端：读用 request 密钥，写用 response 密钥
    read_cipher_ = std::make_unique<VMessCipher>(security_, request_key_.data(), request_iv_.data());
    write_cipher_ = std::make_unique<VMessCipher>(security_, response_key_.data(), response_iv_.data());

    bool masking = (option_ & Option::CHUNK_MASKING) != 0;
    global_padding_ = (option_ & Option::GLOBAL_PADDING) != 0;

    if (masking) {
        // 参考实现: read_mask 用 body_iv, write_mask 用 response_iv
        read_mask_ = std::make_unique<ShakeMask>(request_iv_.data());
        write_mask_ = std::make_unique<ShakeMask>(response_iv_.data());
    }

    // pending_data 已经被 move 到 request_ 中
    // 直接使用 request_.pending_data（已在成员 request_ 中）
    if (!request_.pending_data.empty()) {
        pending_data_ = std::move(request_.pending_data);
    }
}

cobalt::task<bool> VMessServerAsyncStream::SendResponseHeader() {
    if (response_header_sent_) {
        co_return true;
    }
    // 在第一个 co_await 之前置位，防止 AsyncRead 与 AsyncWrite 并发调度时重复发送
    response_header_sent_ = true;

    LOG_ACCESS_DEBUG("VMess stream: SendResponseHeader start");

    // 构造响应头：[response_header][option][command][command_len]
    uint8_t resp_data[4] = {
        request_.response_header,
        option_,  // 使用请求中的 option
        0,  // command (无命令)
        0   // command_len
    };

    // 加密响应头长度
    std::array<uint8_t, 16> len_key;
    std::array<uint8_t, 12> len_iv;
    const std::array<std::string_view, 1> len_key_path{
        KDFSalt::AEAD_RESP_HEADER_LEN_KEY
    };
    const std::array<std::string_view, 1> len_iv_path{
        KDFSalt::AEAD_RESP_HEADER_LEN_IV
    };
    KDF(response_key_.data(), 16, len_key_path, len_key.data(), 16);
    KDF(response_iv_.data(), 16, len_iv_path, len_iv.data(), 12);

    uint8_t len_plain[2] = {0, 4};  // 响应头长度 = 4 bytes
    uint8_t len_enc[18];  // 2 + 16 tag

    if (!AES128GCMEncrypt(len_key.data(), len_iv.data(), nullptr, 0,
                          len_plain, 2, len_enc, len_enc + 2)) {
        LOG_ACCESS_DEBUG("VMess stream: SendResponseHeader GCM encrypt len failed");
        co_return false;
    }

    // 加密响应头
    std::array<uint8_t, 16> header_key;
    std::array<uint8_t, 12> header_iv;
    const std::array<std::string_view, 1> header_key_path{
        KDFSalt::AEAD_RESP_HEADER_PAYLOAD_KEY
    };
    const std::array<std::string_view, 1> header_iv_path{
        KDFSalt::AEAD_RESP_HEADER_PAYLOAD_IV
    };
    KDF(response_key_.data(), 16, header_key_path, header_key.data(), 16);
    KDF(response_iv_.data(), 16, header_iv_path, header_iv.data(), 12);

    uint8_t header_enc[20];  // 4 + 16 tag
    if (!AES128GCMEncrypt(header_key.data(), header_iv.data(), nullptr, 0,
                          resp_data, 4, header_enc, header_enc + 4)) {
        LOG_ACCESS_DEBUG("VMess stream: SendResponseHeader GCM encrypt header failed");
        co_return false;
    }

    // 合并 len_enc + header_enc 为单次写入，避免 2 个 TCP 包
    uint8_t resp_buf[38];
    std::memcpy(resp_buf, len_enc, 18);
    std::memcpy(resp_buf + 18, header_enc, 20);
    if (!co_await WriteFull(resp_buf, 38)) {
        LOG_ACCESS_DEBUG("VMess stream: SendResponseHeader WriteFull failed");
        co_return false;
    }

    LOG_ACCESS_DEBUG("VMess stream: SendResponseHeader OK (security={}, option={:#04x})",
                     static_cast<int>(security_), static_cast<int>(option_));
    co_return true;
}

cobalt::task<size_t> VMessServerAsyncStream::AsyncRead(net::mutable_buffer buffer) {
    uint8_t* buf = static_cast<uint8_t*>(buffer.data());
    size_t len = buffer.size();

    // 首次读取前先发送响应头，避免与上行读等待形成死锁：
    // 客户端在收到响应头之前不会发送 TLS ClientHello 等上行数据，
    // 而下行方向在收到上行数据之前不会触发 AsyncWrite，导致响应头永远不发出。
    if (!response_header_sent_) {
        LOG_ACCESS_DEBUG("VMess stream: AsyncRead triggering SendResponseHeader");
        if (!co_await SendResponseHeader()) {
            LOG_ACCESS_DEBUG("VMess stream: AsyncRead SendResponseHeader failed");
            ThrowVMessWriteError("VMess stream send response header failed");
        }
    }

    // 先从缓冲区读取剩余数据
    size_t buffered = read_buffer_.size() - read_buffer_offset_;
    if (buffered > 0) {
        size_t copy = std::min(len, buffered);
        std::memcpy(buf, read_buffer_.data() + read_buffer_offset_, copy);
        read_buffer_offset_ += copy;

        // 缓冲区用完，清理
        if (read_buffer_offset_ >= read_buffer_.size()) {
            read_buffer_.clear();
            read_buffer_offset_ = 0;
            ReleaseIdleBuffer(read_buffer_, 8 * 1024);
        }
        co_return copy;
    }

    if (read_eof_) {
        co_return 0;
    }

    ssize_t n = co_await ReadChunkInto(buf, len);
    if (n == 0) {
        // 传输层直接断开和 VMess EOF marker 都按 EOF 处理：
        // 对 relay 来说，用户侧已经离线，应尽快进入 half-close 收口，
        // 而不是把这类场景拖成 connection_reset 再走长超时。
        co_return 0;
    }
    if (n < 0) {
        // 错误（TCP-level close / 解密失败 / 数据损坏）：抛异常让 relay 感知错误
        throw boost::system::system_error(
            boost::asio::error::connection_reset,
            "VMess stream read error");
    }
    co_return static_cast<size_t>(n);
}

cobalt::task<size_t> VMessServerAsyncStream::AsyncWrite(net::const_buffer buffer) {
    if (!response_header_sent_) {
        LOG_ACCESS_DEBUG("VMess stream: AsyncWrite triggering SendResponseHeader");
        if (!co_await SendResponseHeader()) {
            LOG_ACCESS_DEBUG("VMess stream: AsyncWrite SendResponseHeader failed");
            ThrowVMessWriteError("VMess stream send response header failed");
        }
    }

    const uint8_t* data = static_cast<const uint8_t*>(buffer.data());
    size_t len = buffer.size();
    size_t total = 0;

    while (total < len) {
        // MAX_CHUNK_SIZE - 16 是最大明文长度（减去 overhead）
        size_t chunk_size = std::min(len - total, size_t(MAX_CHUNK_SIZE - 16));
        if (!co_await WriteChunk(data + total, chunk_size)) {
            ThrowVMessWriteError("VMess stream write chunk failed");
        }
        total += chunk_size;
    }

    co_return total;
}

// ============================================================================
// WriteMultiBuffer — 流式加密到 pool Buffer，再交给下层 scatter-write
// ============================================================================
cobalt::task<void> VMessServerAsyncStream::WriteMultiBuffer(MultiBuffer mb) {
    MultiBufferGuard guard{mb};

    if (!response_header_sent_) {
        if (!co_await SendResponseHeader()) {
            ThrowVMessWriteError("VMess stream send response header failed");
        }
    }

    if (mb.empty()) co_return;

    const size_t overhead = write_cipher_->Overhead();
    if (Buffer::kSize <= 2 + overhead + 63) {
        ThrowVMessWriteError("VMess stream buffer budget too small");
    }
    const size_t stream_chunk_size = std::min(
        size_t(MAX_CHUNK_SIZE - overhead),
        size_t(Buffer::kSize - 2 - overhead - 63));

    MultiBuffer out_mb;
    MultiBufferGuard out_guard{out_mb};
    size_t out_bytes = 0;

    auto flush_out = [this, &out_mb, &out_bytes]() -> cobalt::task<void> {
        if (out_mb.empty()) {
            co_return;
        }
        co_await inner_->WriteMultiBuffer(std::move(out_mb));
        out_mb = MultiBuffer{};
        out_bytes = 0;
    };

    for (auto* buf : mb) {
        auto bytes = buf->Bytes();
        if (bytes.empty()) continue;

        const uint8_t* data = bytes.data();
        size_t len = bytes.size();
        size_t offset = 0;

        while (offset < len) {
            size_t chunk_size = std::min(len - offset, stream_chunk_size);
            Buffer* out = Buffer::New();
            if (!out) {
                throw std::bad_alloc();
            }

            uint8_t* dst = out->Tail().data();
            ssize_t enc_len = write_cipher_->Encrypt(
                data + offset, chunk_size, dst + 2);
            if (enc_len < 0) {
                Buffer::Free(out);
                ThrowVMessWriteError("VMess stream stream encrypt failed");
            }

            // padding + masking（与 WriteChunk 逻辑一致）
            size_t padding_len = 0;
            if (global_padding_ && write_mask_) {
                uint16_t padding_mask = write_mask_->NextMask();
                padding_len = padding_mask % 64;
            }

            uint16_t length_mask = 0;
            if (write_mask_) {
                length_mask = write_mask_->NextMask();
            }

            uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);
            uint16_t masked_len = total_len ^ length_mask;
            write_chunk_count_++;

            const size_t output_size = 2 + static_cast<size_t>(enc_len) + padding_len;
            dst[0] = static_cast<uint8_t>((masked_len >> 8) & 0xFF);
            dst[1] = static_cast<uint8_t>(masked_len & 0xFF);

            if (padding_len > 0) {
                RAND_bytes(dst + 2 + enc_len, static_cast<int>(padding_len));
            }

            out->Produce(static_cast<uint32_t>(output_size));
            out_bytes += output_size;
            try {
                out_mb.push_back(out);
            } catch (...) {
                Buffer::Free(out);
                throw;
            }

            offset += chunk_size;

            if (out_mb.size() >= kStreamFlushBufferCount || out_bytes >= kStreamFlushBytes) {
                co_await flush_out();
            }
        }
    }

    co_await flush_out();
}

// 零拷贝版本：直接解密到用户提供的 buffer
cobalt::task<ssize_t> VMessServerAsyncStream::ReadChunkInto(uint8_t* buf, size_t max_len) {
    uint8_t len_buf[2];
    if (!co_await ReadFull(len_buf, 2)) {
        LOG_ACCESS_DEBUG("VMess stream: ReadChunk TCP-level close (failed to read chunk header) after {} chunks",
                         read_chunk_count_);
        read_eof_ = true;
        co_return 0;
    }

    uint16_t raw_len = (static_cast<uint16_t>(len_buf[0]) << 8) | len_buf[1];

    // 按照 v2ray 的顺序：先获取 padding mask，再获取 size mask
    size_t padding_len = 0;
    if (global_padding_ && read_mask_) {
        uint16_t padding_mask = read_mask_->NextMask();
        padding_len = padding_mask % 64;
    }

    uint16_t chunk_len = raw_len;
    if (read_mask_) {
        uint16_t size_mask = read_mask_->NextMask();
        chunk_len ^= size_mask;
    }

    size_t overhead = read_cipher_->Overhead();

    LOG_ACCESS_DEBUG("VMess stream: ReadChunk raw_len={} chunk_len={} overhead={} padding={} chunk#{}",
                     raw_len, chunk_len, overhead, padding_len, read_chunk_count_);

    // EOF 标记
    if (chunk_len == overhead + padding_len) {
        if (chunk_len > 0 && chunk_len <= BUF_SIZE) {
            EnsureReadBuffers();
            co_await ReadFull(read_crypto_buf_.data(), chunk_len);
        }
        LOG_ACCESS_DEBUG("VMess stream: ReadChunk EOF marker received after {} chunks", read_chunk_count_);
        read_eof_ = true;
        co_return 0;
    }

    // 验证 chunk 长度
    if (chunk_len < overhead + padding_len || chunk_len > MAX_CHUNK_SIZE + overhead + 64) {
        LOG_ACCESS_DEBUG("VMess stream: ReadChunk INVALID length chunk#{} raw_len={} chunk_len={} "
                         "overhead={} padding={} MAX={} (可能 mask 计数器不同步)",
                         read_chunk_count_, raw_len, chunk_len, overhead, padding_len, MAX_CHUNK_SIZE);
        read_eof_ = true;
        co_return -1;
    }

    // 读取加密数据到读缓冲区
    if (chunk_len > BUF_SIZE) {
        LOG_ACCESS_DEBUG("VMess stream: ReadChunk chunk_len={} exceeds BUF_SIZE={}", chunk_len, BUF_SIZE);
        read_eof_ = true;
        co_return -1;
    }

    EnsureReadBuffers();
    if (!co_await ReadFull(read_crypto_buf_.data(), chunk_len)) {
        LOG_ACCESS_DEBUG("VMess stream: ReadChunk ReadFull failed chunk#{} chunk_len={} "
                         "(TCP 连接在 chunk body 传输中断开)",
                         read_chunk_count_, chunk_len);
        read_eof_ = true;
        co_return 0;
    }

    size_t data_len = chunk_len - padding_len;

    // 检查用户 buffer 是否足够大
    size_t expected_plain_len = data_len - overhead;
    if (max_len < expected_plain_len) {
        // 用户 buffer 不够，回退到 read_spare_buf_
        ssize_t dec_len = read_cipher_->Decrypt(
            read_crypto_buf_.data(), data_len, read_spare_buf_.data());
        if (dec_len < 0) {
            LOG_ACCESS_DEBUG("VMess stream: ReadChunk decrypt FAILED chunk#{} data_len={} security={} "
                             "raw_hex=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}...] "
                             "padding={} overhead={}",
                             read_chunk_count_, data_len, static_cast<int>(security_),
                             data_len > 0 ? read_crypto_buf_[0] : 0,
                             data_len > 1 ? read_crypto_buf_[1] : 0,
                             data_len > 2 ? read_crypto_buf_[2] : 0,
                             data_len > 3 ? read_crypto_buf_[3] : 0,
                             data_len > 4 ? read_crypto_buf_[4] : 0,
                             data_len > 5 ? read_crypto_buf_[5] : 0,
                             data_len > 6 ? read_crypto_buf_[6] : 0,
                             data_len > 7 ? read_crypto_buf_[7] : 0,
                             padding_len, overhead);
            read_eof_ = true;
            co_return -1;
        }
        // 拷贝能放下的部分
        const size_t dec_size = static_cast<size_t>(dec_len);
        size_t copy = std::min(max_len, dec_size);
        std::memcpy(buf, read_spare_buf_.data(), copy);
        // 剩余部分存入 read_buffer_
        if (dec_size > copy) {
            read_buffer_.assign(read_spare_buf_.begin() + copy,
                                read_spare_buf_.begin() + dec_size);
            read_buffer_offset_ = 0;
        }
        read_chunk_count_++;
        co_return static_cast<ssize_t>(copy);
    }

    // 直接解密到用户 buffer（零拷贝）
    ssize_t dec_len = read_cipher_->Decrypt(read_crypto_buf_.data(), data_len, buf);
    if (dec_len < 0) {
        LOG_ACCESS_DEBUG("VMess stream: ReadChunk decrypt FAILED chunk#{} data_len={} security={} "
                         "raw_hex=[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}...] "
                         "padding={} overhead={} expected_plain={}",
                         read_chunk_count_, data_len, static_cast<int>(security_),
                         data_len > 0 ? read_crypto_buf_[0] : 0,
                         data_len > 1 ? read_crypto_buf_[1] : 0,
                         data_len > 2 ? read_crypto_buf_[2] : 0,
                         data_len > 3 ? read_crypto_buf_[3] : 0,
                         data_len > 4 ? read_crypto_buf_[4] : 0,
                         data_len > 5 ? read_crypto_buf_[5] : 0,
                         data_len > 6 ? read_crypto_buf_[6] : 0,
                         data_len > 7 ? read_crypto_buf_[7] : 0,
                         padding_len, overhead, expected_plain_len);
        read_eof_ = true;
        co_return -1;
    }

    read_chunk_count_++;
    co_return dec_len;
}

cobalt::task<bool> VMessServerAsyncStream::WriteChunk(const uint8_t* data, size_t len) {
    size_t overhead = write_cipher_->Overhead();

    if (len + overhead > BUF_SIZE) {
        co_return false;
    }

    EnsureWriteBuffers();

    // 加密到写方向缓冲区
    ssize_t enc_len = write_cipher_->Encrypt(data, len, write_crypto_buf_.data());
    if (enc_len < 0) {
        LOG_ACCESS_DEBUG("VMess stream: WriteChunk encrypt failed (len={}, chunk#{})", len, write_chunk_count_);
        co_return false;
    }

    // 按照 v2ray 的顺序：先获取 padding mask，再获取 size mask
    size_t padding_len = 0;
    if (global_padding_ && write_mask_) {
        uint16_t padding_mask = write_mask_->NextMask();
        padding_len = padding_mask % 64;
    }

    uint16_t length_mask = 0;
    if (write_mask_) {
        length_mask = write_mask_->NextMask();
    }

    uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);
    uint16_t masked_len = total_len ^ length_mask;

    write_chunk_count_++;

    size_t output_size = 2 + enc_len + padding_len;

    // 组装输出到写方向 I/O 缓冲区
    write_output_buf_[0] = static_cast<uint8_t>((masked_len >> 8) & 0xFF);
    write_output_buf_[1] = static_cast<uint8_t>(masked_len & 0xFF);
    std::memcpy(write_output_buf_.data() + 2, write_crypto_buf_.data(), enc_len);

    if (padding_len > 0) {
        RAND_bytes(write_output_buf_.data() + 2 + enc_len, static_cast<int>(padding_len));
    }

    co_return co_await WriteFull(write_output_buf_.data(), output_size);
}

cobalt::task<bool> VMessServerAsyncStream::SendEOFMarker() {
    if (write_eof_sent_) {
        co_return true;
    }

    // 按照 v2ray 的顺序：先获取 padding mask，再获取 size mask
    size_t padding_len = 0;
    if (global_padding_ && write_mask_) {
        uint16_t padding_mask = write_mask_->NextMask();
        padding_len = padding_mask % 64;
    }

    uint16_t length_mask = 0;
    if (write_mask_) {
        length_mask = write_mask_->NextMask();
    }

    // EOF marker: 加密空数据，只有 tag
    uint8_t eof_enc[32];
    ssize_t enc_len = write_cipher_->Encrypt(nullptr, 0, eof_enc);
    if (enc_len < 0) {
        co_return false;
    }

    uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);
    uint16_t masked_len = total_len ^ length_mask;

    size_t output_size = 2 + enc_len + padding_len;
    uint8_t eof_buf[128];
    eof_buf[0] = (masked_len >> 8) & 0xFF;
    eof_buf[1] = masked_len & 0xFF;
    std::memcpy(eof_buf + 2, eof_enc, enc_len);

    if (padding_len > 0) {
        RAND_bytes(eof_buf + 2 + enc_len, static_cast<int>(padding_len));
    }

    bool ok = co_await WriteFull(eof_buf, output_size);
    if (ok) {
        write_eof_sent_ = true;
    }
    co_return ok;
}

cobalt::task<bool> VMessServerAsyncStream::ReadFull(uint8_t* buf, size_t len) {
    size_t remaining = len;

    // 先从预读缓冲区读取
    while (remaining > 0 && pending_offset_ < pending_data_.size()) {
        size_t available = pending_data_.size() - pending_offset_;
        size_t to_copy = std::min(remaining, available);
        std::memcpy(buf, pending_data_.data() + pending_offset_, to_copy);
        buf += to_copy;
        remaining -= to_copy;
        pending_offset_ += to_copy;
    }

    // 如果预读数据用完了，清理
    if (pending_offset_ >= pending_data_.size() && !pending_data_.empty()) {
        pending_data_.clear();
        pending_offset_ = 0;
        ReleaseIdleBuffer(pending_data_, 1024);
    }

    // 从底层流读取剩余数据
    while (remaining > 0) {
        size_t n = co_await inner_->AsyncRead(net::buffer(buf, remaining));
        if (n == 0) {
            co_return false;
        }
        buf += n;
        remaining -= n;
    }
    co_return true;
}

cobalt::task<bool> VMessServerAsyncStream::WriteFull(const uint8_t* buf, size_t len) {
    size_t remaining = len;
    while (remaining > 0) {
        size_t n = co_await inner_->AsyncWrite(net::buffer(buf, remaining));
        if (n == 0) {
            co_return false;
        }
        buf += n;
        remaining -= n;
    }
    co_return true;
}

cobalt::task<void> VMessServerAsyncStream::AsyncShutdownWrite() {
    // 发送 VMess EOF marker（协议级关闭）
    // 不关闭底层 socket 的写端
    if (!write_eof_sent_) {
        co_await SendEOFMarker();
    }
    co_return;
}


}  // namespace vmess
}  // namespace acpp
