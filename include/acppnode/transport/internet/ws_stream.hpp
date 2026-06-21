#pragma once

// ============================================================================
// ws_stream.hpp - WebSocket 流公共组件
//
// 统一 WebSocket 客户端和服务端的公共部分：
// - 帧解析/编码
// - 写关闭/完全关闭的幂等管理（per-Worker 普通状态）
// ============================================================================

#include "acppnode/transport/async_stream.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/internet/http_headers.hpp"

#include <openssl/rand.h>

#include <array>
#include <expected>
#include <cstring>
#include <algorithm>

namespace acpp {

using WsHandshakeResult = std::expected<void, ErrorCode>;

[[noreturn]] inline void ThrowWsStreamError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

// ============================================================================
// WebSocket 帧工具
// ============================================================================
namespace ws {

struct EncodedFrameHeader {
    std::array<uint8_t, 14> bytes{};
    size_t size = 0;
};

struct EncodedCloseFrame {
    std::array<uint8_t, 8> bytes{};
    size_t size = 0;
};

// 帧类型
enum class Opcode : uint8_t {
    CONTINUATION = 0x00,
    TEXT = 0x01,
    BINARY = 0x02,
    CLOSE = 0x08,
    PING = 0x09,
    PONG = 0x0A,
};

// 帧头信息
struct FrameHeader {
    bool fin = true;
    Opcode opcode = Opcode::BINARY;
    bool masked = false;
    uint64_t payload_length = 0;
    uint8_t mask_key[4] = {0, 0, 0, 0};
};

// Mask/Unmask 数据（对称操作）
inline void MaskData(uint8_t* data, size_t len, const uint8_t* mask_key,
                     size_t offset = 0);

// 编码帧头
inline EncodedFrameHeader EncodeFrameHeader(
    size_t payload_len,
    Opcode opcode = Opcode::BINARY,
    bool masked = false,
    const uint8_t* mask_key = nullptr) {
    EncodedFrameHeader header;
    uint8_t* out = header.bytes.data();
    size_t offset = 0;

    // FIN + opcode
    out[offset++] = static_cast<uint8_t>(0x80 | static_cast<uint8_t>(opcode));

    // Mask flag + payload length
    uint8_t len_byte = masked ? 0x80 : 0x00;

    if (payload_len <= 125) {
        out[offset++] = static_cast<uint8_t>(len_byte | static_cast<uint8_t>(payload_len));
    } else if (payload_len <= 65535) {
        out[offset++] = static_cast<uint8_t>(len_byte | 126);
        out[offset++] = static_cast<uint8_t>(payload_len >> 8);
        out[offset++] = static_cast<uint8_t>(payload_len & 0xFF);
    } else {
        out[offset++] = static_cast<uint8_t>(len_byte | 127);
        for (int i = 7; i >= 0; --i) {
            out[offset++] = static_cast<uint8_t>((payload_len >> (i * 8)) & 0xFF);
        }
    }

    // Mask key (如果需要)
    if (masked && mask_key) {
        std::memcpy(out + offset, mask_key, 4);
        offset += 4;
    }

    header.size = offset;
    return header;
}

// 编码 Close 帧
inline EncodedCloseFrame EncodeCloseFrame(uint16_t status_code, bool masked = false) {
    EncodedCloseFrame frame;
    size_t offset = 0;

    // Header: FIN + CLOSE opcode
    frame.bytes[offset++] = 0x88;

    if (masked) {
        // 客户端：masked + 2 bytes payload + 4 bytes mask
        frame.bytes[offset++] = 0x82;  // masked + len=2
        uint8_t mask_key[4];
        if (RAND_bytes(mask_key, sizeof(mask_key)) != 1) [[unlikely]] {
            return {};
        }
        std::memcpy(frame.bytes.data() + offset, mask_key, 4);
        offset += 4;

        uint8_t payload[2] = {
            static_cast<uint8_t>((status_code >> 8) & 0xFF),
            static_cast<uint8_t>(status_code & 0xFF),
        };
        MaskData(payload, sizeof(payload), mask_key);
        std::memcpy(frame.bytes.data() + offset, payload, sizeof(payload));
        offset += sizeof(payload);
    } else {
        // 服务端：unmasked + 2 bytes payload
        frame.bytes[offset++] = 0x02;  // len=2
        frame.bytes[offset++] = static_cast<uint8_t>((status_code >> 8) & 0xFF);
        frame.bytes[offset++] = static_cast<uint8_t>(status_code & 0xFF);
    }

    frame.size = offset;
    return frame;
}

inline void MaskData(uint8_t* data, size_t len, const uint8_t* mask_key,
                     size_t offset) {
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= mask_key[(offset + i) % 4];
    }
}

}  // namespace ws

// ============================================================================
// BaseWsStream - WebSocket 流基类
//
// 提供公共功能：
// - 帧读取 (ReadFrame)
// - 写关闭/完全关闭的幂等管理（per-Worker executor 上的普通 bool）
// - pending/decoded 缓冲区管理
//
// 子类需要实现：
// - AsyncWrite（客户端需要 mask，服务端不需要）
// ============================================================================
class BaseWsStream : public AsyncStream {
public:
    // 将协程帧里的临时大数组压回 4KB/8KB，避免 WS 热路径把每个挂起读写放大成 16KB+。
    static constexpr size_t kSmallFrameThreshold = 4 * 1024;
    static constexpr size_t kStreamChunkSize = buf::Buffer::kSize;
    static constexpr size_t kMaxFrameSize = 4 * 1024 * 1024;

    BaseWsStream(std::unique_ptr<AsyncStream> inner, uint64_t conn_id, bool is_client)
        : inner_(std::move(inner))
        , conn_id_(conn_id)
        , is_client_(is_client) {}

    ~BaseWsStream() noexcept override {
        Close();
    }

    // 设置 pending 数据（握手后剩余的数据）
    void SetPendingData(const uint8_t* data, size_t len) {
        size_t offset = 0;
        while (offset < len) {
            buf::BufferGuard buffer{buf::Buffer::New()};
            if (!buffer) {
                throw std::bad_alloc();
            }
            const size_t n = std::min(len - offset,
                                      static_cast<size_t>(buffer->Available()));
            std::memcpy(buffer->Tail().data(), data + offset, n);
            buffer->Produce(static_cast<uint32_t>(n));
            pending_data_.push_back(buffer.release());
            offset += n;
        }
    }

    // ========================================================================
    // AsyncStream 接口实现
    // ========================================================================

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        uint8_t* buf = static_cast<uint8_t*>(buffer.data());
        size_t len = buffer.size();
        if (len == 0) {
            co_return 0;
        }

        while (true) {
            if (frame_payload_remaining_ == 0) {
                if (!co_await PrepareNextDataFrame()) {
                    if (peer_closed_cleanly_ || transport_eof_) {
                        co_return 0;
                    }
                    ThrowWsStreamError("WebSocket read frame header failed");
                }
            }

            size_t chunk = std::min(len, kStreamChunkSize);
            chunk = static_cast<size_t>(std::min<uint64_t>(chunk, frame_payload_remaining_));
            if (!co_await ReadFull(buf, chunk)) {
                frame_payload_remaining_ = 0;
                frame_mask_offset_ = 0;
                if (transport_eof_) {
                    co_return 0;
                }
                ThrowWsStreamError("WebSocket read frame payload failed");
            }

            if (frame_masked_) {
                ws::MaskData(buf, chunk, frame_mask_key_.data(), frame_mask_offset_);
                frame_mask_offset_ += chunk;
            }

            frame_payload_remaining_ -= chunk;
            if (frame_payload_remaining_ == 0) {
                frame_mask_offset_ = 0;
            }
            co_return chunk;
        }
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!CanWrite()) {
            ThrowWsStreamError("WebSocket write on closed stream");
        }

        size_t total_len = 0;
        for (const auto& buffer : buffers) {
            total_len += buffer.size();
        }
        if (total_len == 0) {
            co_return;
        }

        uint8_t mask_key[4]{};
        if (is_client_ &&
            RAND_bytes(mask_key, sizeof(mask_key)) != 1) [[unlikely]] {
            ThrowWsStreamError("WebSocket client generate mask failed");
        }

        auto header = ws::EncodeFrameHeader(
            total_len, ws::Opcode::BINARY, is_client_, mask_key);

        if (!is_client_) {
            ConstBufferSpanBuilder<16> out;
            out.Append(net::const_buffer(header.bytes.data(), header.size));
            out.AppendBuffers(buffers);
            co_await inner_->WriteBuffers(out.Span());
            co_return;
        }

        if (total_len <= kSmallFrameThreshold) {
            std::array<uint8_t, kSmallFrameThreshold + 14> frame{};
            std::memcpy(frame.data(), header.bytes.data(), header.size);
            size_t offset = header.size;
            for (const auto& buffer : buffers) {
                if (buffer.size() == 0) {
                    continue;
                }
                std::memcpy(frame.data() + offset, buffer.data(), buffer.size());
                offset += buffer.size();
            }
            ws::MaskData(frame.data() + header.size, total_len, mask_key);
            std::array<net::const_buffer, 1> out{
                net::const_buffer(frame.data(), header.size + total_len)};
            co_await inner_->WriteBuffers(out);
            co_return;
        }

        std::array<net::const_buffer, 1> header_buf{
            net::const_buffer(header.bytes.data(), header.size)};
        co_await inner_->WriteBuffers(header_buf);

        buf::BufferGuard scratch{buf::Buffer::New()};
        if (!scratch) {
            throw std::bad_alloc();
        }

        uint8_t* masked_chunk = scratch->Tail().data();
        const size_t masked_chunk_size = scratch->Available();
        size_t payload_offset = 0;
        for (const auto& buffer : buffers) {
            const uint8_t* data = static_cast<const uint8_t*>(buffer.data());
            size_t remaining = buffer.size();
            while (remaining > 0) {
                const size_t chunk = std::min(masked_chunk_size, remaining);
                std::memcpy(masked_chunk, data, chunk);
                ws::MaskData(masked_chunk, chunk, mask_key, payload_offset);
                std::array<net::const_buffer, 1> out{
                    net::const_buffer(masked_chunk, chunk)};
                co_await inner_->WriteBuffers(out);
                data += chunk;
                remaining -= chunk;
                payload_offset += chunk;
            }
        }
    }

    void Close() override {
        if (closed_) {
            return;  // 幂等
        }
        closed_ = true;
        inner_->Close();
    }

    void CloseAbortive() override {
        if (closed_) {
            return;
        }
        closed_ = true;
        inner_->CloseAbortive();
    }

    void ShutdownWrite() override {
        if (write_closed_) {
            return;
        }
        write_closed_ = true;
        inner_->ShutdownWrite();
    }

    void ShutdownRead() override {
        inner_->ShutdownRead();
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (write_closed_) {
            co_return;
        }
        write_closed_ = true;

        // 发送 Close 帧（只发送一次，exchange 保证幂等）
        auto close_frame = ws::EncodeCloseFrame(1000, is_client_);
        if (close_frame.size != 0) {
            try {
                co_await WriteBytes(close_frame.bytes.data(), close_frame.size);
                LOG_ACCESS_DEBUG("[conn={}] WS {}: sent close frame", conn_id_, is_client_ ? "client" : "server");
            } catch (...) {
                // 忽略发送错误
            }
        }

        co_await inner_->AsyncShutdownWrite();
    }

    void Cancel() noexcept override {
        closed_ = true;
        inner_->Cancel();
    }

    bool IsOpen() const override { return !closed_ && inner_->IsOpen(); }

    int NativeHandle() const override {
        return inner_->NativeHandle();
    }

protected:
    TcpStream* BaseTcpStream() override {
        return inner_->BaseTcpStream();
    }

    const TcpStream* BaseTcpStream() const override {
        return inner_->BaseTcpStream();
    }

    [[nodiscard]] bool CanWrite() const noexcept {
        return !write_closed_;
    }

    // 读取完整数据
    net::awaitable<bool> ReadFull(uint8_t* buf, size_t len) {
        size_t total = 0;

        // 先从 pending_data_ 读取
        total = PopPendingData(buf, len);

        // 从底层流读取剩余
        while (total < len) {
            size_t n = 0;
            try {
                n = co_await inner_->AsyncRead(net::buffer(buf + total, len - total));
            } catch (const IoSystemError& e) {
                if (e.code() == io_error::eof ||
                    e.code() == io_error::connection_reset ||
                    e.code() == io_error::broken_pipe) {
                    transport_eof_ = true;
                    co_return false;
                }
                throw;
            }
            if (n == 0) {
                transport_eof_ = true;
                co_return false;
            }
            total += n;
        }
        co_return true;
    }

    size_t PopPendingData(uint8_t* dst, size_t max_len) {
        return pending_data_.ConsumePrefixTo(std::span<uint8_t>(dst, max_len));
    }

    // 写入完整数据
    net::awaitable<bool> WriteFull(const uint8_t* buf, size_t len) {
        co_await WriteBytes(buf, len);
        co_return true;
    }

    net::awaitable<void> WriteBytes(const uint8_t* buf, size_t len) {
        if (len == 0) {
            co_return;
        }
        net::const_buffer buffer{buf, len};
        co_await inner_->WriteBuffers(
            std::span<const net::const_buffer>{&buffer, 1});
    }

    net::awaitable<bool> PrepareNextDataFrame() {
        uint8_t header[2];
        while (true) {
            if (!co_await ReadFull(header, 2)) {
                co_return false;
            }

            const auto opcode = static_cast<ws::Opcode>(header[0] & 0x0F);
            const bool masked = (header[1] & 0x80) != 0;
            uint64_t payload_len = header[1] & 0x7F;

            if (payload_len == 126) {
                uint8_t ext_len[2];
                if (!co_await ReadFull(ext_len, 2)) {
                    co_return false;
                }
                payload_len = (static_cast<uint64_t>(ext_len[0]) << 8) | ext_len[1];
            } else if (payload_len == 127) {
                uint8_t ext_len[8];
                if (!co_await ReadFull(ext_len, 8)) {
                    co_return false;
                }
                payload_len = 0;
                for (int i = 0; i < 8; ++i) {
                    payload_len = (payload_len << 8) | ext_len[i];
                }
            }

            std::array<uint8_t, 4> mask_key{0, 0, 0, 0};
            if (masked && !co_await ReadFull(mask_key.data(), mask_key.size())) {
                co_return false;
            }

            if (payload_len > kMaxFrameSize) {
                LOG_ACCESS_DEBUG("[conn={}] WS: frame too large: {}", conn_id_, payload_len);
                co_return false;
            }

            if (opcode == ws::Opcode::CLOSE) {
                LOG_ACCESS_DEBUG("[conn={}] WS {}: received close frame",
                          conn_id_, is_client_ ? "client" : "server");
                if (!co_await DiscardPayload(payload_len)) {
                    co_return false;
                }
                peer_closed_cleanly_ = true;
                co_return false;
            }

            if (opcode == ws::Opcode::PING || opcode == ws::Opcode::PONG) {
                if (!co_await DiscardPayload(payload_len)) {
                    co_return false;
                }
                continue;
            }

            if (payload_len == 0) {
                continue;
            }

            frame_payload_remaining_ = payload_len;
            frame_masked_ = masked;
            frame_mask_offset_ = 0;
            frame_mask_key_ = mask_key;
            co_return true;
        }
    }

    net::awaitable<bool> DiscardPayload(uint64_t payload_len) {
        std::array<uint8_t, 256> small_scratch{};
        if (payload_len <= small_scratch.size()) {
            if (payload_len == 0) {
                co_return true;
            }
            co_return co_await ReadFull(
                small_scratch.data(),
                static_cast<size_t>(payload_len));
        }

        buf::BufferGuard scratch{buf::Buffer::New()};
        if (!scratch) {
            throw std::bad_alloc();
        }
        while (payload_len > 0) {
            const size_t chunk = static_cast<size_t>(
                std::min<uint64_t>(payload_len, scratch->Available()));
            if (!co_await ReadFull(scratch->Tail().data(), chunk)) {
                co_return false;
            }
            payload_len -= chunk;
        }
        co_return true;
    }

    std::unique_ptr<AsyncStream> inner_;
    uint64_t conn_id_;
    bool is_client_;
    buf::MultiBuffer pending_data_;

private:
    uint64_t frame_payload_remaining_ = 0;
    std::array<uint8_t, 4> frame_mask_key_{0, 0, 0, 0};
    size_t frame_mask_offset_ = 0;
    bool frame_masked_ = false;
    bool peer_closed_cleanly_ = false;
    bool transport_eof_ = false;

    // write_closed_：写端已关闭（Close Frame 已发送），幂等标志。
    // closed_：连接已完全关闭（幂等 Close() 标志）。
    bool write_closed_ = false;
    bool closed_ = false;
};

// ============================================================================
// WsServerStream - WebSocket 服务端流（无 mask）
// ============================================================================
class WsServerStream final : public BaseWsStream {
public:
    WsServerStream(std::unique_ptr<AsyncStream> inner, uint64_t conn_id)
        : BaseWsStream(std::move(inner), conn_id, false) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!CanWrite()) {
            mb.clear();
            ThrowWsStreamError("WebSocket server write on closed stream");
        }

        ConstBufferSpanBuilder<16> payload;
        size_t total_len = 0;

        for (auto* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            total_len += bytes.size();
            payload.Append(net::const_buffer(bytes.data(), bytes.size()));
        }
        if (total_len == 0) {
            co_return;
        }

        co_await WriteBuffers(payload.Span());
        mb.clear();
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (!CanWrite()) {
            ThrowWsStreamError("WebSocket server write on closed stream");
        }

        const uint8_t* data = static_cast<const uint8_t*>(buffer.data());
        size_t len = buffer.size();

        // 编码帧头（服务端不需要 mask）
        auto header = ws::EncodeFrameHeader(len, ws::Opcode::BINARY, false);

        if (len <= kSmallFrameThreshold) {
            std::array<uint8_t, kSmallFrameThreshold + 14> frame{};
            std::memcpy(frame.data(), header.bytes.data(), header.size);
            std::memcpy(frame.data() + header.size, data, len);
            if (!co_await WriteFull(frame.data(), header.size + len)) {
                ThrowWsStreamError("WebSocket server write frame failed");
            }
            co_return len;
        }

        const std::array<net::const_buffer, 2> buffers{
            net::const_buffer(header.bytes.data(), header.size),
            net::const_buffer(data, len)
        };
        try {
            co_await inner_->WriteBuffers(buffers);
        } catch (...) {
            ThrowWsStreamError("WebSocket server write frame failed");
        }

        co_return len;
    }
};

// ============================================================================
// WsClientStream - WebSocket 客户端流（需要 mask）
// ============================================================================
class WsClientStream final : public BaseWsStream {
public:
    WsClientStream(std::unique_ptr<AsyncStream> inner, uint64_t conn_id)
        : BaseWsStream(std::move(inner), conn_id, true) {}

    // 执行 WebSocket 握手
    net::awaitable<WsHandshakeResult> Handshake(
        const std::string& host,
        const std::string& path,
        const transport::internet::HttpHeaders* headers = nullptr);

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!CanWrite()) {
            mb.clear();
            ThrowWsStreamError("WebSocket client write on closed stream");
        }

        uint8_t mask_key[4];
        if (RAND_bytes(mask_key, sizeof(mask_key)) != 1) [[unlikely]] {
            ThrowWsStreamError("WebSocket client generate mask failed");
        }

        size_t total_len = 0;

        for (auto* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            total_len += bytes.size();
        }
        if (total_len == 0) {
            co_return;
        }

        auto header = ws::EncodeFrameHeader(total_len, ws::Opcode::BINARY, true, mask_key);
        ConstBufferSpanBuilder<16> out;
        out.Append(net::const_buffer(header.bytes.data(), header.size));
        size_t payload_offset = 0;
        for (auto* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            ws::MaskData(bytes.data(), bytes.size(), mask_key, payload_offset);
            payload_offset += bytes.size();
            out.Append(net::const_buffer(bytes.data(), bytes.size()));
        }
        co_await inner_->WriteBuffers(out.Span());
        mb.clear();
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (!CanWrite()) {
            ThrowWsStreamError("WebSocket client write on closed stream");
        }

        const uint8_t* data = static_cast<const uint8_t*>(buffer.data());
        size_t len = buffer.size();

        // RFC 6455 §5.3: 客户端必须为每帧生成随机 mask key
        uint8_t mask_key[4];
        if (RAND_bytes(mask_key, sizeof(mask_key)) != 1) [[unlikely]] {
            ThrowWsStreamError("WebSocket client generate mask failed");
        }

        // 编码帧头（客户端需要 mask）
        auto header = ws::EncodeFrameHeader(len, ws::Opcode::BINARY, true, mask_key);

        if (len <= kSmallFrameThreshold) {
            std::array<uint8_t, kSmallFrameThreshold + 14> frame{};
            std::memcpy(frame.data(), header.bytes.data(), header.size);
            std::memcpy(frame.data() + header.size, data, len);
            ws::MaskData(frame.data() + header.size, len, mask_key);
            if (!co_await WriteFull(frame.data(), header.size + len)) {
                ThrowWsStreamError("WebSocket client write frame failed");
            }
            co_return len;
        }

        buf::BufferGuard scratch{buf::Buffer::New()};
        if (!scratch) {
            throw std::bad_alloc();
        }
        uint8_t* masked_chunk = scratch->Tail().data();
        const size_t masked_chunk_size = scratch->Available();
        size_t offset = 0;
        bool header_sent = false;
        while (offset < len) {
            const size_t chunk = std::min(masked_chunk_size, len - offset);
            std::memcpy(masked_chunk, data + offset, chunk);
            ws::MaskData(masked_chunk, chunk, mask_key, offset);
            if (!header_sent) {
                const std::array<net::const_buffer, 2> buffers{
                    net::const_buffer(header.bytes.data(), header.size),
                    net::const_buffer(masked_chunk, chunk)
                };
                try {
                    co_await inner_->WriteBuffers(buffers);
                } catch (...) {
                    ThrowWsStreamError("WebSocket client write frame failed");
                }
                header_sent = true;
            } else {
                if (!co_await WriteFull(masked_chunk, chunk)) {
                    ThrowWsStreamError("WebSocket client write payload failed");
                }
            }
            offset += chunk;
        }

        co_return len;
    }
};

}  // namespace acpp
