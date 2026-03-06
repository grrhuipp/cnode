#pragma once

// ============================================================================
// ws_stream.hpp - WebSocket 流公共组件
//
// 统一 WebSocket 客户端和服务端的公共部分：
// - 帧解析/编码
// - 写关闭/完全关闭的幂等管理（两个 atomic<bool>）
// ============================================================================

#include "acppnode/transport/async_stream.hpp"
#include "acppnode/common/circular_buffer.hpp"
#include "acppnode/infra/log.hpp"

#include <openssl/rand.h>

#include <array>
#include <atomic>
#include <expected>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <algorithm>

namespace acpp {

using WsHandshakeResult = std::expected<void, ErrorCode>;

// ============================================================================
// WebSocket 帧工具
// ============================================================================
namespace ws {

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
inline std::vector<uint8_t> EncodeFrameHeader(
    size_t payload_len, 
    Opcode opcode = Opcode::BINARY,
    bool masked = false,
    const uint8_t* mask_key = nullptr) {
    
    std::vector<uint8_t> header;
    
    // FIN + opcode
    header.push_back(0x80 | static_cast<uint8_t>(opcode));
    
    // Mask flag + payload length
    uint8_t len_byte = masked ? 0x80 : 0x00;
    
    if (payload_len <= 125) {
        header.push_back(len_byte | static_cast<uint8_t>(payload_len));
    } else if (payload_len <= 65535) {
        header.push_back(len_byte | 126);
        header.push_back(static_cast<uint8_t>(payload_len >> 8));
        header.push_back(static_cast<uint8_t>(payload_len & 0xFF));
    } else {
        header.push_back(len_byte | 127);
        for (int i = 7; i >= 0; --i) {
            header.push_back(static_cast<uint8_t>((payload_len >> (i * 8)) & 0xFF));
        }
    }
    
    // Mask key (如果需要)
    if (masked && mask_key) {
        header.insert(header.end(), mask_key, mask_key + 4);
    }
    
    return header;
}

// 编码 Close 帧
inline std::vector<uint8_t> EncodeCloseFrame(uint16_t status_code, bool masked = false) {
    std::vector<uint8_t> frame;
    
    // Header: FIN + CLOSE opcode
    frame.push_back(0x88);
    
    if (masked) {
        // 客户端：masked + 2 bytes payload + 4 bytes mask
        frame.push_back(0x82);  // masked + len=2
        uint8_t mask_key[4];
        if (RAND_bytes(mask_key, sizeof(mask_key)) != 1) [[unlikely]] {
            return {};
        }
        frame.insert(frame.end(), mask_key, mask_key + 4);

        uint8_t payload[2] = {
            static_cast<uint8_t>((status_code >> 8) & 0xFF),
            static_cast<uint8_t>(status_code & 0xFF),
        };
        MaskData(payload, sizeof(payload), mask_key);
        frame.insert(frame.end(), payload, payload + sizeof(payload));
    } else {
        // 服务端：unmasked + 2 bytes payload
        frame.push_back(0x02);  // len=2
        frame.push_back((status_code >> 8) & 0xFF);
        frame.push_back(status_code & 0xFF);
    }
    
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
// - 写关闭/完全关闭的幂等管理（write_closed_ / closed_ 两个 atomic<bool>）
// - pending/decoded 缓冲区管理
//
// 子类需要实现：
// - AsyncWrite（客户端需要 mask，服务端不需要）
// ============================================================================
class BaseWsStream : public AsyncStream {
public:
    // 16KB 以内的帧合并 header+payload 为单次写入，覆盖绝大多数 relay 包
    static constexpr size_t kSmallFrameThreshold = 16 * 1024;
    static constexpr size_t kStreamChunkSize = 16 * 1024;
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
        pending_data_.push_back(data, len);
    }
    
    void SetPendingData(const std::vector<uint8_t>& data) {
        pending_data_.push_back(data.data(), data.size());
    }
    
    // ========================================================================
    // AsyncStream 接口实现
    // ========================================================================
    
    cobalt::task<size_t> AsyncRead(net::mutable_buffer buffer) override {
        uint8_t* buf = static_cast<uint8_t*>(buffer.data());
        size_t len = buffer.size();
        if (len == 0) {
            co_return 0;
        }

        // 先消费已解码的数据
        if (!decoded_buffer_.empty()) {
            size_t copied = decoded_buffer_.pop_front(buf, len);
            if (decoded_buffer_.empty()) {
                decoded_buffer_.ShrinkIfOversized(kStreamChunkSize);
            }
            co_return copied;
        }

        while (true) {
            if (frame_payload_remaining_ == 0) {
                if (!co_await PrepareNextDataFrame()) {
                    co_return 0;
                }
            }

            if (frame_payload_remaining_ <= kSmallFrameThreshold) {
                std::array<uint8_t, kSmallFrameThreshold> scratch{};
                const size_t payload_len = static_cast<size_t>(frame_payload_remaining_);
                if (!co_await ReadFull(scratch.data(), payload_len)) {
                    frame_payload_remaining_ = 0;
                    frame_mask_offset_ = 0;
                    co_return 0;
                }

                if (frame_masked_) {
                    ws::MaskData(scratch.data(), payload_len, frame_mask_key_.data(),
                                 frame_mask_offset_);
                }

                frame_payload_remaining_ = 0;
                frame_mask_offset_ = 0;

                const size_t direct = std::min(len, payload_len);
                std::memcpy(buf, scratch.data(), direct);
                if (payload_len > direct) {
                    decoded_buffer_.push_back(scratch.data() + direct,
                                              payload_len - direct);
                }
                co_return direct;
            }

            size_t chunk = std::min(len, kStreamChunkSize);
            chunk = static_cast<size_t>(std::min<uint64_t>(chunk, frame_payload_remaining_));
            if (!co_await ReadFull(buf, chunk)) {
                frame_payload_remaining_ = 0;
                frame_mask_offset_ = 0;
                co_return 0;
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
    
    void Close() override {
        if (closed_.exchange(true, std::memory_order_acq_rel)) {
            return;  // 幂等
        }
        inner_->Close();
    }
    
    void ShutdownWrite() override {
        if (write_closed_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        inner_->ShutdownWrite();
    }
    
    cobalt::task<void> AsyncShutdownWrite() override {
        if (write_closed_.exchange(true, std::memory_order_acq_rel)) {
            co_return;
        }

        // 发送 Close 帧（只发送一次，exchange 保证幂等）
        auto close_frame = ws::EncodeCloseFrame(1000, is_client_);
        if (!close_frame.empty()) {
            try {
                co_await inner_->AsyncWrite(net::buffer(close_frame));
                LOG_ACCESS_DEBUG("[conn={}] WS {}: sent close frame", conn_id_, is_client_ ? "client" : "server");
            } catch (...) {
                // 忽略发送错误
            }
        }

        co_await inner_->AsyncShutdownWrite();
    }
    
    void Cancel() noexcept override {
        closed_.store(true, std::memory_order_release);
        inner_->Cancel();
    }

    int NativeHandle() const override { return inner_->NativeHandle(); }
    net::any_io_executor GetExecutor() const override { return inner_->GetExecutor(); }
    bool IsOpen() const override { return !closed_.load(std::memory_order_acquire) && inner_->IsOpen(); }

    TcpStream* GetBaseTcpStream() override { return inner_->GetBaseTcpStream(); }
    const TcpStream* GetBaseTcpStream() const override { return inner_->GetBaseTcpStream(); }

    [[nodiscard]] bool CanWrite() const noexcept {
        return !write_closed_.load(std::memory_order_acquire);
    }

protected:
    // 读取完整数据
    cobalt::task<bool> ReadFull(uint8_t* buf, size_t len) {
        size_t total = 0;
        
        // 先从 pending_data_ 读取
        if (!pending_data_.empty()) {
            total = pending_data_.pop_front(buf, len);
            if (pending_data_.empty()) {
                pending_data_.ShrinkIfOversized(kSmallFrameThreshold);
            }
        }
        
        // 从底层流读取剩余
        while (total < len) {
            size_t n = co_await inner_->AsyncRead(net::buffer(buf + total, len - total));
            if (n == 0) {
                co_return false;
            }
            total += n;
        }
        co_return true;
    }
    
    // 写入完整数据
    cobalt::task<bool> WriteFull(const uint8_t* buf, size_t len) {
        size_t total = 0;
        while (total < len) {
            size_t n = co_await inner_->AsyncWrite(net::buffer(buf + total, len - total));
            if (n == 0) {
                co_return false;
            }
            total += n;
        }
        co_return true;
    }
    
    cobalt::task<bool> PrepareNextDataFrame() {
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

    cobalt::task<bool> DiscardPayload(uint64_t payload_len) {
        std::array<uint8_t, kStreamChunkSize> discard{};
        while (payload_len > 0) {
            const size_t chunk = static_cast<size_t>(
                std::min<uint64_t>(payload_len, discard.size()));
            if (!co_await ReadFull(discard.data(), chunk)) {
                co_return false;
            }
            payload_len -= chunk;
        }
        co_return true;
    }
    
    std::unique_ptr<AsyncStream> inner_;
    uint64_t conn_id_;
    bool is_client_;
    CircularBuffer pending_data_{4096};
    CircularBuffer decoded_buffer_{8192};

private:
    uint64_t frame_payload_remaining_ = 0;
    std::array<uint8_t, 4> frame_mask_key_{0, 0, 0, 0};
    size_t frame_mask_offset_ = 0;
    bool frame_masked_ = false;

    // write_closed_：写端已关闭（Close Frame 已发送），幂等标志
    // closed_：连接已完全关闭（幂等 Close() 标志）
    std::atomic<bool> write_closed_{false};
    std::atomic<bool> closed_{false};
};

// ============================================================================
// WsServerStream - WebSocket 服务端流（无 mask）
// ============================================================================
class WsServerStream final : public BaseWsStream {
public:
    WsServerStream(std::unique_ptr<AsyncStream> inner, uint64_t conn_id)
        : BaseWsStream(std::move(inner), conn_id, false) {}
    
    cobalt::task<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (!CanWrite()) {
            co_return 0;
        }

        const uint8_t* data = static_cast<const uint8_t*>(buffer.data());
        size_t len = buffer.size();

        // 编码帧头（服务端不需要 mask）
        auto header = ws::EncodeFrameHeader(len, ws::Opcode::BINARY, false);

        if (len <= kSmallFrameThreshold) {
            std::array<uint8_t, kSmallFrameThreshold + 14> frame{};
            std::memcpy(frame.data(), header.data(), header.size());
            std::memcpy(frame.data() + header.size(), data, len);
            if (!co_await WriteFull(frame.data(), header.size() + len)) {
                co_return 0;
            }
            co_return len;
        }

        if (!co_await WriteFull(header.data(), header.size())) {
            co_return 0;
        }

        // 发送 payload
        if (!co_await WriteFull(data, len)) {
            co_return 0;
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
    cobalt::task<WsHandshakeResult> Handshake(
        const std::string& host,
        const std::string& path,
        const std::unordered_map<std::string, std::string>* headers = nullptr);
    
    cobalt::task<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (!CanWrite()) {
            co_return 0;
        }

        const uint8_t* data = static_cast<const uint8_t*>(buffer.data());
        size_t len = buffer.size();

        // RFC 6455 §5.3: 客户端必须为每帧生成随机 mask key
        uint8_t mask_key[4];
        if (RAND_bytes(mask_key, sizeof(mask_key)) != 1) [[unlikely]] {
            co_return 0;
        }

        // 编码帧头（客户端需要 mask）
        auto header = ws::EncodeFrameHeader(len, ws::Opcode::BINARY, true, mask_key);

        if (len <= kSmallFrameThreshold) {
            std::array<uint8_t, kSmallFrameThreshold + 14> frame{};
            std::memcpy(frame.data(), header.data(), header.size());
            std::memcpy(frame.data() + header.size(), data, len);
            ws::MaskData(frame.data() + header.size(), len, mask_key);
            if (!co_await WriteFull(frame.data(), header.size() + len)) {
                co_return 0;
            }
            co_return len;
        }

        if (!co_await WriteFull(header.data(), header.size())) {
            co_return 0;
        }

        std::array<uint8_t, kStreamChunkSize> masked_chunk{};
        size_t offset = 0;
        while (offset < len) {
            const size_t chunk = std::min(masked_chunk.size(), len - offset);
            std::memcpy(masked_chunk.data(), data + offset, chunk);
            ws::MaskData(masked_chunk.data(), chunk, mask_key, offset);
            if (!co_await WriteFull(masked_chunk.data(), chunk)) {
                co_return 0;
            }
            offset += chunk;
        }

        co_return len;
    }
};

// ============================================================================
// 工厂函数
// ============================================================================

[[nodiscard]]
std::unique_ptr<AsyncStream> CreateWsServerStream(
    std::unique_ptr<AsyncStream> inner, uint64_t conn_id);

[[nodiscard]]
std::unique_ptr<AsyncStream> CreateWsClientStream(
    std::unique_ptr<AsyncStream> inner, uint64_t conn_id);

}  // namespace acpp
