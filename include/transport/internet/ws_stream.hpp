#pragma once

// ============================================================================
// ws_stream.hpp - WebSocket 流公共组件
//
// 统一 WebSocket 客户端和服务端的公共部分：
// - 帧解析/编码
// - 写关闭/完全关闭的幂等管理（per-Worker 普通状态）
// ============================================================================

#include "transport/async_stream.hpp"
#include "transport/internet/async_write_gate.hpp"
#include "transport/internet/http_headers.hpp"

#include <array>
#include <cstring>
#include <optional>
#include <tl/expected.hpp>


using WsHandshakeResult = tl::expected<void, ErrorCode>;

// ============================================================================
// WebSocket 帧工具
// ============================================================================
namespace ws {

struct EncodedFrameHeader {
    std::array<uint8_t, 14> bytes{};
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

// RFC 6455 §5.3 mask/unmask (symmetric). |offset| is the payload position of
// data[0]; eight bytes are XORed per step with the key rotated to that offset.
inline void MaskData(uint8_t* data, size_t len, const uint8_t* mask_key,
                     size_t offset = 0) {
    std::array<uint8_t, 8> pattern;
    for (size_t i = 0; i < pattern.size(); ++i) pattern[i] = mask_key[(offset + i) & 3];
    uint64_t word_mask;
    std::memcpy(&word_mask, pattern.data(), sizeof(word_mask));
    size_t i = 0;
    for (; len - i >= sizeof(word_mask); i += sizeof(word_mask)) {
        uint64_t word;
        std::memcpy(&word, data + i, sizeof(word));
        word ^= word_mask;
        std::memcpy(data + i, &word, sizeof(word));
    }
    for (; i < len; ++i) data[i] ^= pattern[i & 7];
}

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
            out[offset++] = static_cast<uint8_t>((static_cast<uint64_t>(payload_len) >> (i * 8)) & 0xFF);
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

[[nodiscard]] std::string ComputeWsAccept(std::string_view ws_key);
[[nodiscard]] std::array<char, 28> EncodeWsAccept(std::string_view ws_key) noexcept;

}  // namespace ws

// One read operation owns the incremental decoder; one gate owns every complete
// physical write, including control frames and the closing handshake.
class BaseWsStream : public AsyncStream {
public:
    static constexpr size_t kMaxFrameSize = 4 * 1024 * 1024;

    BaseWsStream(std::unique_ptr<AsyncStream> inner, uint64_t conn_id, bool is_client);
    ~BaseWsStream() noexcept override;

    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::CloseLink;
    }
    bool WriteShutdownClosesLink() const noexcept override { return true; }

    void SetPendingData(const uint8_t* data, size_t len);
    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override;
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer buffers) override;

    void Close() override;
    void CloseAbortive() override;
    void ShutdownWrite() override;
    void ShutdownRead() override;
    net::awaitable<void> AsyncShutdownWrite() override;
    void Cancel() noexcept override;
    transport::CancellationSource& Cancellation() noexcept override {
        return inner_->Cancellation();
    }
    bool IsOpen() const override;
    int NativeHandle() const override;

protected:
    TcpStream* BaseTcpStream() override;
    const TcpStream* BaseTcpStream() const override;

    std::unique_ptr<AsyncStream> inner_;
    uint64_t conn_id_;
    bool is_client_;

private:
    using WriteGate = transport::internet::AsyncWriteGate;
    enum class ReadStage { Header, Length, Mask, Payload, Control };

    struct Utf8State {
        bool Consume(std::span<const uint8_t> bytes) noexcept;
        uint8_t remaining = 0;
        uint8_t minimum = 0x80;
        uint8_t maximum = 0xbf;
    };

    [[noreturn]] void ProtocolFailure(const char* reason);
    void CheckWritable() const;
    net::awaitable<bool> EnsurePendingData();
    net::awaitable<size_t> ReadSome(uint8_t* data, size_t size);
    net::awaitable<bool> FillHeader();
    net::awaitable<bool> PrepareNextDataFrame();
    net::awaitable<size_t> ReadPayload(net::mutable_buffer buffer);
    void FinishDataFrame();
    void ValidateClose();

    net::awaitable<WriteGate::Lease> AcquireWrite(net::cancellation_slot caller_slot);
    net::awaitable<void> WriteDataFrame(
        std::span<const net::const_buffer> buffers, size_t size);
    net::awaitable<void> WriteControlFrame(ws::Opcode opcode, std::span<const uint8_t> payload);

    buf::MultiBuffer pending_data_;
    // Header and control payload are protocol session state, not read scratch:
    // every completed lower-layer read is committed before the next suspension.
    std::array<uint8_t, 14> header_{};
    size_t header_used_ = 0;
    size_t header_required_ = 2;
    ReadStage read_stage_ = ReadStage::Header;
    ws::Opcode frame_opcode_ = ws::Opcode::BINARY;
    uint64_t frame_payload_remaining_ = 0;
    std::array<uint8_t, 4> frame_mask_key_{};
    size_t frame_mask_offset_ = 0;
    bool frame_masked_ = false;
    bool frame_fin_ = true;
    bool fragmented_ = false;
    bool text_message_ = false;
    Utf8State text_utf8_;
    std::array<uint8_t, 125> control_payload_{};
    size_t control_used_ = 0;
    bool peer_closed_cleanly_ = false;
    bool read_closed_ = false;
    bool close_requested_ = false;
    bool write_closed_ = false;
    bool closed_ = false;
    WriteGate write_gate_;
};

class WsServerStream final : public BaseWsStream {
public:
    WsServerStream(std::unique_ptr<AsyncStream> inner, uint64_t conn_id)
        : BaseWsStream(std::move(inner), conn_id, false) {}
};

class WsClientStream final : public BaseWsStream {
public:
    WsClientStream(std::unique_ptr<AsyncStream> inner, uint64_t conn_id)
        : BaseWsStream(std::move(inner), conn_id, true) {}

    net::awaitable<WsHandshakeResult> Handshake(
        std::string_view host,
        std::string_view path,
        const transport::internet::HttpHeaders* headers = nullptr);
};

