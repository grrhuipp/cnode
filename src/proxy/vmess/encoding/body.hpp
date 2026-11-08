#pragma once

// ============================================================================
// body.hpp — VMess AEAD body chunk 编解码（请求/响应两个方向共用）
//
// 每个方向由同一组请求参数派生：chunk cipher、可选的认证长度 cipher，以及
// 同时驱动长度掩码与全局 padding 的 SHAKE128 流。客户端与服务端只是取不同
// 方向，因此编码器与解码器各只保留一份实现。
// ============================================================================

#include "../vmess_cipher.hpp"
#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "transport/link.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace vmess::encoding {

struct BodyKey {
    std::array<uint8_t, 16> key{};
    std::array<uint8_t, 16> iv{};
    ~BodyKey() noexcept {
        ::SecureZeroMemory(key.data(), key.size());
        ::SecureZeroMemory(iv.data(), iv.size());
    }
};

// Response body key/IV: first 16 bytes of SHA-256 over the request body
// key/IV, as in Xray-core.
[[nodiscard]] BodyKey ResponseBodyKey(const BodyKey& request);

// Request header fields that select the body framing for both directions.
struct BodyOptions {
    Security security = Security::AES_128_GCM;
    uint8_t options = 0;
    Command command = Command::TCP;
};

// Framing state of one body direction. As in Xray-core, the authenticated
// length cipher derives its key from the request body key and its nonce from
// the request body IV in both directions; payload cipher and mask use the
// direction's own key/IV.
class BodyChunkCipher {
public:
    BodyChunkCipher(const BodyOptions& options,
                    const BodyKey& request_body,
                    const BodyKey& direction_key,
                    proxy::AeadDirection direction);

    [[nodiscard]] size_t Overhead() const { return payload_.Overhead(); }
    [[nodiscard]] size_t LengthSize() const { return length_ ? length_->Overhead() + 2 : 2; }
    [[nodiscard]] size_t MaxPaddingSize() const noexcept { return padding_mask() ? 64 : 0; }
    [[nodiscard]] bool PacketMode() const noexcept { return packet_mode_; }

    // Draws this chunk's padding from the mask stream; must precede the
    // length mask of the same chunk on both peers.
    [[nodiscard]] size_t NextPaddingSize();
    // Writes LengthSize() bytes announcing `chunk_size` (sealed payload plus padding).
    [[nodiscard]] bool EncodeLength(size_t chunk_size, uint8_t* out);
    // Reads LengthSize() bytes; nullopt when the authenticated length fails.
    [[nodiscard]] std::optional<size_t> DecodeLength(const uint8_t* in);

    VMessCipher& Payload() noexcept { return payload_; }

private:
    [[nodiscard]] bool padding_mask() const noexcept { return global_padding_ && mask_; }

    VMessCipher payload_;
    std::optional<VMessCipher> length_;
    std::optional<ShakeMask> mask_;
    bool global_padding_ = false;
    bool packet_mode_ = false;
};

class BodyEncoder {
public:
    BodyEncoder(const BodyOptions& options,
                const BodyKey& request_body,
                const BodyKey& direction_key);

    // Stream mode splits payload into chunks that fit one pooled buffer;
    // packet mode seals the whole datagram as exactly one chunk, rejecting
    // empty UDP with NOT_SUPPORTED because an empty body is the EOF marker.
    void Encode(const buf::MultiBuffer& payload, buf::MultiBuffer& out);
    void Encode(std::span<const net::const_buffer> payload, buf::MultiBuffer& out);
    // Zero-length chunk ending this direction.
    void EncodeEnd(buf::MultiBuffer& out);
    [[nodiscard]] size_t EncodeEndTo(std::span<uint8_t, 128> out);
    [[nodiscard]] bool PacketMode() const noexcept { return cipher_.PacketMode(); }

private:
    void EncodeStream(std::span<const uint8_t> bytes, buf::MultiBuffer& out);
    void EncodePacket(std::span<const uint8_t> bytes, buf::MultiBuffer& out);
    void EncodeChunk(std::span<const uint8_t> bytes, buf::MultiBuffer& out);

    BodyChunkCipher cipher_;
    size_t stream_chunk_size_ = 0;
};

// Resumable body reader state. A cancelled read keeps buffered bytes, the
// decoded length, mask/length-cipher progress and decoded-but-unreturned
// chunks, so the next Read continues the same record.
class BodyDecoder {
public:
    BodyDecoder(const BodyOptions& options,
                const BodyKey& request_body,
                const BodyKey& direction_key);

    // Empty result: EOF chunk, or transport EOF exactly at a record boundary.
    // Transport EOF inside a record or authentication failure throws
    // connection_reset; afterwards every Read returns empty.
    net::awaitable<buf::MultiBuffer> Read(transport::MultiBufferReader& src);

    // Exact read through the same buffered input, for the response header
    // that precedes the body. `filled` is caller-owned progress.
    net::awaitable<bool> ReadExact(transport::MultiBufferReader& src,
                                   std::span<uint8_t> out,
                                   size_t& filled);

private:
    net::awaitable<buf::MultiBuffer> ReadChunk(transport::MultiBufferReader& src);
    [[noreturn]] void Fail(const char* what);
    void FinishRecord() noexcept;

    BodyChunkCipher cipher_;
    buf::MultiBuffer pending_read_;
    buf::MultiBuffer pending_output_;
    size_t pending_output_chunks_ = 0;
    // Length header (≤ 18 bytes), then reused for the EOF chunk body, which is
    // at most an AEAD tag plus 63 padding bytes.
    std::array<uint8_t, 128> header_{};
    size_t header_read_ = 0;
    size_t body_read_ = 0;
    size_t chunk_len_ = 0;
    size_t padding_len_ = 0;
    bool header_decoded_ = false;
    buf::ContiguousWriteBuffer read_buffer_;
    bool eof_ = false;
};

}  // namespace vmess::encoding
