#pragma once

// ============================================================================
// body.hpp — VMess AEAD body chunk 编解码（请求/响应两个方向共用）
//
// 每个方向由同一组请求参数派生：chunk cipher、可选的认证长度 cipher，以及
// 同时驱动长度掩码与全局 padding 的 SHAKE128 流。客户端与服务端只是取不同
// 方向，因此编码器与解码器各只保留一份实现。
// ============================================================================

#include "../vmess_crypto.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "common/asio_types.hpp"
#include "common/address_codec.hpp"
#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"
#include "common/target_address.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"
#include <openssl/aes.h>
#include <tl/expected.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace vmess {

// 通过 AuthID 查找用户，限定 tag（优化：O(N_tag) 而非 O(N_total)）
[[nodiscard]] std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential>
FindByAuthIDForTag(std::string_view tag,
                   const uint8_t* auth_id,
                   int64_t* out_timestamp = nullptr);

// Records AEAD request body key/IV for replay protection.
// Returns false if the same user/key/IV tuple is still inside the replay window.
[[nodiscard]] net::awaitable<bool> RegisterSessionIfNew(
    const proxyman::inbound::UserStore::VmessCredential& user,
    const std::array<uint8_t, 16>& body_key,
    const std::array<uint8_t, 16>& body_iv);

inline void ValidateFixedUdpDatagram(const buf::MultiBuffer& payload,
                                     const TargetAddress& fixed_target) {
    const auto datagram = buf::InspectUdpDatagram(payload);
    if (datagram.status == buf::UdpDatagramStatus::Empty) {
        return;
    }
    if (!datagram.Valid() || !datagram.target ||
        !datagram.target->IsValid()) {
        throw IoSystemError(
            io_error::invalid_argument,
            "VMess UDP datagram contains missing or mixed endpoints");
    }
    if (!datagram.target->SameEndpoint(fixed_target)) {
        throw IoSystemError(
            io_error::invalid_argument,
            "VMess UDP datagram target differs from the fixed session target");
    }
    // VMess reserves an empty authenticated body for end-of-stream.
    if (datagram.payload_size == 0) {
        throw transport::LinkError(ErrorCode::NOT_SUPPORTED);
    }
}

}  // namespace vmess

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
    // Input/output must be distinct; input rejection does not advance framing.
    void Encode(const buf::MultiBuffer& payload, buf::MultiBuffer& out);
    void Encode(std::span<const net::const_buffer> payload, buf::MultiBuffer& out);
    // Zero-length chunk ending this direction; repeated EOF emits no bytes.
    [[nodiscard]] size_t EncodeEndTo(std::span<uint8_t, 128> out);
    [[nodiscard]] bool PacketMode() const noexcept { return cipher_.PacketMode(); }

    net::awaitable<void> WriteMultiBuffer(
        AsyncStream& stream,
        buf::MultiBuffer mb,
        const char* cancel_what,
        std::span<const uint8_t> first_header = std::span<const uint8_t>{},
        bool* header_sent = nullptr,
        const TargetAddress* udp_target = nullptr);
    net::awaitable<void> WriteBuffers(
        AsyncStream& stream,
        std::span<const net::const_buffer> buffers,
        const char* cancel_what,
        std::span<const uint8_t> first_header = std::span<const uint8_t>{},
        bool* header_sent = nullptr);
    net::awaitable<void> WriteEOF(
        AsyncStream& stream,
        const char* cancel_what,
        std::span<const uint8_t> first_header = std::span<const uint8_t>{},
        bool* header_sent = nullptr);

    // Framing failures and failed downstream writes retire this direction.
    // A clean downstream WriteClosed instead finishes it without touching reads.
    void CheckWritable() const;
    [[nodiscard]] bool Failed() const noexcept { return state_ == State::Failed; }
    [[nodiscard]] bool Finished() const noexcept { return state_ == State::Finished; }
    void Abort() noexcept { state_ = State::Failed; }
    void Finish() noexcept {
        if (state_ != State::Failed) state_ = State::Finished;
    }

private:
    net::awaitable<void> WriteFirstEncodedChunks(
        AsyncStream& stream,
        buf::MultiBuffer chunks,
        std::span<const uint8_t> first_header,
        bool& header_sent);
    enum class State { Active, Finished, Failed };

    void EncodeStream(std::span<const uint8_t> bytes, buf::MultiBuffer& out);
    void EncodePacket(std::span<const uint8_t> bytes, buf::MultiBuffer& out);
    void EncodeChunk(std::span<const uint8_t> bytes, buf::MultiBuffer& out);

    BodyChunkCipher cipher_;
    size_t stream_chunk_size_ = 0;
    State state_ = State::Active;
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
    // Transport EOF inside a record, authentication failure and other real
    // errors are terminal; subsequent reads throw connection_reset.
    net::awaitable<buf::MultiBuffer> Read(transport::MultiBufferReader& src);

    // Exact read through the same buffered input, for the response header
    // that precedes the body. `filled` is caller-owned progress.
    net::awaitable<bool> ReadExact(transport::MultiBufferReader& src,
                                   std::span<uint8_t> out,
                                   size_t& filled);

    // Discards this direction's buffered input and any undelivered plaintext.
    // The response header shares this failure state with its body decoder.
    void Abort() noexcept;

private:
    enum class State { Active, Finished, Failed };

    [[nodiscard]] bool TryConsumePending(std::span<uint8_t> out, size_t& filled) noexcept;
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
    State state_ = State::Active;
};


using VMessHandshakeResult = tl::expected<void, ErrorCode>;

class ClientSession final {
public:
    ClientSession(Security security, Command command);

    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;

    // Pre-start cancellation preserves framing. Once framing starts, failures
    // (including cancellation) retire request writes. Clean EOF/WriteClosed
    // ends only the request direction; responses remain readable.
    net::awaitable<VMessHandshakeResult> EncodeRequestHeader(
        AsyncStream& stream,
        const MemoryAccount& user,
        const AES_KEY& auth_id_key,
        const TargetAddress& target,
        Command command,
        ForwardedMetadataView forwarded = {});
    net::awaitable<void> EncodeRequestBody(
        AsyncStream& stream,
        buf::MultiBuffer mb);
    net::awaitable<void> EncodeRequestBody(
        AsyncStream& stream,
        std::span<const net::const_buffer> buffers);
    net::awaitable<void> EncodeRequestBodyEOF(AsyncStream& stream);
    // Authenticates the response header on first use, then returns body
    // chunks; empty at the end of the response body.
    // Authentication/truncation and real I/O errors are terminal; a cancelled
    // read instead preserves the current header/body progress for resumption.
    net::awaitable<buf::MultiBuffer> DecodeResponse(AsyncStream& stream);

private:
    struct SessionKeys {
        BodyKey request;
        BodyKey response;
        uint8_t response_header = 0;
    };

    [[nodiscard]] static SessionKeys GenerateKeys();
    net::awaitable<void> DecodeResponseHeader(AsyncStream& stream);
    net::awaitable<buf::MultiBuffer> DecodeFirstResponse(AsyncStream& stream);

    Security security_ = Security::AES_128_GCM;
    SessionKeys keys_;
    bool request_header_sent_ = false;
    BodyEncoder request_encoder_;
    BodyDecoder response_decoder_;
    // Response header progress survives a cancelled read.
    std::array<uint8_t, 18> response_length_{};
    size_t response_length_read_ = 0;
    memory::ByteVector response_header_sealed_;
    size_t response_header_read_ = 0;
    bool response_header_received_ = false;
};

inline constexpr size_t kResponseHeaderSize = 38;
inline constexpr size_t kMaxRequestHeaderWireSize =
    42 + 38 + kMaxEncodedAddressSize + 15 + 4 + 16;

class RequestBodyReader final : public transport::MultiBufferReader {
public:
    RequestBodyReader(const VMessRequest& request, AsyncStream& stream);

    RequestBodyReader(const RequestBodyReader&) = delete;
    RequestBodyReader& operator=(const RequestBodyReader&) = delete;
    RequestBodyReader(RequestBodyReader&&) noexcept = default;
    RequestBodyReader& operator=(RequestBodyReader&&) noexcept = default;

    transport::CancellationSource& Cancellation() noexcept override {
        return stream_->Cancellation();
    }
    transport::EofAction ReadEofAction() const noexcept override {
        return is_udp_ ? transport::EofAction::WaitForPeer : stream_->ReadEofAction();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!is_udp_) {
            return decoder_.Read(*stream_);
        }
        return ReadUdpMultiBuffer();
    }

private:
    net::awaitable<buf::MultiBuffer> ReadUdpMultiBuffer();

    BodyDecoder decoder_;
    AsyncStream* stream_ = nullptr;
    bool is_udp_ = false;
    TargetAddress udp_target_;
};

// The response header is coalesced into the first body write.
class ResponseBodyWriter final : public transport::MultiBufferWriter {
public:
    ResponseBodyWriter(const VMessRequest& request,
                       const BodyKey& response,
                       AsyncStream& stream,
                       const std::array<uint8_t, kResponseHeaderSize>& response_header);

    ResponseBodyWriter(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter& operator=(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter(ResponseBodyWriter&&) noexcept = default;
    ResponseBodyWriter& operator=(ResponseBodyWriter&&) noexcept = default;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        return encoder_.WriteMultiBuffer(
            *stream_, std::move(mb), "VMess response write cancelled before start",
            response_header_, &header_sent_, &udp_target_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return encoder_.WriteBuffers(
            *stream_, buffers, "VMess response write cancelled before start",
            response_header_, &header_sent_);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return encoder_.WriteEOF(
            *stream_, "VMess response EOF cancelled before start",
            response_header_, &header_sent_);
    }

private:
    BodyEncoder encoder_;
    AsyncStream* stream_ = nullptr;
    TargetAddress udp_target_;
    std::array<uint8_t, kResponseHeaderSize> response_header_{};
    bool header_sent_ = false;
};

class ServerSession final {
public:
    explicit ServerSession(std::string_view tag);

    // Re-submit the same growing prefix until complete. RequiredHeaderBytes()
    // is the next structured boundary; zero with no request is terminal failure.
    // This step authenticates/decrypts syntax only. The inbound handshake must
    // await validator.RegisterSessionIfNew before accepting or dispatching it.
    std::pair<std::optional<VMessRequest>, size_t> DecodeRequestHeader(
        const uint8_t* data,
        size_t len,
        uint64_t trace_conn_id = 0);
    [[nodiscard]] size_t RequiredHeaderBytes() const noexcept { return required_header_bytes_; }
    [[nodiscard]] std::string_view HeaderFailureReason() const noexcept { return header_failure_reason_; }
    [[nodiscard]] const VMessRequest* AuthenticatedRejectedHeader() const noexcept {
        return !request_set_ && request_.user ? &request_ : nullptr;
    }

    void SetRequest(VMessRequest request);

    std::optional<RequestBodyReader> DecodeRequestBody(
        AsyncStream& stream);

    std::optional<ResponseBodyWriter> EncodeResponseBodyWithHeader(
        AsyncStream& stream);
private:
    std::string_view tag_;
    VMessRequest request_;
    bool request_set_ = false;
    std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential> header_user_;
    size_t required_header_bytes_ = 42;
    uint16_t header_length_ = 0;
    std::string_view header_failure_reason_;
};

}  // namespace vmess::encoding
