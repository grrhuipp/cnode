#include "proxy/vmess/encoding/body.hpp"
#include "proxy/buffered_stream_reader.hpp"
#include "proxy/vmess/session_history.hpp"
#include "transport/failure.hpp"
#include "common/scoped_cleanse.hpp"

#include "app/proxyman/inbound/user_store.hpp"
#include "app/session_group_executor.hpp"
#include "common/address_codec.hpp"
#include "common/const_buffer_span.hpp"
#include "common/eof_cancellation.hpp"
#include "common/byte_reader.hpp"
#include "common/hash_container_shrink.hpp"
#include "common/error.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/string_hash.hpp"
#include "infra/log.hpp"
#include "transport/link.hpp"

#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/siphash.h>
#include <asio/this_coro.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>
namespace proxy::vmess::encoding {

namespace {

constexpr size_t kStreamReadBatchChunks = 16;
constexpr size_t kMaxPaddingSize = 64;

// The largest length header, AEAD tag and padding must leave room for payload
// in one fixed-size Buffer.
static_assert(buf::Buffer::kSize > (2 + GCM_TAG_SIZE) + GCM_TAG_SIZE + kMaxPaddingSize);

[[noreturn]] void ThrowWriteError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

}  // namespace

BodyKey ResponseBodyKey(const BodyKey& request) {
    auto key_hash = SHA256Hash(request.key.data(), request.key.size());
    auto iv_hash = SHA256Hash(request.iv.data(), request.iv.size());
    BodyKey response;
    std::memcpy(response.key.data(), key_hash.data(), response.key.size());
    std::memcpy(response.iv.data(), iv_hash.data(), response.iv.size());
    OPENSSL_cleanse(key_hash.data(), key_hash.size());
    OPENSSL_cleanse(iv_hash.data(), iv_hash.size());
    return response;
}

BodyChunkCipher::BodyChunkCipher(const BodyOptions& options,
                                 const BodyKey& request_body,
                                 const BodyKey& direction_key)
    : payload_(options.security, direction_key.key.data(), direction_key.iv.data())
    , global_padding_((options.options & Option::GLOBAL_PADDING) != 0 &&
                      !((options.security == Security::NONE ||
                         options.security == Security::ZERO) &&
                        options.command != Command::UDP))
    , packet_mode_(options.command == Command::UDP) {
    if ((options.options & Option::AUTHENTICATED_LENGTH) != 0 &&
        (options.security == Security::AES_128_GCM ||
         options.security == Security::CHACHA20_POLY1305)) {
        const std::array<std::string_view, 1> path{"auth_len"};
        auto length_key = KDF16(request_body.key.data(), request_body.key.size(), path);
        length_.emplace(options.security, length_key.data(), request_body.iv.data());
        OPENSSL_cleanse(length_key.data(), length_key.size());
    }
    if ((options.options & Option::CHUNK_MASKING) != 0) {
        mask_.emplace(direction_key.iv.data());
    }
}

size_t BodyChunkCipher::NextPaddingSize() {
    return padding_mask() ? mask_->NextMask() % kMaxPaddingSize : 0;
}

bool BodyChunkCipher::EncodeLength(size_t chunk_size, uint8_t* out) {
    if (length_) {
        const size_t overhead = length_->Overhead();
        if (chunk_size < overhead || chunk_size - overhead > 0xFFFF) {
            return false;
        }
        const size_t plain_size = chunk_size - overhead;
        const uint8_t plain[2] = {
            static_cast<uint8_t>(plain_size >> 8),
            static_cast<uint8_t>(plain_size),
        };
        return length_->Encrypt(plain, sizeof(plain), out) ==
            static_cast<ssize_t>(LengthSize());
    }
    if (chunk_size > 0xFFFF) {
        return false;
    }
    uint16_t wire = static_cast<uint16_t>(chunk_size);
    if (mask_) {
        wire ^= mask_->NextMask();
    }
    out[0] = static_cast<uint8_t>(wire >> 8);
    out[1] = static_cast<uint8_t>(wire);
    return true;
}

std::optional<size_t> BodyChunkCipher::DecodeLength(const uint8_t* in) {
    if (length_) {
        uint8_t plain[2];
        if (length_->Decrypt(in, LengthSize(), plain) != static_cast<ssize_t>(sizeof(plain))) {
            return std::nullopt;
        }
        return static_cast<size_t>(common::LoadU16BE(&plain[0])) + length_->Overhead();
    }
    uint16_t wire = common::LoadU16BE(&in[0]);
    if (mask_) {
        wire ^= mask_->NextMask();
    }
    return wire;
}

// ============================================================================
// BodyEncoder
// ============================================================================

BodyEncoder::BodyEncoder(const BodyOptions& options,
                         const BodyKey& request_body,
                         const BodyKey& direction_key)
    : cipher_(options, request_body, direction_key) {
    const size_t reserved =
        cipher_.LengthSize() + cipher_.Overhead() + cipher_.MaxPaddingSize();
    stream_chunk_size_ = std::min(MAX_CHUNK_SIZE - cipher_.Overhead(),
                                  size_t{buf::Buffer::kSize} - reserved);
}

void BodyEncoder::CheckWritable() const {
    if (state_ == State::Failed) {
        ThrowWriteError("VMess body writer is failed");
    }
    if (state_ == State::Finished) {
        throw transport::WriteClosed();
    }
}

void BodyEncoder::Encode(const buf::MultiBuffer& payload, buf::MultiBuffer& out) {
    CheckWritable();
    if (&payload == &out) {
        throw transport::LinkError(common::ErrorCode::INVALID_ARGUMENT);
    }
    if (PacketMode() &&
        (payload.byte_size() != 0 || buf::InspectUdpDatagram(payload).Valid())) {
        ValidatePacketSize(payload.byte_size());
        const buf::ContiguousBufferView packet(payload);
        EncodeChunk(packet.Bytes(), out);
        return;
    }
    if (payload.byte_size() == 0) {
        return;
    }
    for (const buf::Buffer* buffer : payload) {
        if (buffer) {
            EncodeStream(buffer->Bytes(), out);
        }
    }
}

void BodyEncoder::Encode(std::span<const net::const_buffer> payload, buf::MultiBuffer& out) {
    CheckWritable();
    if (PacketMode()) {
        const size_t size = proxy::RequireUdpPayloadSize(
            payload, MAX_CHUNK_SIZE - cipher_.Overhead());
        ValidatePacketSize(size);
        for (const auto& buffer : payload) {
            if (buffer.size() != 0 && !buffer.data()) {
                throw transport::LinkError(common::ErrorCode::INVALID_ARGUMENT);
            }
        }
        const buf::ContiguousBufferView packet(payload);
        EncodeChunk(packet.Bytes(), out);
        return;
    }
    const bool has_data = std::any_of(payload.begin(), payload.end(),
        [](const net::const_buffer& buffer) { return buffer.data() && buffer.size() > 0; });
    if (!has_data) {
        return;
    }
    for (const net::const_buffer& buffer : payload) {
        if (buffer.data() && buffer.size() > 0) {
            EncodeStream(std::span<const uint8_t>(
                static_cast<const uint8_t*>(buffer.data()), buffer.size()), out);
        }
    }
}

void BodyEncoder::EncodeStream(std::span<const uint8_t> bytes, buf::MultiBuffer& out) {
    while (!bytes.empty()) {
        const size_t chunk_size = std::min(bytes.size(), stream_chunk_size_);
        EncodeChunk(bytes.first(chunk_size), out);
        bytes = bytes.subspan(chunk_size);
    }
}

size_t BodyEncoder::EncodeEndTo(std::span<uint8_t, 128> out) {
    if (state_ == State::Finished) return 0;
    CheckWritable();
    try {
        const size_t padding = cipher_.NextPaddingSize();
        const size_t length_size = cipher_.LengthSize();
        const size_t capacity = length_size + cipher_.Overhead() + padding;
        if (capacity > out.size()) {
            ThrowWriteError("VMess EOF chunk exceeds inline buffer");
        }
        const size_t written = SealChunkTo({}, length_size, padding, out.data());
        Finish();
        return written;
    } catch (...) {
        Abort();
        throw;
    }
}

net::awaitable<void> BodyEncoder::WriteFirstEncodedChunks(
    transport::AsyncStream& stream,
    buf::MultiBuffer chunks,
    std::span<const uint8_t> first_header,
    bool& header_sent) {
    header_sent = true;
    common::ConstBufferSpanBuilder<1 + buf::MultiBuffer::kInlineCapacity> framed;
    framed.Append(net::buffer(first_header.data(), first_header.size()));
    framed.AppendMultiBuffer(chunks);
    co_await stream.WriteBuffers(framed.Span());
    chunks.clear();
}

template <typename Payload>
net::awaitable<void> BodyEncoder::WriteEncoded(
    transport::AsyncStream& stream,
    Payload payload,
    const char* cancel_what,
    std::span<const uint8_t> first_header,
    bool* header_sent,
    [[maybe_unused]] const common::TargetAddress* udp_target) {
    constexpr bool kOwnsPayload = std::is_same_v<Payload, buf::MultiBuffer>;
    CheckWritable();
    if ((co_await net::this_coro::cancellation_state).cancelled() !=
        net::cancellation_type::none) {
        throw IoSystemError(io_error::operation_aborted, cancel_what);
    }
    bool frame_generated = false;
    try {
        if constexpr (kOwnsPayload) {
            if (udp_target && PacketMode()) {
                ValidateFixedUdpDatagram(payload, *udp_target);
            }
        }
        buf::MultiBuffer chunks;
        Encode(payload, chunks);
        if constexpr (kOwnsPayload) {
            payload.clear();
        }
        frame_generated = chunks.byte_size() != 0;
        if (frame_generated) {
            if (header_sent && !*header_sent) {
                co_await WriteFirstEncodedChunks(
                    stream, std::move(chunks), first_header, *header_sent);
            } else {
                co_await stream.WriteMultiBuffer(std::move(chunks));
            }
        }
    } catch (const transport::WriteClosed&) {
        Finish();
        throw;
    } catch (...) {
        if (frame_generated || Failed()) {
            Abort();
            stream.CloseAbortive();
        }
        throw;
    }
}

net::awaitable<void> BodyEncoder::WriteMultiBuffer(
    transport::AsyncStream& stream,
    buf::MultiBuffer mb,
    const char* cancel_what,
    std::span<const uint8_t> first_header,
    bool* header_sent,
    const common::TargetAddress* udp_target) {
    return WriteEncoded(stream, std::move(mb), cancel_what, first_header, header_sent,
                        udp_target);
}

net::awaitable<void> BodyEncoder::WriteBuffers(
    transport::AsyncStream& stream,
    std::span<const net::const_buffer> buffers,
    const char* cancel_what,
    std::span<const uint8_t> first_header,
    bool* header_sent) {
    return WriteEncoded(stream, buffers, cancel_what, first_header, header_sent, nullptr);
}
net::awaitable<void> BodyEncoder::WriteEOF(
    transport::AsyncStream& stream,
    const char* cancel_what,
    std::span<const uint8_t> first_header,
    bool* header_sent) {
    if (Finished()) co_return;
    CheckWritable();
    if ((co_await net::this_coro::cancellation_state).cancelled() !=
        net::cancellation_type::none) {
        throw IoSystemError(io_error::operation_aborted, cancel_what);
    }
    bool frame_generated = false;
    try {
        std::array<uint8_t, 128> eof_chunk{};
        const size_t eof_len = EncodeEndTo(eof_chunk);
        if (eof_len == 0) co_return;
        frame_generated = true;
        common::ConstBufferSpanBuilder<2> buffers;
        if (header_sent && !*header_sent) {
            *header_sent = true;
            buffers.Append(net::buffer(first_header.data(), first_header.size()));
        }
        buffers.Append(net::buffer(eof_chunk.data(), eof_len));
        co_await stream.WriteBuffers(buffers.Span());
    } catch (const transport::WriteClosed&) {
        Finish();
        throw;
    } catch (...) {
        if (frame_generated || Failed()) {
            Abort();
            stream.CloseAbortive();
        }
        throw;
    }
}

void BodyEncoder::ValidatePacketSize(size_t size) const {
    // Standard VMess framing uses an empty body exclusively as EOF.
    if (size == 0) {
        throw transport::LinkError(common::ErrorCode::NOT_SUPPORTED);
    }
    if (size > MAX_CHUNK_SIZE - cipher_.Overhead()) {
        throw transport::LinkError(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
}

size_t BodyEncoder::SealChunkTo(std::span<const uint8_t> bytes,
                                size_t length_size,
                                size_t padding,
                                uint8_t* dst) {
    const ssize_t sealed = cipher_.Payload().Encrypt(
        bytes.data(), bytes.size(), dst + length_size);
    if (sealed < 0) {
        ThrowWriteError("VMess body encrypt failed");
    }
    const size_t chunk_size = static_cast<size_t>(sealed) + padding;
    if (!cipher_.EncodeLength(chunk_size, dst)) {
        ThrowWriteError("VMess body length encode failed");
    }
    // Padding must never expose recycled buffer contents.
    if (padding > 0 &&
        RAND_bytes(dst + length_size + sealed, static_cast<int>(padding)) != 1) {
        ThrowWriteError("VMess body padding generation failed");
    }
    return length_size + chunk_size;
}

void BodyEncoder::EncodeChunk(std::span<const uint8_t> bytes, buf::MultiBuffer& out) try {
    const size_t padding = cipher_.NextPaddingSize();
    const size_t length_size = cipher_.LengthSize();
    const size_t capacity = length_size + bytes.size() + cipher_.Overhead() + padding;

    buf::ContiguousWriteBuffer encoded;
    uint8_t* dst = encoded.Prepare(capacity);
    encoded.AppendTo(SealChunkTo(bytes, length_size, padding, dst), out);
} catch (...) {
    Abort();
    throw;
}

// ============================================================================
// BodyDecoder
// ============================================================================

BodyDecoder::BodyDecoder(const BodyOptions& options,
                         const BodyKey& request_body,
                         const BodyKey& direction_key)
    : cipher_(options, request_body, direction_key) {}

net::awaitable<bool> BodyDecoder::ReadExact(transport::MultiBufferReader& src,
                                            std::span<uint8_t> out,
                                            size_t& filled) {
    if (state_ == State::Failed) {
        Fail("VMess body reader is failed");
    }
    if (state_ == State::Finished) {
        co_return false;
    }
    co_return co_await proxy::BufferedStreamReader::ReadExactFrom(
        src, pending_read_, out.data(), out.size(), &filled);
}

net::awaitable<buf::MultiBuffer> BodyDecoder::Read(transport::MultiBufferReader& src) {
    // A later chunk in a stream batch can suspend after earlier chunks decoded.
    // Keep that output owned by the decoder until this invocation returns it.
    try {
        if (cipher_.PacketMode()) {
            co_return co_await ReadChunk(src);
        }
        while (pending_output_chunks_ < kStreamReadBatchChunks) {
            if (pending_output_.byte_size() != 0 && !header_decoded_ && header_read_ == 0 &&
                pending_read_.byte_size() == 0) {
                break;
            }
            buf::MultiBuffer chunk = co_await ReadChunk(src);
            if (chunk.byte_size() == 0) {
                break;
            }
            chunk.MoveTo(pending_output_);
            ++pending_output_chunks_;
        }
        pending_output_chunks_ = 0;
        co_return std::move(pending_output_);
    } catch (const IoSystemError& error) {
        if (error.code() != io_error::operation_aborted) {
            Abort();
        }
        throw;
    } catch (...) {
        Abort();
        throw;
    }
}

net::awaitable<buf::MultiBuffer> BodyDecoder::ReadChunk(transport::MultiBufferReader& src) {
    if (state_ == State::Failed) {
        Fail("VMess body reader is failed");
    }
    if (state_ == State::Finished) {
        co_return buf::MultiBuffer{};
    }

    const size_t overhead = cipher_.Overhead();
    if (!header_decoded_) {
        const size_t length_size = cipher_.LengthSize();
        const auto header_span = std::span<uint8_t>(header_.data(), length_size);
        if (!proxy::BufferedStreamReader::ReadBufferedFrom(pending_read_, header_span.data(), header_span.size(), header_read_) &&
            !co_await ReadExact(src, header_span, header_read_)) {
            if (header_read_ != 0) {
                Fail("VMess body length truncated");
            }
            state_ = State::Finished;
            FinishRecord();
            co_return buf::MultiBuffer{};
        }
        padding_len_ = cipher_.NextPaddingSize();
        const auto chunk_len = cipher_.DecodeLength(header_.data());
        if (!chunk_len) {
            Fail("VMess body length authentication failed");
        }
        if (*chunk_len < overhead + padding_len_ ||
            *chunk_len > MAX_CHUNK_SIZE + overhead + kMaxPaddingSize) {
            LOG_NET_DEBUG("invalid chunk length {} overhead={} padding={}",
                          *chunk_len, overhead, padding_len_);
            Fail("VMess body chunk length invalid");
        }
        chunk_len_ = *chunk_len;
        header_decoded_ = true;
    }

    const size_t chunk_len = chunk_len_;
    if (chunk_len == overhead + padding_len_) {
        // The EOF chunk is at most a tag plus 63 padding bytes; the decoded
        // length no longer needs the inline header storage.
        const auto eof_span = std::span<uint8_t>(header_.data(), chunk_len);
        if (!proxy::BufferedStreamReader::ReadBufferedFrom(pending_read_, eof_span.data(), eof_span.size(), body_read_) &&
            !co_await ReadExact(src, eof_span, body_read_)) {
            Fail("VMess body EOF chunk truncated");
        }
        if (overhead > 0 &&
            cipher_.Payload().Decrypt(header_.data(), overhead, header_.data()) != 0) {
            Fail("VMess body EOF authentication failed");
        }
        state_ = State::Finished;
        FinishRecord();
        co_return buf::MultiBuffer{};
    }

    const size_t data_len = chunk_len - padding_len_;
    if (body_read_ == 0 && read_buffer_.Empty()) {
        if (auto sealed = pending_read_.TakeFrontIfLen(chunk_len)) {
            const ssize_t opened = cipher_.Payload().Decrypt(
                sealed->Bytes().data(), data_len, sealed->Bytes().data());
            if (opened < 0) {
                Fail("VMess body authentication failed");
            }
            sealed->end = sealed->start + static_cast<uint32_t>(opened);
            FinishRecord();
            co_return buf::MultiBuffer{std::move(sealed)};
        }
        (void)read_buffer_.Prepare(chunk_len);
    }

    uint8_t* sealed = read_buffer_.Data();
    const auto body_span = std::span<uint8_t>(sealed, chunk_len);
    if (!proxy::BufferedStreamReader::ReadBufferedFrom(pending_read_, body_span.data(), body_span.size(), body_read_) &&
        !co_await ReadExact(src, body_span, body_read_)) {
        Fail("VMess body chunk truncated");
    }
    const ssize_t opened = cipher_.Payload().Decrypt(sealed, data_len, sealed);
    if (opened < 0) {
        Fail("VMess body authentication failed");
    }
    buf::MultiBuffer out;
    const bool appended = read_buffer_.TryAppendTo(static_cast<size_t>(opened), out);
    FinishRecord();
    if (!appended) {
        throw std::bad_alloc();
    }
    co_return out;
}

void BodyDecoder::Abort() noexcept {
    state_ = State::Failed;
    pending_read_.clear();
    pending_output_.clear();
    pending_output_chunks_ = 0;
    FinishRecord();
}

void BodyDecoder::Fail(const char* what) {
    Abort();
    throw IoSystemError(io_error::connection_reset, what);
}

void BodyDecoder::FinishRecord() noexcept {
    header_read_ = 0;
    body_read_ = 0;
    chunk_len_ = 0;
    padding_len_ = 0;
    header_decoded_ = false;
    read_buffer_.Reset();
    pending_read_.ReleaseIfIdle();
}


// ============================================================================
// ClientSession
// ============================================================================

namespace {

// Version, body IV/key, response header, options, security, reserved,
// command, largest address, optional padding and FNV-1a checksum.
constexpr size_t kRequestHeaderMax =
    1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + common::kMaxEncodedAddressSize + 15 + 4;
// AuthID, sealed length, connection nonce, sealed header.
constexpr size_t kRequestPacketMax = 16 + 18 + 8 + kRequestHeaderMax + 16;
constexpr size_t kResponseHeaderMax = 1024;
[[nodiscard]] constexpr uint8_t ClientOptions(Security security) noexcept {
    uint8_t options = Option::CHUNK_STREAM | Option::CHUNK_MASKING;
    if (security != Security::NONE && security != Security::ZERO) {
        options |= Option::GLOBAL_PADDING;
    }
    return options;
}

tl::expected<size_t, common::ErrorCode> BuildRequestHeaderPacket(
    const MemoryAccount& user,
    const AES_KEY& auth_id_key,
    const common::TargetAddress& target,
    Security security,
    Command command,
    const BodyKey& request_body,
    uint8_t response_header,
    common::ForwardedMetadataView forwarded,
    std::array<uint8_t, kRequestPacketMax>& packet) {
    std::array<uint8_t, kRequestHeaderMax> header{};
    common::ScopedCleanse cleanse_header{header};
    common::ByteWriter writer(header.data(), header.size());
    writer.WriteU8(VERSION);
    writer.WriteBytes(request_body.iv.data(), request_body.iv.size());
    writer.WriteBytes(request_body.key.data(), request_body.key.size());
    writer.WriteU8(response_header);
    writer.WriteU8(ClientOptions(security));
    // High nibble: header padding length, always zero here.
    writer.WriteU8(static_cast<uint8_t>(security));
    writer.WriteU8(0);
    writer.WriteU8(static_cast<uint8_t>(command));
    if (!writer.Ok()) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    size_t header_len = writer.Position();
    if (command == Command::TCP || command == Command::UDP) {
        if (!target.IsValid() || (target.IsDomain() && target.host.size() > 253)) {
            return tl::unexpected(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        const size_t address_size = common::EncodeAddressTo(
            target, header.data() + header_len, header.size() - header_len,
            common::AddressWireFormat::PortFirst, forwarded);
        if (address_size == 0) {
            return tl::unexpected(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        header_len += address_size;
    } else if (command != Command::Mux) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    const uint32_t checksum = common::Fnv1a32(std::span<const uint8_t>(header.data(), header_len));
    header[header_len++] = static_cast<uint8_t>(checksum >> 24);
    header[header_len++] = static_cast<uint8_t>(checksum >> 16);
    header[header_len++] = static_cast<uint8_t>(checksum >> 8);
    header[header_len++] = static_cast<uint8_t>(checksum);

    const int64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint8_t* auth_id = packet.data();
    uint8_t* sealed_length = packet.data() + 16;
    uint8_t* connection_nonce = packet.data() + kConnectionNonceOffset;
    uint8_t* sealed_header = packet.data() + kRequestHeaderPrefixSize;
    GenerateAuthID(auth_id_key, timestamp, auth_id);
    if (RAND_bytes(connection_nonce, 8) != 1) {
        return tl::unexpected(common::ErrorCode::INTERNAL);
    }
    const std::span<const uint8_t, 16> auth_id_view(auth_id, 16);
    const std::span<const uint8_t, 8> nonce_view(connection_nonce, 8);

    const auto length_key = RequestHeaderLengthKey(user.cmd_key, auth_id_view, nonce_view);
    const uint8_t length_plain[2] = {
        static_cast<uint8_t>(header_len >> 8),
        static_cast<uint8_t>(header_len),
    };
    if (!proxy::SealScatterOneShotAead(EVP_aead_aes_128_gcm(), {length_key.key.data(), 16}, {length_key.nonce.data(), 12}, {length_plain, sizeof(length_plain)}, {auth_id, 16}, sealed_length, {sealed_length + 2, 16})) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    const auto payload_key = RequestHeaderPayloadKey(user.cmd_key, auth_id_view, nonce_view);
    if (!proxy::SealScatterOneShotAead(EVP_aead_aes_128_gcm(), {payload_key.key.data(), 16}, {payload_key.nonce.data(), 12}, {header.data(), header_len}, {auth_id, 16}, sealed_header, {sealed_header + header_len, 16})) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    return kRequestHeaderPrefixSize + header_len + GCM_TAG_SIZE;
}

[[noreturn]] void ThrowResponseHeaderError() {
    throw IoSystemError(io_error::connection_reset, "VMess client read response header failed");
}

}  // namespace

ClientSession::SessionKeys ClientSession::GenerateKeys() {
    std::array<uint8_t, 33> random_bytes{};
    if (RAND_bytes(random_bytes.data(), static_cast<int>(random_bytes.size())) != 1) {
        throw IoSystemError(io_error::operation_aborted, "VMess client session random init failed");
    }
    SessionKeys keys;
    std::memcpy(keys.request.key.data(), random_bytes.data(), 16);
    std::memcpy(keys.request.iv.data(), random_bytes.data() + 16, 16);
    keys.response_header = random_bytes[32];
    keys.response = ResponseBodyKey(keys.request);
    OPENSSL_cleanse(random_bytes.data(), random_bytes.size());
    return keys;
}

ClientSession::ClientSession(Security security, Command command)
    : security_(security)
    , keys_(GenerateKeys())
    , request_encoder_(BodyOptions{security, ClientOptions(security), command},
                       keys_.request, keys_.request)
    , response_decoder_(BodyOptions{security, ClientOptions(security), command},
                        keys_.request, keys_.response) {}

net::awaitable<VMessHandshakeResult> ClientSession::EncodeRequestHeader(
    transport::AsyncStream& stream,
    const MemoryAccount& user,
    const AES_KEY& auth_id_key,
    const common::TargetAddress& target,
    Command command,
    common::ForwardedMetadataView forwarded) {
    if (request_encoder_.Failed()) {
        co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    }
    if (request_header_sent_) {
        co_return VMessHandshakeResult{};
    }
    try {
        request_encoder_.CheckWritable();
    } catch (const transport::WriteClosed&) {
        co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    }
    if ((co_await net::this_coro::cancellation_state).cancelled() !=
        net::cancellation_type::none) {
        co_return tl::unexpected(common::ErrorCode::CANCELLED);
    }
    std::array<uint8_t, kRequestPacketMax> packet{};
    common::ScopedCleanse cleanse_packet{packet};
    auto built = BuildRequestHeaderPacket(
        user, auth_id_key, target, security_, command, keys_.request,
        keys_.response_header, forwarded, packet);
    if (!built) {
        co_return tl::unexpected(built.error());
    }
    OPENSSL_cleanse(keys_.request.key.data(), keys_.request.key.size());
    OPENSSL_cleanse(keys_.request.iv.data(), keys_.request.iv.size());
    auto fail_request = [&]() {
        request_encoder_.Abort();
        stream.CloseAbortive();
    };
    try {
        const std::array<net::const_buffer, 1> buffers{net::buffer(packet.data(), *built)};
        co_await stream.WriteBuffers(buffers);
    } catch (const transport::WriteClosed&) {
        request_encoder_.Finish();
        co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    } catch (...) {
        fail_request();
        co_return tl::unexpected(transport::ClassifyFailure(
            std::current_exception(), common::ErrorCode::SOCKET_WRITE_FAILED));
    }
    request_header_sent_ = true;
    co_return VMessHandshakeResult{};
}

net::awaitable<void> ClientSession::EncodeRequestBody(
    transport::AsyncStream& stream,
    buf::MultiBuffer mb) {
    return request_encoder_.WriteMultiBuffer(
        stream, std::move(mb), "VMess request write cancelled before start");
}

net::awaitable<void> ClientSession::EncodeRequestBody(
    transport::AsyncStream& stream,
    std::span<const net::const_buffer> buffers) {
    return request_encoder_.WriteBuffers(
        stream, buffers, "VMess request write cancelled before start");
}

net::awaitable<void> ClientSession::EncodeRequestBodyEOF(transport::AsyncStream& stream) {
    return request_encoder_.WriteEOF(
        stream, "VMess request EOF cancelled before start");
}

net::awaitable<void> ClientSession::DecodeResponseHeader(transport::AsyncStream& stream) {
    auto reset_header_state = [this]() noexcept {
        std::vector<uint8_t>{}.swap(response_header_sealed_);
        response_length_read_ = 0;
        response_header_read_ = 0;
    };
    auto fail_response = [&]() noexcept {
        response_decoder_.Abort();
        reset_header_state();
        OPENSSL_cleanse(keys_.response.key.data(), keys_.response.key.size());
        OPENSSL_cleanse(keys_.response.iv.data(), keys_.response.iv.size());
    };
    try {
        if (response_header_sealed_.empty()) {
            if (!co_await response_decoder_.ReadExact(
                    stream, response_length_, response_length_read_)) {
                ThrowResponseHeaderError();
            }
            const auto length_key = ResponseHeaderLengthKey(keys_.response.key, keys_.response.iv);
            std::array<uint8_t, 2> length{};
            size_t length_size = 0;
            if (!proxy::OpenOneShotAead(EVP_aead_aes_128_gcm(), {length_key.key.data(), 16}, {length_key.nonce.data(), length_key.nonce.size()}, {response_length_.data(), response_length_.size()}, {}, {length.data(), length.size()}, length_size) ||
                length_size != length.size()) {
                ThrowResponseHeaderError();
            }
            const size_t header_len = common::LoadU16BE(&length[0]);
            if (header_len < 4 || header_len > kResponseHeaderMax) {
                ThrowResponseHeaderError();
            }
            response_header_sealed_.resize(header_len + 16);
        }

        if (!co_await response_decoder_.ReadExact(
                stream, response_header_sealed_, response_header_read_)) {
            ThrowResponseHeaderError();
        }
        const auto payload_key = ResponseHeaderPayloadKey(keys_.response.key, keys_.response.iv);
        const size_t header_len = response_header_sealed_.size() - 16;
        size_t opened = 0;
        if (!proxy::OpenOneShotAead(EVP_aead_aes_128_gcm(), {payload_key.key.data(), 16}, {payload_key.nonce.data(), payload_key.nonce.size()}, {response_header_sealed_.data(), response_header_sealed_.size()}, {}, {response_header_sealed_.data(), header_len}, opened) ||
            opened != header_len ||
            response_header_sealed_[0] != keys_.response_header) {
            ThrowResponseHeaderError();
        }
        response_header_received_ = true;
        OPENSSL_cleanse(keys_.response.key.data(), keys_.response.key.size());
        OPENSSL_cleanse(keys_.response.iv.data(), keys_.response.iv.size());
        reset_header_state();
    } catch (const IoSystemError& error) {
        if (error.code() != io_error::operation_aborted) {
            fail_response();
        }
        throw;
    } catch (...) {
        fail_response();
        throw;
    }
}

net::awaitable<buf::MultiBuffer> ClientSession::DecodeResponse(transport::AsyncStream& stream) {
    if (response_header_received_) {
        return response_decoder_.Read(stream);
    }
    return DecodeFirstResponse(stream);
}

net::awaitable<buf::MultiBuffer> ClientSession::DecodeFirstResponse(transport::AsyncStream& stream) {
    if (!response_header_received_) {
        co_await DecodeResponseHeader(stream);
    }
    co_return co_await response_decoder_.Read(stream);
}

// ============================================================================
// ServerSession
// ============================================================================

namespace {

// AuthID (16) + sealed length (2 + 16) + connection nonce (8).

[[nodiscard]] bool IsSupportedSecurity(Security security) noexcept {
    switch (security) {
    case Security::AES_128_GCM:
    case Security::CHACHA20_POLY1305:
    case Security::NONE:
    case Security::ZERO:
        return true;
    default:
        return false;
    }
}

bool ParseDecryptedHeader(const uint8_t* data, size_t len,
                          uint64_t trace_conn_id,
                          VMessRequest& request) {
    static constexpr size_t kFixedHeaderSize = kRequestHeaderFixedSize;
    if (len < kFixedHeaderSize + 4) {
        LOG_CONN_TRACE(trace_conn_id, "decrypted header too short len={} min={}",
                         len,
                         kFixedHeaderSize + 4);
        return false;
    }

    common::ByteReader reader(data, len);

    const uint8_t version = reader.ReadU8();
    if (!reader.Ok() || version != VERSION) {
        LOG_CONN_DEBUG(trace_conn_id, "unsupported version {}", version);
        return false;
    }

    auto iv_span = reader.ReadBytes(16);
    if (!reader.Ok()) return false;
    std::memcpy(request.body_iv.data(), iv_span.data(), 16);

    auto key_span = reader.ReadBytes(16);
    if (!reader.Ok()) return false;
    std::memcpy(request.body_key.data(), key_span.data(), 16);

    request.response_header = reader.ReadU8();
    request.options = reader.ReadU8();

    uint8_t ps = reader.ReadU8();
    const uint8_t padding_len = (ps >> 4) & 0x0F;
    request.security = static_cast<Security>(ps & 0x0F);
    // Reject before routing: an unknown body security can never be framed.
    if (!IsSupportedSecurity(request.security)) {
        LOG_CONN_DEBUG(trace_conn_id, "unsupported security {}", static_cast<int>(request.security));
        return false;
    }

    reader.Skip(1);

    request.command = static_cast<Command>(reader.ReadU8());
    if (!reader.Ok()) return false;

    if (request.command == Command::Mux) {
        request.target = common::TargetAddress("v1.mux.cool", 0);
    } else if (request.command == Command::TCP || request.command == Command::UDP) {
        auto address = common::DecodeAddress(
            std::span(data + reader.Position(), reader.Remaining()),
            common::AddressWireFormat::PortFirst,
            {.require_non_empty_domain = true, .allow_metadata = true});
        if (address.status != common::AddressDecodeStatus::Complete) return false;
        reader.Skip(address.consumed);
        request.target = std::move(address.target);
        request.forwarded = std::move(address.forwarded);
        if (!request.target.IsValid()) return false;
    } else {
        LOG_CONN_DEBUG(trace_conn_id, "unsupported command {}", static_cast<int>(request.command));
        return false;
    }

    reader.Skip(padding_len);
    if (!reader.Ok()) return false;

    size_t pos = reader.Position();
    if (pos + 4 != len) return false;

    uint32_t expected_fnv = common::Fnv1a32(std::span<const uint8_t>(data, pos));
    uint32_t actual_fnv = reader.ReadU32BE();

    if (!reader.Ok() || expected_fnv != actual_fnv) {
        LOG_CONN_DEBUG(trace_conn_id, "request header checksum mismatch");
        return false;
    }

    LOG_CONN_TRACE(trace_conn_id, "header decoded target={} command={} security={} options={:#04x} padding={}",
                     request.target,
                     static_cast<int>(request.command),
                     static_cast<int>(request.security),
                     static_cast<int>(request.options),
                     padding_len);

    return true;
}

// `packet` starts at the AuthID and holds the whole sealed header.
bool OpenRequestHeader(const uint8_t* packet,
                       std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential>& user,
                       size_t header_len,
                       uint64_t trace_conn_id,
                       VMessRequest& request,
                       std::string_view& failure_reason) {
    std::array<uint8_t, kRequestHeaderMax> plain{};
    if (header_len > plain.size()) {
        failure_reason = "invalid authenticated request header";
        return false;
    }
    const auto key = RequestHeaderPayloadKey(
        user->cmd_key,
        std::span<const uint8_t, 16>(packet, 16),
        std::span<const uint8_t, 8>(packet + kConnectionNonceOffset, 8));
    common::ScopedCleanse cleanse_plain{plain};
    size_t written = 0;
    if (!proxy::OpenOneShotAead(EVP_aead_aes_128_gcm(), {key.key.data(), 16}, {key.nonce.data(), key.nonce.size()}, {packet + kRequestHeaderPrefixSize, header_len + 16}, {packet, 16}, {plain.data(), header_len}, written)) {
        failure_reason = "authentication failed: request header integrity check failed";
        LOG_CONN_DEBUG(trace_conn_id, "request header authentication failed");
        return false;
    }
    request.user = std::move(user);
    if (!ParseDecryptedHeader(plain.data(), written, trace_conn_id, request)) {
        failure_reason = "invalid authenticated request header";
        return false;
    }
    return true;
}

[[nodiscard]] BodyOptions RequestBodyOptions(const VMessRequest& request) noexcept {
    return BodyOptions{request.security, request.options, request.command};
}

[[nodiscard]] BodyKey RequestBodyKey(const VMessRequest& request) noexcept {
    return BodyKey{request.body_key, request.body_iv};
}

bool BuildResponseHeader(const VMessRequest& request,
                         const BodyKey& response,
                         std::array<uint8_t, kResponseHeaderSize>& out) {
    // xray-core does not echo request body options in the response header.
    const uint8_t payload[4] = {request.response_header, 0, 0, 0};
    const uint8_t length[2] = {0, sizeof(payload)};

    const auto length_key = ResponseHeaderLengthKey(response.key, response.iv);
    if (!proxy::SealScatterOneShotAead(EVP_aead_aes_128_gcm(), {length_key.key.data(), 16}, {length_key.nonce.data(), 12}, {length, sizeof(length)}, {}, out.data(), {out.data() + 2, 16})) {
        return false;
    }
    const auto payload_key = ResponseHeaderPayloadKey(response.key, response.iv);
    return proxy::SealScatterOneShotAead(EVP_aead_aes_128_gcm(), {payload_key.key.data(), 16}, {payload_key.nonce.data(), 12}, {payload, sizeof(payload)}, {}, out.data() + 18, {out.data() + 22, 16});
}

}  // namespace

RequestBodyReader::RequestBodyReader(const VMessRequest& request,
                                     transport::AsyncStream& stream)
    : decoder_(RequestBodyOptions(request), RequestBodyKey(request),
               RequestBodyKey(request))
    , stream_(&stream)
    , is_udp_(request.command == Command::UDP)
    , udp_target_(is_udp_ ? request.target : common::TargetAddress{}) {}

net::awaitable<buf::MultiBuffer> RequestBodyReader::ReadUdpMultiBuffer() {
    auto mb = co_await decoder_.Read(*stream_);
    if (mb.byte_size() != 0 && !buf::SetUdpTarget(mb, udp_target_)) {
        throw std::bad_alloc();
    }
    co_return mb;
}

ResponseBodyWriter::ResponseBodyWriter(
    const VMessRequest& request,
    const BodyKey& response,
    transport::AsyncStream& stream,
    const std::array<uint8_t, kResponseHeaderSize>& response_header)
    : encoder_(RequestBodyOptions(request), RequestBodyKey(request), response)
    , stream_(&stream)
    , udp_target_(request.command == Command::UDP ? request.target : common::TargetAddress{})
    , response_header_(response_header) {}

ServerSession::ServerSession(std::string_view tag)
    : tag_(tag), state_(Pending{}) {}

std::pair<std::optional<VMessRequest>, size_t> ServerSession::DecodeRequestHeader(
    const uint8_t* data, size_t len, uint64_t trace_conn_id) {
    auto* pending_ptr = std::get_if<Pending>(&state_);
    if (!pending_ptr) return {std::nullopt, 0};
    auto& pending = *pending_ptr;
    if (len < kRequestHeaderPrefixSize) {
        required_header_bytes_ = kRequestHeaderPrefixSize;
        return {std::nullopt, 0};
    }
    const std::span<const uint8_t, 16> auth_id(data, 16);
    if (!pending.user) {
        pending.user = FindByAuthIDForTag(tag_, auth_id.data());
        if (!pending.user) {
            header_failure_reason_ = "authentication failed: no acceptable AuthID";
            required_header_bytes_ = 0;
            return {std::nullopt, 0};
        }
        const auto key = RequestHeaderLengthKey(
            pending.user->cmd_key, auth_id, std::span<const uint8_t, 8>(data + kConnectionNonceOffset, 8));
        std::array<uint8_t, 2> plain{};
        size_t written = 0;
        if (!proxy::OpenOneShotAead(EVP_aead_aes_128_gcm(), {key.key.data(), 16}, {key.nonce.data(), key.nonce.size()}, {data + 16, 18}, {auth_id.data(), auth_id.size()}, {plain.data(), plain.size()}, written) ||
            written != plain.size()) {
            header_failure_reason_ = "authentication failed: header length integrity check failed";
            pending.user.reset();
            required_header_bytes_ = 0;
            return {std::nullopt, 0};
        }
        pending.header_length = common::LoadU16BE(&plain[0]);
        constexpr size_t kMinRequestHeaderLength = kRequestHeaderFixedSize + kRequestHeaderChecksumSize;
        if (pending.header_length < kMinRequestHeaderLength ||
            pending.header_length > kRequestHeaderMax) {
            header_failure_reason_ = "invalid authenticated request header";
            pending.user.reset();
            required_header_bytes_ = 0;
            return {std::nullopt, 0};
        }
        required_header_bytes_ =
            kRequestHeaderPrefixSize + static_cast<size_t>(pending.header_length) + 16;
    }
    if (len < required_header_bytes_) return {std::nullopt, 0};

    VMessRequest request;
    const size_t consumed = required_header_bytes_;
    required_header_bytes_ = 0;
    if (!OpenRequestHeader(data, pending.user, pending.header_length, trace_conn_id, request,
                           header_failure_reason_)) {
        if (request.user) {
            state_ = Rejected{std::move(request.user), request.command, std::move(request.target)};
        } else {
            pending.user.reset();
        }
        LOG_CONN_DEBUG(trace_conn_id, "request rejected > {}", header_failure_reason_);
        return {std::nullopt, 0};
    }
    return {std::move(request), consumed};
}

void ServerSession::SetRequest(VMessRequest request) {
    state_ = Accepted{std::move(request)};
}

tl::expected<RequestBodyReader, common::ErrorCode> ServerSession::DecodeRequestBody(
    transport::AsyncStream& stream) {
    const auto* accepted = std::get_if<Accepted>(&state_);
    if (!accepted) return tl::unexpected(common::ErrorCode::INTERNAL);
    try {
        return RequestBodyReader(accepted->request, stream);
    } catch (const std::bad_alloc&) {
        return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
    }
}

tl::expected<ResponseBodyWriter, common::ErrorCode> ServerSession::EncodeResponseBodyWithHeader(
    transport::AsyncStream& stream) {
    const auto* accepted = std::get_if<Accepted>(&state_);
    if (!accepted) return tl::unexpected(common::ErrorCode::INTERNAL);
    try {
        const auto& request = accepted->request;
        const BodyKey response = ResponseBodyKey(RequestBodyKey(request));
        std::array<uint8_t, kResponseHeaderSize> response_header{};
        if (!BuildResponseHeader(request, response, response_header))
            return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
        return ResponseBodyWriter(request, response, stream, response_header);
    } catch (const std::bad_alloc&) {
        return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
    }
}
}  // namespace proxy::vmess::encoding

namespace proxy::vmess {

namespace {

using SessionKey = std::array<uint8_t, 32>;


struct alignas(64) HotUserCache {
    static constexpr size_t kMaxHotUsers = 32;
    static constexpr int64_t kWindowSeconds = 300;
    using Credential = proxyman::inbound::UserStore::VmessCredential;
    using AuthIDLookupTable = proxyman::inbound::UserStore::VmessUserMap;

    struct HotEntry {
        const Credential* user = nullptr;
        const AuthIDLookupTable* table = nullptr;
        int64_t last_seen = 0;
    };

    std::array<HotEntry, kMaxHotUsers> entries{};
    size_t size = 0;
    uint64_t view_revision = 0;
    int64_t last_cleanup = 0;

    void Touch(const Credential* user,
               const AuthIDLookupTable* table,
               int64_t now) noexcept {
        const auto begin = entries.begin();
        const auto end = begin + size;
        for (auto it = begin; it != end; ++it) {
            if (it->user == user) {
                HotEntry entry = *it;
                entry.table = table;
                entry.last_seen = now;
                if (it != begin) {
                    std::move_backward(begin, it, it + 1);
                    entries.front() = entry;
                } else {
                    *it = entry;
                }
                return;
            }
        }

        const size_t shift = std::min(size, kMaxHotUsers - 1);
        if (shift > 0) {
            std::move_backward(begin, begin + shift, begin + shift + 1);
        }
        entries.front() = HotEntry{user, table, now};
        if (size < kMaxHotUsers) {
            ++size;
        }
    }

    void Cleanup(int64_t now) noexcept {
        size_t write = 0;
        for (size_t read = 0; read < size; ++read) {
            if (entries[read].last_seen + kWindowSeconds >= now) {
                if (write != read) {
                    entries[write] = entries[read];
                }
                ++write;
            }
        }
        size = write;
    }

    void Clear() noexcept {
        size = 0;
    }
};

static HotUserCache& ThreadHotCache() noexcept {
    thread_local HotUserCache cache;
    return cache;
}

struct HistoryService final : net::execution_context::service {
    inline static net::execution_context::id id;
    explicit HistoryService(net::execution_context& context) : service(context) {}
    void shutdown() override {}
    SessionHistory history;
};

}  // namespace

std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential>
FindByAuthIDForTag(
    std::string_view tag,
    const uint8_t* auth_id,
    int64_t* out_timestamp) {

    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto tryUser = [&](const proxyman::inbound::UserStore::VmessCredential& user) -> bool {
        std::array<uint8_t, 16> plaintext{};
        AES_decrypt(auth_id, plaintext.data(), &user.auth_id_key);

        int64_t timestamp = 0;
        for (int i = 0; i < 8; i++) {
            timestamp = (timestamp << 8) | plaintext[i];
        }

        if (timestamp > now + TIMESTAMP_TOLERANCE || timestamp < now - TIMESTAMP_TOLERANCE) {
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
            return false;
        }

        uint32_t crc = CRC32(plaintext.data(), 12);
        uint32_t expected_crc = (static_cast<uint32_t>(plaintext[12]) << 24) |
                                (static_cast<uint32_t>(plaintext[13]) << 16) |
                                (static_cast<uint32_t>(plaintext[14]) << 8) |
                                plaintext[15];
        OPENSSL_cleanse(plaintext.data(), plaintext.size());

        if (crc == expected_crc) {
            if (out_timestamp) {
                *out_timestamp = timestamp;
            }
            return true;
        }
        return false;
    };

    auto view = proxyman::inbound::UserStore::VmessUsers(tag);
    const uint64_t revision = proxyman::inbound::UserStore::WorkerViewRevision();
    auto& tls_hot_cache = ThreadHotCache();
    if (revision == 0 || tls_hot_cache.view_revision != revision) {
        tls_hot_cache.Clear();
        tls_hot_cache.view_revision = revision;
    }

    if (revision != 0 && now - tls_hot_cache.last_cleanup > 60) {
        tls_hot_cache.last_cleanup = now;
        tls_hot_cache.Cleanup(now);
    }

    if (!view.users) {
        return {};
    }

    if (revision != 0) {
        for (size_t i = 0; i < tls_hot_cache.size; ++i) {
            const auto& entry = tls_hot_cache.entries[i];
            if (entry.table == view.users.get() &&
                entry.last_seen + HotUserCache::kWindowSeconds >= now) {
                const auto* user = entry.user;
                if (tryUser(*user)) {
                    tls_hot_cache.Touch(user, view.users.get(), now);
                    return view.Share(*user);
                }
            }
        }
    }

    for (const auto& user : *view.users) {
        if (tryUser(user)) {
            if (revision != 0) {
                tls_hot_cache.Touch(&user, view.users.get(), now);
            }
            return view.Share(user);
        }
    }

    return {};
}

net::awaitable<bool> RegisterSessionIfNew(
    app::GroupCoordinator& coordinator,
    const proxyman::inbound::UserStore::VmessCredential& user,
    const std::array<uint8_t, 16>& body_key,
    const std::array<uint8_t, 16>& body_iv) {
    std::array<uint8_t, 48> material{};
    std::memcpy(material.data(), user.uuid_bytes.data(), 16);
    std::memcpy(material.data() + 16, body_key.data(), 16);
    std::memcpy(material.data() + 32, body_iv.data(), 16);
    const SessionKey key = SHA256Hash(material.data(), material.size());
    OPENSSL_cleanse(material.data(), material.size());
    co_return co_await coordinator.PostCall([&coordinator, key] {
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return net::use_service<HistoryService>(
            coordinator.Services()).history.AddIfNew(key, now);
    });
}

}  // namespace proxy::vmess
