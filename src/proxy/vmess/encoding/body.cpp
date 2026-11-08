#include "body.hpp"

#include "common/buf/contiguous_buffer_view.hpp"
#include "common/buffer_util.hpp"
#include "common/error.hpp"
#include "infra/log.hpp"
#include "transport/link.hpp"

#include <openssl/mem.h>
#include <openssl/rand.h>
#include <asio/this_coro.hpp>

#include <algorithm>
#include <cstring>
#include <new>
#include <string_view>

namespace vmess::encoding {

namespace {

constexpr size_t kStreamReadBatchChunks = 16;
constexpr size_t kMaxPaddingSize = 64;

// The largest length header, AEAD tag and padding must leave room for payload
// in one pooled buffer.
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
                                 const BodyKey& direction_key,
                                 proxy::AeadDirection direction)
    : payload_(options.security, direction_key.key.data(), direction_key.iv.data(), direction)
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
        length_.emplace(options.security, length_key.data(), request_body.iv.data(), direction);
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
        return ((static_cast<size_t>(plain[0]) << 8) | plain[1]) + length_->Overhead();
    }
    uint16_t wire = static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) | in[1]);
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
    : cipher_(options, request_body, direction_key, proxy::AeadDirection::Encrypt) {
    const size_t reserved =
        cipher_.LengthSize() + cipher_.Overhead() + cipher_.MaxPaddingSize();
    stream_chunk_size_ = std::min(MAX_CHUNK_SIZE - cipher_.Overhead(),
                                  size_t{buf::Buffer::kSize} - reserved);
}

void BodyEncoder::Encode(const buf::MultiBuffer& payload, buf::MultiBuffer& out) {
    if (PacketMode() &&
        (payload.byte_size() != 0 || buf::InspectUdpDatagram(payload).Valid())) {
        const buf::ContiguousBufferView packet(payload);
        EncodePacket(packet.Bytes(), out);
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
    if (PacketMode()) {
        const buf::ContiguousBufferView packet(payload);
        EncodePacket(packet.Bytes(), out);
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

void BodyEncoder::EncodeEnd(buf::MultiBuffer& out) {
    EncodeChunk({}, out);
}

void BodyEncoder::EncodeStream(std::span<const uint8_t> bytes, buf::MultiBuffer& out) {
    while (!bytes.empty()) {
        const size_t chunk_size = std::min(bytes.size(), stream_chunk_size_);
        EncodeChunk(bytes.first(chunk_size), out);
        bytes = bytes.subspan(chunk_size);
    }
}

size_t BodyEncoder::EncodeEndTo(std::span<uint8_t, 128> out) {
    const size_t padding = cipher_.NextPaddingSize();
    const size_t length_size = cipher_.LengthSize();
    const size_t capacity = length_size + cipher_.Overhead() + padding;
    if (capacity > out.size()) {
        ThrowWriteError("VMess EOF chunk exceeds inline buffer");
    }
    uint8_t* dst = out.data();
    const ssize_t sealed = cipher_.Payload().Encrypt(nullptr, 0, dst + length_size);
    if (sealed < 0) {
        ThrowWriteError("VMess body encrypt failed");
    }
    const size_t chunk_size = static_cast<size_t>(sealed) + padding;
    if (!cipher_.EncodeLength(chunk_size, dst)) {
        ThrowWriteError("VMess body length encode failed");
    }
    if (padding > 0 &&
        RAND_bytes(dst + length_size + sealed, static_cast<int>(padding)) != 1) {
        ThrowWriteError("VMess body padding generation failed");
    }
    return length_size + chunk_size;
}

void BodyEncoder::EncodePacket(std::span<const uint8_t> bytes, buf::MultiBuffer& out) {
    // Standard VMess framing uses an empty body exclusively as EOF.
    if (bytes.empty()) {
        throw transport::LinkError(ErrorCode::NOT_SUPPORTED);
    }
    if (bytes.size() > MAX_CHUNK_SIZE - cipher_.Overhead()) {
        throw IoSystemError(
            io_error::message_size,
            "VMess UDP datagram exceeds one authenticated chunk");
    }
    EncodeChunk(bytes, out);
}

void BodyEncoder::EncodeChunk(std::span<const uint8_t> bytes, buf::MultiBuffer& out) {
    const size_t padding = cipher_.NextPaddingSize();
    const size_t length_size = cipher_.LengthSize();
    const size_t capacity = length_size + bytes.size() + cipher_.Overhead() + padding;

    buf::ContiguousWriteBuffer encoded;
    uint8_t* dst = encoded.Prepare(capacity);

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

    encoded.AppendTo(length_size + chunk_size, out);
}

// ============================================================================
// BodyDecoder
// ============================================================================

BodyDecoder::BodyDecoder(const BodyOptions& options,
                         const BodyKey& request_body,
                         const BodyKey& direction_key)
    : cipher_(options, request_body, direction_key, proxy::AeadDirection::Decrypt) {}

net::awaitable<bool> BodyDecoder::ReadExact(transport::MultiBufferReader& src,
                                            std::span<uint8_t> out,
                                            size_t& filled) {
    while (filled < out.size()) {
        if (pending_read_.byte_size() == 0) {
            pending_read_.ReleaseIfIdle();
            pending_read_ = co_await ReadMultiBufferOrThrowOnCancel(
                src, "VMess read cancelled");
            if (pending_read_.byte_size() == 0) {
                co_return false;
            }
        }
        filled += pending_read_.ConsumePrefixTo(out.subspan(filled));
    }
    co_return true;
}

net::awaitable<buf::MultiBuffer> BodyDecoder::Read(transport::MultiBufferReader& src) {
    if (cipher_.PacketMode()) {
        co_return co_await ReadChunk(src);
    }

    // A later chunk in a stream batch can suspend after earlier chunks decoded.
    // Keep that output owned by the decoder until this invocation returns it.
    try {
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
    } catch (const IoSystemError& error) {
        if (error.code() != io_error::operation_aborted) {
            pending_output_.clear();
            pending_output_chunks_ = 0;
        }
        throw;
    } catch (...) {
        pending_output_.clear();
        pending_output_chunks_ = 0;
        throw;
    }
    pending_output_chunks_ = 0;
    co_return std::move(pending_output_);
}

net::awaitable<buf::MultiBuffer> BodyDecoder::ReadChunk(transport::MultiBufferReader& src) {
    if (eof_) {
        co_return buf::MultiBuffer{};
    }

    const size_t overhead = cipher_.Overhead();
    if (!header_decoded_) {
        const size_t length_size = cipher_.LengthSize();
        if (!co_await ReadExact(src, std::span<uint8_t>(header_.data(), length_size),
                                header_read_)) {
            if (header_read_ != 0) {
                Fail("VMess body length truncated");
            }
            eof_ = true;
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
        if (!co_await ReadExact(src, std::span<uint8_t>(header_.data(), chunk_len),
                                body_read_)) {
            Fail("VMess body EOF chunk truncated");
        }
        if (overhead > 0 &&
            cipher_.Payload().Decrypt(header_.data(), overhead, header_.data()) != 0) {
            Fail("VMess body EOF authentication failed");
        }
        eof_ = true;
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
    if (!co_await ReadExact(src, std::span<uint8_t>(sealed, chunk_len), body_read_)) {
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

void BodyDecoder::Fail(const char* what) {
    eof_ = true;
    FinishRecord();
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

}  // namespace vmess::encoding
