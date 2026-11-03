#include "server.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/buf/contiguous_buffer_view.hpp"
#include "acppnode/common/byte_reader.hpp"
#include "acppnode/common/unsafe.hpp"
#include "acppnode/common/address_codec.hpp"
#include "acppnode/infra/log.hpp"
#include "../vmess_cipher.hpp"
#include "../udp_datagram.hpp"
#include <openssl/rand.h>
#include <algorithm>
#include <cstring>
#include <asio/this_coro.hpp>

namespace acpp::vmess::encoding {

namespace {

struct EncodeResponseHeaderState final {
    uint8_t response_header = 0;
    uint8_t option = 0;
    Security security = Security::AES_128_GCM;
    std::array<uint8_t, 16> response_key{};
    std::array<uint8_t, 16> response_iv{};
    bool sent = false;
};

struct EncodeResponseBodyState final {
    Security security = Security::AES_128_GCM;
    uint8_t option = 0;
    std::optional<VMessCipher> cipher;
    std::optional<VMessCipher> length_cipher;
    std::optional<ShakeMask> mask;
    buf::MultiBuffer pending_prefix;
    bool global_padding = false;
    bool packet_mode = false;
    bool eof_sent = false;
    uint32_t chunk_count = 0;
};

struct DecodeRequestBodyState final {
    VMessRequest* request = nullptr;
    std::optional<VMessCipher> cipher;
    std::optional<VMessCipher> length_cipher;
    std::optional<ShakeMask> mask;
    buf::MultiBuffer pending_read;
    buf::MultiBuffer pending_output;
    size_t pending_output_chunks = 0;
    // A cancelled read may resume in another coroutine. Bytes, decoded length,
    // and mask/length-cipher progress therefore belong to the reader, not its frame.
    std::array<uint8_t, 128> header{};
    size_t header_read = 0;
    size_t body_read = 0;
    size_t chunk_len = 0;
    size_t padding_len = 0;
    bool header_decoded = false;
    buf::BufferGuard read_crypto_pool;
    memory::ByteVector read_crypto_buf;
    bool global_padding = false;
    bool packet_mode = false;
    bool eof = false;
    uint32_t chunk_count = 0;

    void FinishRecord() {
        header_read = 0;
        body_read = 0;
        chunk_len = 0;
        padding_len = 0;
        header_decoded = false;
        read_crypto_pool = {};
        memory::ByteVector{}.swap(read_crypto_buf);
    }
};

}  // namespace

bool ParseRequestHeader(const uint8_t* data,
                        size_t len,
                        const proxyman::inbound::UserStore::VmessCredential* user,
                        const uint8_t* auth_id,
                        size_t header_len,
                        uint64_t trace_conn_id,
                        VMessRequest& request,
                        size_t& consumed);

bool ParseDecryptedHeader(const uint8_t* data,
                          size_t len,
                          uint64_t trace_conn_id,
                          VMessRequest& request);

namespace {
constexpr size_t kStreamReadBatchChunks = 16;
constexpr size_t kStreamMaxPaddingLen = 64;

[[noreturn]] void ThrowVMessWriteError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

uint8_t* PrepareScratch(memory::ByteVector& buffer, size_t size) {
    if (buffer.size() < size) {
        buffer.resize(size);
    }
    return buffer.data();
}

[[nodiscard]] bool EncodeChunkLength(VMessCipher* length_cipher,
                                     ShakeMask* mask,
                                     uint16_t total_len,
                                     uint8_t* out,
                                     size_t& out_len) {
    if (length_cipher) {
        const size_t length_overhead = length_cipher->Overhead();
        if (total_len < length_overhead) {
            return false;
        }
        const uint16_t plain_len =
            static_cast<uint16_t>(total_len - static_cast<uint16_t>(length_overhead));
        const uint8_t plain[2] = {
            static_cast<uint8_t>((plain_len >> 8) & 0xFF),
            static_cast<uint8_t>(plain_len & 0xFF),
        };
        const ssize_t enc_len = length_cipher->Encrypt(plain, sizeof(plain), out);
        if (enc_len < 0) {
            return false;
        }
        out_len = static_cast<size_t>(enc_len);
        return true;
    }

    uint16_t masked_len = total_len;
    if (mask) {
        masked_len ^= mask->NextMask();
    }
    out[0] = static_cast<uint8_t>((masked_len >> 8) & 0xFF);
    out[1] = static_cast<uint8_t>(masked_len & 0xFF);
    out_len = 2;
    return true;
}

bool BuildResponseHeader(
    EncodeResponseHeaderState& state,
    std::array<uint8_t, 38>& resp_buf) {
    if (state.sent) {
        return true;
    }
    state.sent = true;

    LOG_NET_DEBUG("VMess encoding: EncodeResponseHeader start");

    uint8_t resp_data[4] = {
        state.response_header,
        state.option,
        0,
        0
    };

    std::array<uint8_t, 16> len_key;
    std::array<uint8_t, 12> len_iv;
    const std::array<std::string_view, 1> len_key_path{
        KDFSalt::AEAD_RESP_HEADER_LEN_KEY
    };
    const std::array<std::string_view, 1> len_iv_path{
        KDFSalt::AEAD_RESP_HEADER_LEN_IV
    };
    KDF(state.response_key.data(), 16, len_key_path, len_key.data(), 16);
    KDF(state.response_iv.data(), 16, len_iv_path, len_iv.data(), 12);

    uint8_t len_plain[2] = {0, 4};

    if (!AES128GCMEncrypt(len_key.data(), len_iv.data(), nullptr, 0,
                          len_plain, 2, resp_buf.data(), resp_buf.data() + 2)) {
        LOG_NET_DEBUG("VMess encoding: EncodeResponseHeader GCM encrypt len failed");
        return false;
    }

    std::array<uint8_t, 16> header_key;
    std::array<uint8_t, 12> header_iv;
    const std::array<std::string_view, 1> header_key_path{
        KDFSalt::AEAD_RESP_HEADER_PAYLOAD_KEY
    };
    const std::array<std::string_view, 1> header_iv_path{
        KDFSalt::AEAD_RESP_HEADER_PAYLOAD_IV
    };
    KDF(state.response_key.data(), 16, header_key_path, header_key.data(), 16);
    KDF(state.response_iv.data(), 16, header_iv_path, header_iv.data(), 12);

    if (!AES128GCMEncrypt(header_key.data(), header_iv.data(), nullptr, 0,
                          resp_data, 4, resp_buf.data() + 18, resp_buf.data() + 22)) {
        LOG_NET_DEBUG("VMess encoding: EncodeResponseHeader GCM encrypt header failed");
        return false;
    }

    return true;
}

struct ResponseBodyEncodeBudget final {
    size_t stream_chunk_size = 0;
};

[[nodiscard]] ResponseBodyEncodeBudget MakeResponseBodyEncodeBudget(
    const EncodeResponseBodyState& state) {
    const size_t overhead = state.cipher->Overhead();
    const size_t length_header_size = state.length_cipher ? state.length_cipher->Overhead() + 2 : 2;
    const size_t max_padding_len =
        (state.global_padding && state.mask) ? kStreamMaxPaddingLen : 0;
    if (buf::Buffer::kSize <= length_header_size + overhead + max_padding_len) {
        ThrowVMessWriteError("VMess encoding buffer budget too small");
    }
    const size_t stream_chunk_size = std::min(
        size_t(MAX_CHUNK_SIZE - overhead),
        size_t(buf::Buffer::kSize - length_header_size - overhead - max_padding_len));
    return ResponseBodyEncodeBudget{stream_chunk_size};
}

void EncodeResponseBodyChunk(EncodeResponseBodyState& state,
                             std::span<const uint8_t> bytes,
                             buf::MultiBuffer& out_mb) {
    const size_t overhead = state.cipher->Overhead();
    if (bytes.empty() || bytes.size() > MAX_CHUNK_SIZE - overhead) {
        throw IoSystemError(
            io_error::message_size,
            "VMess UDP datagram exceeds one authenticated chunk");
    }

    size_t padding_len = 0;
    if (state.global_padding && state.mask) {
        const uint16_t padding_mask = state.mask->NextMask();
        padding_len = padding_mask % 64;
    }
    const size_t length_header_size = state.length_cipher
        ? state.length_cipher->Overhead() + 2
        : 2;
    const size_t output_capacity =
        length_header_size + bytes.size() + overhead + padding_len;

    buf::BufferGuard pooled;
    memory::ByteVector scratch;
    uint8_t* dst = nullptr;
    if (output_capacity <= buf::Buffer::kSize) {
        pooled = buf::BufferGuard{buf::Buffer::New()};
        if (!pooled) {
            throw std::bad_alloc();
        }
        dst = pooled->Tail().data();
    } else {
        dst = PrepareScratch(scratch, output_capacity);
    }

    const ssize_t enc_len = state.cipher->Encrypt(
        bytes.data(), bytes.size(), dst + length_header_size);
    if (enc_len < 0) {
        ThrowVMessWriteError("VMess encoding packet encrypt failed");
    }

    const uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);
    size_t encoded_length_size = 0;
    if (!EncodeChunkLength(state.length_cipher ? &*state.length_cipher : nullptr,
                           state.length_cipher ? nullptr : (state.mask ? &*state.mask : nullptr),
                           total_len,
                           dst,
                           encoded_length_size)) {
        ThrowVMessWriteError("VMess encoding length encrypt failed");
    }
    if (padding_len > 0) {
        RAND_bytes(dst + encoded_length_size + enc_len, static_cast<int>(padding_len));
    }

    const size_t output_size =
        encoded_length_size + static_cast<size_t>(enc_len) + padding_len;
    ++state.chunk_count;
    if (pooled) {
        pooled->Produce(static_cast<uint32_t>(output_size));
        out_mb.push_back(std::move(pooled));
        return;
    }
    if (!buf::AppendSpanToMultiBuffer(
            std::span<const uint8_t>(dst, output_size), out_mb)) {
        throw std::bad_alloc();
    }
}

void EncodeResponseBodyBytes(EncodeResponseBodyState& state,
                             const ResponseBodyEncodeBudget& budget,
                             std::span<const uint8_t> bytes,
                             buf::MultiBuffer& out_mb) {
    if (bytes.empty()) {
        return;
    }

    const uint8_t* data = bytes.data();
    const size_t len = bytes.size();
    size_t offset = 0;

    while (offset < len) {
        const size_t chunk_size = std::min(len - offset, budget.stream_chunk_size);
        EncodeResponseBodyChunk(
            state,
            std::span<const uint8_t>(data + offset, chunk_size),
            out_mb);
        offset += chunk_size;
    }
}

net::awaitable<void> FlushResponseBody(EncodeResponseBodyState& state,
                                       AsyncStream& stream,
                                       buf::MultiBuffer out_mb) {
    if (buf::HasData(state.pending_prefix)) {
        if (!buf::HasData(out_mb)) {
            out_mb = std::move(state.pending_prefix);
        } else {
            buf::MultiBuffer merged;
            merged.reserve(state.pending_prefix.size() + out_mb.size());
            state.pending_prefix.MoveTo(merged);
            out_mb.MoveTo(merged);
            out_mb = std::move(merged);
        }
    }

    if (buf::HasData(out_mb)) {
        co_await stream.WriteMultiBuffer(std::move(out_mb));
    }
}

net::awaitable<void> EncodeResponseBodyMultiBuffer(EncodeResponseBodyState& state,
                                                   AsyncStream& stream,
                                                   buf::MultiBuffer mb) {

    if (!buf::HasData(mb)) {
        co_return;
    }

    if (state.packet_mode) {
        const buf::ContiguousBufferView packet(mb);
        buf::MultiBuffer out_mb;
        EncodeResponseBodyChunk(state, packet.Bytes(), out_mb);
        co_await FlushResponseBody(state, stream, std::move(out_mb));
        co_return;
    }

    const ResponseBodyEncodeBudget budget = MakeResponseBodyEncodeBudget(state);
    buf::MultiBuffer out_mb;
    out_mb.reserve(mb.size());

    for (auto* buffer : mb) {
        if (!buffer) {
            continue;
        }
        EncodeResponseBodyBytes(state, budget, buffer->Bytes(), out_mb);
    }
    mb.clear();

    co_await FlushResponseBody(state, stream, std::move(out_mb));
}

net::awaitable<void> EncodeResponseBodyBuffers(
    EncodeResponseBodyState& state,
    AsyncStream& stream,
    std::span<const net::const_buffer> buffers) {
    bool has_data = false;
    for (const net::const_buffer& buffer : buffers) {
        if (buffer.data() && buffer.size() > 0) {
            has_data = true;
            break;
        }
    }
    if (!has_data) {
        co_return;
    }

    if (state.packet_mode) {
        const buf::ContiguousBufferView packet(buffers);
        buf::MultiBuffer out_mb;
        EncodeResponseBodyChunk(state, packet.Bytes(), out_mb);
        co_await FlushResponseBody(state, stream, std::move(out_mb));
        co_return;
    }

    const ResponseBodyEncodeBudget budget = MakeResponseBodyEncodeBudget(state);
    buf::MultiBuffer out_mb;
    out_mb.reserve(buffers.size());

    for (const net::const_buffer& buffer : buffers) {
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        if (!data || buffer.size() == 0) {
            continue;
        }
        EncodeResponseBodyBytes(
            state,
            budget,
            std::span<const uint8_t>(data, buffer.size()),
            out_mb);
    }

    co_await FlushResponseBody(state, stream, std::move(out_mb));
}

net::awaitable<void> EncodeResponseBodyEOF(EncodeResponseBodyState& state,
                                           AsyncStream& stream) {
    if (state.eof_sent) {
        co_return;
    }

    size_t padding_len = 0;
    if (state.global_padding && state.mask) {
        const uint16_t padding_mask = state.mask->NextMask();
        padding_len = padding_mask % 64;
    }

    buf::BufferGuard out{buf::Buffer::New()};
    if (!out) {
        throw std::bad_alloc();
    }
    uint8_t* eof_buf = out->Tail().data();
    const size_t length_header_size = state.length_cipher ? state.length_cipher->Overhead() + 2 : 2;
    ssize_t enc_len = state.cipher->Encrypt(nullptr, 0, eof_buf + length_header_size);
    if (enc_len < 0) {
        ThrowVMessWriteError("VMess server EOF encrypt failed");
    }

    const uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);
    size_t encoded_length_size = 0;
    if (!EncodeChunkLength(state.length_cipher ? &*state.length_cipher : nullptr,
                           state.length_cipher ? nullptr : (state.mask ? &*state.mask : nullptr),
                           total_len,
                           eof_buf,
                           encoded_length_size)) {
        ThrowVMessWriteError("VMess server EOF length encrypt failed");
    }

    if (padding_len > 0 &&
        RAND_bytes(eof_buf + encoded_length_size + enc_len, static_cast<int>(padding_len)) != 1) {
        ThrowVMessWriteError("VMess server EOF padding failed");
    }

    const size_t output_size = encoded_length_size + static_cast<size_t>(enc_len) + padding_len;
    out->Produce(static_cast<uint32_t>(output_size));
    buf::MultiBuffer mb{std::move(out)};
    co_await FlushResponseBody(state, stream, std::move(mb));
    state.eof_sent = true;
    LOG_NET_TRACE("VMess server: response EOF sent bytes={}", output_size);
}

net::awaitable<bool> DecodeRequestBodyReadFull(DecodeRequestBodyState& state,
                                               AsyncStream& stream,
                                               uint8_t* dst,
                                               size_t len,
                                               size_t& consumed) {
    while (consumed < len && state.request && state.request->HasPendingData()) {
        const auto pending_data = state.request->PendingDataSpan();
        const size_t to_copy = std::min(len - consumed, pending_data.size());
        std::memcpy(dst + consumed, pending_data.data(), to_copy);
        consumed += to_copy;
        state.request->ConsumePendingData(to_copy);
    }

    while (consumed < len) {
        if (!buf::HasData(state.pending_read)) {
            state.pending_read = co_await stream.ReadMultiBuffer();
            if (state.pending_read.empty()) {
                const auto cancellation = co_await net::this_coro::cancellation_state;
                if (cancellation.cancelled() != net::cancellation_type::none) {
                    throw IoSystemError(io_error::operation_aborted, "VMess body read cancelled");
                }
                co_return false;
            }
        }

        const size_t n = state.pending_read.ConsumePrefixTo(
            std::span<uint8_t>(dst + consumed, len - consumed));
        if (n == 0) {
            co_return false;
        }
        consumed += n;
    }
    co_return true;
}

net::awaitable<buf::MultiBuffer> DecodeRequestBody(DecodeRequestBodyState& state,
                                              AsyncStream& stream) {
    if (state.eof) {
        co_return buf::MultiBuffer{};
    }

    const size_t overhead = state.cipher->Overhead();
    if (!state.header_decoded) {
        const size_t length_header_size = state.length_cipher ? state.length_cipher->Overhead() + 2 : 2;
        if (!co_await DecodeRequestBodyReadFull(
                state, stream, state.header.data(), length_header_size, state.header_read)) {
            LOG_NET_DEBUG("VMess encoding: DecodeRequestBody TCP-level close (failed to read chunk header) after {} chunks",
                          state.chunk_count);
            state.eof = true;
            state.FinishRecord();
            co_return buf::MultiBuffer{};
        }

        uint16_t raw_len = 0;
        if (state.length_cipher) {
            uint8_t len_plain[2];
            const ssize_t dec_len = state.length_cipher->Decrypt(
                state.header.data(), length_header_size, len_plain);
            if (dec_len != 2) {
                LOG_NET_DEBUG("VMess encoding: DecodeRequestBody authenticated length decrypt failed");
                state.eof = true;
                state.FinishRecord();
                throw IoSystemError(io_error::connection_reset, "VMess encoding read error");
            }
            raw_len = static_cast<uint16_t>(
                (static_cast<uint16_t>(len_plain[0]) << 8) | len_plain[1]);
            raw_len = static_cast<uint16_t>(raw_len + state.length_cipher->Overhead());
        } else {
            raw_len = (static_cast<uint16_t>(state.header[0]) << 8) | state.header[1];
        }

        if (state.global_padding && state.mask) {
            const uint16_t padding_mask = state.mask->NextMask();
            state.padding_len = padding_mask % 64;
        }

        uint16_t chunk_len = raw_len;
        if (!state.length_cipher && state.mask) {
            chunk_len ^= state.mask->NextMask();
        }
        state.chunk_len = chunk_len;
        state.header_decoded = true;

        if (chunk_len < overhead + state.padding_len || chunk_len > MAX_CHUNK_SIZE + overhead + 64) {
            LOG_NET_DEBUG("VMess encoding: DecodeRequestBody INVALID length chunk#{} raw_len={} chunk_len={} "
                          "overhead={} padding={} MAX={} (可能 mask 计数器不同步)",
                          state.chunk_count, raw_len, chunk_len, overhead, state.padding_len, MAX_CHUNK_SIZE);
            state.eof = true;
            state.FinishRecord();
            throw IoSystemError(io_error::connection_reset, "VMess encoding read error");
        }
    }

    const size_t chunk_len = state.chunk_len;
    if (chunk_len == overhead + state.padding_len) {
        // EOF has at most an AEAD tag plus 63 padding bytes. The length has
        // already been interpreted, so its inline storage can hold these bytes.
        if (!co_await DecodeRequestBodyReadFull(
                state, stream, state.header.data(), chunk_len, state.body_read)) {
            state.eof = true;
            state.FinishRecord();
            co_return buf::MultiBuffer{};
        }
        LOG_NET_DEBUG("VMess encoding: DecodeRequestBody EOF marker received after {} chunks",
                      state.chunk_count);
        state.eof = true;
        state.FinishRecord();
        co_return buf::MultiBuffer{};
    }

    if (state.body_read == 0 && !state.read_crypto_pool && state.read_crypto_buf.empty()) {
        if (auto pending_body = state.pending_read.TakeFrontIfLen(chunk_len)) {
            const size_t data_len = chunk_len - state.padding_len;
            const ssize_t dec_len = state.cipher->Decrypt(
                pending_body->Bytes().data(), data_len, pending_body->Bytes().data());
            if (dec_len < 0) {
                state.eof = true;
                state.FinishRecord();
                throw IoSystemError(io_error::connection_reset, "VMess encoding read error");
            }
            pending_body->end = pending_body->start + static_cast<uint32_t>(dec_len);
            ++state.chunk_count;
            state.FinishRecord();
            co_return buf::MultiBuffer{std::move(pending_body)};
        }

        if (chunk_len <= buf::Buffer::kSize) {
            state.read_crypto_pool = buf::BufferGuard{buf::Buffer::New()};
            if (!state.read_crypto_pool) {
                throw std::bad_alloc();
            }
        } else {
            state.read_crypto_buf.resize(chunk_len);
        }
    }

    uint8_t* read_crypto = state.read_crypto_pool
        ? state.read_crypto_pool->Tail().data()
        : state.read_crypto_buf.data();
    if (!co_await DecodeRequestBodyReadFull(
            state, stream, read_crypto, chunk_len, state.body_read)) {
        LOG_NET_DEBUG("VMess encoding: DecodeRequestBody ReadFull failed chunk#{} chunk_len={} "
                      "(TCP 连接在 chunk body 传输中断开)",
                      state.chunk_count, chunk_len);
        state.eof = true;
        state.FinishRecord();
        co_return buf::MultiBuffer{};
    }

    const size_t data_len = chunk_len - state.padding_len;
    const ssize_t dec_len = state.cipher->Decrypt(read_crypto, data_len, read_crypto);
    if (dec_len < 0) {
        state.eof = true;
        state.FinishRecord();
        throw IoSystemError(io_error::connection_reset, "VMess encoding read error");
    }
    if (state.read_crypto_pool) {
        state.read_crypto_pool->Produce(static_cast<uint32_t>(dec_len));
        buf::MultiBuffer out_mb{std::move(state.read_crypto_pool)};
        ++state.chunk_count;
        state.FinishRecord();
        co_return out_mb;
    }

    const size_t dec_size = static_cast<size_t>(dec_len);
    buf::MultiBuffer out_mb;
    out_mb.reserve((dec_size + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
    const bool appended = buf::AppendSpanToMultiBuffer(
        std::span<const uint8_t>(read_crypto, dec_size), out_mb);
    state.FinishRecord();
    if (!appended) {
        co_return buf::MultiBuffer{};
    }
    ++state.chunk_count;
    co_return out_mb;
}

net::awaitable<buf::MultiBuffer> DecodeRequestBodyMultiBuffer(DecodeRequestBodyState& state,
                                                              AsyncStream& stream) {
    if (state.packet_mode) {
        co_return co_await DecodeRequestBody(state, stream);
    }

    // A later chunk in a stream batch can suspend after earlier chunks decoded.
    // Keep that output owned by the reader until this invocation returns it.
    auto& out = state.pending_output;
    try {
        while (state.pending_output_chunks < kStreamReadBatchChunks) {
            if (buf::HasData(out) && !state.header_decoded && state.header_read == 0 &&
                !buf::HasData(state.pending_read)) {
                break;
            }

            buf::MultiBuffer chunk = co_await DecodeRequestBody(state, stream);
            if (!buf::HasData(chunk)) {
                break;
            }
            chunk.MoveTo(out);
            ++state.pending_output_chunks;
        }
    } catch (const IoSystemError& error) {
        if (error.code() != io_error::operation_aborted) {
            out.clear();
            state.pending_output_chunks = 0;
        }
        throw;
    } catch (...) {
        out.clear();
        state.pending_output_chunks = 0;
        throw;
    }
    state.pending_output_chunks = 0;
    co_return std::move(out);
}

}  // namespace

namespace {

void InitRequestBodyState(DecodeRequestBodyState& state, VMessRequest& request) {
    const Security security = request.security;
    const uint8_t option = request.options;
    std::array<uint8_t, 16> request_key{};
    std::array<uint8_t, 16> request_iv{};

    std::memcpy(request_key.data(), request.body_key.data(), 16);
    std::memcpy(request_iv.data(), request.body_iv.data(), 16);

    state.request = &request;
    state.packet_mode = request.command == Command::UDP;
    state.cipher.emplace(
        security, request_key.data(), request_iv.data(), proxy::AeadDirection::Decrypt);
    if ((option & Option::AUTHENTICATED_LENGTH) != 0 &&
        (security == Security::AES_128_GCM || security == Security::CHACHA20_POLY1305)) {
        const std::array<std::string_view, 1> path{"auth_len"};
        auto length_key = KDF16(request_key.data(), request_key.size(), path);
        state.length_cipher.emplace(
            security, length_key.data(), request_iv.data(), proxy::AeadDirection::Decrypt);
    }
    state.global_padding = (option & Option::GLOBAL_PADDING) != 0 &&
        !(security == Security::NONE && request.command != Command::UDP);
    if ((option & Option::CHUNK_MASKING) != 0) {
        state.mask.emplace(request_iv.data());
    }
}

void ComputeResponseBodyKeys(const VMessRequest& request,
                             std::array<uint8_t, 16>& response_key,
                             std::array<uint8_t, 16>& response_iv) {
    std::array<uint8_t, 16> request_key{};
    std::array<uint8_t, 16> request_iv{};

    std::memcpy(request_key.data(), request.body_key.data(), 16);
    std::memcpy(request_iv.data(), request.body_iv.data(), 16);

    // Match xray-core VMess response body key derivation from request body key/IV.
    auto resp_key_hash = SHA256Sum(request_key.data(), 16);
    auto resp_iv_hash = SHA256Sum(request_iv.data(), 16);
    std::memcpy(response_key.data(), resp_key_hash.data(), 16);
    std::memcpy(response_iv.data(), resp_iv_hash.data(), 16);
}

void InitResponseHeaderState(EncodeResponseHeaderState& state, const VMessRequest& request) {
    state.response_header = request.response_header;
    // xray-core does not echo request body options in the response header.
    // Body encoding still uses request.options in InitResponseBodyState.
    state.option = 0;
    state.security = request.security;
    ComputeResponseBodyKeys(request, state.response_key, state.response_iv);
}

void InitResponseBodyState(EncodeResponseBodyState& state, const VMessRequest& request) {
    const Security security = request.security;
    const uint8_t option = request.options;
    std::array<uint8_t, 16> response_key{};
    std::array<uint8_t, 16> response_iv{};

    ComputeResponseBodyKeys(request, response_key, response_iv);

    state.security = security;
    state.option = option;
    state.cipher.emplace(
        security, response_key.data(), response_iv.data(), proxy::AeadDirection::Encrypt);
    if ((option & Option::AUTHENTICATED_LENGTH) != 0 &&
        (security == Security::AES_128_GCM || security == Security::CHACHA20_POLY1305)) {
        std::array<uint8_t, 16> request_key{};
        std::array<uint8_t, 16> request_iv{};
        std::memcpy(request_key.data(), request.body_key.data(), 16);
        std::memcpy(request_iv.data(), request.body_iv.data(), 16);
        const std::array<std::string_view, 1> path{"auth_len"};
        auto length_key = KDF16(request_key.data(), request_key.size(), path);
        state.length_cipher.emplace(
            security, length_key.data(), request_iv.data(), proxy::AeadDirection::Encrypt);
    }
    state.global_padding = (option & Option::GLOBAL_PADDING) != 0 &&
        !(security == Security::NONE && request.command != Command::UDP);
    state.packet_mode = request.command == Command::UDP;
    if ((option & Option::CHUNK_MASKING) != 0) {
        state.mask.emplace(response_iv.data());
    }
}

}  // namespace

std::pair<std::optional<VMessRequest>, size_t> ServerSession::DecodeRequestHeader(
    const uint8_t* data, size_t len, uint64_t trace_conn_id) {
    if (len < 42) {
        required_header_bytes_ = 42;
        return {std::nullopt, 0};
    }
    const uint8_t* auth_id = data;
    const uint8_t* connection_nonce = data + 34;
    if (!header_user_) {
        int64_t timestamp = 0;
        header_user_ = validator_->FindByAuthIDForTag(tag_, auth_id, timestamp);
        if (!header_user_) {
            required_header_bytes_ = 0;
            return {std::nullopt, 0};
        }
        const std::string_view auth_id_sv(unsafe::ptr_cast<const char>(auth_id), 16);
        const std::string_view nonce_sv(unsafe::ptr_cast<const char>(connection_nonce), 8);
        const std::array<std::string_view, 3> key_path{
            KDFSalt::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, auth_id_sv, nonce_sv};
        const auto key = KDF16(header_user_->cmd_key.data(), 16, key_path);
        const std::array<std::string_view, 3> iv_path{
            KDFSalt::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, auth_id_sv, nonce_sv};
        std::array<uint8_t, 12> iv{};
        KDF(header_user_->cmd_key.data(), 16, iv_path, iv.data(), iv.size());
        std::array<uint8_t, 2> plain{};
        size_t written = 0;
        if (!AES128GCMDecryptTo(key.data(), iv.data(), iv.size(),
                data + 16, 18, auth_id, 16, plain.data(), plain.size(), written) ||
            written != plain.size()) {
            header_user_.reset();
            required_header_bytes_ = 0;
            return {std::nullopt, 0};
        }
        header_length_ = (static_cast<uint16_t>(plain[0]) << 8) | plain[1];
        required_header_bytes_ = 42 + static_cast<size_t>(header_length_) + 16;
    }
    if (len < required_header_bytes_) return {std::nullopt, 0};

    VMessRequest request;
    size_t consumed = 0;
    required_header_bytes_ = 0;
    if (!ParseRequestHeader(data + 16, len - 16, header_user_.get(), auth_id,
            header_length_, trace_conn_id, request, consumed) ||
        !validator_->RegisterSessionIfNew(*header_user_, request.body_key, request.body_iv)) {
        header_user_.reset();
        LOG_NET_DEBUG("VMess: invalid authenticated request header or replay");
        return {std::nullopt, 0};
    }
    request.user = std::move(header_user_);
    return {std::move(request), 16 + consumed};
}

bool ParseRequestHeader(const uint8_t* data,
                        size_t len,
                        const proxyman::inbound::UserStore::VmessCredential* user,
                        const uint8_t* auth_id,
                        size_t header_len,
                        uint64_t trace_conn_id,
                        VMessRequest& request,
                        size_t& consumed) {
    const size_t needed = 26 + header_len + 16;
    if (len < needed) return false;
    const uint8_t* connection_nonce = data + 18;
    const std::string_view auth_id_sv(unsafe::ptr_cast<const char>(auth_id), 16);
    const std::string_view nonce_sv(unsafe::ptr_cast<const char>(connection_nonce), 8);
    const std::array<std::string_view, 3> key_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_AEAD_KEY, auth_id_sv, nonce_sv};
    const auto key = KDF16(user->cmd_key.data(), 16, key_path);
    const std::array<std::string_view, 3> iv_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_AEAD_IV, auth_id_sv, nonce_sv};
    std::array<uint8_t, 12> iv{};
    KDF(user->cmd_key.data(), 16, iv_path, iv.data(), iv.size());
    memory::ByteVector plain(header_len);
    size_t written = 0;
    if (!AES128GCMDecryptTo(key.data(), iv.data(), iv.size(),
            data + 26, header_len + 16, auth_id, 16,
            plain.data(), plain.size(), written)) {
        LOG_NET_DEBUG("VMess: request header authentication failed");
        return false;
    }
    if (!ParseDecryptedHeader(plain.data(), written, trace_conn_id, request)) return false;
    consumed = needed;
    return true;
}

bool ParseDecryptedHeader(const uint8_t* data, size_t len,
                                         uint64_t trace_conn_id,
                                         VMessRequest& request) {
    static constexpr size_t kFixedHeaderSize = 38;
    if (len < kFixedHeaderSize + 4) {
        LOG_NET_TRACE("[conn={}] VMess: decrypted header too short len={} min={}",
                         trace_conn_id,
                         len,
                         kFixedHeaderSize + 4);
        return false;
    }

    ByteReader reader(data, len);

    request.version = reader.ReadU8();
    if (!reader.Ok() || request.version != VERSION) {
        LOG_NET_DEBUG("VMess: unsupported version {}", request.version);
        LOG_NET_TRACE("[conn={}] VMess: unsupported version={}", trace_conn_id, request.version);
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
    request.padding_len = (ps >> 4) & 0x0F;
    request.security = static_cast<Security>(ps & 0x0F);

    reader.Skip(1);

    request.command = static_cast<Command>(reader.ReadU8());
    if (!reader.Ok()) return false;

    TargetAddress target;

    if (request.command == Command::Mux) {
        target = TargetAddress("v1.mux.cool", 0);
    } else if (request.command == Command::TCP || request.command == Command::UDP) {
        auto address = DecodeAddress(
            std::span(data + reader.Position(), reader.Remaining()),
            AddressWireFormat::PortFirst);
        if (address.status != AddressDecodeStatus::Complete) return false;
        reader.Skip(address.consumed);
        target = std::move(address.target);
    } else {
        LOG_NET_DEBUG("VMess: unsupported command {}", static_cast<int>(request.command));
        LOG_NET_TRACE("[conn={}] VMess: unsupported command={}",
                      trace_conn_id, static_cast<int>(request.command));
        return false;
    }

    request.target = std::move(target);

    reader.Skip(request.padding_len);
    if (!reader.Ok()) return false;

    size_t pos = reader.Position();
    if (pos + 4 > len) return false;

    uint32_t expected_fnv = FNV1a32(data, pos);
    uint32_t actual_fnv = reader.ReadU32BE();

    if (!reader.Ok() || expected_fnv != actual_fnv) {
        LOG_NET_DEBUG("VMess: FNV1a checksum mismatch");
        LOG_NET_TRACE("[conn={}] VMess: request header checksum mismatch", trace_conn_id);
        return false;
    }

    LOG_NET_TRACE("[conn={}] VMess: header ok target={} command={} security={} options={:#04x} padding={}",
                     trace_conn_id,
                     request.target,
                     static_cast<int>(request.command),
                     static_cast<int>(request.security),
                     static_cast<int>(request.options),
                     request.padding_len);

    return true;
}


namespace {

class RequestBodyReader final
    : public memory::ThreadAllocated
    , public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return stream_->Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override {
        return is_udp_ ? transport::EofAction::WaitForPeer : stream_->ReadEofAction();
    }

    RequestBodyReader(VMessRequest& request, AsyncStream& stream)
        : stream_(&stream)
        , is_udp_(request.command == Command::UDP)
        , udp_target_(request.target) {
        InitRequestBodyState(request_body_state_, request);
    }

    RequestBodyReader(const RequestBodyReader&) = delete;
    RequestBodyReader& operator=(const RequestBodyReader&) = delete;
    RequestBodyReader(RequestBodyReader&&) = delete;
    RequestBodyReader& operator=(RequestBodyReader&&) = delete;

    ~RequestBodyReader() noexcept override {
        request_body_state_.pending_read.clear();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "VMess request reader has no stream");
        }
        auto mb = co_await DecodeRequestBodyMultiBuffer(request_body_state_, *stream_);
        if (is_udp_) {
            for (buf::Buffer* buffer : mb) {
                if (buffer && !buffer->IsEmpty()) {
                    buffer->SetUDP(udp_target_);
                }
            }
        }
        co_return mb;
    }

private:
    DecodeRequestBodyState request_body_state_;
    AsyncStream* stream_ = nullptr;
    bool is_udp_ = false;
    TargetAddress udp_target_;
};

class ResponseBodyWriter final
    : public memory::ThreadAllocated
    , public transport::MultiBufferWriter {
public:
    ResponseBodyWriter(const VMessRequest& request,
                       AsyncStream& stream,
                       std::array<uint8_t, 38> response_header)
        : stream_(&stream)
        , packet_mode_(request.command == Command::UDP)
        , udp_target_(request.target) {
        InitResponseBodyState(response_body_state_, request);
        if (!buf::AppendSpanToMultiBuffer(
                std::span<const uint8_t>(response_header.data(), response_header.size()),
                response_body_state_.pending_prefix)) {
            throw std::bad_alloc();
        }
    }

    ResponseBodyWriter(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter& operator=(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter(ResponseBodyWriter&&) = delete;
    ResponseBodyWriter& operator=(ResponseBodyWriter&&) = delete;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "VMess response writer has no stream");
        }
        if (packet_mode_) {
            ::acpp::vmess::ValidateFixedUdpDatagram(mb, udp_target_);
            for (buf::Buffer* buffer : mb) {
                if (buffer) {
                    buffer->ClearUDP();
                }
            }
        }
        co_await EncodeResponseBodyMultiBuffer(response_body_state_, *stream_, std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "VMess response writer has no stream");
        }
        co_await EncodeResponseBodyBuffers(response_body_state_, *stream_, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "VMess response writer has no stream");
        }
        if (!response_body_state_.eof_sent) {
            co_await EncodeResponseBodyEOF(response_body_state_, *stream_);
        }
    }

private:
    EncodeResponseBodyState response_body_state_;
    AsyncStream* stream_ = nullptr;
    bool packet_mode_ = false;
    TargetAddress udp_target_;
};

}  // namespace

ServerSession::ServerSession(const TimedUserValidator& validator, std::string_view tag)
    : validator_(&validator)
    , tag_(tag) {}


void ServerSession::SetRequest(VMessRequest request) {
    request_ = std::move(request);
    request_set_ = true;
}

std::unique_ptr<transport::MultiBufferReader> ServerSession::DecodeRequestBody(
    AsyncStream& stream) {
    if (!request_set_) {
        return nullptr;
    }
    try {
        return std::make_unique<RequestBodyReader>(request_, stream);
    } catch (...) {
        return nullptr;
    }
}

std::unique_ptr<transport::MultiBufferWriter> ServerSession::EncodeResponseBodyWithHeader(
    AsyncStream& stream) {
    if (!request_set_) {
        return nullptr;
    }
    try {
        EncodeResponseHeaderState state;
        InitResponseHeaderState(state, request_);
        std::array<uint8_t, 38> response_header{};
        if (!BuildResponseHeader(state, response_header)) {
            return nullptr;
        }
        return std::make_unique<ResponseBodyWriter>(request_, stream, response_header);
    } catch (...) {
        return nullptr;
    }
}

}  // namespace acpp::vmess::encoding
