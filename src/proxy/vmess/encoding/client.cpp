#include "client.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include "acppnode/common/buffer_util.hpp"

namespace acpp {

namespace {

constexpr size_t kVMessHandshakeHeaderMax = 512;
constexpr size_t kVMessHandshakeHeaderEncMax = kVMessHandshakeHeaderMax + 16;
constexpr size_t kVMessHandshakePacketMax = 16 + 18 + 8 + kVMessHandshakeHeaderEncMax;
constexpr size_t kVMessResponseHeaderMax = 1024;
constexpr size_t kVMessBodyMaxChunkSize = 16 * 1024;
constexpr size_t kStreamMaxPaddingLen = 64;

[[noreturn]] void ThrowVMessWriteError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

net::awaitable<bool> ReadFull(AsyncStream& stream, uint8_t* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        size_t r = 0;
        try {
            r = co_await stream.AsyncRead(net::buffer(buf + got, len - got));
        } catch (...) {
            co_return false;
        }
        if (r == 0) {
            co_return false;
        }
        got += r;
    }
    co_return true;
}

net::awaitable<bool> WriteFull(AsyncStream& stream, const uint8_t* buf, size_t len) {
    if (len == 0) {
        co_return true;
    }

    try {
        const std::array<net::const_buffer, 1> buffers{
            net::buffer(buf, len)
        };
        co_await stream.WriteBuffers(buffers);
    } catch (...) {
        co_return false;
    }
    co_return true;
}

uint8_t* PrepareScratch(memory::ByteVector& buffer, size_t size) {
    if (buffer.size() < size) {
        buffer.resize(size);
    }
    return buffer.data();
}

[[nodiscard]] bool EncodeChunkLength(vmess::VMessCipher* length_cipher,
                                     vmess::ShakeMask* mask,
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

}  // namespace

namespace vmess::encoding {

namespace {

struct EncodeRequestHeaderState final {
    MemoryAccount user;
    TargetAddress target;
    Security security = Security::AES_128_GCM;
    Command command = Command::TCP;
    bool sent = false;

    std::array<uint8_t, 16> body_key{};
    std::array<uint8_t, 16> body_iv{};
    std::array<uint8_t, 16> request_key{};
    std::array<uint8_t, 16> request_iv{};
    std::array<uint8_t, 16> response_key{};
    std::array<uint8_t, 16> response_iv{};
    uint8_t response_header = 0;
    uint8_t options = 0;
};

struct DecodeResponseHeaderState final {
    std::array<uint8_t, 16> response_key{};
    std::array<uint8_t, 16> response_iv{};
    uint8_t response_header = 0;
    bool received = false;
};

}  // namespace

net::awaitable<bool> EncodeRequestBodyChunk(EncodeRequestBodyState& state,
                                            AsyncStream& stream,
                                            const uint8_t* data,
                                            size_t len) {
    size_t padding_len = 0;
    if (state.global_padding && state.mask) {
        const uint16_t padding_mask = state.mask->NextMask();
        padding_len = padding_mask % 64;
    }

    const size_t length_header_size = state.length_cipher ? state.length_cipher->Overhead() + 2 : 2;
    const size_t max_output_size =
        length_header_size + len + state.cipher->Overhead() + padding_len;
    if (max_output_size <= buf::Buffer::kSize) {
        buf::BufferGuard out{buf::Buffer::New()};
        if (!out) {
            co_return false;
        }

        uint8_t* write_scratch = out->Tail().data();
        ssize_t enc_len = state.cipher->Encrypt(data, len, write_scratch + length_header_size);
        if (enc_len < 0) {
            co_return false;
        }

        const uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);
        size_t encoded_length_size = 0;
        if (!EncodeChunkLength(state.length_cipher ? &*state.length_cipher : nullptr,
                               state.length_cipher ? nullptr : (state.mask ? &*state.mask : nullptr),
                               total_len,
                               write_scratch,
                               encoded_length_size)) {
            co_return false;
        }

        if (padding_len > 0) {
            RAND_bytes(write_scratch + encoded_length_size + enc_len, static_cast<int>(padding_len));
        }

        const size_t output_size = encoded_length_size + static_cast<size_t>(enc_len) + padding_len;
        out->Produce(static_cast<uint32_t>(output_size));
        buf::MultiBuffer mb{out.release()};
        try {
            co_await stream.WriteMultiBuffer(std::move(mb));
        } catch (...) {
            co_return false;
        }
        co_return true;
    }

    memory::ByteVector write_output_buf;
    uint8_t* write_scratch = PrepareScratch(write_output_buf, max_output_size);

    ssize_t enc_len = state.cipher->Encrypt(data, len, write_scratch + length_header_size);
    if (enc_len < 0) {
        ReleaseIdleBuffer(write_output_buf, 0);
        co_return false;
    }

    const uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);
    size_t encoded_length_size = 0;
    if (!EncodeChunkLength(state.length_cipher ? &*state.length_cipher : nullptr,
                           state.length_cipher ? nullptr : (state.mask ? &*state.mask : nullptr),
                           total_len,
                           write_scratch,
                           encoded_length_size)) {
        ReleaseIdleBuffer(write_output_buf, 0);
        co_return false;
    }

    if (padding_len > 0) {
        RAND_bytes(write_scratch + encoded_length_size + enc_len, static_cast<int>(padding_len));
    }

    const size_t output_size = encoded_length_size + static_cast<size_t>(enc_len) + padding_len;
    const bool ok = co_await WriteFull(stream, write_scratch, output_size);
    ReleaseIdleBuffer(write_output_buf, 0);
    co_return ok;
}

struct RequestBodyEncodeBudget final {
    size_t length_header_size = 0;
    size_t stream_chunk_size = 0;
};

[[nodiscard]] RequestBodyEncodeBudget MakeRequestBodyEncodeBudget(
    const EncodeRequestBodyState& state) {
    const size_t overhead = state.cipher->Overhead();
    const size_t length_header_size = state.length_cipher ? state.length_cipher->Overhead() + 2 : 2;
    const size_t max_padding_len =
        (state.global_padding && state.mask) ? kStreamMaxPaddingLen : 0;
    if (buf::Buffer::kSize <= length_header_size + overhead + max_padding_len) {
        ThrowVMessWriteError("VMess client buffer budget too small");
    }
    const size_t stream_chunk_size = std::min(
        size_t(kVMessBodyMaxChunkSize - overhead),
        size_t(buf::Buffer::kSize - length_header_size - overhead - max_padding_len));
    return RequestBodyEncodeBudget{length_header_size, stream_chunk_size};
}

void EncodeRequestBodyBytes(EncodeRequestBodyState& state,
                            const RequestBodyEncodeBudget& budget,
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

        size_t padding_len = 0;
        if (state.global_padding && state.mask) {
            const uint16_t padding_mask = state.mask->NextMask();
            padding_len = padding_mask % 64;
        }

        buf::BufferGuard out{buf::Buffer::New()};
        if (!out) {
            throw std::bad_alloc();
        }

        uint8_t* dst = out->Tail().data();
        ssize_t enc_len = state.cipher->Encrypt(
            data + offset, chunk_size, dst + budget.length_header_size);
        if (enc_len < 0) {
            ThrowVMessWriteError("VMess client stream encrypt failed");
        }

        const uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);
        size_t encoded_length_size = 0;
        if (!EncodeChunkLength(state.length_cipher ? &*state.length_cipher : nullptr,
                               state.length_cipher ? nullptr : (state.mask ? &*state.mask : nullptr),
                               total_len,
                               dst,
                               encoded_length_size)) {
            ThrowVMessWriteError("VMess client length encrypt failed");
        }

        if (padding_len > 0) {
            RAND_bytes(dst + encoded_length_size + enc_len, static_cast<int>(padding_len));
        }

        const size_t output_size =
            encoded_length_size + static_cast<size_t>(enc_len) + padding_len;
        out->Produce(static_cast<uint32_t>(output_size));
        out_mb.push_back(out.release());

        offset += chunk_size;
    }
}

net::awaitable<void> EncodeRequestBodyMultiBuffer(EncodeRequestBodyState& state,
                                                  AsyncStream& stream,
                                                  buf::MultiBuffer mb) {

    if (!buf::HasData(mb)) {
        co_return;
    }

    const RequestBodyEncodeBudget budget = MakeRequestBodyEncodeBudget(state);
    buf::MultiBuffer out_mb;
    out_mb.reserve(mb.size());

    for (auto* buffer : mb) {
        if (!buffer) {
            continue;
        }
        EncodeRequestBodyBytes(state, budget, buffer->Bytes(), out_mb);
    }
    mb.clear();

    if (buf::HasData(out_mb)) {
        co_await stream.WriteMultiBuffer(std::move(out_mb));
    }
}

net::awaitable<void> EncodeRequestBodyBuffers(
    EncodeRequestBodyState& state,
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

    const RequestBodyEncodeBudget budget = MakeRequestBodyEncodeBudget(state);
    buf::MultiBuffer out_mb;
    out_mb.reserve(buffers.size());

    for (const net::const_buffer& buffer : buffers) {
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        if (!data || buffer.size() == 0) {
            continue;
        }
        EncodeRequestBodyBytes(
            state,
            budget,
            std::span<const uint8_t>(data, buffer.size()),
            out_mb);
    }

    if (buf::HasData(out_mb)) {
        co_await stream.WriteMultiBuffer(std::move(out_mb));
    }
}

net::awaitable<void> EncodeRequestBodyEOF(EncodeRequestBodyState& state,
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
        co_return;
    }
    uint8_t* eof_buf = out->Tail().data();
    const size_t length_header_size = state.length_cipher ? state.length_cipher->Overhead() + 2 : 2;
    ssize_t enc_len = state.cipher->Encrypt(nullptr, 0, eof_buf + length_header_size);
    if (enc_len < 0) {
        co_return;
    }

    const uint16_t total_len = static_cast<uint16_t>(enc_len + padding_len);
    size_t encoded_length_size = 0;
    if (!EncodeChunkLength(state.length_cipher ? &*state.length_cipher : nullptr,
                           state.length_cipher ? nullptr : (state.mask ? &*state.mask : nullptr),
                           total_len,
                           eof_buf,
                           encoded_length_size)) {
        co_return;
    }

    if (padding_len > 0) {
        RAND_bytes(eof_buf + encoded_length_size + enc_len, static_cast<int>(padding_len));
    }

    const size_t output_size = encoded_length_size + static_cast<size_t>(enc_len) + padding_len;
    out->Produce(static_cast<uint32_t>(output_size));
    buf::MultiBuffer mb{out.release()};
    try {
        co_await stream.WriteMultiBuffer(std::move(mb));
    } catch (...) {
        co_return;
    }
    state.eof_sent = true;
}

net::awaitable<buf::MultiBuffer> DecodeResponseBody(DecodeResponseBodyState& state,
                                               AsyncStream& stream) {
    if (state.eof) {
        co_return buf::MultiBuffer{};
    }

    uint8_t len_buf[18];
    const size_t length_header_size = state.length_cipher ? state.length_cipher->Overhead() + 2 : 2;
    if (!co_await ReadFull(stream, len_buf, length_header_size)) {
        LOG_ACCESS_DEBUG("VMess client: DecodeResponseBody TCP-level close "
                         "(failed to read chunk header)");
        state.eof = true;
        throw IoSystemError(io_error::connection_reset, "VMess client stream read error");
    }

    uint16_t raw_len = 0;
    if (state.length_cipher) {
        uint8_t len_plain[2];
        const ssize_t dec_len = state.length_cipher->Decrypt(
            len_buf, length_header_size, len_plain);
        if (dec_len != 2) {
            LOG_ACCESS_DEBUG("VMess client: DecodeResponseBody authenticated length decrypt failed");
            state.eof = true;
            throw IoSystemError(io_error::connection_reset, "VMess client stream read error");
        }
        raw_len = static_cast<uint16_t>(
            (static_cast<uint16_t>(len_plain[0]) << 8) | len_plain[1]);
        raw_len = static_cast<uint16_t>(raw_len + state.length_cipher->Overhead());
    } else {
        raw_len = (static_cast<uint16_t>(len_buf[0]) << 8) | len_buf[1];
    }

    size_t padding_len = 0;
    if (state.global_padding && state.mask) {
        const uint16_t padding_mask = state.mask->NextMask();
        padding_len = padding_mask % 64;
    }

    uint16_t chunk_len = raw_len;
    if (!state.length_cipher && state.mask) {
        const uint16_t size_mask = state.mask->NextMask();
        chunk_len ^= size_mask;
    }

    const size_t overhead = state.cipher->Overhead();

    if (chunk_len == overhead + padding_len) {
        alignas(16) uint8_t eof_stack[128];
        memory::ByteVector eof_buf;
        uint8_t* eof_crypto = eof_stack;
        if (chunk_len > sizeof(eof_stack)) {
            eof_crypto = PrepareScratch(eof_buf, chunk_len);
        }

        const bool ok = co_await ReadFull(stream, eof_crypto, chunk_len);
        ReleaseIdleBuffer(eof_buf, 0);
        if (!ok) {
            state.eof = true;
            throw IoSystemError(io_error::connection_reset, "VMess client stream read error");
        }
        state.eof = true;
        co_return buf::MultiBuffer{};
    }

    if (chunk_len < overhead + padding_len || chunk_len > kVMessBodyMaxChunkSize + overhead + 64) {
        LOG_ACCESS_DEBUG("VMess client: DecodeResponseBody INVALID length raw_len={} chunk_len={} "
                         "overhead={} padding={}", raw_len, chunk_len, overhead, padding_len);
        state.eof = true;
        throw IoSystemError(io_error::connection_reset, "VMess client stream read error");
    }

    buf::BufferGuard crypto_pool;
    memory::ByteVector crypto_buf;
    uint8_t* crypto_scratch = nullptr;
    if (chunk_len <= buf::Buffer::kSize) {
        crypto_pool = buf::BufferGuard{buf::Buffer::New()};
        if (!crypto_pool) {
            throw std::bad_alloc();
        }
        crypto_scratch = crypto_pool->Tail().data();
    } else {
        crypto_scratch = PrepareScratch(crypto_buf, chunk_len);
    }

    if (!co_await ReadFull(stream, crypto_scratch, chunk_len)) {
        ReleaseIdleBuffer(crypto_buf, 0);
        LOG_ACCESS_DEBUG("VMess client: DecodeResponseBody ReadFull failed chunk_len={} "
                         "(TCP 连接在 chunk body 传输中断开)", chunk_len);
        state.eof = true;
        throw IoSystemError(io_error::connection_reset, "VMess client stream read error");
    }

    const size_t data_len = chunk_len - padding_len;
    const size_t expected_plain_len = data_len - overhead;

    if (crypto_pool && expected_plain_len <= buf::Buffer::kSize) {
        ssize_t dec_len = state.cipher->Decrypt(crypto_scratch, data_len, crypto_scratch);
        if (dec_len < 0) {
            ReleaseIdleBuffer(crypto_buf, 0);
            state.eof = true;
            throw IoSystemError(io_error::connection_reset, "VMess client stream read error");
        }
        crypto_pool->Produce(static_cast<uint32_t>(dec_len));
        co_return buf::MultiBuffer{crypto_pool.release()};
    }

    memory::ByteVector plain_buf;
    uint8_t* plain = PrepareScratch(plain_buf, expected_plain_len);
    ssize_t dec_len = state.cipher->Decrypt(crypto_scratch, data_len, plain);
    if (dec_len < 0) {
        ReleaseIdleBuffer(crypto_buf, 0);
        ReleaseIdleBuffer(plain_buf, 0);
        state.eof = true;
        throw IoSystemError(io_error::connection_reset, "VMess client stream read error");
    }
    ReleaseIdleBuffer(crypto_buf, 0);

    buf::BufferGuard out{buf::Buffer::New()};
    if (!out) {
        ReleaseIdleBuffer(plain_buf, 0);
        throw std::bad_alloc();
    }

    const size_t dec_size = static_cast<size_t>(dec_len);
    const size_t first_copy = std::min<size_t>(dec_size, out->Available());
    std::memcpy(out->Tail().data(), plain, first_copy);
    out->Produce(static_cast<uint32_t>(first_copy));

    buf::MultiBuffer out_mb;
    out_mb.reserve((dec_size + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
    out_mb.push_back(out.release());
    if (first_copy < dec_size &&
        !buf::AppendSpanToMultiBuffer(
            std::span<const uint8_t>(plain + first_copy, dec_size - first_copy),
            out_mb)) {
        ReleaseIdleBuffer(plain_buf, 0);
        co_return buf::MultiBuffer{};
    }
    ReleaseIdleBuffer(plain_buf, 0);
    buf::MultiBuffer result = std::move(out_mb);
    out_mb.clear();
    co_return result;
}

net::awaitable<VMessHandshakeResult> EncodeRequestHeader(EncodeRequestHeaderState& state,
                                                         AsyncStream& stream);

net::awaitable<bool> DecodeResponseHeader(DecodeResponseHeaderState& state,
                                          AsyncStream& stream);

}  // namespace vmess::encoding


namespace vmess::encoding {

net::awaitable<VMessHandshakeResult> EncodeRequestBody(
    EncodeRequestBodyState& state,
    AsyncStream& stream,
    std::span<const uint8_t> payload) {
    const size_t overhead = state.cipher->Overhead();
    const size_t max_padding_len =
        (state.global_padding && state.mask) ? kStreamMaxPaddingLen : 0;
    if (buf::Buffer::kSize <= 2 + overhead + max_padding_len) {
        co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    const size_t max_chunk_size = std::min(
        size_t(kVMessBodyMaxChunkSize - overhead),
        size_t(buf::Buffer::kSize - 2 - overhead - max_padding_len));

    size_t offset = 0;
    while (offset < payload.size()) {
        const size_t chunk_size = std::min(
            payload.size() - offset,
            max_chunk_size);
        if (!co_await EncodeRequestBodyChunk(
                state,
                stream,
                payload.data() + offset,
                chunk_size)) {
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
        offset += chunk_size;
    }
    co_return VMessHandshakeResult{};
}

net::awaitable<void> EncodeRequestBody(
    EncodeRequestBodyState& state,
    AsyncStream& stream,
    buf::MultiBuffer mb) {
    co_await EncodeRequestBodyMultiBuffer(state, stream, std::move(mb));
}

net::awaitable<void> EncodeRequestBody(
    EncodeRequestBodyState& state,
    AsyncStream& stream,
    std::span<const net::const_buffer> buffers) {
    co_await EncodeRequestBodyBuffers(state, stream, buffers);
}

net::awaitable<VMessHandshakeResult> EncodeRequestHeader(EncodeRequestHeaderState& state,
                                                         AsyncStream& stream) {
    auto fail = [](ErrorCode code) -> VMessHandshakeResult {
        if (code == ErrorCode::OK) {
            code = ErrorCode::PROTOCOL_AUTH_FAILED;
        }
        return std::unexpected(code);
    };

    if (state.sent) {
        co_return VMessHandshakeResult{};
    }

    // 获取当前时间戳
    auto now = std::chrono::system_clock::now();
    int64_t ts = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    // 构建请求头（固定缓冲，避免握手阶段临时堆分配）
    std::array<uint8_t, kVMessHandshakeHeaderMax> header{};
    size_t header_len = 0;
    auto append_header = [&](const void* data, size_t len) -> bool {
        if (header_len + len > header.size()) return false;
        std::memcpy(header.data() + header_len, data, len);
        header_len += len;
        return true;
    };
    auto append_header_u8 = [&](uint8_t v) -> bool {
        return append_header(&v, 1);
    };

    if (!append_header_u8(VERSION)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_header(state.body_iv.data(), state.body_iv.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_header(state.body_key.data(), state.body_key.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_header_u8(state.response_header)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_header_u8(state.options)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);

    // Padding Length + Security (1 byte)
    uint8_t padding_len = 0;
    if (!append_header_u8(static_cast<uint8_t>((padding_len << 4) | static_cast<uint8_t>(state.security)))) {
        co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    if (!append_header_u8(0)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);  // Reserved
    if (!append_header_u8(static_cast<uint8_t>(state.command))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);

    const uint8_t port_be[2] = {
        static_cast<uint8_t>(state.target.port >> 8),
        static_cast<uint8_t>(state.target.port & 0xFF)
    };
    if (!append_header(port_be, sizeof(port_be))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);

    // Address
    if (state.target.IsDomain()) {
        if (state.target.host.size() > 255) co_return fail(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        if (!append_header_u8(2)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
        if (!append_header_u8(static_cast<uint8_t>(state.target.host.size()))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
        if (!append_header(state.target.host.data(), state.target.host.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    } else if (state.target.resolved_addr && state.target.resolved_addr->is_v4()) {
        if (!append_header_u8(1)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
        auto bytes = state.target.resolved_addr->to_v4().to_bytes();
        if (!append_header(bytes.data(), bytes.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    } else if (state.target.resolved_addr && state.target.resolved_addr->is_v6()) {
        if (!append_header_u8(3)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
        auto bytes = state.target.resolved_addr->to_v6().to_bytes();
        if (!append_header(bytes.data(), bytes.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    } else {
        co_return fail(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }

    // Padding (可选)
    if (padding_len > 0) {
        if (header_len + padding_len > header.size()) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
        if (RAND_bytes(header.data() + header_len, static_cast<int>(padding_len)) != 1) {
            co_return fail(ErrorCode::INTERNAL);
        }
        header_len += padding_len;
    }

    // F (checksum) - FNV1a of header
    uint32_t checksum = FNV1a32(header.data(), header_len);
    const uint8_t checksum_be[4] = {
        static_cast<uint8_t>(checksum >> 24),
        static_cast<uint8_t>(checksum >> 16),
        static_cast<uint8_t>(checksum >> 8),
        static_cast<uint8_t>(checksum)
    };
    if (!append_header(checksum_be, sizeof(checksum_be))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);

    // 生成 AuthID
    std::array<uint8_t, 16> auth_id;
    GenerateAuthID(state.user.auth_key.data(), ts, auth_id.data());

    // 生成 connection nonce (8 bytes)
    uint8_t connection_nonce[8];
    if (RAND_bytes(connection_nonce, 8) != 1) {
        co_return fail(ErrorCode::INTERNAL);
    }

    // 派生密钥需要 auth_id 和 nonce。KDF path 支持二进制 string_view，
    // 避免为每次 VMess 握手构造 16B/8B 临时 std::string。
    const std::string_view auth_id_sv(unsafe::ptr_cast<const char>(auth_id.data()), 16);
    const std::string_view nonce_sv(unsafe::ptr_cast<const char>(connection_nonce), 8);

    // 加密长度
    const std::array<std::string_view, 3> len_key_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
        auth_id_sv,
        nonce_sv
    };
    auto len_key = KDF16(state.user.cmd_key.data(), 16, len_key_path);

    uint8_t len_iv[12];
    const std::array<std::string_view, 3> len_iv_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
        auth_id_sv,
        nonce_sv
    };
    KDF(state.user.cmd_key.data(), 16, len_iv_path, len_iv, 12);

    uint8_t len_plain[2] = {
        static_cast<uint8_t>((header_len >> 8) & 0xFF),
        static_cast<uint8_t>(header_len & 0xFF)
    };

    // 加密长度（使用 AAD = auth_id）
    uint8_t len_enc[18];
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        co_return fail(ErrorCode::INTERNAL);
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, len_key.data(), len_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    // AAD = auth_id
    int out_len;
    if (EVP_EncryptUpdate(ctx, nullptr, &out_len, auth_id.data(),
                          static_cast<int>(auth_id.size())) != 1 ||
        EVP_EncryptUpdate(ctx, len_enc, &out_len, len_plain,
                          static_cast<int>(sizeof(len_plain))) != 1 ||
        EVP_EncryptFinal_ex(ctx, len_enc + out_len, &out_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, len_enc + 2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    EVP_CIPHER_CTX_free(ctx);

    // 加密请求头
    const std::array<std::string_view, 3> header_key_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_AEAD_KEY,
        auth_id_sv,
        nonce_sv
    };
    auto header_key = KDF16(state.user.cmd_key.data(), 16, header_key_path);

    uint8_t header_iv[12];
    const std::array<std::string_view, 3> header_iv_path{
        KDFSalt::VMESS_HEADER_PAYLOAD_AEAD_IV,
        auth_id_sv,
        nonce_sv
    };
    KDF(state.user.cmd_key.data(), 16, header_iv_path, header_iv, 12);

    // 加密头部（使用 AAD = auth_id）
    std::array<uint8_t, kVMessHandshakeHeaderEncMax> header_enc{};
    const size_t header_enc_len = header_len + 16;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        co_return fail(ErrorCode::INTERNAL);
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, header_key.data(), header_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    // AAD = auth_id
    if (EVP_EncryptUpdate(ctx, nullptr, &out_len, auth_id.data(),
                          static_cast<int>(auth_id.size())) != 1 ||
        EVP_EncryptUpdate(ctx, header_enc.data(), &out_len, header.data(),
                          static_cast<int>(header_len)) != 1 ||
        EVP_EncryptFinal_ex(ctx, header_enc.data() + out_len, &out_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                            header_enc.data() + header_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    EVP_CIPHER_CTX_free(ctx);

    // 发送: AuthID (16) + EncLen (18) + ConnectionNonce (8) + EncHeader
    std::array<uint8_t, kVMessHandshakePacketMax> packet{};
    size_t packet_len = 0;
    auto append_packet = [&](const void* data, size_t len) -> bool {
        if (packet_len + len > packet.size()) return false;
        std::memcpy(packet.data() + packet_len, data, len);
        packet_len += len;
        return true;
    };
    if (!append_packet(auth_id.data(), auth_id.size())) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_packet(len_enc, sizeof(len_enc))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_packet(connection_nonce, sizeof(connection_nonce))) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);
    if (!append_packet(header_enc.data(), header_enc_len)) co_return fail(ErrorCode::PROTOCOL_ENCODE_FAILED);

    if (!co_await WriteFull(stream, packet.data(), packet_len)) {
        co_return fail(ErrorCode::SOCKET_WRITE_FAILED);
    }

    state.sent = true;
    co_return VMessHandshakeResult{};
}

net::awaitable<bool> DecodeResponseHeader(DecodeResponseHeaderState& state,
                                          AsyncStream& stream) {
    if (state.received) {
        co_return true;
    }

    // 读取响应头长度 (2 + 16 bytes)
    uint8_t len_enc[18];
    if (!co_await ReadFull(stream, len_enc, 18)) {
        co_return false;
    }

    // 派生响应头长度解密密钥
    uint8_t len_key[16], len_iv[12];
    const std::array<std::string_view, 1> resp_len_key_path{
        KDFSalt::AEAD_RESP_HEADER_LEN_KEY
    };
    const std::array<std::string_view, 1> resp_len_iv_path{
        KDFSalt::AEAD_RESP_HEADER_LEN_IV
    };
    KDF(state.response_key.data(), 16, resp_len_key_path, len_key, 16);
    KDF(state.response_iv.data(), 16, resp_len_iv_path, len_iv, 12);

    // 解密长度
    uint8_t len_dec[2];
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, len_key, len_iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, len_enc + 2);

    int out_len;
    EVP_DecryptUpdate(ctx, len_dec, &out_len, len_enc, 2);
    int ret = EVP_DecryptFinal_ex(ctx, len_dec + out_len, &out_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        co_return false;
    }

    uint16_t header_len = (static_cast<uint16_t>(len_dec[0]) << 8) | len_dec[1];

    if (header_len < 4 || header_len > kVMessResponseHeaderMax) {
        co_return false;
    }

    // 读取响应头
    std::array<uint8_t, kVMessResponseHeaderMax + 16> header_enc{};
    if (!co_await ReadFull(stream, header_enc.data(), static_cast<size_t>(header_len) + 16)) {
        co_return false;
    }

    // 派生响应头解密密钥
    uint8_t header_key[16], header_iv[12];
    const std::array<std::string_view, 1> resp_header_key_path{
        KDFSalt::AEAD_RESP_HEADER_PAYLOAD_KEY
    };
    const std::array<std::string_view, 1> resp_header_iv_path{
        KDFSalt::AEAD_RESP_HEADER_PAYLOAD_IV
    };
    KDF(state.response_key.data(), 16, resp_header_key_path, header_key, 16);
    KDF(state.response_iv.data(), 16, resp_header_iv_path, header_iv, 12);

    std::array<uint8_t, kVMessResponseHeaderMax> header_dec{};
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, header_key, header_iv);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, header_enc.data() + header_len);

    EVP_DecryptUpdate(ctx, header_dec.data(), &out_len, header_enc.data(), static_cast<int>(header_len));
    ret = EVP_DecryptFinal_ex(ctx, header_dec.data() + out_len, &out_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        co_return false;
    }

    // 验证 response_header 字节
    if (header_dec[0] != state.response_header) {
        co_return false;
    }

    state.received = true;
    co_return true;
}

ClientSession::ClientSession(const MemoryAccount& user,
                             const TargetAddress& target,
                             Security security,
                             Command command,
                             uint8_t options)
    : user_(user)
    , target_(target)
    , security_(security)
    , command_(command) {
    std::array<uint8_t, 33> random_bytes{};
    if (RAND_bytes(random_bytes.data(), static_cast<int>(random_bytes.size())) != 1) {
        throw IoSystemError(io_error::operation_aborted, "VMess client session random init failed");
    }
    std::memcpy(request_body_key_.data(), random_bytes.data(), 16);
    std::memcpy(request_body_iv_.data(), random_bytes.data() + 16, 16);
    response_header_ = random_bytes[32];
    std::memcpy(request_key_.data(), request_body_key_.data(), 16);
    std::memcpy(request_iv_.data(), request_body_iv_.data(), 16);
    auto body_key_hash = SHA256Sum(request_body_key_.data(), request_body_key_.size());
    auto body_iv_hash = SHA256Sum(request_body_iv_.data(), request_body_iv_.size());
    std::memcpy(response_key_.data(), body_key_hash.data(), 16);
    std::memcpy(response_iv_.data(), body_iv_hash.data(), 16);
    options_ = options;
    if (options_ == 0) {
        options_ = Option::CHUNK_STREAM | Option::CHUNK_MASKING | Option::GLOBAL_PADDING;
    }

    request_body_state_.cipher.emplace(security_, request_key_.data(), request_iv_.data());
    if ((options_ & Option::AUTHENTICATED_LENGTH) != 0 &&
        (security_ == Security::AES_128_GCM || security_ == Security::CHACHA20_POLY1305)) {
        const std::array<std::string_view, 1> path{"auth_len"};
        auto length_key = KDF16(request_body_key_.data(), request_body_key_.size(), path);
        request_body_state_.length_cipher.emplace(
            security_, length_key.data(), request_body_iv_.data());
    }
    request_body_state_.global_padding = (options_ & Option::GLOBAL_PADDING) != 0 &&
        !(security_ == Security::NONE && command_ != Command::UDP);
    if ((options_ & Option::CHUNK_MASKING) != 0) {
        request_body_state_.mask.emplace(request_body_iv_.data());
    }

    response_body_state_.cipher.emplace(security_, response_key_.data(), response_iv_.data());
    if ((options_ & Option::AUTHENTICATED_LENGTH) != 0 &&
        (security_ == Security::AES_128_GCM || security_ == Security::CHACHA20_POLY1305)) {
        const std::array<std::string_view, 1> path{"auth_len"};
        auto length_key = KDF16(request_body_key_.data(), request_body_key_.size(), path);
        response_body_state_.length_cipher.emplace(
            security_, length_key.data(), request_body_iv_.data());
    }
    response_body_state_.global_padding = (options_ & Option::GLOBAL_PADDING) != 0 &&
        !(security_ == Security::NONE && command_ != Command::UDP);
    if ((options_ & Option::CHUNK_MASKING) != 0) {
        response_body_state_.mask.emplace(response_iv_.data());
    }
}

net::awaitable<VMessHandshakeResult> ClientSession::EncodeRequestHeader(AsyncStream& stream) {
    EncodeRequestHeaderState state;
    state.user = user_;
    state.target = target_;
    state.security = security_;
    state.command = command_;
    state.sent = sent_;
    state.body_key = request_body_key_;
    state.body_iv = request_body_iv_;
    state.request_key = request_key_;
    state.request_iv = request_iv_;
    state.response_key = response_key_;
    state.response_iv = response_iv_;
    state.response_header = response_header_;
    state.options = options_;
    auto result = co_await ::acpp::vmess::encoding::EncodeRequestHeader(state, stream);
    sent_ = state.sent;
    co_return result;
}

net::awaitable<VMessHandshakeResult> ClientSession::EncodeRequestBody(
    AsyncStream& stream,
    std::span<const uint8_t> payload) {
    auto result = co_await ::acpp::vmess::encoding::EncodeRequestBody(
        request_body_state_, stream, payload);
    co_return result;
}

net::awaitable<void> ClientSession::EncodeRequestBody(
    AsyncStream& stream,
    buf::MultiBuffer mb) {
    co_await ::acpp::vmess::encoding::EncodeRequestBody(
        request_body_state_, stream, std::move(mb));
}

net::awaitable<void> ClientSession::EncodeRequestBody(
    AsyncStream& stream,
    std::span<const net::const_buffer> buffers) {
    co_await ::acpp::vmess::encoding::EncodeRequestBody(
        request_body_state_, stream, buffers);
}

net::awaitable<void> ClientSession::EncodeRequestBodyEOF(AsyncStream& stream) {
    co_await ::acpp::vmess::encoding::EncodeRequestBodyEOF(
        request_body_state_, stream);
}

net::awaitable<bool> ClientSession::DecodeResponseHeader(AsyncStream& stream) {
    DecodeResponseHeaderState state;
    state.response_key = response_key_;
    state.response_iv = response_iv_;
    state.response_header = response_header_;
    state.received = response_header_initialized_;
    auto ok = co_await ::acpp::vmess::encoding::DecodeResponseHeader(state, stream);
    response_header_initialized_ = state.received;
    co_return ok;
}

net::awaitable<buf::MultiBuffer> ClientSession::DecodeResponseBody(AsyncStream& stream) {
    auto mb = co_await ::acpp::vmess::encoding::DecodeResponseBody(
        response_body_state_, stream);
    co_return mb;
}

}  // namespace vmess::encoding
}  // namespace acpp
