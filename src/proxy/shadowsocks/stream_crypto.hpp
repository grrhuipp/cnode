#pragma once

#include "shadowsocks_crypto.hpp"
#include "../handshake_timeout.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/buf/length_prefixed_packet_buffer.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <algorithm>
#include <array>
#include <exception>
#include <new>
#include <optional>
#include <span>
#include <tl/expected.hpp>

namespace acpp::ss::detail {

inline constexpr size_t kStreamChunkPayloadSize =
    buf::Buffer::kSize - (2 + SsAeadCipher::kTagSize) - SsAeadCipher::kTagSize;

[[noreturn]] inline void ThrowSsWriteError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

// Returns false on EOF before len bytes arrived.
inline net::awaitable<bool> ReadFull(AsyncStream& stream, uint8_t* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        const size_t r = co_await stream.AsyncRead(net::buffer(buf + got, len - got));
        if (r == 0) {
            co_return false;
        }
        got += r;
    }
    co_return true;
}

inline std::array<uint8_t, 12> MakeNonce(uint64_t counter) noexcept {
    std::array<uint8_t, 12> nonce{};
    for (size_t i = 0; i < 8; ++i)
        nonce[i] = static_cast<uint8_t>(counter >> (8 * i));
    return nonce;
}

inline void EncryptToMultiBuffer(SsAeadCipher& cipher,
                                 uint64_t& nonce,
                                 std::span<const uint8_t> bytes,
                                 buf::MultiBuffer& out_mb,
                                 size_t* skip_first_bytes = nullptr) {
    static constexpr size_t kLenHeaderSize = 2 + SsAeadCipher::kTagSize;

    const uint8_t* data = bytes.data();
    size_t remaining = bytes.size();
    if (skip_first_bytes && *skip_first_bytes > 0) {
        const size_t skip = std::min(*skip_first_bytes, remaining);
        data += skip;
        remaining -= skip;
        *skip_first_bytes -= skip;
        if (remaining == 0) {
            return;
        }
    }

    while (remaining > 0) {
        const size_t chunk_size = std::min(remaining, kStreamChunkPayloadSize);
        buf::BufferGuard out{buf::Buffer::New()};
        if (!out) {
            throw std::bad_alloc();
        }

        uint8_t* dst = out->Tail().data();

        const uint8_t len_plain[2] = {
            static_cast<uint8_t>(chunk_size >> 8),
            static_cast<uint8_t>(chunk_size & 0xFF)
        };
        const auto nonce_l = MakeNonce(nonce);
        if (!cipher.Encrypt(nonce_l.data(), len_plain, 2, dst)) {
            throw IoSystemError(
                io_error::connection_reset,
                "Shadowsocks stream encrypt length failed");
        }
        ++nonce;

        const auto nonce_p = MakeNonce(nonce);
        if (!cipher.Encrypt(
                nonce_p.data(), data, chunk_size,
                dst + kLenHeaderSize)) {
            throw IoSystemError(
                io_error::connection_reset,
                "Shadowsocks stream encrypt payload failed");
        }
        ++nonce;

        const size_t output_size =
            kLenHeaderSize +
            chunk_size +
            SsAeadCipher::kTagSize;
        out->Produce(static_cast<uint32_t>(output_size));
        out_mb.push_back(std::move(out));

        data += chunk_size;
        remaining -= chunk_size;
    }
}

// Publish only authenticated plaintext. The cipher owns the reusable EVP state;
// this operation does not copy a key or create a per-record context.
[[nodiscard]] inline bool DecryptStreamPayload(
    SsAeadCipher& cipher, const uint8_t* ciphertext, size_t payload_len,
    const uint8_t* tag, buf::MultiBuffer& output) {
    if ((payload_len && !ciphertext) || !tag) return false;
    buf::MultiBuffer decoded;
    decoded.reserve((payload_len + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
    size_t offset = 0;
    while (offset < payload_len) {
        buf::BufferGuard plain{buf::Buffer::New()};
        if (!plain) throw std::bad_alloc();
        const size_t chunk = std::min(payload_len - offset, size_t(plain->Available()));
        if (!cipher.DecryptUpdate({ciphertext + offset, chunk}, plain->Tail().first(chunk))) return false;
        plain->Produce(static_cast<uint32_t>(chunk));
        decoded.push_back(std::move(plain));
        offset += chunk;
    }
    if (!cipher.FinishDecrypt(tag)) return false;
    decoded.MoveTo(output);
    return true;
}

[[nodiscard]] inline net::awaitable<tl::expected<void, ErrorCode>>
ReadAndDecryptStreamPayload(
    AsyncStream& stream,
    SsAeadCipher& cipher,
    std::span<const uint8_t, 12> nonce,
    size_t payload_len,
    buf::MultiBuffer& output) {
    if (!cipher.BeginDecrypt(nonce.data())) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    buf::MultiBuffer decoded;
    decoded.reserve((payload_len + buf::Buffer::kSize - 1) / buf::Buffer::kSize);

    if (payload_len > 0) {
        buf::BufferGuard cipher_buf{buf::Buffer::New()};
        if (!cipher_buf) {
            co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        }

        size_t remaining = payload_len;
        while (remaining > 0) {
            buf::BufferGuard plain{buf::Buffer::New()};
            if (!plain) {
                co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
            }

            const size_t to_process =
                std::min(remaining, static_cast<size_t>(plain->Available()));
            cipher_buf->Reset();
            if (!co_await ReadFull(stream, cipher_buf->Tail().data(), to_process)) {
                co_return tl::unexpected(
                    proxy::ResolveHandshakeReadFailure(stream));
            }
            cipher_buf->Produce(static_cast<uint32_t>(to_process));

            if (!cipher.DecryptUpdate(cipher_buf->Bytes(), plain->Tail().first(to_process))) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            plain->Produce(static_cast<uint32_t>(to_process));
            decoded.push_back(std::move(plain));
            remaining -= to_process;
        }
    }

    std::array<uint8_t, SsAeadCipher::kTagSize> payload_tag{};
    if (!co_await ReadFull(stream, payload_tag.data(), payload_tag.size())) {
        co_return tl::unexpected(
            proxy::ResolveHandshakeReadFailure(stream));
    }
    if (!cipher.FinishDecrypt(payload_tag.data())) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    decoded.MoveTo(output);
    co_return tl::expected<void, ErrorCode>{};
}

// Both TCP directions use this state machine. A length is authenticated and
// consumed once; partial ciphertext remains owned across cancellation. Return
// one record at a time, leaving a subsequent corrupt record for the next read
// rather than discarding its error after producing earlier plaintext.
class BodyReader final : public memory::ThreadAllocated,
                         public transport::MultiBufferReader {
public:
    BodyReader(SsAeadCipher cipher, uint64_t nonce, transport::MultiBufferReader& stream,
               size_t max_payload = kMaxChunkPayload, buf::MultiBuffer pending = {})
        : cipher_(std::move(cipher)), nonce_(nonce), stream_(stream),
          max_payload_(max_payload), plaintext_(std::move(pending)) {}

    transport::CancellationSource& Cancellation() noexcept override { return stream_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return stream_.ReadEofAction(); }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (failure_) std::rethrow_exception(failure_);
        if (plaintext_.byte_size() != 0) co_return std::move(plaintext_);
        for (;;) {
            try {
                auto record = DecodePending();
                if (record.byte_size() != 0) co_return record;
            } catch (...) {
                ciphertext_.clear();
                plaintext_.clear();
                failure_ = std::current_exception();
                throw;
            }
            ciphertext_.ReleaseIfIdle();
            auto raw = co_await ReadMultiBufferOrThrowOnCancel(stream_);
            if (raw.byte_size() == 0) {
                if (length_ || ciphertext_.byte_size() != 0) {
                    try { throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED); }
                    catch (...) {
                        ciphertext_.clear();
                        plaintext_.clear();
                        failure_ = std::current_exception();
                        throw;
                    }
                }
                co_return buf::MultiBuffer{};
            }
            try { AppendRaw(std::move(raw)); }
            catch (...) {
                ciphertext_.clear();
                plaintext_.clear();
                failure_ = std::current_exception();
                throw;
            }
        }
    }

private:
    void AppendRaw(buf::MultiBuffer raw) {
        buf::AppendCoalescedStreamInput(ciphertext_, std::move(raw));
    }

    buf::MultiBuffer DecodePending() {
        for (;;) {
            if (!length_) {
                std::array<uint8_t, 2 + SsAeadCipher::kTagSize> header{};
                if (ciphertext_.byte_size() < header.size()) return {};
                ciphertext_.CopyPrefixTo(header);
                std::array<uint8_t, 2> plain{};
                const auto nonce = MakeNonce(nonce_);
                if (!cipher_.Decrypt(nonce.data(), header.data(), header.size(), plain.data()))
                    throw transport::LinkError(ErrorCode::PROTOCOL_AUTH_FAILED);
                const size_t length = (size_t(plain[0]) << 8) | plain[1];
                if (length > max_payload_)
                    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
                length_ = length;
                ciphertext_.DropPrefixBytes(header.size());
                ++nonce_;
            }
            if (ciphertext_.byte_size() < *length_ + SsAeadCipher::kTagSize) return {};
            buf::MultiBuffer decoded;
            if (!ciphertext_.MovePrefixTo(decoded, *length_)) throw std::bad_alloc();
            const auto nonce = MakeNonce(nonce_);
            if (!cipher_.BeginDecrypt(nonce.data()))
                throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
            for (auto* block : decoded) {
                if (!block || block->IsEmpty()) continue;
                auto bytes = block->Bytes();
                if (!cipher_.DecryptUpdate(bytes, bytes))
                    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            std::array<uint8_t, SsAeadCipher::kTagSize> tag{};
            ciphertext_.ConsumePrefixTo(tag);
            if (!cipher_.FinishDecrypt(tag.data()))
                throw transport::LinkError(ErrorCode::PROTOCOL_AUTH_FAILED);
            length_.reset();
            ++nonce_;
            if (decoded.byte_size() != 0) return decoded;
            // An authenticated zero-length record carries no application data;
            // it is not transport EOF and cannot hide later malformed bytes.
        }
    }

    SsAeadCipher cipher_;
    uint64_t nonce_;
    transport::MultiBufferReader& stream_;
    size_t max_payload_;
    buf::MultiBuffer plaintext_;
    buf::MultiBuffer ciphertext_;
    std::optional<size_t> length_;
    std::exception_ptr failure_;
};

} // namespace acpp::ss::detail
