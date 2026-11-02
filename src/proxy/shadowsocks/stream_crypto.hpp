#pragma once

#include "shadowsocks_crypto.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/transport/link.hpp"

#include <algorithm>
#include <array>
#include <exception>
#include <optional>

namespace acpp::ss::detail {

inline std::array<uint8_t, 12> MakeNonce(uint64_t counter) noexcept {
    std::array<uint8_t, 12> nonce{};
    for (size_t i = 0; i < 8; ++i)
        nonce[i] = static_cast<uint8_t>(counter >> (8 * i));
    return nonce;
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
        if (buf::HasData(plaintext_)) co_return std::move(plaintext_);
        for (;;) {
            try {
                auto record = DecodePending();
                if (buf::HasData(record)) co_return record;
            } catch (...) {
                failure_ = std::current_exception();
                throw;
            }
            auto raw = co_await stream_.ReadMultiBuffer();
            if (!buf::HasData(raw)) {
                const auto cancellation = co_await net::this_coro::cancellation_state;
                if (cancellation.cancelled() != net::cancellation_type::none)
                    throw IoSystemError(io_error::operation_aborted);
                if (length_ || buf::HasData(ciphertext_)) {
                    try { throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED); }
                    catch (...) { failure_ = std::current_exception(); throw; }
                }
                co_return buf::MultiBuffer{};
            }
            try { AppendRaw(std::move(raw)); }
            catch (...) { failure_ = std::current_exception(); throw; }
        }
    }

private:
    void AppendRaw(buf::MultiBuffer raw) {
        while (!raw.empty()) {
            auto block = raw.pop_front();
            if (!block || block->IsEmpty()) continue;
            auto* tail = ciphertext_.back();
            if (tail && tail->Available()) {
                // Without coalescing, one-byte TCP fragments could retain one
                // entire relay block per byte of a 64 KiB SS2022 record.
                const auto count = std::min(size_t(tail->Available()), size_t(block->Len()));
                if (!buf::AppendSpanToMultiBuffer(block->Bytes().first(count), ciphertext_))
                    throw std::bad_alloc();
                block->Advance(static_cast<uint32_t>(count));
            }
            if (!block->IsEmpty()) ciphertext_.push_back(std::move(block));
        }
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
            if (buf::HasData(decoded)) return decoded;
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
