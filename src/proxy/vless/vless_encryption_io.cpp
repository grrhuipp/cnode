#include "vless_encryption_io.hpp"

#include "common/error.hpp"
#include "common/buffer_util.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace vless {
namespace {

[[noreturn]] void ThrowVlessEncryptionIoError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

// Replaces the AEAD after the record sealed or opened at the maximum nonce;
// `context` is that complete wire record.
[[nodiscard]] bool RekeyAead(VlessEncryptionAead& aead,
                             std::span<const uint8_t> context,
                             const VlessEncryptionUnitedKey& united_key) noexcept {
    auto next = VlessEncryptionAead::Create(
        context,
        united_key.bytes,
        aead.Cipher());
    if (!next) {
        return false;
    }
    aead = std::move(*next);
    return true;
}

[[nodiscard]] bool WillReachVlessEncryptionMaxNonce(
    const VlessEncryptionNonce& nonce) noexcept {
    auto next = nonce;
    IncreaseVlessEncryptionNonce(next);
    return IsVlessEncryptionMaxNonce(next);
}

}  // namespace

VlessEncryptionReader::VlessEncryptionReader(
    transport::MultiBufferReader& src,
    VlessEncryptionReadKeys keys,
    const VlessEncryptionUnitedKey& united_key,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept
    : src_(src)
    , keys_(std::move(keys))
    , united_key_(united_key)
    , header_xor_(std::move(header_xor)) {
    if (const auto* deferred = std::get_if<VlessEncryptionDeferredRead>(&keys_)) {
        unverified_ticket_ = deferred->ticket_rejection;
    }
}

void VlessEncryptionReader::RejectDeferredTicket() noexcept {
    if (unverified_ticket_) {
        unverified_ticket_->rejected = true;
        unverified_ticket_ = nullptr;
    }
}

VlessEncryptionAead& VlessEncryptionReader::KeyDeferredRead(
    const VlessEncryptionDeferredRead& deferred) {
    auto aead = VlessEncryptionAead::Create(
        server_random_, united_key_.bytes, deferred.cipher);
    if (!aead) {
        ThrowVlessEncryptionIoError("VLESS Encryption server random invalid");
    }
    if (deferred.header_xor) {
        header_xor_ = VlessEncryptionHeaderXor::Create(
            united_key_.bytes, server_random_);
        if (!header_xor_) {
            ThrowVlessEncryptionIoError("VLESS Encryption lazy xor failed");
        }
    }
    bytes_read_ = 0;
    return keys_.emplace<VlessEncryptionAead>(std::move(*aead));
}

bool VlessEncryptionReader::EnableRawRead() noexcept {
    if (header_read_ != 0 || bytes_read_ != 0 || encrypted_size_ != 0 ||
        !std::holds_alternative<VlessEncryptionAead>(keys_)) {
        return false;
    }
    // Xray unwraps CommonConn, not its underlying TLS transport a second time.
    // In random mode XorConn stays in place across the transition.
    raw_read_ = true;
    return true;
}

net::awaitable<buf::MultiBuffer> VlessEncryptionReader::ReadMultiBuffer() {
    if (raw_read_) {
        auto out = co_await ReadMultiBufferOrThrowOnCancel(
            src_, "VLESS Encryption read cancelled");
        if (header_xor_) {
            for (auto* buffer : out) {
                if (!header_xor_->XorInboundInPlace(buffer->Bytes())) {
                    ThrowVlessEncryptionIoError("VLESS Encryption direct header xor failed");
                }
            }
        }
        co_return out;
    }
    try {
        auto* aead = std::get_if<VlessEncryptionAead>(&keys_);
        if (!aead) {
            if (!co_await src_.ReadExact(server_random_.data(),
                                         server_random_.size(),
                                         false, &bytes_read_)) {
                ThrowVlessEncryptionIoError("VLESS Encryption server random missing");
            }
            aead = &KeyDeferredRead(std::get<VlessEncryptionDeferredRead>(keys_));
        }

        for (;;) {
            auto& header = read_header_;
            if (encrypted_size_ == 0) {
                const bool have_header = co_await src_.ReadExact(
                    header.data(), header.size(), true, &header_read_);
                if (!have_header) {
                    if (header_read_ != 0) {
                        ThrowVlessEncryptionIoError("VLESS Encryption record header truncated");
                    }
                    const auto cancellation =
                        co_await net::this_coro::cancellation_state;
                    if (cancellation.cancelled() !=
                        net::cancellation_type::none) {
                        throw IoSystemError(
                            io_error::operation_aborted,
                            "VLESS Encryption read cancelled");
                    }
                    RejectDeferredTicket();
                    read_record_.Reset();
                    co_return buf::MultiBuffer{};
                }
                if (header_xor_ && !header_xor_->XorInboundInPlace(header)) {
                    ThrowVlessEncryptionIoError("VLESS Encryption header xor failed");
                }
                const auto encrypted_len = DecodeVlessEncryptionRecordHeader(header);
                if (!encrypted_len) {
                    ThrowVlessEncryptionIoError("VLESS Encryption record header invalid");
                }
                encrypted_size_ = *encrypted_len;
            }

            // `encrypted_size_` is bounded by kVlessEncryptionMaxRecordCiphertextSize.
            if (bytes_read_ == 0 && read_record_.Empty()) {
                (void)read_record_.Prepare(encrypted_size_);
            }
            uint8_t* record_bytes = read_record_.Data();
            if (!co_await src_.ReadExact(record_bytes, encrypted_size_,
                                         false, &bytes_read_)) {
                ThrowVlessEncryptionIoError("VLESS Encryption record truncated");
            }
            auto encrypted_span = std::span<uint8_t>(record_bytes, encrypted_size_);
            if (header_xor_ && !header_xor_->XorInboundInPlace(encrypted_span)) {
                ThrowVlessEncryptionIoError("VLESS Encryption body xor state failed");
            }

            memory::ByteVector rekey_context;
            if (WillReachVlessEncryptionMaxNonce(aead->Nonce())) {
                rekey_context.resize(header.size() + encrypted_span.size());
                auto next = std::copy(header.begin(), header.end(), rekey_context.begin());
                std::copy(encrypted_span.begin(), encrypted_span.end(), next);
            }

            const auto opened = OpenVlessEncryptionRecord(
                *aead,
                header,
                encrypted_span,
                encrypted_span);
            if (!opened) {
                ThrowVlessEncryptionIoError("VLESS Encryption record decrypt failed");
            }
            unverified_ticket_ = nullptr;

            if (!rekey_context.empty() &&
                !RekeyAead(*aead, rekey_context, united_key_)) {
                ThrowVlessEncryptionIoError("VLESS Encryption read rekey failed");
            }

            header_read_ = 0;
            bytes_read_ = 0;
            encrypted_size_ = 0;
            if (*opened == 0) {
                read_record_.Reset();
                continue;
            }
            buf::MultiBuffer out;
            if (!read_record_.TryAppendTo(*opened, out)) {
                throw IoSystemError(io_error::fault,
                                    "VLESS Encryption buffer allocation failed");
            }
            co_return out;
        }
    } catch (const IoSystemError& error) {
        if (error.code() != io_error::operation_aborted) {
            RejectDeferredTicket();
            header_read_ = 0;
            bytes_read_ = 0;
            encrypted_size_ = 0;
            read_record_.Reset();
        }
        throw;
    } catch (...) {
        RejectDeferredTicket();
        header_read_ = 0;
        bytes_read_ = 0;
        encrypted_size_ = 0;
        read_record_.Reset();
        throw;
    }
}

VlessEncryptionWriter::VlessEncryptionWriter(
    transport::MultiBufferWriter& dst,
    VlessEncryptionAead aead,
    const VlessEncryptionUnitedKey& united_key,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept
    : dst_(dst)
    , aead_(std::move(aead))
    , united_key_(united_key)
    , header_xor_(std::move(header_xor)) {}

net::awaitable<void> VlessEncryptionWriter::WriteMultiBuffer(
    buf::MultiBuffer mb) {
    if (mb.empty()) {
        co_return;
    }
    ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> buffers;
    buffers.AppendMultiBuffer(mb);
    if (!buffers.empty()) {
        co_await WriteBuffers(buffers.Span());
    }
    mb.clear();
}

net::awaitable<void> VlessEncryptionWriter::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    size_t idx = 0;
    size_t offset = 0;
    auto skip_empty = [&]() noexcept {
        while (idx < buffers.size()) {
            const auto* data = static_cast<const uint8_t*>(buffers[idx].data());
            if (data && offset < buffers[idx].size()) {
                return;
            }
            ++idx;
            offset = 0;
        }
    };

    skip_empty();
    while (idx < buffers.size()) {
        const auto* first_data =
            static_cast<const uint8_t*>(buffers[idx].data()) + offset;
        const size_t first_rem = buffers[idx].size() - offset;

        bool has_more = false;
        if (first_rem < kVlessEncryptionMaxPlaintextSize) {
            for (size_t j = idx + 1; j < buffers.size(); ++j) {
                if (buffers[j].data() && buffers[j].size() > 0) {
                    has_more = true;
                    break;
                }
            }
        }

        if (!has_more) {
            const size_t n = std::min(first_rem, kVlessEncryptionMaxPlaintextSize);
            offset += n;
            skip_empty();
            co_await WritePlaintext(std::span<const uint8_t>{first_data, n});
            continue;
        }

        static_assert(kVlessEncryptionMaxPlaintextSize <= buf::Buffer::kSize);
        buf::BufferGuard chunk{buf::Buffer::New()};
        if (!chunk) {
            ThrowVlessEncryptionIoError("VLESS Encryption buffer allocation failed");
        }
        uint8_t* dst = chunk->Tail().data();
        size_t filled = 0;
        while (idx < buffers.size() && filled < kVlessEncryptionMaxPlaintextSize) {
            const auto* data =
                static_cast<const uint8_t*>(buffers[idx].data()) + offset;
            const size_t rem = buffers[idx].size() - offset;
            const size_t copy_len =
                std::min(rem, kVlessEncryptionMaxPlaintextSize - filled);
            std::memcpy(dst + filled, data, copy_len);
            filled += copy_len;
            offset += copy_len;
            skip_empty();
        }
        chunk->Produce(static_cast<uint32_t>(filled));
        try {
            co_await WritePlaintext(chunk->Bytes());
        } catch (...) {
            OPENSSL_cleanse(dst, filled);
            throw;
        }
        OPENSSL_cleanse(dst, filled);
    }
}

net::awaitable<void> VlessEncryptionWriter::AsyncShutdownWrite() {
    co_await dst_.AsyncShutdownWrite();
}

net::awaitable<void> VlessEncryptionWriter::WritePlaintext(
    std::span<const uint8_t> data) {
    while (!data.empty()) {
        const size_t n = std::min<size_t>(
            data.size(),
            kVlessEncryptionMaxPlaintextSize);
        const size_t frame_capacity =
            kVlessEncryptionRecordHeaderSize + n + kVlessEncryptionTagSize;
        buf::ContiguousWriteBuffer frame_buffer;
        uint8_t* frame_ptr = frame_buffer.TryPrepare(frame_capacity);
        if (!frame_ptr) {
            ThrowVlessEncryptionIoError("VLESS Encryption buffer allocation failed");
        }
        std::span<uint8_t> frame{frame_ptr, frame_capacity};

        const auto written = SealVlessEncryptionRecord(
            aead_,
            data.first(n),
            frame);
        if (!written) {
            ThrowVlessEncryptionIoError("VLESS Encryption record encrypt failed");
        }
        auto frame_view = frame.first(*written);
        if (IsVlessEncryptionMaxNonce(aead_.Nonce()) &&
            !RekeyAead(aead_, frame_view, united_key_)) {
            ThrowVlessEncryptionIoError("VLESS Encryption write rekey failed");
        }
        if (header_xor_ &&
            !header_xor_->XorOutboundInPlace(frame_view)) {
            ThrowVlessEncryptionIoError("VLESS Encryption write xor failed");
        }

        net::const_buffer buffer{frame_view.data(), frame_view.size()};
        co_await dst_.WriteBuffers(
            std::span<const net::const_buffer>{&buffer, 1});
        data = data.subspan(n);
    }
}

}  // namespace vless
