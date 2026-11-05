#include "vless_encryption_io.hpp"

#include "acppnode/common/error.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace acpp::vless {
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

}  // namespace

VlessEncryptionReader::VlessEncryptionReader(
    transport::MultiBufferReader& src,
    VlessEncryptionReadKeys keys,
    const VlessEncryptionUnitedKey& united_key,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept
    : src_(src)
    , keys_(std::move(keys))
    , united_key_(united_key)
    , header_xor_(std::move(header_xor)) {}

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
        auto out = co_await src_.ReadMultiBuffer();
        if (header_xor_) {
            for (auto* buffer : out) {
                if (!header_xor_->XorInboundInPlace(buffer->Bytes())) {
                    ThrowVlessEncryptionIoError("VLESS Encryption direct header xor failed");
                }
            }
        }
        co_return out;
    }
    auto* aead = std::get_if<VlessEncryptionAead>(&keys_);
    if (!aead) {
        if (!co_await src_.ReadExact(server_random_.data(),
                                     server_random_.size(),
                                     false, &bytes_read_)) {
            ThrowVlessEncryptionIoError("VLESS Encryption server random missing");
        }
        aead = &KeyDeferredRead(std::get<VlessEncryptionDeferredRead>(keys_));
    }

    auto& header = read_header_;
    if (encrypted_size_ == 0) {
        const bool have_header = co_await src_.ReadExact(
            header.data(), header.size(), true, &header_read_);
        if (!have_header) {
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
    if (read_bytes_.size() < encrypted_size_) {
        read_bytes_.resize(encrypted_size_);
    }
    if (!co_await src_.ReadExact(read_bytes_.data(), encrypted_size_,
                                 false, &bytes_read_)) {
        ThrowVlessEncryptionIoError("VLESS Encryption record truncated");
    }
    auto encrypted_span = std::span<uint8_t>(read_bytes_.data(), encrypted_size_);
    if (header_xor_ && !header_xor_->XorInboundInPlace(encrypted_span)) {
        ThrowVlessEncryptionIoError("VLESS Encryption body xor state failed");
    }

    const size_t plain_capacity = encrypted_span.size() - kVlessEncryptionTagSize;
    const bool rekey = IsVlessEncryptionMaxNonce(aead->Nonce());
    buf::MultiBuffer out;
    buf::BufferGuard plain_buffer;
    memory::ByteVector plain_scratch;
    std::span<uint8_t> plain;
    if (plain_capacity <= buf::Buffer::kSize) {
        plain_buffer = buf::BufferGuard{buf::Buffer::New()};
        if (!plain_buffer) {
            throw IoSystemError(io_error::fault,
                                "VLESS Encryption buffer allocation failed");
        }
        plain = plain_buffer->Tail().first(plain_capacity);
    } else {
        plain_scratch.resize(plain_capacity);
        plain = std::span<uint8_t>(plain_scratch.data(), plain_capacity);
    }

    const auto opened = OpenVlessEncryptionRecord(
        *aead,
        header,
        encrypted_span,
        plain);
    if (!opened) {
        ThrowVlessEncryptionIoError("VLESS Encryption record decrypt failed");
    }

    if (rekey) {
        memory::ByteVector rekey_context(header.size() + encrypted_span.size());
        auto next = std::copy(header.begin(), header.end(), rekey_context.begin());
        std::copy(encrypted_span.begin(), encrypted_span.end(), next);
        if (!RekeyAead(*aead, rekey_context, united_key_)) {
            ThrowVlessEncryptionIoError("VLESS Encryption read rekey failed");
        }
    }

    if (*opened > 0) {
        if (plain_buffer) {
            plain_buffer->Produce(static_cast<uint32_t>(*opened));
            out.push_back(std::move(plain_buffer));
        } else if (!buf::AppendSpanToMultiBuffer(
                       plain.first(*opened),
                       out)) {
            throw IoSystemError(io_error::fault,
                                "VLESS Encryption buffer allocation failed");
        }
    }
    header_read_ = 0;
    bytes_read_ = 0;
    encrypted_size_ = 0;
    memory::ByteVector{read_bytes_.get_allocator()}.swap(read_bytes_);
    co_return out;
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
    for (buf::Buffer* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        co_await WritePlaintext(buffer->Bytes());
    }
    mb.clear();
}

net::awaitable<void> VlessEncryptionWriter::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    for (const net::const_buffer& buffer : buffers) {
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        const size_t size = buffer.size();
        if (!data || size == 0) {
            continue;
        }
        co_await WritePlaintext(std::span<const uint8_t>{data, size});
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
        buf::BufferGuard frame_buffer;
        memory::ByteVector large_frame;
        std::span<uint8_t> frame;
        if (frame_capacity <= buf::Buffer::kSize) {
            frame_buffer = buf::BufferGuard{buf::Buffer::New()};
            if (!frame_buffer) {
                ThrowVlessEncryptionIoError("VLESS Encryption buffer allocation failed");
            }
            frame = frame_buffer->Tail().first(frame_capacity);
        } else {
            large_frame.resize(frame_capacity);
            frame = std::span<uint8_t>(large_frame.data(), frame_capacity);
        }

        const bool rekey = IsVlessEncryptionMaxNonce(aead_.Nonce());
        const auto written = SealVlessEncryptionRecord(
            aead_,
            data.first(n),
            frame);
        if (!written) {
            ThrowVlessEncryptionIoError("VLESS Encryption record encrypt failed");
        }
        auto frame_view = frame.first(*written);
        if (rekey && !RekeyAead(aead_, frame_view, united_key_)) {
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

}  // namespace acpp::vless
