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

}  // namespace

std::optional<VlessEncryptionReader> VlessEncryptionReader::Create(
    transport::MultiBufferReader& src,
    std::span<const uint8_t> read_context,
    std::span<const uint8_t> united_key,
    VlessEncryptionAeadCipher cipher,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept {
    auto aead = VlessEncryptionAead::Create(read_context, united_key, cipher);
    if (!aead) {
        return std::nullopt;
    }
    return VlessEncryptionReader(
        src,
        std::move(*aead),
        memory::ByteVector(united_key.begin(), united_key.end()),
        std::move(header_xor));
}

VlessEncryptionReader VlessEncryptionReader::CreateLazyReadContext(
    transport::MultiBufferReader& src,
    size_t read_context_size,
    std::span<const uint8_t> united_key,
    VlessEncryptionAeadCipher cipher,
    bool header_xor_from_context) noexcept {
    return VlessEncryptionReader(
        src,
        read_context_size,
        cipher,
        memory::ByteVector(united_key.begin(), united_key.end()),
        header_xor_from_context);
}

VlessEncryptionReader::VlessEncryptionReader(
    transport::MultiBufferReader& src,
    VlessEncryptionAead aead,
    memory::ByteVector united_key,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept
    : src_(src)
    , aead_(std::move(aead))
    , united_key_(std::move(united_key))
    , header_xor_(std::move(header_xor)) {}

VlessEncryptionReader::VlessEncryptionReader(
    transport::MultiBufferReader& src,
    size_t read_context_size,
    VlessEncryptionAeadCipher cipher,
    memory::ByteVector united_key,
    bool header_xor_from_context) noexcept
    : src_(src)
    , united_key_(std::move(united_key))
    , aead_ready_(false)
    , cipher_(cipher)
    , pending_read_context_size_(read_context_size)
    , header_xor_from_context_(header_xor_from_context) {}

net::awaitable<buf::MultiBuffer> VlessEncryptionReader::ReadMultiBuffer() {
    if (!aead_ready_) {
        if (pending_read_context_size_ > kVlessEncryptionMaxRecordCiphertextSize) {
            ThrowVlessEncryptionIoError("VLESS Encryption lazy context too large");
        }
        std::array<uint8_t, kVlessEncryptionMaxRecordCiphertextSize> context;
        if (!co_await src_.ReadExact(context.data(), pending_read_context_size_)) {
            ThrowVlessEncryptionIoError("VLESS Encryption lazy context missing");
        }
        auto context_span = std::span<const uint8_t>(
            context.data(), pending_read_context_size_);
        auto aead = VlessEncryptionAead::Create(context_span, united_key_, cipher_);
        if (!aead) {
            ThrowVlessEncryptionIoError("VLESS Encryption lazy context invalid");
        }
        aead_ = std::move(*aead);
        if (header_xor_from_context_) {
            if (context_span.size() != kVlessEncryptionCtrIvSize) {
                ThrowVlessEncryptionIoError("VLESS Encryption lazy xor context invalid");
            }
            auto xor_ctx = VlessEncryptionHeaderXor::Create(
                united_key_,
                std::span<const uint8_t, kVlessEncryptionCtrIvSize>(
                    context.data(),
                    context.size()));
            if (!xor_ctx) {
                ThrowVlessEncryptionIoError("VLESS Encryption lazy xor failed");
            }
            header_xor_ = std::move(*xor_ctx);
        }
        aead_ready_ = true;
        pending_read_context_size_ = 0;
        header_xor_from_context_ = false;
    }

    std::array<uint8_t, kVlessEncryptionRecordHeaderSize> header{};
    const bool have_header = co_await src_.ReadExact(
        header.data(),
        header.size(),
        true);
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

    std::array<uint8_t, kVlessEncryptionMaxRecordCiphertextSize> encrypted;
    if (!co_await src_.ReadExact(encrypted.data(), *encrypted_len)) {
        ThrowVlessEncryptionIoError("VLESS Encryption record truncated");
    }
    auto encrypted_span = std::span<uint8_t>(encrypted.data(), *encrypted_len);
    if (header_xor_ && !header_xor_->XorInboundInPlace(encrypted_span)) {
        ThrowVlessEncryptionIoError("VLESS Encryption body xor state failed");
    }

    const size_t plain_capacity = encrypted_span.size() - kVlessEncryptionTagSize;
    const bool rekey = IsVlessEncryptionMaxNonce(aead_.Nonce());
    buf::MultiBuffer out;
    buf::BufferGuard plain_buffer;
    std::array<
        uint8_t,
        kVlessEncryptionMaxRecordCiphertextSize - kVlessEncryptionTagSize>
        plain_scratch;
    std::span<uint8_t> plain;
    if (plain_capacity <= buf::Buffer::kSize) {
        plain_buffer = buf::BufferGuard{buf::Buffer::New()};
        if (!plain_buffer) {
            throw IoSystemError(io_error::fault,
                                "VLESS Encryption buffer allocation failed");
        }
        plain = plain_buffer->Tail().first(plain_capacity);
    } else {
        plain = std::span<uint8_t>(plain_scratch.data(), plain_capacity);
    }

    const auto opened = OpenVlessEncryptionRecord(
        aead_,
        header,
        encrypted_span,
        plain);
    if (!opened) {
        ThrowVlessEncryptionIoError("VLESS Encryption record decrypt failed");
    }

    if (rekey) {
        std::array<
            uint8_t,
            kVlessEncryptionRecordHeaderSize +
                kVlessEncryptionMaxRecordCiphertextSize>
            rekey_context;
        std::copy(header.begin(), header.end(), rekey_context.begin());
        std::copy(
            encrypted_span.begin(),
            encrypted_span.end(),
            rekey_context.begin() + static_cast<std::ptrdiff_t>(header.size()));
        if (!Rekey(std::span<const uint8_t>(
                rekey_context.data(),
                header.size() + encrypted_span.size()))) {
            ThrowVlessEncryptionIoError("VLESS Encryption read rekey failed");
        }
    }

    if (*opened > 0) {
        if (plain_buffer) {
            plain_buffer->Produce(static_cast<uint32_t>(*opened));
            out.push_back(plain_buffer.release());
        } else if (!buf::AppendSpanToMultiBuffer(
                       plain.first(*opened),
                       out)) {
            throw IoSystemError(io_error::fault,
                                "VLESS Encryption buffer allocation failed");
        }
    }
    co_return out;
}

bool VlessEncryptionReader::Rekey(
    std::span<const uint8_t> context) noexcept {
    auto next = VlessEncryptionAead::Create(
        context,
        united_key_,
        aead_.Cipher());
    if (!next) {
        return false;
    }
    aead_ = std::move(*next);
    return true;
}

std::optional<VlessEncryptionWriter> VlessEncryptionWriter::Create(
    transport::MultiBufferWriter& dst,
    std::span<const uint8_t> write_context,
    std::span<const uint8_t> united_key,
    VlessEncryptionAeadCipher cipher,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept {
    auto aead = VlessEncryptionAead::Create(write_context, united_key, cipher);
    if (!aead) {
        return std::nullopt;
    }
    return VlessEncryptionWriter(
        dst,
        std::move(*aead),
        memory::ByteVector(united_key.begin(), united_key.end()),
        std::move(header_xor));
}

VlessEncryptionWriter::VlessEncryptionWriter(
    transport::MultiBufferWriter& dst,
    VlessEncryptionAead aead,
    memory::ByteVector united_key,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept
    : dst_(dst)
    , aead_(std::move(aead))
    , united_key_(std::move(united_key))
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
        std::array<
            uint8_t,
            kVlessEncryptionRecordHeaderSize +
                kVlessEncryptionMaxPlaintextSize +
                kVlessEncryptionTagSize> frame{};

        const bool rekey = IsVlessEncryptionMaxNonce(aead_.Nonce());
        const auto written = SealVlessEncryptionRecord(
            aead_,
            data.first(n),
            frame);
        if (!written) {
            ThrowVlessEncryptionIoError("VLESS Encryption record encrypt failed");
        }
        if (rekey && !Rekey(std::span<const uint8_t>(
                         frame.data(),
                         *written))) {
            ThrowVlessEncryptionIoError("VLESS Encryption write rekey failed");
        }
        auto frame_view = std::span<uint8_t>(frame.data(), *written);
        if (header_xor_ &&
            !header_xor_->XorOutboundInPlace(frame_view)) {
            ThrowVlessEncryptionIoError("VLESS Encryption write xor failed");
        }

        net::const_buffer buffer{frame.data(), *written};
        co_await dst_.WriteBuffers(
            std::span<const net::const_buffer>{&buffer, 1});
        data = data.subspan(n);
    }
}

bool VlessEncryptionWriter::Rekey(
    std::span<const uint8_t> context) noexcept {
    auto next = VlessEncryptionAead::Create(
        context,
        united_key_,
        aead_.Cipher());
    if (!next) {
        return false;
    }
    aead_ = std::move(*next);
    return true;
}

}  // namespace acpp::vless
