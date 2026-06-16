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

void AppendBytesToMultiBuffer(buf::MultiBuffer& out,
                              std::span<const uint8_t> data) {
    while (!data.empty()) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            throw IoSystemError(io_error::fault,
                                "VLESS Encryption buffer allocation failed");
        }
        const size_t n = std::min<size_t>(data.size(), buffer->Available());
        std::memcpy(buffer->Tail().data(), data.data(), n);
        buffer->Produce(static_cast<uint32_t>(n));
        out.push_back(buffer.release());
        data = data.subspan(n);
    }
}

[[nodiscard]] std::vector<uint8_t> BuildRekeyContext(
    std::span<const uint8_t, kVlessEncryptionRecordHeaderSize> header,
    std::span<const uint8_t> ciphertext) {
    std::vector<uint8_t> context;
    context.reserve(header.size() + ciphertext.size());
    context.insert(context.end(), header.begin(), header.end());
    context.insert(context.end(), ciphertext.begin(), ciphertext.end());
    return context;
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
        std::vector<uint8_t>(united_key.begin(), united_key.end()),
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
        std::vector<uint8_t>(united_key.begin(), united_key.end()),
        header_xor_from_context);
}

VlessEncryptionReader::VlessEncryptionReader(
    transport::MultiBufferReader& src,
    VlessEncryptionAead aead,
    std::vector<uint8_t> united_key,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept
    : src_(src)
    , aead_(std::move(aead))
    , united_key_(std::move(united_key))
    , header_xor_(std::move(header_xor)) {}

VlessEncryptionReader::VlessEncryptionReader(
    transport::MultiBufferReader& src,
    size_t read_context_size,
    VlessEncryptionAeadCipher cipher,
    std::vector<uint8_t> united_key,
    bool header_xor_from_context) noexcept
    : src_(src)
    , united_key_(std::move(united_key))
    , aead_ready_(false)
    , cipher_(cipher)
    , pending_read_context_size_(read_context_size)
    , header_xor_from_context_(header_xor_from_context) {}

net::awaitable<buf::MultiBuffer> VlessEncryptionReader::ReadMultiBuffer() {
    if (!aead_ready_) {
        std::vector<uint8_t> context(pending_read_context_size_);
        if (!co_await src_.ReadExact(context.data(), context.size())) {
            ThrowVlessEncryptionIoError("VLESS Encryption lazy context missing");
        }
        auto aead = VlessEncryptionAead::Create(context, united_key_, cipher_);
        if (!aead) {
            ThrowVlessEncryptionIoError("VLESS Encryption lazy context invalid");
        }
        aead_ = std::move(*aead);
        if (header_xor_from_context_) {
            if (context.size() != kVlessEncryptionCtrIvSize) {
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

    std::vector<uint8_t> encrypted(*encrypted_len);
    if (!co_await src_.ReadExact(encrypted.data(), encrypted.size())) {
        ThrowVlessEncryptionIoError("VLESS Encryption record truncated");
    }
    if (header_xor_ && !header_xor_->XorInboundInPlace(encrypted)) {
        ThrowVlessEncryptionIoError("VLESS Encryption body xor state failed");
    }

    std::vector<uint8_t> plain(encrypted.size() - kVlessEncryptionTagSize);
    const bool rekey = IsVlessEncryptionMaxNonce(aead_.Nonce());
    const auto opened = OpenVlessEncryptionRecord(
        aead_,
        header,
        encrypted,
        plain);
    if (!opened) {
        ThrowVlessEncryptionIoError("VLESS Encryption record decrypt failed");
    }
    plain.resize(*opened);

    if (rekey) {
        auto context = BuildRekeyContext(header, encrypted);
        if (!Rekey(context)) {
            ThrowVlessEncryptionIoError("VLESS Encryption read rekey failed");
        }
    }

    buf::MultiBuffer out;
    AppendBytesToMultiBuffer(out, plain);
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
        std::vector<uint8_t>(united_key.begin(), united_key.end()),
        std::move(header_xor));
}

VlessEncryptionWriter::VlessEncryptionWriter(
    transport::MultiBufferWriter& dst,
    VlessEncryptionAead aead,
    std::vector<uint8_t> united_key,
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
        std::span<const uint8_t> data = buffer->Bytes();
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

            co_await WriteVlessBytes(
                dst_,
                std::span<const uint8_t>(frame.data(), *written));
            data = data.subspan(n);
        }
    }
    mb.clear();
}

net::awaitable<void> VlessEncryptionWriter::AsyncShutdownWrite() {
    co_await dst_.AsyncShutdownWrite();
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
