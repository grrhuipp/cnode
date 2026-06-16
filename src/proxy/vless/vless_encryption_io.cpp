#include "vless_encryption_io.hpp"

#include "acppnode/common/error.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace acpp::vless {
namespace {

[[noreturn]] void ThrowVlessEncryptionIoError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

net::awaitable<bool> ReadFullFromStream(AsyncStream& stream,
                                        uint8_t* data,
                                        size_t len,
                                        bool eof_ok_at_start) {
    size_t done = 0;
    while (done < len) {
        const size_t n = co_await stream.AsyncRead(
            net::buffer(data + done, len - done));
        if (n == 0) {
            if (done == 0 && eof_ok_at_start) {
                co_return false;
            }
            ThrowVlessEncryptionIoError("VLESS Encryption record truncated");
        }
        done += n;
    }
    co_return true;
}

net::awaitable<void> WriteFullToStream(AsyncStream& stream,
                                       const uint8_t* data,
                                       size_t len) {
    size_t done = 0;
    while (done < len) {
        const size_t n = co_await stream.AsyncWrite(
            net::buffer(data + done, len - done));
        if (n == 0) {
            ThrowVlessEncryptionIoError("VLESS Encryption record write stalled");
        }
        done += n;
    }
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
    AsyncStream& src,
    std::span<const uint8_t> read_context,
    std::span<const uint8_t> united_key,
    VlessEncryptionAeadCipher cipher) noexcept {
    auto aead = VlessEncryptionAead::Create(read_context, united_key, cipher);
    if (!aead) {
        return std::nullopt;
    }
    return VlessEncryptionReader(
        src,
        std::move(*aead),
        std::vector<uint8_t>(united_key.begin(), united_key.end()));
}

VlessEncryptionReader::VlessEncryptionReader(
    AsyncStream& src,
    VlessEncryptionAead aead,
    std::vector<uint8_t> united_key) noexcept
    : src_(src)
    , aead_(std::move(aead))
    , united_key_(std::move(united_key)) {}

net::awaitable<buf::MultiBuffer> VlessEncryptionReader::ReadMultiBuffer() {
    std::array<uint8_t, kVlessEncryptionRecordHeaderSize> header{};
    const bool have_header = co_await ReadFullFromStream(
        src_,
        header.data(),
        header.size(),
        true);
    if (!have_header) {
        co_return buf::MultiBuffer{};
    }

    const auto encrypted_len = DecodeVlessEncryptionRecordHeader(header);
    if (!encrypted_len) {
        ThrowVlessEncryptionIoError("VLESS Encryption record header invalid");
    }

    std::vector<uint8_t> encrypted(*encrypted_len);
    co_await ReadFullFromStream(
        src_,
        encrypted.data(),
        encrypted.size(),
        false);

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
    AsyncStream& dst,
    std::span<const uint8_t> write_context,
    std::span<const uint8_t> united_key,
    VlessEncryptionAeadCipher cipher) noexcept {
    auto aead = VlessEncryptionAead::Create(write_context, united_key, cipher);
    if (!aead) {
        return std::nullopt;
    }
    return VlessEncryptionWriter(
        dst,
        std::move(*aead),
        std::vector<uint8_t>(united_key.begin(), united_key.end()));
}

VlessEncryptionWriter::VlessEncryptionWriter(
    AsyncStream& dst,
    VlessEncryptionAead aead,
    std::vector<uint8_t> united_key) noexcept
    : dst_(dst)
    , aead_(std::move(aead))
    , united_key_(std::move(united_key)) {}

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

            co_await WriteFullToStream(dst_, frame.data(), *written);
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
