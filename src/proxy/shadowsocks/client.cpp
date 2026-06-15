#include "shadowsocks_crypto.hpp"
#include "client.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <new>
#include <optional>
#include <utility>
#include <vector>

namespace acpp::ss {

namespace {

constexpr size_t kStreamFlushBufferCount = 2;
constexpr size_t kStreamFlushBytes = buf::Buffer::kSize * kStreamFlushBufferCount;
constexpr size_t kStreamChunkPayloadSize =
    buf::Buffer::kSize - 2 - SsAeadCipher::kTagSize;

[[noreturn]] void ThrowSsWriteError(const char* what) {
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

[[nodiscard]] std::array<uint8_t, 12> MakeNonce(uint64_t counter) {
    std::array<uint8_t, 12> nonce{};
    for (int i = 0; i < 8; ++i) {
        nonce[static_cast<size_t>(i)] = static_cast<uint8_t>(counter >> (8 * i));
    }
    return nonce;
}

class SsAeadStreamDecryptor {
public:
    explicit SsAeadStreamDecryptor(const SsAeadCipher& cipher)
        : type_(cipher.Type())
        , key_size_(cipher.Key().size()) {
        if (key_size_ == 0 || key_size_ > key_.size()) {
            return;
        }
        std::memcpy(key_.data(), cipher.Key().data(), key_size_);
        ctx_ = EVP_CIPHER_CTX_new();
    }

    ~SsAeadStreamDecryptor() {
        if (ctx_) {
            EVP_CIPHER_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }

    SsAeadStreamDecryptor(const SsAeadStreamDecryptor&) = delete;
    SsAeadStreamDecryptor& operator=(const SsAeadStreamDecryptor&) = delete;

    bool Init(const uint8_t* nonce) noexcept {
        if (!ctx_ || !nonce) return false;

        const EVP_CIPHER* cipher = GetCipher(type_);
        if (!cipher) return false;

        if (EVP_CIPHER_CTX_reset(ctx_) != 1) return false;
        if (EVP_DecryptInit_ex(ctx_, cipher, nullptr, nullptr, nullptr) != 1) return false;
        if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) return false;
        if (EVP_DecryptInit_ex(ctx_, nullptr, nullptr, key_.data(), nonce) != 1) return false;
        return true;
    }

    bool Update(const uint8_t* ciphertext,
                size_t ciphertext_len,
                uint8_t* output,
                int* out_len) noexcept {
        if (!ctx_ || !ciphertext || !output || !out_len) return false;

        return EVP_DecryptUpdate(
            ctx_, output, out_len,
            ciphertext, static_cast<int>(ciphertext_len)) == 1;
    }

    bool Final(const uint8_t* tag) noexcept {
        if (!ctx_ || !tag) return false;

        if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_TAG, 16,
                                 const_cast<uint8_t*>(tag)) != 1) {
            return false;
        }

        int final_len = 0;
        uint8_t dummy[1]{};
        return EVP_DecryptFinal_ex(ctx_, dummy, &final_len) == 1;
    }

private:
    static const EVP_CIPHER* GetCipher(SsCipherType type) noexcept {
        switch (BaseCipherType(type)) {
            case SsCipherType::AES_128_GCM:      return EVP_aes_128_gcm();
            case SsCipherType::AES_256_GCM:      return EVP_aes_256_gcm();
            case SsCipherType::CHACHA20_POLY1305:return EVP_chacha20_poly1305();
            default:                             return nullptr;
        }
    }

    SsCipherType type_;
    std::array<uint8_t, 32> key_{};
    size_t key_size_ = 0;
    EVP_CIPHER_CTX* ctx_ = nullptr;
};

size_t EncodeSocks5AddressTo(const TargetAddress& addr,
                            uint8_t* output,
                            size_t output_size) {
    const size_t needed = addr.IsDomain()
        ? (1 + 1 + addr.host.size() + 2)
        : (addr.resolved_addr && addr.resolved_addr->is_v4()
               ? (1 + 4 + 2)
               : addr.resolved_addr && addr.resolved_addr->is_v6()
                     ? (1 + 16 + 2)
                     : 0);
    if (needed == 0 || needed > output_size) {
        return 0;
    }

    size_t pos = 0;
    if (addr.IsDomain()) {
        if (addr.host.size() > 255) return 0;
        output[pos++] = 0x03;
        output[pos++] = static_cast<uint8_t>(addr.host.size());
        std::memcpy(output + pos, addr.host.data(), addr.host.size());
        pos += addr.host.size();
    } else {
        if (addr.resolved_addr && addr.resolved_addr->is_v4()) {
            output[pos++] = 0x01;
            auto bytes = addr.resolved_addr->to_v4().to_bytes();
            std::memcpy(output + pos, bytes.data(), bytes.size());
            pos += bytes.size();
        } else if (addr.resolved_addr && addr.resolved_addr->is_v6()) {
            output[pos++] = 0x04;
            auto bytes = addr.resolved_addr->to_v6().to_bytes();
            std::memcpy(output + pos, bytes.data(), bytes.size());
            pos += bytes.size();
        } else {
            return 0;
        }
    }

    output[pos++] = static_cast<uint8_t>(addr.port >> 8);
    output[pos++] = static_cast<uint8_t>(addr.port & 0xFF);
    return pos;
}

bool WriteBytesToMultiBuffer(std::span<const uint8_t> data, buf::MultiBuffer& out) {
    size_t offset = 0;
    while (offset < data.size()) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            return false;
        }
        const size_t n = std::min(data.size() - offset,
                                  static_cast<size_t>(buffer->Available()));
        std::memcpy(buffer->Tail().data(), data.data() + offset, n);
        buffer->Produce(static_cast<uint32_t>(n));
        out.push_back(buffer.release());
        offset += n;
    }
    return true;
}

class RequestBodyWriter final : public transport::MultiBufferWriter {
public:
    RequestBodyWriter(SsAeadCipher write_cipher,
                      uint64_t write_nonce,
                      AsyncStream& stream)
        : write_cipher_(std::move(write_cipher))
        , write_nonce_(write_nonce)
        , stream_(&stream) {}

    RequestBodyWriter(const RequestBodyWriter&) = delete;
    RequestBodyWriter& operator=(const RequestBodyWriter&) = delete;
    RequestBodyWriter(RequestBodyWriter&&) = delete;
    RequestBodyWriter& operator=(RequestBodyWriter&&) = delete;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "Shadowsocks request writer has no stream");
        }
        if (mb.empty()) {
            co_return;
        }
        if (!write_cipher_) {
            ThrowSsWriteError("Shadowsocks client request writer is not initialized");
        }

        static constexpr size_t kLenHeaderSize = 2 + SsAeadCipher::kTagSize;

        buf::MultiBuffer out_mb;
        out_mb.reserve(kStreamFlushBufferCount);
        size_t out_bytes = 0;

        auto flush_out = [&stream = *stream_, &out_mb, &out_bytes]() -> net::awaitable<void> {
            if (out_mb.empty()) {
                co_return;
            }
            co_await stream.WriteMultiBuffer(std::move(out_mb));
            out_mb.clear();
            out_bytes = 0;
        };

        for (auto* buf : mb) {
            auto bytes = buf->Bytes();
            if (bytes.empty()) continue;

            const uint8_t* data = bytes.data();
            size_t remaining = bytes.size();

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
                auto nonce_l = MakeNonce(write_nonce_);
                if (!write_cipher_->Encrypt(nonce_l.data(), len_plain, 2, dst)) {
                    ThrowSsWriteError("Shadowsocks client stream encrypt length failed");
                }
                ++write_nonce_;

                auto nonce_p = MakeNonce(write_nonce_);
                if (!write_cipher_->Encrypt(
                        nonce_p.data(), data, chunk_size,
                        dst + kLenHeaderSize)) {
                    ThrowSsWriteError("Shadowsocks client stream encrypt payload failed");
                }
                ++write_nonce_;

                const size_t output_size =
                    kLenHeaderSize +
                    chunk_size +
                    SsAeadCipher::kTagSize;
                out->Produce(static_cast<uint32_t>(output_size));
                out_bytes += output_size;
                out_mb.push_back(out.release());

                data += chunk_size;
                remaining -= chunk_size;

                if (out_mb.size() >= kStreamFlushBufferCount || out_bytes >= kStreamFlushBytes) {
                    co_await flush_out();
                }
            }
        }

        co_await flush_out();
    }

private:
    std::optional<SsAeadCipher> write_cipher_;
    uint64_t write_nonce_ = 0;
    AsyncStream* stream_ = nullptr;
};

class ResponseBodyReader final : public transport::MultiBufferReader {
public:
    ResponseBodyReader(SsAeadCipher read_cipher,
                       uint64_t read_nonce,
                       AsyncStream& stream,
                       size_t max_chunk_payload = kMaxChunkPayload,
                       buf::MultiBuffer pending = {})
        : read_cipher_(std::move(read_cipher))
        , read_nonce_(read_nonce)
        , stream_(&stream)
        , max_chunk_payload_(max_chunk_payload)
        , pending_(std::move(pending)) {}

    ResponseBodyReader(const ResponseBodyReader&) = delete;
    ResponseBodyReader& operator=(const ResponseBodyReader&) = delete;
    ResponseBodyReader(ResponseBodyReader&&) = delete;
    ResponseBodyReader& operator=(ResponseBodyReader&&) = delete;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "Shadowsocks response reader has no stream");
        }
        if (!read_cipher_) {
            ThrowSsWriteError("Shadowsocks client response reader is not initialized");
        }
        if (!pending_.empty()) {
            buf::MultiBuffer result = std::move(pending_);
            pending_.clear();
            co_return result;
        }

        uint8_t enc_len_buf[2 + SsAeadCipher::kTagSize];
        if (!co_await ReadFull(*stream_, enc_len_buf, sizeof(enc_len_buf))) {
            co_return buf::MultiBuffer{};
        }

        uint8_t len_plain[2];
        auto nonce = MakeNonce(read_nonce_);
        if (!read_cipher_->Decrypt(nonce.data(), enc_len_buf, sizeof(enc_len_buf), len_plain)) {
            co_return buf::MultiBuffer{};
        }
        ++read_nonce_;

        const uint16_t payload_len =
            static_cast<uint16_t>((len_plain[0] << 8) | len_plain[1]);
        if (payload_len == 0 || payload_len > max_chunk_payload_) {
            co_return buf::MultiBuffer{};
        }

        SsAeadStreamDecryptor decryptor(*read_cipher_);
        auto nonce2 = MakeNonce(read_nonce_);
        if (!decryptor.Init(nonce2.data())) {
            co_return buf::MultiBuffer{};
        }

        buf::MultiBuffer out_mb;
        out_mb.reserve((payload_len + buf::Buffer::kSize - 1) / buf::Buffer::kSize);

        buf::BufferGuard cipher{buf::Buffer::New()};
        if (!cipher) {
            co_return buf::MultiBuffer{};
        }

        size_t remaining = payload_len;
        while (remaining > 0) {
            buf::BufferGuard out{buf::Buffer::New()};
            if (!out) {
                co_return buf::MultiBuffer{};
            }

            const size_t to_process = std::min(remaining, static_cast<size_t>(out->Available()));
            cipher->Reset();
            if (!co_await ReadFull(*stream_, cipher->Tail().data(), to_process)) {
                co_return buf::MultiBuffer{};
            }
            cipher->Produce(static_cast<uint32_t>(to_process));

            int produced = 0;
            if (!decryptor.Update(cipher->Bytes().data(), to_process,
                                  out->Tail().data(), &produced)) {
                co_return buf::MultiBuffer{};
            }
            if (produced < 0 || static_cast<size_t>(produced) != to_process) {
                co_return buf::MultiBuffer{};
            }

            out->Produce(static_cast<uint32_t>(produced));
            out_mb.push_back(out.release());
            remaining -= to_process;
        }

        uint8_t payload_tag[SsAeadCipher::kTagSize];
        if (!co_await ReadFull(*stream_, payload_tag, sizeof(payload_tag))) {
            co_return buf::MultiBuffer{};
        }
        if (!decryptor.Final(payload_tag)) {
            co_return buf::MultiBuffer{};
        }

        ++read_nonce_;

        buf::MultiBuffer result = std::move(out_mb);
        out_mb.clear();
        co_return result;
    }

private:
    std::optional<SsAeadCipher> read_cipher_;
    uint64_t read_nonce_ = 0;
    AsyncStream* stream_ = nullptr;
    size_t max_chunk_payload_ = kMaxChunkPayload;
    buf::MultiBuffer pending_;
};

net::awaitable<bool> WriteRawBytes(AsyncStream& stream, std::span<const uint8_t> data) {
    buf::MultiBuffer mb;
    mb.reserve((data.size() + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
    if (!WriteBytesToMultiBuffer(data, mb)) {
        co_return false;
    }
    try {
        co_await stream.WriteMultiBuffer(std::move(mb));
        mb.clear();
    } catch (...) {
        co_return false;
    }
    co_return true;
}

bool AppendIdentityHeaders(const SsCipherInfo& cipher_info,
                           std::span<const KeyBytes> psk_chain,
                           std::span<const uint8_t> salt,
                           std::vector<uint8_t>& out) {
    if (psk_chain.size() <= 1) {
        return true;
    }
    if (!Is2022AesCipher(cipher_info.type)) {
        return false;
    }

    for (size_t i = 0; i + 1 < psk_chain.size(); ++i) {
        const auto& current = psk_chain[i];
        const auto& next = psk_chain[i + 1];
        if (current.size < cipher_info.key_size || next.size < cipher_info.key_size) {
            return false;
        }

        std::array<uint8_t, 32> block_key{};
        if (!Derive2022IdentitySubkey(
                current.data(), cipher_info.key_size,
                salt.data(), salt.size(), block_key.data())) {
            return false;
        }

        std::array<uint8_t, 16> user_hash{};
        if (!Hash2022Psk(next.span(), std::span<uint8_t, 16>(user_hash))) {
            return false;
        }

        std::array<uint8_t, 16> encrypted{};
        if (!AesBlockCrypt(
                std::span<const uint8_t>(block_key.data(), cipher_info.key_size),
                std::span<const uint8_t, 16>(user_hash),
                std::span<uint8_t, 16>(encrypted),
                true)) {
            return false;
        }
        out.insert(out.end(), encrypted.begin(), encrypted.end());
    }
    return true;
}

net::awaitable<std::expected<WriteTCPRequestResult, ErrorCode>>
WriteTCPRequest2022(const TargetAddress& target,
                    const SsCipherInfo& cipher_info,
                    const KeyBytes& master_key,
                    std::span<const KeyBytes> psk_chain,
                    AsyncStream& stream) {
    if (cipher_info.salt_size > KeyBytes::kMaxSize ||
        cipher_info.key_size > KeyBytes::kMaxSize ||
        master_key.size < cipher_info.key_size) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    if (psk_chain.empty()) {
        psk_chain = std::span<const KeyBytes>(&master_key, 1);
    }

    std::array<uint8_t, 259> addr_bytes{};
    const size_t addr_size = EncodeSocks5AddressTo(target, addr_bytes.data(), addr_bytes.size());
    if (addr_size == 0) {
        co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    constexpr size_t kPaddingLen = 1;
    const size_t variable_len = addr_size + 2 + kPaddingLen;
    if (variable_len > kSs2022MaxChunkPayload) {
        co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    KeyBytes request_salt;
    request_salt.size = cipher_info.salt_size;
    if (RAND_bytes(request_salt.data(), static_cast<int>(request_salt.size)) != 1) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    std::array<uint8_t, 32> write_subkey{};
    if (!Derive2022Subkey(master_key.data(), cipher_info.key_size,
                          request_salt.data(), request_salt.size,
                          write_subkey.data())) {
        co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    std::array<uint8_t, kSs2022RequestFixedHeaderSize> fixed_plain{};
    fixed_plain[0] = 0;
    PutU64BE(fixed_plain.data() + 1, UnixSecondsNow());
    PutU16BE(fixed_plain.data() + 9, static_cast<uint16_t>(variable_len));

    std::vector<uint8_t> variable_plain(variable_len);
    std::memcpy(variable_plain.data(), addr_bytes.data(), addr_size);
    PutU16BE(variable_plain.data() + addr_size, static_cast<uint16_t>(kPaddingLen));
    if (RAND_bytes(variable_plain.data() + addr_size + 2, static_cast<int>(kPaddingLen)) != 1) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    SsAeadCipher write_cipher(cipher_info.type, write_subkey.data(), cipher_info.key_size);
    std::vector<uint8_t> handshake;
    handshake.reserve(
        request_salt.size + (psk_chain.size() > 0 ? (psk_chain.size() - 1) * 16 : 0) +
        fixed_plain.size() + SsAeadCipher::kTagSize +
        variable_plain.size() + SsAeadCipher::kTagSize);
    handshake.insert(handshake.end(), request_salt.bytes.begin(),
                     request_salt.bytes.begin() + static_cast<std::ptrdiff_t>(request_salt.size));
    if (!AppendIdentityHeaders(cipher_info, psk_chain, request_salt.span(), handshake)) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    const size_t fixed_offset = handshake.size();
    handshake.resize(handshake.size() + fixed_plain.size() + SsAeadCipher::kTagSize);
    auto nonce0 = MakeNonce(0);
    if (!write_cipher.Encrypt(nonce0.data(), fixed_plain.data(), fixed_plain.size(),
                              handshake.data() + fixed_offset)) {
        co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    const size_t variable_offset = handshake.size();
    handshake.resize(handshake.size() + variable_plain.size() + SsAeadCipher::kTagSize);
    auto nonce1 = MakeNonce(1);
    if (!write_cipher.Encrypt(nonce1.data(), variable_plain.data(), variable_plain.size(),
                              handshake.data() + variable_offset)) {
        co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    if (!co_await WriteRawBytes(stream, handshake)) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    WriteTCPRequestResult result;
    result.request_writer = std::make_unique<RequestBodyWriter>(
        std::move(write_cipher), 2, stream);
    result.request_salt = request_salt;
    co_return result;
}

}  // namespace

net::awaitable<std::expected<WriteTCPRequestResult, ErrorCode>>
WriteTCPRequest(const TargetAddress& target,
                const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                std::span<const KeyBytes> psk_chain,
                AsyncStream& stream) {
    if (Is2022Cipher(cipher_info)) {
        co_return co_await WriteTCPRequest2022(
            target, cipher_info, master_key, psk_chain, stream);
    }

    if (cipher_info.salt_size > 64 || cipher_info.key_size > 64 ||
        master_key.size < cipher_info.key_size) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    try {
        std::array<uint8_t, 259> addr_bytes{};
        const size_t addr_size = EncodeSocks5AddressTo(target, addr_bytes.data(), addr_bytes.size());
        if (addr_size == 0 || addr_size > kMaxChunkPayload) {
            co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }

        std::array<uint8_t, 64> client_salt{};
        if (RAND_bytes(client_salt.data(), static_cast<int>(cipher_info.salt_size)) != 1) {
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }

        std::array<uint8_t, 64> write_subkey{};
        if (!DeriveSubkey(master_key.data(), cipher_info.key_size,
                          client_salt.data(), cipher_info.salt_size,
                          write_subkey.data())) {
            co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }

        buf::BufferGuard out{buf::Buffer::New()};
        if (!out) {
            co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        }

        std::memcpy(out->Tail().data(), client_salt.data(), cipher_info.salt_size);
        out->Produce(static_cast<uint32_t>(cipher_info.salt_size));

        SsAeadCipher write_cipher(cipher_info.type, write_subkey.data(), cipher_info.key_size);
        const size_t payload_size = addr_size;
        const uint8_t len_plain[2] = {
            static_cast<uint8_t>(payload_size >> 8),
            static_cast<uint8_t>(payload_size & 0xFF)
        };

        auto nonce_l = MakeNonce(0);
        if (!write_cipher.Encrypt(nonce_l.data(), len_plain, 2, out->Tail().data())) {
            co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }
        out->Produce(static_cast<uint32_t>(2 + SsAeadCipher::kTagSize));

        auto nonce_p = MakeNonce(1);
        if (!write_cipher.Encrypt(
                nonce_p.data(), addr_bytes.data(), addr_size,
                out->Tail().data())) {
            co_return std::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }
        out->Produce(static_cast<uint32_t>(addr_size + SsAeadCipher::kTagSize));

        buf::MultiBuffer handshake_mb;
        handshake_mb.reserve(1);
        handshake_mb.push_back(out.release());

        try {
            co_await stream.WriteMultiBuffer(std::move(handshake_mb));
        } catch (const IoSystemError& e) {
            co_return std::unexpected(MapAsioError(e.code()));
        } catch (...) {
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }

        WriteTCPRequestResult result;
        result.request_writer = std::make_unique<RequestBodyWriter>(
            std::move(write_cipher), 2, stream);
        co_return result;
    } catch (const std::bad_alloc&) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (const IoSystemError&) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    } catch (...) {
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
}

net::awaitable<std::expected<std::unique_ptr<transport::MultiBufferReader>, ErrorCode>>
ReadTCPResponse(const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                const KeyBytes& request_salt,
                AsyncStream& stream) {
    if (cipher_info.salt_size > 64 || cipher_info.key_size > 64 ||
        master_key.size < cipher_info.key_size) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    try {
        if (Is2022Cipher(cipher_info)) {
            if (request_salt.size != cipher_info.salt_size) {
                co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
            }

            std::array<uint8_t, 64> server_salt{};
            if (!co_await ReadFull(stream, server_salt.data(), cipher_info.salt_size)) {
                co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
            }

            std::array<uint8_t, 32> read_subkey{};
            if (!Derive2022Subkey(master_key.data(), cipher_info.key_size,
                                  server_salt.data(), cipher_info.salt_size,
                                  read_subkey.data())) {
                co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }

            SsAeadCipher read_cipher(cipher_info.type, read_subkey.data(), cipher_info.key_size);
            const size_t fixed_plain_size = 1 + 8 + cipher_info.salt_size + 2;
            std::vector<uint8_t> fixed_cipher(fixed_plain_size + SsAeadCipher::kTagSize);
            if (!co_await ReadFull(stream, fixed_cipher.data(), fixed_cipher.size())) {
                co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
            }

            std::vector<uint8_t> fixed_plain(fixed_plain_size);
            auto nonce0 = MakeNonce(0);
            if (!read_cipher.Decrypt(nonce0.data(), fixed_cipher.data(), fixed_cipher.size(),
                                     fixed_plain.data())) {
                co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            if (fixed_plain[0] != 1 ||
                !TimestampFresh(GetU64BE(fixed_plain.data() + 1), UnixSecondsNow()) ||
                std::memcmp(fixed_plain.data() + 9,
                            request_salt.data(),
                            request_salt.size) != 0) {
                co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }

            const uint16_t payload_len =
                GetU16BE(fixed_plain.data() + 9 + cipher_info.salt_size);
            buf::MultiBuffer pending;
            uint64_t next_nonce = 1;
            if (payload_len > 0) {
                std::vector<uint8_t> payload_cipher(payload_len + SsAeadCipher::kTagSize);
                if (!co_await ReadFull(stream, payload_cipher.data(), payload_cipher.size())) {
                    co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
                }
                std::vector<uint8_t> payload_plain(payload_len);
                auto nonce1 = MakeNonce(1);
                if (!read_cipher.Decrypt(nonce1.data(), payload_cipher.data(),
                                         payload_cipher.size(), payload_plain.data())) {
                    co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                if (!WriteBytesToMultiBuffer(payload_plain, pending)) {
                    co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
                }
                next_nonce = 2;
            }

            co_return std::make_unique<ResponseBodyReader>(
                std::move(read_cipher), next_nonce, stream,
                kSs2022MaxChunkPayload, std::move(pending));
        }

        std::array<uint8_t, 64> server_salt{};
        if (!co_await ReadFull(stream, server_salt.data(), cipher_info.salt_size)) {
            co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
        }

        std::array<uint8_t, 64> read_subkey{};
        if (!DeriveSubkey(master_key.data(), cipher_info.key_size,
                          server_salt.data(), cipher_info.salt_size,
                          read_subkey.data())) {
            co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }

        SsAeadCipher read_cipher(cipher_info.type, read_subkey.data(), cipher_info.key_size);
        co_return std::make_unique<ResponseBodyReader>(
            std::move(read_cipher), 0, stream);
    } catch (const std::bad_alloc&) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (const IoSystemError&) {
        co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
    } catch (...) {
        co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }
}

}  // namespace acpp::ss
