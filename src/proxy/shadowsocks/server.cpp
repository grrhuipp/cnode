#include "shadowsocks_crypto.hpp"
#include "server.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <new>
#include <utility>

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

SsCipherType ToSsCipher(proxyman::inbound::PreparedAeadCipher type) {
    using Prepared = proxyman::inbound::PreparedAeadCipher;
    switch (type) {
        case Prepared::AES_128_GCM:
            return SsCipherType::AES_128_GCM;
        case Prepared::AES_256_GCM:
            return SsCipherType::AES_256_GCM;
        case Prepared::CHACHA20_POLY1305:
            return SsCipherType::CHACHA20_POLY1305;
    }
    return SsCipherType::AES_256_GCM;
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
        switch (type) {
            case SsCipherType::AES_128_GCM:      return EVP_aes_128_gcm();
            case SsCipherType::AES_256_GCM:      return EVP_aes_256_gcm();
            case SsCipherType::CHACHA20_POLY1305:return EVP_chacha20_poly1305();
        }
        return nullptr;
    }

    SsCipherType type_;
    std::array<uint8_t, 32> key_{};
    size_t key_size_ = 0;
    EVP_CIPHER_CTX* ctx_ = nullptr;
};

struct SsAddress {
    TargetAddress target;
    size_t consumed = 0;
};

std::optional<SsAddress> ParseSocks5Address(const uint8_t* data, size_t len) {
    if (len < 1) return std::nullopt;

    SsAddress result;
    size_t idx = 0;

    const uint8_t atyp = data[idx++];
    if (atyp == 0x01) {
        if (idx + 4 + 2 > len) return std::nullopt;
        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), data + idx, bytes.size());
        idx += 4;
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        result.target = TargetAddress(net::ip::make_address_v4(bytes), port);
    } else if (atyp == 0x03) {
        if (idx + 1 > len) return std::nullopt;
        const size_t name_len = data[idx++];
        if (idx + name_len + 2 > len) return std::nullopt;
        std::string domain(reinterpret_cast<const char*>(data + idx), name_len);
        idx += name_len;
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        result.target = TargetAddress(std::string_view(domain.data(), domain.size()), port);
    } else if (atyp == 0x04) {
        if (idx + 16 + 2 > len) return std::nullopt;
        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), data + idx, bytes.size());
        idx += bytes.size();
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        result.target = TargetAddress(net::ip::make_address_v6(bytes), port);
    } else {
        return std::nullopt;
    }

    result.consumed = idx;
    return result;
}

net::awaitable<bool> WriteFull(AsyncStream& stream, const uint8_t* buf, size_t len) {
    if (len == 0) {
        co_return true;
    }

    buf::MultiBuffer mb;
    mb.reserve((len + buf::Buffer::kSize - 1) / buf::Buffer::kSize);

    size_t offset = 0;
    while (offset < len) {
        buf::BufferGuard out{buf::Buffer::New()};
        if (!out) {
            co_return false;
        }
        const size_t chunk = std::min(
            len - offset,
            static_cast<size_t>(out->Available()));
        std::memcpy(out->Tail().data(), buf + offset, chunk);
        out->Produce(static_cast<uint32_t>(chunk));
        mb.push_back(out.release());
        offset += chunk;
    }

    try {
        co_await stream.WriteMultiBuffer(std::move(mb));
        mb.clear();
    } catch (...) {
        co_return false;
    }
    co_return true;
}

class RequestBodyReader final : public transport::MultiBufferReader {
public:
    RequestBodyReader(SsCipherType cipher_type,
                      size_t key_size,
                      std::span<const uint8_t> read_subkey,
                      uint64_t read_nonce,
                      AsyncStream& stream)
        : read_cipher_(cipher_type, read_subkey.data(), key_size)
        , read_nonce_(read_nonce)
        , stream_(&stream) {
    }

    RequestBodyReader(const RequestBodyReader&) = delete;
    RequestBodyReader& operator=(const RequestBodyReader&) = delete;
    RequestBodyReader(RequestBodyReader&&) = delete;
    RequestBodyReader& operator=(RequestBodyReader&&) = delete;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "Shadowsocks request reader has no stream");
        }
        auto& state = *this;
        AsyncStream& stream = *stream_;

        uint8_t enc_len_buf[2 + SsAeadCipher::kTagSize];
        if (!co_await ReadFull(stream, enc_len_buf, sizeof(enc_len_buf))) {
            co_return buf::MultiBuffer{};
        }

        uint8_t len_plain[2];
        auto nonce = MakeNonce(state.read_nonce_);
        if (!state.read_cipher_.Decrypt(nonce.data(), enc_len_buf, sizeof(enc_len_buf), len_plain)) {
            co_return buf::MultiBuffer{};
        }
        ++state.read_nonce_;

        const uint16_t payload_len =
            static_cast<uint16_t>((len_plain[0] << 8) | len_plain[1]);
        if (payload_len == 0 || payload_len > kMaxChunkPayload) {
            co_return buf::MultiBuffer{};
        }

        SsAeadStreamDecryptor decryptor(state.read_cipher_);
        auto nonce2 = MakeNonce(state.read_nonce_);
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
            if (!co_await ReadFull(stream, cipher->Tail().data(), to_process)) {
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

        std::array<uint8_t, SsAeadCipher::kTagSize> payload_tag{};
        if (!co_await ReadFull(stream, payload_tag.data(), payload_tag.size())) {
            co_return buf::MultiBuffer{};
        }
        if (!decryptor.Final(payload_tag.data())) {
            co_return buf::MultiBuffer{};
        }
        ++read_nonce_;

        buf::MultiBuffer result = std::move(out_mb);
        out_mb.clear();
        co_return result;
    }

private:
    SsAeadCipher read_cipher_;
    uint64_t read_nonce_ = 0;
    AsyncStream* stream_ = nullptr;
};

class ResponseBodyWriter final : public transport::MultiBufferWriter {
public:
    ResponseBodyWriter(const proxyman::inbound::UserStore::ShadowsocksCredential& user,
                       AsyncStream& stream)
        : cipher_type_(ToSsCipher(user.cipher_type))
        , key_size_(user.key_size)
        , salt_size_(user.salt_size) {
        if (user.derived_key.size <= master_key_.size()) {
            std::memcpy(master_key_.data(), user.derived_key.data(), user.derived_key.size);
        } else {
            key_size_ = 0;
        }
        stream_ = &stream;
    }

    ResponseBodyWriter(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter& operator=(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter(ResponseBodyWriter&&) = delete;
    ResponseBodyWriter& operator=(ResponseBodyWriter&&) = delete;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "Shadowsocks response writer has no stream");
        }
        auto& state = *this;
        AsyncStream& stream = *stream_;

        if (mb.empty()) co_return;

        if (!state.write_init_) {
            if (!co_await EnsureTCPResponseWriter(state, stream)) {
                ThrowSsWriteError("Shadowsocks server init write cipher failed");
            }
        }

        buf::MultiBuffer out_mb;
        out_mb.reserve(kStreamFlushBufferCount);
        size_t out_bytes = 0;

        auto flush_out = [&stream, &out_mb, &out_bytes]() -> net::awaitable<void> {
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
                auto nonce_l = MakeNonce(state.write_nonce_);
                if (!state.write_cipher_->Encrypt(nonce_l.data(), len_plain, 2, dst)) {
                    ThrowSsWriteError("Shadowsocks server stream encrypt length failed");
                }
                ++state.write_nonce_;

                auto nonce_p = MakeNonce(state.write_nonce_);
                if (!state.write_cipher_->Encrypt(
                        nonce_p.data(), data, chunk_size,
                        dst + kLenHeaderSize)) {
                    ThrowSsWriteError("Shadowsocks server stream encrypt payload failed");
                }
                ++state.write_nonce_;

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

    net::awaitable<void> AsyncShutdownWrite() override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "Shadowsocks response writer has no stream");
        }
        co_await stream_->AsyncShutdownWrite();
    }

private:
    static constexpr size_t kLenHeaderSize = 2 + SsAeadCipher::kTagSize;

    static net::awaitable<bool> EnsureTCPResponseWriter(ResponseBodyWriter& state,
                                                         AsyncStream& stream) {
        if (state.salt_size_ > 64 || state.key_size_ > 64) {
            co_return false;
        }

        std::array<uint8_t, 64> server_salt{};
        if (RAND_bytes(server_salt.data(), static_cast<int>(state.salt_size_)) != 1) {
            co_return false;
        }

        std::array<uint8_t, 64> write_subkey{};
        if (!DeriveSubkey(state.master_key_.data(), state.key_size_,
                          server_salt.data(), state.salt_size_,
                          write_subkey.data())) {
            co_return false;
        }

        state.write_cipher_.emplace(state.cipher_type_, write_subkey.data(), state.key_size_);
        state.write_nonce_ = 0;

        if (!co_await WriteFull(stream, server_salt.data(), state.salt_size_)) {
            co_return false;
        }

        state.write_init_ = true;
        co_return true;
    }

    SsCipherType cipher_type_;
    size_t key_size_;
    size_t salt_size_;
    std::array<uint8_t, 32> master_key_{};
    std::optional<SsAeadCipher> write_cipher_;
    uint64_t write_nonce_ = 0;
    bool write_init_ = false;
    AsyncStream* stream_ = nullptr;
};

}  // namespace

net::awaitable<std::expected<ReadTCPSessionResult, ErrorCode>> ReadTCPSession(
    AsyncStream& stream,
    Validator& validator,
    const SsCipherInfo& cipher_info,
    std::string_view tag,
    size_t& last_matched_index) {
    const size_t salt_size = cipher_info.salt_size;
    const size_t key_size = cipher_info.key_size;
    if (salt_size > 64 || key_size > 64) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    std::array<uint8_t, 64> salt{};
    if (!co_await ReadFull(stream, salt.data(), salt_size)) {
        co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }

    std::array<uint8_t, 2 + SsAeadCipher::kTagSize> enc_len{};
    if (!co_await ReadFull(stream, enc_len.data(), enc_len.size())) {
        co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }

    const auto users = validator.FindUsersForTag(tag);
    if (users.empty()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    ReadTCPSessionResult result;
    uint8_t len_plain[2]{};

    auto try_user = [&](
        const proxyman::inbound::UserStore::ShadowsocksCredential& user,
        std::array<uint8_t, 64>& read_subkey) -> bool {
        if (!DeriveSubkey(user.derived_key.data(), key_size,
                          salt.data(), salt_size,
                          read_subkey.data())) {
            return false;
        }
        SsAeadCipher try_cipher(cipher_info.type, read_subkey.data(), key_size);
        auto nonce0 = MakeNonce(0);
        return try_cipher.Decrypt(nonce0.data(), enc_len.data(), enc_len.size(), len_plain);
    };

    std::array<uint8_t, 64> read_subkey{};
    const size_t hint = last_matched_index;
    if (hint < users.size() && try_user(users[hint], read_subkey)) {
        result.SetUser(users.Share(users[hint]));
    } else {
        for (size_t i = 0; i < users.size(); ++i) {
            if (i == hint) continue;
            if (try_user(users[i], read_subkey)) {
                result.SetUser(users.Share(users[i]));
                last_matched_index = i;
                break;
            }
        }
    }

    if (!result.user) {
        co_return std::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    SsAeadCipher read_cipher(cipher_info.type, read_subkey.data(), key_size);
    uint64_t read_nonce = 1;  // nonce=0 was used for the length header.

    const uint16_t payload_len =
        static_cast<uint16_t>((len_plain[0] << 8) | len_plain[1]);
    if (payload_len == 0 || payload_len > kMaxChunkPayload) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto nonce1 = MakeNonce(read_nonce);
    SsAeadStreamDecryptor decryptor(read_cipher);
    if (!decryptor.Init(nonce1.data())) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    buf::MultiBuffer payload_mb;
    payload_mb.reserve((payload_len + buf::Buffer::kSize - 1) / buf::Buffer::kSize);

    buf::BufferGuard cipher{buf::Buffer::New()};
    if (!cipher) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    size_t remaining = payload_len;
    while (remaining > 0) {
        buf::BufferGuard plain{buf::Buffer::New()};
        if (!plain) {
            co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        }

        const size_t to_process = std::min(remaining, static_cast<size_t>(plain->Available()));
        cipher->Reset();
        if (!co_await ReadFull(stream, cipher->Tail().data(), to_process)) {
            co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
        }
        cipher->Produce(static_cast<uint32_t>(to_process));

        int produced = 0;
        if (!decryptor.Update(cipher->Bytes().data(), to_process,
                              plain->Tail().data(), &produced)) {
            co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        if (produced < 0 || static_cast<size_t>(produced) != to_process) {
            co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        plain->Produce(static_cast<uint32_t>(produced));
        payload_mb.push_back(plain.release());
        remaining -= to_process;
    }

    std::array<uint8_t, SsAeadCipher::kTagSize> payload_tag{};
    if (!co_await ReadFull(stream, payload_tag.data(), payload_tag.size())) {
        co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }
    if (!decryptor.Final(payload_tag.data())) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    ++read_nonce;

    buf::Buffer* first_payload = nullptr;
    for (auto* buffer : payload_mb) {
        if (buffer && !buffer->IsEmpty()) {
            first_payload = buffer;
            break;
        }
    }
    if (!first_payload) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto first_bytes = first_payload->Bytes();
    auto addr_result = ParseSocks5Address(first_bytes.data(), first_bytes.size());
    if (!addr_result) {
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    result.target = std::move(addr_result->target);

    const size_t addr_consumed = addr_result->consumed;
    if (addr_consumed < payload_len) {
        size_t skip = addr_consumed;
        for (auto* buffer : payload_mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            auto bytes = buffer->Bytes();
            if (skip >= bytes.size()) {
                skip -= bytes.size();
                continue;
            }
            result.initial_payload.append(
                bytes.data() + skip,
                bytes.size() - skip);
            skip = 0;
        }
    }

    try {
        result.body_reader = std::make_unique<RequestBodyReader>(
            cipher_info.type,
            key_size,
            std::span<const uint8_t>(read_subkey.data(), key_size),
            read_nonce,
            stream);
    } catch (...) {
        co_return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    co_return result;
}

std::expected<std::unique_ptr<transport::MultiBufferWriter>, ErrorCode> WriteTCPResponse(
    const proxyman::inbound::UserStore::ShadowsocksCredential& user,
    AsyncStream& stream) {
    try {
        return std::make_unique<ResponseBodyWriter>(user, stream);
    } catch (...) {
        return std::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
}

}  // namespace acpp::ss
