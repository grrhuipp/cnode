#include "shadowsocks_crypto.hpp"
#include "common/byte_reader.hpp"
#include "stream_crypto.hpp"
#include "client.hpp"
#include "common/address_codec.hpp"
#include "common/allocator.hpp"

#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>
#include <new>
#include <optional>
#include <utility>

namespace ss {

namespace {

using detail::MakeNonce;
using detail::ReadFull;
using detail::ThrowSsWriteError;

class RequestBodyWriter final
    : public memory::ThreadAllocated
    , public transport::MultiBufferWriter {
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
        if (mb.byte_size() == 0) {
            co_return;
        }
        if (!write_cipher_) {
            ThrowSsWriteError("Shadowsocks client request writer is not initialized");
        }

        buf::MultiBuffer out_mb;
        out_mb.reserve(mb.size());

        for (auto* buf : mb) {
            auto bytes = buf->Bytes();
            if (bytes.empty()) continue;

            detail::EncryptToMultiBuffer(
                *write_cipher_, write_nonce_, bytes, out_mb);
        }

        mb.clear();
        if (out_mb.byte_size() != 0) {
            co_await stream_->WriteMultiBuffer(std::move(out_mb));
        }
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "Shadowsocks request writer has no stream");
        }
        if (!write_cipher_) {
            ThrowSsWriteError("Shadowsocks client request writer is not initialized");
        }

        buf::MultiBuffer out_mb;
        out_mb.reserve(buffers.size());
        for (const net::const_buffer& buffer : buffers) {
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            const size_t size = buffer.size();
            if (!data || size == 0) {
                continue;
            }
            detail::EncryptToMultiBuffer(
                *write_cipher_,
                write_nonce_,
                std::span<const uint8_t>{data, size},
                out_mb);
        }
        if (out_mb.byte_size() != 0) {
            co_await stream_->WriteMultiBuffer(std::move(out_mb));
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return stream_->AsyncShutdownWrite();
    }

    bool WriteShutdownClosesLink() const noexcept override {
        return stream_ && stream_->WriteShutdownClosesLink();
    }

private:
    std::optional<SsAeadCipher> write_cipher_;
    uint64_t write_nonce_ = 0;
    AsyncStream* stream_ = nullptr;
};


bool WriteIdentityHeadersTo(const SsCipherInfo& cipher_info,
                            std::span<const KeyBytes> psk_chain,
                            std::span<const uint8_t> salt,
                            uint8_t* out,
                            size_t cap,
                            size_t& written) {
    written = 0;
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
            OPENSSL_cleanse(block_key.data(), block_key.size());
            return false;
        }

        std::array<uint8_t, 16> encrypted{};
        const bool ok = AesBlockCrypt(
            std::span<const uint8_t>(block_key.data(), cipher_info.key_size),
            std::span<const uint8_t, 16>(user_hash),
            std::span<uint8_t, 16>(encrypted),
            true);
        OPENSSL_cleanse(block_key.data(), block_key.size());
        if (!ok) {
            return false;
        }
        if (written + encrypted.size() > cap) {
            return false;
        }
        std::memcpy(out + written, encrypted.data(), encrypted.size());
        written += encrypted.size();
    }
    return true;
}

struct PreparedTCPRequestHandshake {
    buf::MultiBuffer handshake_mb;
    std::optional<SsAeadCipher> write_cipher;
    KeyBytes request_salt;

    PreparedTCPRequestHandshake() = default;
    PreparedTCPRequestHandshake(const PreparedTCPRequestHandshake&) = delete;
    PreparedTCPRequestHandshake& operator=(const PreparedTCPRequestHandshake&) = delete;
    PreparedTCPRequestHandshake(PreparedTCPRequestHandshake&&) noexcept = default;
    PreparedTCPRequestHandshake& operator=(PreparedTCPRequestHandshake&&) noexcept = default;

    ~PreparedTCPRequestHandshake() noexcept {
        OPENSSL_cleanse(request_salt.bytes.data(), request_salt.bytes.size());
    }
};

tl::expected<PreparedTCPRequestHandshake, ErrorCode>
PrepareTCPRequest2022(const TargetAddress& target,
                      const SsCipherInfo& cipher_info,
                      const KeyBytes& master_key,
                      std::span<const KeyBytes> psk_chain,
                      ForwardedMetadataView forwarded) {
    if (cipher_info.salt_size > KeyBytes::kMaxSize ||
        cipher_info.key_size > KeyBytes::kMaxSize ||
        master_key.size < cipher_info.key_size) {
        return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    if (psk_chain.empty()) {
        psk_chain = std::span<const KeyBytes>(&master_key, 1);
    }

    std::array<uint8_t, kMaxEncodedAddressSize> addr_bytes{};
    const size_t addr_size = EncodeAddressTo(
        target, addr_bytes.data(), addr_bytes.size(), AddressWireFormat::Socks5, forwarded);
    if (addr_size == 0) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    constexpr size_t kPaddingLen = 1;
    const size_t variable_len = addr_size + 2 + kPaddingLen;
    if (variable_len > kSs2022MaxChunkPayload) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    PreparedTCPRequestHandshake prepared;
    prepared.request_salt.size = cipher_info.salt_size;
    if (RAND_bytes(prepared.request_salt.data(),
                   static_cast<int>(prepared.request_salt.size)) != 1) {
        return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    std::array<uint8_t, 32> write_subkey{};
    struct CleanseWriteSubkey {
        std::array<uint8_t, 32>& buf;
        ~CleanseWriteSubkey() noexcept { OPENSSL_cleanse(buf.data(), buf.size()); }
    } cleanse_write_subkey{write_subkey};
    if (!Derive2022Subkey(master_key.data(), cipher_info.key_size,
                          prepared.request_salt.data(), prepared.request_salt.size,
                          write_subkey.data())) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    std::array<uint8_t, kSs2022RequestFixedHeaderSize> fixed_plain{};
    fixed_plain[0] = 0;
    StoreU64BE(fixed_plain.data() + 1, UnixSecondsNow());
    StoreU16BE(fixed_plain.data() + 9, static_cast<uint16_t>(variable_len));

    constexpr size_t kMaxVariablePlain =
        kMaxEncodedAddressSize + 2 + kPaddingLen;
    std::array<uint8_t, kMaxVariablePlain> variable_plain{};
    std::memcpy(variable_plain.data(), addr_bytes.data(), addr_size);
    StoreU16BE(variable_plain.data() + addr_size, static_cast<uint16_t>(kPaddingLen));
    if (RAND_bytes(variable_plain.data() + addr_size + 2, static_cast<int>(kPaddingLen)) != 1) {
        OPENSSL_cleanse(write_subkey.data(), write_subkey.size());
        return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    prepared.write_cipher.emplace(
        cipher_info.type, write_subkey.data(), cipher_info.key_size,
        proxy::AeadDirection::Encrypt);
    OPENSSL_cleanse(write_subkey.data(), write_subkey.size());
    const size_t handshake_size =
        prepared.request_salt.size +
        (psk_chain.size() > 0 ? (psk_chain.size() - 1) * 16 : 0) +
        fixed_plain.size() + SsAeadCipher::kTagSize +
        variable_len + SsAeadCipher::kTagSize;
    if (handshake_size > buf::Buffer::kSize) {
        return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    buf::BufferGuard handshake{buf::Buffer::New()};
    if (!handshake) {
        return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    std::memcpy(handshake->Tail().data(),
                prepared.request_salt.data(),
                prepared.request_salt.size);
    handshake->Produce(static_cast<uint32_t>(prepared.request_salt.size));

    size_t identity_len = 0;
    if (!WriteIdentityHeadersTo(
            cipher_info,
            psk_chain,
            prepared.request_salt.span(),
            handshake->Tail().data(),
            handshake->Available(),
            identity_len)) {
        return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    handshake->Produce(static_cast<uint32_t>(identity_len));

    if (handshake->Available() < fixed_plain.size() + SsAeadCipher::kTagSize) {
        return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    auto nonce0 = MakeNonce(0);
    if (!prepared.write_cipher->Encrypt(
            nonce0.data(), fixed_plain.data(), fixed_plain.size(),
            handshake->Tail().data())) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    handshake->Produce(
        static_cast<uint32_t>(fixed_plain.size() + SsAeadCipher::kTagSize));

    if (handshake->Available() < variable_len + SsAeadCipher::kTagSize) {
        return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    auto nonce1 = MakeNonce(1);
    if (!prepared.write_cipher->Encrypt(
            nonce1.data(), variable_plain.data(), variable_len,
            handshake->Tail().data())) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    handshake->Produce(static_cast<uint32_t>(variable_len + SsAeadCipher::kTagSize));

    prepared.handshake_mb.reserve(1);
    prepared.handshake_mb.push_back(std::move(handshake));
    return prepared;
}

tl::expected<PreparedTCPRequestHandshake, ErrorCode>
PrepareTCPRequestLegacy(const TargetAddress& target,
                        const SsCipherInfo& cipher_info,
                        const KeyBytes& master_key,
                        ForwardedMetadataView forwarded) {
    if (cipher_info.salt_size > 64 || cipher_info.key_size > 64 ||
        master_key.size < cipher_info.key_size) {
        return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    std::array<uint8_t, kMaxEncodedAddressSize> addr_bytes{};
    const size_t addr_size = EncodeAddressTo(
        target, addr_bytes.data(), addr_bytes.size(), AddressWireFormat::Socks5, forwarded);
    if (addr_size == 0 || addr_size > kMaxChunkPayload) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    std::array<uint8_t, 64> client_salt{};
    if (RAND_bytes(client_salt.data(), static_cast<int>(cipher_info.salt_size)) != 1) {
        return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    std::array<uint8_t, 64> write_subkey{};
    struct CleanseLegacySecrets {
        std::array<uint8_t, 64>& salt;
        std::array<uint8_t, 64>& subkey;
        ~CleanseLegacySecrets() noexcept {
            OPENSSL_cleanse(salt.data(), salt.size());
            OPENSSL_cleanse(subkey.data(), subkey.size());
        }
    } cleanse_legacy{client_salt, write_subkey};
    if (!DeriveSubkey(master_key.data(), cipher_info.key_size,
                      client_salt.data(), cipher_info.salt_size,
                      write_subkey.data())) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    buf::BufferGuard out{buf::Buffer::New()};
    if (!out) {
        return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    std::memcpy(out->Tail().data(), client_salt.data(), cipher_info.salt_size);
    out->Produce(static_cast<uint32_t>(cipher_info.salt_size));

    PreparedTCPRequestHandshake prepared;
    prepared.write_cipher.emplace(
        cipher_info.type, write_subkey.data(), cipher_info.key_size,
        proxy::AeadDirection::Encrypt);
    OPENSSL_cleanse(write_subkey.data(), write_subkey.size());
    const size_t payload_size = addr_size;
    const uint8_t len_plain[2] = {
        static_cast<uint8_t>(payload_size >> 8),
        static_cast<uint8_t>(payload_size & 0xFF)
    };

    auto nonce_l = MakeNonce(0);
    if (!prepared.write_cipher->Encrypt(nonce_l.data(), len_plain, 2, out->Tail().data())) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    out->Produce(static_cast<uint32_t>(2 + SsAeadCipher::kTagSize));

    auto nonce_p = MakeNonce(1);
    if (!prepared.write_cipher->Encrypt(
            nonce_p.data(), addr_bytes.data(), addr_size,
            out->Tail().data())) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    out->Produce(static_cast<uint32_t>(addr_size + SsAeadCipher::kTagSize));

    prepared.handshake_mb.reserve(1);
    prepared.handshake_mb.push_back(std::move(out));
    return prepared;
}

net::awaitable<tl::expected<WriteTCPRequestResult, ErrorCode>>
WriteTCPRequest2022(const TargetAddress& target,
                    const SsCipherInfo& cipher_info,
                    const KeyBytes& master_key,
                    std::span<const KeyBytes> psk_chain,
                    AsyncStream& stream,
                    ForwardedMetadataView forwarded) {
    buf::MultiBuffer handshake_mb;
    std::optional<SsAeadCipher> write_cipher;
    KeyBytes request_salt;
    struct CleanseRequestSalt {
        KeyBytes& salt;
        ~CleanseRequestSalt() noexcept {
            OPENSSL_cleanse(salt.bytes.data(), salt.bytes.size());
        }
    } cleanse_request_salt{request_salt};
    {
        auto prepared = PrepareTCPRequest2022(
            target, cipher_info, master_key, psk_chain, forwarded);
        if (!prepared) {
            co_return tl::unexpected(prepared.error());
        }
        handshake_mb = std::move(prepared->handshake_mb);
        write_cipher = std::move(prepared->write_cipher);
        request_salt = prepared->request_salt;
    }
    try {
        co_await stream.WriteMultiBuffer(std::move(handshake_mb));
    } catch (const IoSystemError& e) {
        co_return tl::unexpected(MapAsioError(e.code()));
    } catch (...) {
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    WriteTCPRequestResult result;
    result.request_writer = std::make_unique<RequestBodyWriter>(
        std::move(*write_cipher), 2, stream);
    result.request_salt = request_salt;
    co_return result;
}

}  // namespace

net::awaitable<tl::expected<WriteTCPRequestResult, ErrorCode>>
WriteTCPRequest(const TargetAddress& target,
                const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                std::span<const KeyBytes> psk_chain,
                AsyncStream& stream,
                ForwardedMetadataView forwarded) {
    if (Is2022Cipher(cipher_info.type)) {
        co_return co_await WriteTCPRequest2022(
            target, cipher_info, master_key, psk_chain, stream, forwarded);
    }

    try {
        buf::MultiBuffer handshake_mb;
        std::optional<SsAeadCipher> write_cipher;
        {
            auto prepared = PrepareTCPRequestLegacy(
                target, cipher_info, master_key, forwarded);
            if (!prepared) {
                co_return tl::unexpected(prepared.error());
            }
            handshake_mb = std::move(prepared->handshake_mb);
            write_cipher = std::move(prepared->write_cipher);
        }

        try {
            co_await stream.WriteMultiBuffer(std::move(handshake_mb));
        } catch (const IoSystemError& e) {
            co_return tl::unexpected(MapAsioError(e.code()));
        } catch (...) {
            co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }

        WriteTCPRequestResult result;
        result.request_writer = std::make_unique<RequestBodyWriter>(
            std::move(*write_cipher), 2, stream);
        co_return result;
    } catch (const std::bad_alloc&) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (const IoSystemError&) {
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    } catch (...) {
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
}

net::awaitable<tl::expected<std::unique_ptr<transport::MultiBufferReader>, ErrorCode>>
ReadTCPResponse(const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                const KeyBytes& request_salt,
                AsyncStream& stream) {
    if (cipher_info.salt_size > 64 || cipher_info.key_size > 64 ||
        master_key.size < cipher_info.key_size) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    try {
        if (Is2022Cipher(cipher_info.type)) {
            if (request_salt.size != cipher_info.salt_size) {
                co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
            }

            std::array<uint8_t, 64> server_salt{};
            if (!co_await ReadFull(stream, server_salt.data(), cipher_info.salt_size)) {
                co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
            }

            std::array<uint8_t, 32> read_subkey{};
            struct Cleanse2022ReadSecrets {
                std::array<uint8_t, 64>& salt;
                std::array<uint8_t, 32>& subkey;
                ~Cleanse2022ReadSecrets() noexcept {
                    OPENSSL_cleanse(salt.data(), salt.size());
                    OPENSSL_cleanse(subkey.data(), subkey.size());
                }
            } cleanse_2022_read{server_salt, read_subkey};
            if (!Derive2022Subkey(master_key.data(), cipher_info.key_size,
                                  server_salt.data(), cipher_info.salt_size,
                                  read_subkey.data())) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }

            SsAeadCipher read_cipher(cipher_info.type, read_subkey.data(), cipher_info.key_size,
                                     proxy::AeadDirection::Decrypt);
            OPENSSL_cleanse(server_salt.data(), server_salt.size());
            OPENSSL_cleanse(read_subkey.data(), read_subkey.size());
            const size_t fixed_plain_size = 1 + 8 + cipher_info.salt_size + 2;
            constexpr size_t kFixedPlainMaxSize = 1 + 8 + KeyBytes::kMaxSize + 2;
            constexpr size_t kFixedCipherMaxSize =
                kFixedPlainMaxSize + SsAeadCipher::kTagSize;
            if (fixed_plain_size > kFixedPlainMaxSize) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            std::array<uint8_t, kFixedCipherMaxSize> fixed_cipher{};
            const size_t fixed_cipher_size = fixed_plain_size + SsAeadCipher::kTagSize;
            if (!co_await ReadFull(stream, fixed_cipher.data(), fixed_cipher_size)) {
                co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
            }

            std::array<uint8_t, kFixedPlainMaxSize> fixed_plain{};
            struct CleanseFixedPlain {
                std::array<uint8_t, kFixedPlainMaxSize>& buf;
                ~CleanseFixedPlain() noexcept { OPENSSL_cleanse(buf.data(), buf.size()); }
            } cleanse_fixed_plain{fixed_plain};
            auto nonce0 = MakeNonce(0);
            if (!read_cipher.Decrypt(nonce0.data(), fixed_cipher.data(), fixed_cipher_size,
                                     fixed_plain.data())) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            if (fixed_plain[0] != 1 ||
                !TimestampFresh(LoadU64BE(fixed_plain.data() + 1), UnixSecondsNow()) ||
                std::memcmp(fixed_plain.data() + 9,
                            request_salt.data(),
                            request_salt.size) != 0) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }

            const uint16_t payload_len =
                LoadU16BE(fixed_plain.data() + 9 + cipher_info.salt_size);
            buf::MultiBuffer pending;
            uint64_t next_nonce = 1;
            if (payload_len > 0) {
                if (auto decrypt_res = co_await detail::ReadAndDecryptStreamPayload(
                        stream, read_cipher, MakeNonce(1), payload_len, pending);
                    !decrypt_res) {
                    co_return tl::unexpected(decrypt_res.error());
                }
                next_nonce = 2;
            }

            co_return std::make_unique<detail::BodyReader>(
                std::move(read_cipher), next_nonce, stream,
                kSs2022MaxChunkPayload, std::move(pending));
        }

        std::array<uint8_t, 64> server_salt{};
        if (!co_await ReadFull(stream, server_salt.data(), cipher_info.salt_size)) {
            co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
        }

        std::array<uint8_t, 64> read_subkey{};
        struct CleanseLegacyReadSecrets {
            std::array<uint8_t, 64>& salt;
            std::array<uint8_t, 64>& subkey;
            ~CleanseLegacyReadSecrets() noexcept {
                OPENSSL_cleanse(salt.data(), salt.size());
                OPENSSL_cleanse(subkey.data(), subkey.size());
            }
        } cleanse_legacy_read{server_salt, read_subkey};
        if (!DeriveSubkey(master_key.data(), cipher_info.key_size,
                          server_salt.data(), cipher_info.salt_size,
                          read_subkey.data())) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }

        SsAeadCipher read_cipher(cipher_info.type, read_subkey.data(), cipher_info.key_size,
                                 proxy::AeadDirection::Decrypt);
        OPENSSL_cleanse(server_salt.data(), server_salt.size());
        OPENSSL_cleanse(read_subkey.data(), read_subkey.size());
        co_return std::make_unique<detail::BodyReader>(
            std::move(read_cipher), 0, stream);
    } catch (const std::bad_alloc&) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (const IoSystemError& e) {
        co_return tl::unexpected(MapAsioError(e.code()));
    } catch (...) {
        co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }
}

}  // namespace ss
