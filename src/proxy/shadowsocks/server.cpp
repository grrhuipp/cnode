#include "shadowsocks_crypto.hpp"
#include "stream_crypto.hpp"
#include "server.hpp"
#include "acppnode/common/address_codec.hpp"
#include "acppnode/common/allocator.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <new>
#include <optional>
#include <utility>

namespace acpp::ss {

namespace {

using detail::kStreamChunkPayloadSize;
constexpr size_t kSs2022SmallVariableBufferSize = 512;

[[noreturn]] void ThrowSsWriteError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

net::awaitable<bool> ReadFull(AsyncStream& stream, uint8_t* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        size_t r = co_await stream.AsyncRead(net::buffer(buf + got, len - got));
        if (r == 0) {
            co_return false;
        }
        got += r;
    }
    co_return true;
}

using detail::MakeNonce;

SsCipherType ToSsCipher(proxyman::inbound::PreparedAeadCipher type) {
    using Prepared = proxyman::inbound::PreparedAeadCipher;
    switch (type) {
        case Prepared::AES_128_GCM:
            return SsCipherType::AES_128_GCM;
        case Prepared::AES_256_GCM:
            return SsCipherType::AES_256_GCM;
        case Prepared::CHACHA20_POLY1305:
            return SsCipherType::CHACHA20_POLY1305;
        case Prepared::AES_128_GCM_2022:
            return SsCipherType::AES_128_GCM_2022;
        case Prepared::AES_256_GCM_2022:
            return SsCipherType::AES_256_GCM_2022;
        case Prepared::CHACHA20_POLY1305_2022:
            return SsCipherType::CHACHA20_POLY1305_2022;
    }
    return SsCipherType::AES_256_GCM;
}



class ResponseBodyWriter final
    : public memory::ThreadAllocated
    , public transport::MultiBufferWriter {
public:
    ResponseBodyWriter(const proxyman::inbound::UserStore::ShadowsocksCredential& user,
                       const SsCipherInfo& cipher_info,
                       const KeyBytes& request_salt,
                       AsyncStream& stream)
        : cipher_type_(ToSsCipher(user.cipher_type))
        , key_size_(user.key_size)
        , salt_size_(user.salt_size)
        , request_salt_(request_salt)
        , is_2022_(Is2022Cipher(cipher_info)) {
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

        if (!buf::HasData(mb)) co_return;

        if (!state.write_init_) {
            if (!state.is_2022_) {
                if (!co_await EnsureTCPResponseWriter(state, stream)) {
                    ThrowSsWriteError("Shadowsocks server init write cipher failed");
                }
            } else {
                auto first_plain = state.FirstChunkView(mb);
                const auto first_plain_bytes = first_plain.Bytes();
                if (!co_await EnsureTCPResponseWriter2022(
                        state, stream, first_plain_bytes)) {
                    ThrowSsWriteError("Shadowsocks server init write cipher failed");
                }
                state.skip_first_bytes_ = first_plain_bytes.size();
            }
        }

        buf::MultiBuffer out_mb;
        out_mb.reserve(mb.size());
        for (auto* buf : mb) {
            auto bytes = buf->Bytes();
            if (bytes.empty()) continue;
            detail::EncryptToMultiBuffer(
                *state.write_cipher_,
                state.write_nonce_,
                bytes,
                out_mb,
                &state.skip_first_bytes_);
        }
        mb.clear();

        co_await state.FlushPendingAndWrite(stream, std::move(out_mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "Shadowsocks response writer has no stream");
        }
        auto& state = *this;
        AsyncStream& stream = *stream_;

        bool has_data = false;
        for (const net::const_buffer& buffer : buffers) {
            if (buffer.data() && buffer.size() > 0) {
                has_data = true;
                break;
            }
        }
        if (!has_data) co_return;

        if (!state.write_init_) {
            if (!state.is_2022_) {
                if (!co_await EnsureTCPResponseWriter(state, stream)) {
                    ThrowSsWriteError("Shadowsocks server init write cipher failed");
                }
            } else {
                auto first_plain = state.FirstChunkView(buffers);
                const auto first_plain_bytes = first_plain.Bytes();
                if (!co_await EnsureTCPResponseWriter2022(
                        state, stream, first_plain_bytes)) {
                    ThrowSsWriteError("Shadowsocks server init write cipher failed");
                }
                state.skip_first_bytes_ = first_plain_bytes.size();
            }
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
                *state.write_cipher_,
                state.write_nonce_,
                std::span<const uint8_t>{data, size},
                out_mb,
                &state.skip_first_bytes_);
        }

        co_await state.FlushPendingAndWrite(stream, std::move(out_mb));
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "Shadowsocks response writer has no stream");
        }
        co_await stream_->AsyncShutdownWrite();
    }

private:
    static constexpr size_t kLenHeaderSize = 2 + SsAeadCipher::kTagSize;

    struct FirstChunk {
        std::span<const uint8_t> direct;
        memory::ByteVector storage;

        [[nodiscard]] std::span<const uint8_t> Bytes() const noexcept {
            if (!storage.empty()) {
                return std::span<const uint8_t>(storage.data(), storage.size());
            }
            return direct;
        }
    };

    FirstChunk FirstChunkView(const buf::MultiBuffer& mb) const {
        FirstChunk first;
        const size_t want = std::min(buf::TotalLen(mb), kStreamChunkPayloadSize);
        if (want == 0) {
            return first;
        }

        for (auto* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            if (bytes.size() >= want) {
                first.direct = bytes.first(want);
                return first;
            }
            break;
        }

        first.storage.reserve(want);
        for (auto* buffer : mb) {
            if (!buffer || buffer->IsEmpty() || first.storage.size() >= want) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            const size_t n = std::min(bytes.size(), want - first.storage.size());
            first.storage.insert(
                first.storage.end(),
                bytes.data(),
                bytes.data() + static_cast<std::ptrdiff_t>(n));
        }
        return first;
    }

    FirstChunk FirstChunkView(std::span<const net::const_buffer> buffers) const {
        FirstChunk first;
        size_t total = 0;
        for (const net::const_buffer& buffer : buffers) {
            total += buffer.size();
            if (total >= kStreamChunkPayloadSize) {
                total = kStreamChunkPayloadSize;
                break;
            }
        }
        if (total == 0) {
            return first;
        }

        for (const net::const_buffer& buffer : buffers) {
            if (!buffer.data() || buffer.size() == 0) {
                continue;
            }
            if (buffer.size() >= total) {
                first.direct = std::span<const uint8_t>(
                    static_cast<const uint8_t*>(buffer.data()),
                    total);
                return first;
            }
            break;
        }

        first.storage.reserve(total);
        for (const net::const_buffer& buffer : buffers) {
            if (!buffer.data() || buffer.size() == 0 || first.storage.size() >= total) {
                continue;
            }
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            const size_t n = std::min(buffer.size(), total - first.storage.size());
            first.storage.insert(
                first.storage.end(),
                data,
                data + static_cast<std::ptrdiff_t>(n));
        }
        return first;
    }

    net::awaitable<void> FlushPendingAndWrite(
        AsyncStream& stream,
        buf::MultiBuffer out_mb) {
        if (!buf::HasData(out_mb) && !buf::HasData(pending_prefix_)) {
            co_return;
        }
        if (buf::HasData(pending_prefix_)) {
            buf::MultiBuffer merged;
            merged.reserve(pending_prefix_.size() + out_mb.size());
            pending_prefix_.MoveTo(merged);
            out_mb.MoveTo(merged);
            out_mb = std::move(merged);
        }
        co_await stream.WriteMultiBuffer(std::move(out_mb));
    }

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

        state.write_cipher_.emplace(state.cipher_type_, write_subkey.data(), state.key_size_,
                                     proxy::AeadDirection::Encrypt);
        state.write_nonce_ = 0;

        if (!buf::AppendSpanToMultiBuffer(
                std::span<const uint8_t>(server_salt.data(), state.salt_size_),
                state.pending_prefix_)) {
            co_return false;
        }

        state.write_init_ = true;
        co_return true;
    }

    static net::awaitable<bool> EnsureTCPResponseWriter2022(
        ResponseBodyWriter& state,
        AsyncStream& stream,
        std::span<const uint8_t> first_payload) {
        if (state.salt_size_ > KeyBytes::kMaxSize ||
            state.key_size_ > KeyBytes::kMaxSize ||
            state.request_salt_.size != state.salt_size_ ||
            first_payload.size() > kSs2022MaxChunkPayload) {
            co_return false;
        }

        std::array<uint8_t, 32> server_salt{};
        if (RAND_bytes(server_salt.data(), static_cast<int>(state.salt_size_)) != 1) {
            co_return false;
        }

        std::array<uint8_t, 32> write_subkey{};
        if (!Derive2022Subkey(state.master_key_.data(), state.key_size_,
                              server_salt.data(), state.salt_size_,
                              write_subkey.data())) {
            co_return false;
        }

        state.write_cipher_.emplace(state.cipher_type_, write_subkey.data(), state.key_size_,
                                     proxy::AeadDirection::Encrypt);

        constexpr size_t kFixedPlainMaxSize = 1 + 8 + KeyBytes::kMaxSize + 2;
        constexpr size_t kFixedCipherMaxSize =
            kFixedPlainMaxSize + SsAeadCipher::kTagSize;

        const size_t fixed_plain_size = 1 + 8 + state.salt_size_ + 2;
        std::array<uint8_t, kFixedPlainMaxSize> fixed_plain{};
        fixed_plain[0] = 1;
        PutU64BE(fixed_plain.data() + 1, UnixSecondsNow());
        std::memcpy(fixed_plain.data() + 9, state.request_salt_.data(), state.salt_size_);
        PutU16BE(fixed_plain.data() + 9 + state.salt_size_,
                 static_cast<uint16_t>(first_payload.size()));

        std::array<uint8_t, kFixedCipherMaxSize> fixed_cipher{};
        const size_t fixed_cipher_size = fixed_plain_size + SsAeadCipher::kTagSize;
        auto nonce0 = MakeNonce(0);
        if (!state.write_cipher_->Encrypt(nonce0.data(), fixed_plain.data(), fixed_plain_size,
                                          fixed_cipher.data())) {
            co_return false;
        }
        state.write_nonce_ = 1;

        if (!buf::AppendSpanToMultiBuffer(
                std::span<const uint8_t>(server_salt.data(), state.salt_size_),
                state.pending_prefix_) ||
            !buf::AppendSpanToMultiBuffer(
                std::span<const uint8_t>(fixed_cipher.data(), fixed_cipher_size),
                state.pending_prefix_)) {
            co_return false;
        }

        if (!first_payload.empty()) {
            buf::BufferGuard payload_cipher{buf::Buffer::New()};
            if (!payload_cipher ||
                first_payload.size() + SsAeadCipher::kTagSize > payload_cipher->Available()) {
                co_return false;
            }
            auto nonce1 = MakeNonce(1);
            if (!state.write_cipher_->Encrypt(nonce1.data(), first_payload.data(),
                                               first_payload.size(),
                                               payload_cipher->Tail().data())) {
                co_return false;
            }
            state.write_nonce_ = 2;
            payload_cipher->Produce(static_cast<uint32_t>(
                first_payload.size() + SsAeadCipher::kTagSize));
            state.pending_prefix_.push_back(std::move(payload_cipher));
        }
        state.write_init_ = true;
        co_return true;
    }

    SsCipherType cipher_type_;
    size_t key_size_;
    size_t salt_size_;
    std::array<uint8_t, 32> master_key_{};
    KeyBytes request_salt_;
    std::optional<SsAeadCipher> write_cipher_;
    buf::MultiBuffer pending_prefix_;
    uint64_t write_nonce_ = 0;
    bool write_init_ = false;
    bool is_2022_ = false;
    size_t skip_first_bytes_ = 0;
    AsyncStream* stream_ = nullptr;
};

bool HasIdentityKey(
    const proxyman::inbound::UserStore::ShadowsocksUsersView& users,
    size_t key_size) {
    for (size_t i = 0; i < users.size(); ++i) {
        if (users[i].identity_key.size >= key_size) {
            return true;
        }
    }
    return false;
}

bool MatchIdentityHeader(const proxyman::inbound::UserStore::ShadowsocksCredential& user,
                         const SsCipherInfo& cipher_info,
                         std::span<const uint8_t> salt,
                         std::span<const uint8_t, 16> encrypted_identity) {
    if (user.identity_key.size < cipher_info.key_size ||
        user.derived_key.size < cipher_info.key_size) {
        return false;
    }

    std::array<uint8_t, 32> block_key{};
    if (!Derive2022IdentitySubkey(user.identity_key.data(), cipher_info.key_size,
                                  salt.data(), salt.size(), block_key.data())) {
        return false;
    }

    std::array<uint8_t, 16> identity_hash{};
    if (!AesBlockCrypt(
            std::span<const uint8_t>(block_key.data(), cipher_info.key_size),
            encrypted_identity,
            std::span<uint8_t, 16>(identity_hash),
            false)) {
        return false;
    }

    return identity_hash == user.psk_hash;
}

bool DecryptSs2022FixedHeader(const proxyman::inbound::UserStore::ShadowsocksCredential& user,
                              const SsCipherInfo& cipher_info,
                              std::span<const uint8_t> salt,
                              std::span<const uint8_t> encrypted_fixed,
                              SsAeadCipher& read_cipher,
                              std::array<uint8_t, kSs2022RequestFixedHeaderSize>& fixed_plain) {
    if (user.derived_key.size < cipher_info.key_size) return false;
    std::array<uint8_t, 32> subkey{};
    if (!Derive2022Subkey(user.derived_key.data(), cipher_info.key_size,
                          salt.data(), salt.size(), subkey.data()) ||
        !read_cipher.ResetKey(subkey.data(), cipher_info.key_size)) return false;
    const auto nonce = MakeNonce(0);
    return read_cipher.Decrypt(nonce.data(), encrypted_fixed.data(), encrypted_fixed.size(),
                               fixed_plain.data());
}

net::awaitable<tl::expected<ReadTCPSessionResult, ErrorCode>> ReadTCPSession2022(
    AsyncStream& stream,
    const SsCipherInfo& cipher_info,
    std::string_view tag,
    size_t& last_matched_index) {
    const size_t salt_size = cipher_info.salt_size;
    const size_t key_size = cipher_info.key_size;
    if (salt_size > KeyBytes::kMaxSize || key_size > KeyBytes::kMaxSize) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    const auto users = proxyman::inbound::UserStore::ShadowsocksUsers(tag);
    if (users.empty()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    ReadTCPSessionResult result;
    result.request_salt.size = salt_size;
    if (!co_await ReadFull(stream, result.request_salt.data(), salt_size)) {
        co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }

    const bool use_identity = Is2022AesCipher(cipher_info.type) && HasIdentityKey(users, key_size);
    std::array<uint8_t, 16> identity_header{};
    if (use_identity &&
        !co_await ReadFull(stream, identity_header.data(), identity_header.size())) {
        co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }

    std::array<uint8_t, kSs2022RequestFixedHeaderSize + SsAeadCipher::kTagSize> enc_fixed{};
    if (!co_await ReadFull(stream, enc_fixed.data(), enc_fixed.size())) {
        co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }

    SsAeadCipher read_cipher(cipher_info.type, proxy::AeadDirection::Decrypt);
    std::array<uint8_t, kSs2022RequestFixedHeaderSize> fixed_plain{};
    const size_t hint = last_matched_index;

    auto try_user = [&](size_t index) -> bool {
        const auto& user = users[index];
        if (use_identity &&
            !MatchIdentityHeader(
                user, cipher_info, result.request_salt.span(),
                std::span<const uint8_t, 16>(identity_header))) {
            return false;
        }
        if (!DecryptSs2022FixedHeader(
                user,
                cipher_info,
                result.request_salt.span(),
                enc_fixed,
                read_cipher,
                fixed_plain)) {
            return false;
        }
        result.user = users.Share(user);
        last_matched_index = index;
        return true;
    };

    if (hint >= users.size() || !try_user(hint)) {
        for (size_t i = 0; i < users.size(); ++i) {
            if (i == hint) continue;
            if (try_user(i)) {
                break;
            }
        }
    }

    if (!result.user) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    if (fixed_plain[0] != 0 ||
        !TimestampFresh(GetU64BE(fixed_plain.data() + 1), UnixSecondsNow())) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const uint16_t variable_len = GetU16BE(fixed_plain.data() + 9);
    if (variable_len == 0) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const size_t variable_cipher_len = variable_len + SsAeadCipher::kTagSize;
    std::array<uint8_t, kSs2022SmallVariableBufferSize + SsAeadCipher::kTagSize>
        small_variable_cipher{};
    std::array<uint8_t, kSs2022SmallVariableBufferSize> small_variable_plain{};
    memory::ByteVector heap_variable_cipher;
    memory::ByteVector heap_variable_plain;

    uint8_t* variable_cipher = small_variable_cipher.data();
    uint8_t* variable_plain = small_variable_plain.data();
    if (variable_len > kSs2022SmallVariableBufferSize) {
        try {
            heap_variable_cipher.resize(variable_cipher_len);
            heap_variable_plain.resize(variable_len);
        } catch (...) {
            co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        }
        variable_cipher = heap_variable_cipher.data();
        variable_plain = heap_variable_plain.data();
    }

    if (!co_await ReadFull(stream, variable_cipher, variable_cipher_len)) {
        co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }
    auto nonce1 = MakeNonce(1);
    if (!read_cipher.Decrypt(nonce1.data(), variable_cipher, variable_cipher_len,
                             variable_plain)) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto addr_result = DecodeAddress({variable_plain, variable_len}, AddressWireFormat::Socks5);
    if (addr_result.status != AddressDecodeStatus::Complete) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    result.target = std::move(addr_result.target);

    size_t offset = addr_result.consumed;
    if (offset + 2 > variable_len) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    const uint16_t padding_len = GetU16BE(variable_plain + offset);
    offset += 2;
    if (offset + padding_len > variable_len) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    offset += padding_len;
    if (offset < variable_len) {
        result.initial_payload.append({variable_plain + offset, variable_len - offset});
    }

    try {
        result.body_reader = std::make_unique<detail::BodyReader>(
            std::move(read_cipher), 2, stream, kSs2022MaxChunkPayload);
    } catch (...) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    co_return result;
}

}  // namespace

net::awaitable<tl::expected<ReadTCPSessionResult, ErrorCode>> ReadTCPSession(
    AsyncStream& stream,
    const SsCipherInfo& cipher_info,
    std::string_view tag,
    size_t& last_matched_index) {
    if (Is2022Cipher(cipher_info)) {
        co_return co_await ReadTCPSession2022(
            stream, cipher_info, tag, last_matched_index);
    }

    const size_t salt_size = cipher_info.salt_size;
    const size_t key_size = cipher_info.key_size;
    if (salt_size > KeyBytes::kMaxSize || key_size > KeyBytes::kMaxSize) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    ReadTCPSessionResult result;

    std::array<uint8_t, KeyBytes::kMaxSize> salt{};
    if (!co_await ReadFull(stream, salt.data(), salt_size)) {
        co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }
    result.request_salt.assign(std::span<const uint8_t>(salt.data(), salt_size));

    std::array<uint8_t, 2 + SsAeadCipher::kTagSize> enc_len{};
    if (!co_await ReadFull(stream, enc_len.data(), enc_len.size())) {
        co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }

    const auto users = proxyman::inbound::UserStore::ShadowsocksUsers(tag);
    if (users.empty()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    uint8_t len_plain[2]{};
    SsAeadCipher read_cipher(cipher_info.type, proxy::AeadDirection::Decrypt);

    auto try_user = [&](const proxyman::inbound::UserStore::ShadowsocksCredential& user) -> bool {
        std::array<uint8_t, 32> read_subkey{};
        if (!DeriveSubkey(user.derived_key.data(), key_size,
                          salt.data(), salt_size,
                          read_subkey.data())) {
            return false;
        }
        if (!read_cipher.ResetKey(read_subkey.data(), key_size)) return false;
        auto nonce0 = MakeNonce(0);
        return read_cipher.Decrypt(nonce0.data(), enc_len.data(), enc_len.size(), len_plain);
    };

    const size_t hint = last_matched_index;
    if (hint < users.size() && try_user(users[hint])) {
        result.user = users.Share(users[hint]);
    } else {
        for (size_t i = 0; i < users.size(); ++i) {
            if (i == hint) continue;
            if (try_user(users[i])) {
                result.user = users.Share(users[i]);
                last_matched_index = i;
                break;
            }
        }
    }

    if (!result.user) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    uint64_t read_nonce = 1;  // nonce=0 was used for the length header.

    const uint16_t payload_len =
        static_cast<uint16_t>((len_plain[0] << 8) | len_plain[1]);
    if (payload_len == 0 || payload_len > kMaxChunkPayload) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto nonce1 = MakeNonce(read_nonce);
    if (!read_cipher.BeginDecrypt(nonce1.data())) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    buf::MultiBuffer payload_mb;
    payload_mb.reserve((payload_len + buf::Buffer::kSize - 1) / buf::Buffer::kSize);

    buf::BufferGuard cipher{buf::Buffer::New()};
    if (!cipher) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    size_t remaining = payload_len;
    while (remaining > 0) {
        buf::BufferGuard plain{buf::Buffer::New()};
        if (!plain) {
            co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        }

        const size_t to_process = std::min(remaining, static_cast<size_t>(plain->Available()));
        cipher->Reset();
        if (!co_await ReadFull(stream, cipher->Tail().data(), to_process)) {
            co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
        }
        cipher->Produce(static_cast<uint32_t>(to_process));

        if (!read_cipher.DecryptUpdate(cipher->Bytes(), plain->Tail().first(to_process))) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        plain->Produce(static_cast<uint32_t>(to_process));
        payload_mb.push_back(std::move(plain));
        remaining -= to_process;
    }

    std::array<uint8_t, SsAeadCipher::kTagSize> payload_tag{};
    if (!co_await ReadFull(stream, payload_tag.data(), payload_tag.size())) {
        co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
    }
    if (!read_cipher.FinishDecrypt(payload_tag.data())) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
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
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto first_bytes = first_payload->Bytes();
    auto addr_result = DecodeAddress(first_bytes, AddressWireFormat::Socks5);
    if (addr_result.status != AddressDecodeStatus::Complete) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    result.target = std::move(addr_result.target);

    const size_t addr_consumed = addr_result.consumed;
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
            result.initial_payload.append(bytes.subspan(skip));
            skip = 0;
        }
    }

    try {
        result.body_reader = std::make_unique<detail::BodyReader>(
            std::move(read_cipher), read_nonce, stream);
    } catch (...) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    co_return result;
}

tl::expected<std::unique_ptr<transport::MultiBufferWriter>, ErrorCode> WriteTCPResponse(
    const proxyman::inbound::UserStore::ShadowsocksCredential& user,
    const SsCipherInfo& cipher_info,
    const KeyBytes& request_salt,
    AsyncStream& stream) {
    try {
        return std::make_unique<ResponseBodyWriter>(user, cipher_info, request_salt, stream);
    } catch (...) {
        return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
}

}  // namespace acpp::ss
