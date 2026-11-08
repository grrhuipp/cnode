#include "shadowsocks_crypto.hpp"
#include "common/byte_reader.hpp"
#include "stream_crypto.hpp"
#include "server.hpp"
#include "../uot/uot.hpp"
#include "../handshake_timeout.hpp"
#include "common/address_codec.hpp"
#include "common/allocator.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <new>
#include <optional>
#include <utility>

namespace ss {

namespace {

using detail::kStreamChunkPayloadSize;

using detail::MakeNonce;
using detail::ThrowSsWriteError;

net::awaitable<tl::expected<void, ErrorCode>> ReadFull(
    AsyncStream& stream, uint8_t* buf, size_t len) {
    try {
        if (!co_await detail::ReadFull(stream, buf, len)) {
            co_return tl::unexpected(proxy::ResolveHandshakeReadFailure(stream));
        }
        co_return tl::expected<void, ErrorCode>{};
    } catch (const std::bad_alloc&) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (const IoSystemError& error) {
        co_return tl::unexpected(
            proxy::ClassifyHandshakeReadException(stream, error));
    }
}

net::awaitable<tl::expected<void, ErrorCode>> ReadStreamPayload(
    AsyncStream& stream,
    SsAeadCipher& cipher,
    std::span<const uint8_t, 12> nonce,
    size_t payload_len,
    buf::MultiBuffer& output) {
    try {
        auto res = co_await detail::ReadAndDecryptStreamPayload(
            stream, cipher, nonce, payload_len, output);
        if (!res) {
            co_return tl::unexpected(
                proxy::ResolveHandshakeReadFailure(stream, res.error()));
        }
        co_return res;
    } catch (const std::bad_alloc&) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (const IoSystemError& error) {
        co_return tl::unexpected(
            proxy::ClassifyHandshakeReadException(stream, error));
    }
}
class ResponseBodyWriter final
    : public memory::ThreadAllocated
    , public transport::MultiBufferWriter {
public:
    ResponseBodyWriter(const proxyman::inbound::UserStore::ShadowsocksCredential& user,
                       const SsCipherInfo& cipher_info,
                       const KeyBytes& request_salt,
                       AsyncStream& stream)
        : cipher_type_(cipher_info.type)
        , key_size_(user.key_size)
        , salt_size_(user.salt_size)
        , request_salt_(request_salt)
        , is_2022_(Is2022Cipher(cipher_info.type)) {
        if (user.derived_key.size <= master_key_.size()) {
            std::memcpy(master_key_.data(), user.derived_key.data(), user.derived_key.size);
        } else {
            key_size_ = 0;
        }
        stream_ = &stream;
    }
    ~ResponseBodyWriter() override {
        ClearHandshakeKeys();
    }

    ResponseBodyWriter(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter& operator=(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter(ResponseBodyWriter&&) = delete;
    ResponseBodyWriter& operator=(ResponseBodyWriter&&) = delete;
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "Shadowsocks response writer has no stream");
        }
        if (write_finished_) throw transport::WriteClosed();
        auto& state = *this;
        AsyncStream& stream = *stream_;

        if (mb.byte_size() == 0) co_return;

        const auto cancellation = co_await net::this_coro::cancellation_state;
        if (cancellation.cancelled() != net::cancellation_type::none) {
            throw IoSystemError(io_error::operation_aborted);
        }
        const uint64_t initial_nonce = write_nonce_;
        try {
            if (!state.write_init_) {
                if (!state.is_2022_) {
                    if (!InitResponseCipher(state)) {
                        ThrowSsWriteError("Shadowsocks server init write cipher failed");
                    }
                } else {
                    auto first_plain = state.FirstChunkView(mb);
                    const auto first_plain_bytes = first_plain.Bytes();
                    if (!InitResponseCipher2022(state, first_plain_bytes)) {
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
        } catch (const transport::WriteClosed&) {
            Finish();
            throw;
        } catch (const std::bad_alloc&) {
            if (write_nonce_ != initial_nonce) Retire();
            throw;
        } catch (...) {
            Retire();
            throw;
        }
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "Shadowsocks response writer has no stream");
        }
        if (write_finished_) throw transport::WriteClosed();
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

        const auto cancellation = co_await net::this_coro::cancellation_state;
        if (cancellation.cancelled() != net::cancellation_type::none) {
            throw IoSystemError(io_error::operation_aborted);
        }
        const uint64_t initial_nonce = write_nonce_;
        try {
            if (!state.write_init_) {
                if (!state.is_2022_) {
                    if (!InitResponseCipher(state)) {
                        ThrowSsWriteError("Shadowsocks server init write cipher failed");
                    }
                } else {
                    auto first_plain = state.FirstChunkView(buffers);
                    const auto first_plain_bytes = first_plain.Bytes();
                    if (!InitResponseCipher2022(state, first_plain_bytes)) {
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
        } catch (const transport::WriteClosed&) {
            Finish();
            throw;
        } catch (const std::bad_alloc&) {
            if (write_nonce_ != initial_nonce) Retire();
            throw;
        } catch (...) {
            Retire();
            throw;
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (!stream_) {
            throw IoSystemError(io_error::not_connected, "Shadowsocks response writer has no stream");
        }
        if (write_finished_) co_return;
        const auto cancellation = co_await net::this_coro::cancellation_state;
        if (cancellation.cancelled() != net::cancellation_type::none) {
            throw IoSystemError(io_error::operation_aborted);
        }
        const uint64_t initial_nonce = write_nonce_;
        bool shutdown_started = false;
        try {
            if (!write_init_) {
                const bool ok = is_2022_
                    ? InitResponseCipher2022(*this, {})
                    : InitResponseCipher(*this);
                if (!ok) {
                    ThrowSsWriteError("Shadowsocks server init write cipher failed");
                }
                co_await FlushPendingAndWrite(*stream_, {});
            }
            shutdown_started = true;
            co_await stream_->AsyncShutdownWrite();
            Finish();
        } catch (const transport::WriteClosed&) {
            Finish();
            throw;
        } catch (const std::bad_alloc&) {
            if (write_nonce_ != initial_nonce || shutdown_started) Retire();
            throw;
        } catch (...) {
            Retire();
            throw;
        }
    }

    bool WriteShutdownClosesLink() const noexcept override {
        return stream_ && stream_->WriteShutdownClosesLink();
    }

private:
    void ClearHandshakeKeys() noexcept {
        OPENSSL_cleanse(master_key_.data(), master_key_.size());
        OPENSSL_cleanse(request_salt_.bytes.data(), request_salt_.bytes.size());
        request_salt_.size = 0;
    }

    void Finish() {
        write_finished_ = true;
        write_cipher_.reset();
        pending_prefix_.clear();
        ClearHandshakeKeys();
    }

    void Retire() {
        auto* stream = std::exchange(stream_, nullptr);
        write_cipher_.reset();
        pending_prefix_.clear();
        ClearHandshakeKeys();
        if (stream) stream->CloseAbortive();
    }

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
        const size_t want = std::min(mb.byte_size(), kStreamChunkPayloadSize);
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
        if (out_mb.byte_size() == 0 && pending_prefix_.byte_size() == 0) {
            co_return;
        }
        if (pending_prefix_.byte_size() != 0) {
            buf::MultiBuffer merged;
            merged.reserve(pending_prefix_.size() + out_mb.size());
            pending_prefix_.MoveTo(merged);
            out_mb.MoveTo(merged);
            out_mb = std::move(merged);
        }
        try {
            co_await stream.WriteMultiBuffer(std::move(out_mb));
        } catch (const transport::WriteClosed&) {
            throw;
        } catch (...) {
            Retire();
            throw;
        }
    }

    // Synchronous key setup; the salt and header are staged in pending_prefix_
    // and sent with the first response write.
    static bool InitResponseCipher(ResponseBodyWriter& state) {
        if (state.salt_size_ > 64 || state.key_size_ > 64) {
            return false;
        }

        std::array<uint8_t, 64> server_salt{};
        if (RAND_bytes(server_salt.data(), static_cast<int>(state.salt_size_)) != 1) {
            return false;
        }

        std::array<uint8_t, 64> write_subkey{};
        struct CleanseInitLegacy {
            std::array<uint8_t, 64>& salt;
            std::array<uint8_t, 64>& subkey;
            ~CleanseInitLegacy() noexcept {
                OPENSSL_cleanse(salt.data(), salt.size());
                OPENSSL_cleanse(subkey.data(), subkey.size());
            }
        } cleanse_init_legacy{server_salt, write_subkey};
        if (!DeriveSubkey(state.master_key_.data(), state.key_size_,
                          server_salt.data(), state.salt_size_,
                          write_subkey.data())) {
            return false;
        }

        state.write_cipher_.emplace(state.cipher_type_, write_subkey.data(), state.key_size_,
                                     proxy::AeadDirection::Encrypt);
        OPENSSL_cleanse(write_subkey.data(), write_subkey.size());
        state.write_nonce_ = 0;

        if (!buf::AppendSpanToMultiBuffer(
                std::span<const uint8_t>(server_salt.data(), state.salt_size_),
                state.pending_prefix_)) {
            return false;
        }
        state.ClearHandshakeKeys();
        state.write_init_ = true;
        return true;
    }

    static bool InitResponseCipher2022(
        ResponseBodyWriter& state,
        std::span<const uint8_t> first_payload) {
        if (state.salt_size_ > KeyBytes::kMaxSize ||
            state.key_size_ > KeyBytes::kMaxSize ||
            state.request_salt_.size != state.salt_size_ ||
            first_payload.size() > kSs2022MaxChunkPayload) {
            return false;
        }

        std::array<uint8_t, 32> server_salt{};
        if (RAND_bytes(server_salt.data(), static_cast<int>(state.salt_size_)) != 1) {
            return false;
        }

        std::array<uint8_t, 32> write_subkey{};
        constexpr size_t kFixedPlainMaxSize = 1 + 8 + KeyBytes::kMaxSize + 2;
        constexpr size_t kFixedCipherMaxSize =
            kFixedPlainMaxSize + SsAeadCipher::kTagSize;
        std::array<uint8_t, kFixedPlainMaxSize> fixed_plain{};
        struct CleanseInit2022 {
            std::array<uint8_t, 32>& salt;
            std::array<uint8_t, 32>& subkey;
            std::array<uint8_t, kFixedPlainMaxSize>& plain;
            ~CleanseInit2022() noexcept {
                OPENSSL_cleanse(salt.data(), salt.size());
                OPENSSL_cleanse(subkey.data(), subkey.size());
                OPENSSL_cleanse(plain.data(), plain.size());
            }
        } cleanse_init_2022{server_salt, write_subkey, fixed_plain};
        if (!Derive2022Subkey(state.master_key_.data(), state.key_size_,
                              server_salt.data(), state.salt_size_,
                              write_subkey.data())) {
            return false;
        }

        state.write_cipher_.emplace(state.cipher_type_, write_subkey.data(), state.key_size_,
                                     proxy::AeadDirection::Encrypt);
        OPENSSL_cleanse(write_subkey.data(), write_subkey.size());

        const size_t fixed_plain_size = 1 + 8 + state.salt_size_ + 2;
        fixed_plain[0] = 1;
        StoreU64BE(fixed_plain.data() + 1, UnixSecondsNow());
        std::memcpy(fixed_plain.data() + 9, state.request_salt_.data(), state.salt_size_);
        StoreU16BE(fixed_plain.data() + 9 + state.salt_size_,
                 static_cast<uint16_t>(first_payload.size()));

        std::array<uint8_t, kFixedCipherMaxSize> fixed_cipher{};
        const size_t fixed_cipher_size = fixed_plain_size + SsAeadCipher::kTagSize;
        auto nonce0 = MakeNonce(0);
        if (!state.write_cipher_->Encrypt(nonce0.data(), fixed_plain.data(), fixed_plain_size,
                                          fixed_cipher.data())) {
            return false;
        }
        state.write_nonce_ = 1;

        state.pending_prefix_.clear();
        if (!buf::AppendSpanToMultiBuffer(
                std::span<const uint8_t>(server_salt.data(), state.salt_size_),
                state.pending_prefix_) ||
            !buf::AppendSpanToMultiBuffer(
                std::span<const uint8_t>(fixed_cipher.data(), fixed_cipher_size),
                state.pending_prefix_)) {
            state.pending_prefix_.clear();
            return false;
        }

        if (!first_payload.empty()) {
            buf::BufferGuard payload_cipher{buf::Buffer::New()};
            if (!payload_cipher ||
                first_payload.size() + SsAeadCipher::kTagSize > payload_cipher->Available()) {
                state.pending_prefix_.clear();
                return false;
            }
            auto nonce1 = MakeNonce(1);
            if (!state.write_cipher_->Encrypt(nonce1.data(), first_payload.data(),
                                               first_payload.size(),
                                               payload_cipher->Tail().data())) {
                state.pending_prefix_.clear();
                return false;
            }
            state.write_nonce_ = 2;
            payload_cipher->Produce(static_cast<uint32_t>(
                first_payload.size() + SsAeadCipher::kTagSize));
            state.pending_prefix_.push_back(std::move(payload_cipher));
        }
        state.ClearHandshakeKeys();
        state.write_init_ = true;
        return true;
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
    bool write_finished_ = false;
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
    const bool ok = AesBlockCrypt(
        std::span<const uint8_t>(block_key.data(), cipher_info.key_size),
        encrypted_identity,
        std::span<uint8_t, 16>(identity_hash),
        false);
    OPENSSL_cleanse(block_key.data(), block_key.size());
    if (!ok) {
        OPENSSL_cleanse(identity_hash.data(), identity_hash.size());
        return false;
    }

    const bool matched =
        CRYPTO_memcmp(identity_hash.data(), user.psk_hash.data(), identity_hash.size()) == 0;
    OPENSSL_cleanse(identity_hash.data(), identity_hash.size());
    return matched;
}

bool DecryptSs2022FixedHeader(const proxyman::inbound::UserStore::ShadowsocksCredential& user,
                              const SsCipherInfo& cipher_info,
                              std::span<const uint8_t> salt,
                              std::span<const uint8_t> encrypted_fixed,
                              SsAeadCipher& read_cipher,
                              std::array<uint8_t, kSs2022RequestFixedHeaderSize>& fixed_plain) {
    if (user.derived_key.size < cipher_info.key_size) return false;
    std::array<uint8_t, 32> subkey{};
    const bool key_ok = Derive2022Subkey(user.derived_key.data(), cipher_info.key_size,
                                         salt.data(), salt.size(), subkey.data()) &&
                        read_cipher.ResetKey(subkey.data(), cipher_info.key_size);
    OPENSSL_cleanse(subkey.data(), subkey.size());
    if (!key_ok) return false;
    const auto nonce = MakeNonce(0);
    return read_cipher.Decrypt(nonce.data(), encrypted_fixed.data(), encrypted_fixed.size(),
                               fixed_plain.data());
}

net::awaitable<tl::expected<ReadTCPSessionResult, ErrorCode>> ReadTCPSession2022(
    AsyncStream& stream,
    const SsCipherInfo& cipher_info,
    std::string_view tag,
    size_t& last_matched_index) {
    try {
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
    if (auto read_res = co_await ReadFull(stream, result.request_salt.data(), salt_size);
        !read_res) {
        co_return tl::unexpected(read_res.error());
    }

    const bool use_identity = Is2022AesCipher(cipher_info.type) && HasIdentityKey(users, key_size);
    std::array<uint8_t, 16> identity_header{};
    if (use_identity) {
        if (auto read_res = co_await ReadFull(stream, identity_header.data(), identity_header.size());
            !read_res) {
            co_return tl::unexpected(read_res.error());
        }
    }

    std::array<uint8_t, kSs2022RequestFixedHeaderSize + SsAeadCipher::kTagSize> enc_fixed{};
    if (auto read_res = co_await ReadFull(stream, enc_fixed.data(), enc_fixed.size());
        !read_res) {
        co_return tl::unexpected(read_res.error());
    }

    SsAeadCipher read_cipher(cipher_info.type, proxy::AeadDirection::Decrypt);
    std::array<uint8_t, kSs2022RequestFixedHeaderSize> fixed_plain{};
    struct CleanseRequestFixedPlain {
        std::array<uint8_t, kSs2022RequestFixedHeaderSize>& buf;
        ~CleanseRequestFixedPlain() noexcept { OPENSSL_cleanse(buf.data(), buf.size()); }
    } cleanse_req_fixed{fixed_plain};
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
        !TimestampFresh(LoadU64BE(fixed_plain.data() + 1), UnixSecondsNow())) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const uint16_t variable_len = LoadU16BE(fixed_plain.data() + 9);
    if (variable_len == 0) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    buf::MultiBuffer variable_mb;
    if (auto decrypt_res = co_await ReadStreamPayload(
            stream, read_cipher, MakeNonce(1), variable_len, variable_mb);
        !decrypt_res) {
        co_return tl::unexpected(decrypt_res.error());
    }

    buf::Buffer* first_payload = variable_mb.empty() ? nullptr : *variable_mb.begin();
    if (!first_payload || first_payload->IsEmpty()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    const auto first_bytes = first_payload->Bytes();
    auto addr_result = DecodeAddress(
        first_bytes, AddressWireFormat::Socks5,
        {.require_non_empty_domain = true, .allow_metadata = true});
    if (addr_result.status != AddressDecodeStatus::Complete) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    result.target = std::move(addr_result.target);
    result.forwarded = std::move(addr_result.forwarded);
    if (!result.target.IsValid() && !proxy::uot::VersionFromMagicAddress(result.target)) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    size_t offset = addr_result.consumed;
    if (offset + 2 > first_bytes.size()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    const uint16_t padding_len = LoadU16BE(first_bytes.data() + offset);
    offset += 2;
    if (offset + padding_len > variable_len) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    offset += padding_len;
    variable_mb.DropPrefixBytes(offset);
    variable_mb.ReleaseIfIdle();
    result.initial_payload = InitialPayload(std::move(variable_mb));

    result.body_reader = std::make_unique<detail::BodyReader>(
        std::move(read_cipher), 2, stream, kSs2022MaxChunkPayload);
    co_return result;
    } catch (const std::bad_alloc&) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (const IoSystemError& error) {
        co_return tl::unexpected(
            proxy::ClassifyHandshakeReadException(stream, error));
    }
}

}  // namespace

net::awaitable<tl::expected<ReadTCPSessionResult, ErrorCode>> ReadTCPSession(
    AsyncStream& stream,
    const SsCipherInfo& cipher_info,
    std::string_view tag,
    size_t& last_matched_index) {
    try {
    if (Is2022Cipher(cipher_info.type)) {
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
    struct CleanseLegacySalt {
        std::array<uint8_t, KeyBytes::kMaxSize>& buf;
        ~CleanseLegacySalt() noexcept { OPENSSL_cleanse(buf.data(), buf.size()); }
    } cleanse_legacy_salt{salt};
    if (auto read_res = co_await ReadFull(stream, salt.data(), salt_size);
        !read_res) {
        co_return tl::unexpected(read_res.error());
    }
    result.request_salt.assign(std::span<const uint8_t>(salt.data(), salt_size));
    std::array<uint8_t, 2 + SsAeadCipher::kTagSize> enc_len{};
    if (auto read_res = co_await ReadFull(stream, enc_len.data(), enc_len.size());
        !read_res) {
        co_return tl::unexpected(read_res.error());
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
        const bool key_ok = read_cipher.ResetKey(read_subkey.data(), key_size);
        OPENSSL_cleanse(read_subkey.data(), read_subkey.size());
        if (!key_ok) return false;
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

    buf::MultiBuffer payload_mb;
    if (auto decrypt_res = co_await ReadStreamPayload(
            stream, read_cipher, MakeNonce(read_nonce), payload_len, payload_mb);
        !decrypt_res) {
        co_return tl::unexpected(decrypt_res.error());
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
    auto addr_result = DecodeAddress(
        first_bytes, AddressWireFormat::Socks5,
        {.require_non_empty_domain = true, .allow_metadata = true});
    if (addr_result.status != AddressDecodeStatus::Complete) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    result.target = std::move(addr_result.target);
    result.forwarded = std::move(addr_result.forwarded);
    if (!result.target.IsValid() && !proxy::uot::VersionFromMagicAddress(result.target)) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }

    const size_t addr_consumed = addr_result.consumed;
    payload_mb.DropPrefixBytes(addr_consumed);
    payload_mb.ReleaseIfIdle();
    result.initial_payload = InitialPayload(std::move(payload_mb));

    result.body_reader = std::make_unique<detail::BodyReader>(
        std::move(read_cipher), read_nonce, stream);
    co_return result;
    } catch (const std::bad_alloc&) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (const IoSystemError& error) {
        co_return tl::unexpected(
            proxy::ClassifyHandshakeReadException(stream, error));
    }
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

}  // namespace ss
