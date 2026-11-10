#include "../ss_udp.hpp"
#include "../../inbound_admission.hpp"
#include "transport/async_stream.hpp"
#include "common/address_codec.hpp"
#include "../../uot/uot.hpp"
#include "app/rate_limiter.hpp"
#include "app/relay.hpp"
#include "app/stats.hpp"
#include "features/routing/dispatcher.hpp"
#include "app/proxyman/inbound/handler.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "common/allocator.hpp"
#include "common/initial_payload.hpp"
#include "common/session.hpp"

#include "common/buffer_util.hpp"
#include "common/byte_reader.hpp"
#include "common/buf/multi_buffer.hpp"
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <algorithm>
#include <cstring>
#include <new>
#include <optional>
#include <span>
#include <utility>
#include <variant>

namespace ss {

namespace {

using buf::ChunkBytes;
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

}  // namespace

net::awaitable<void> ResponseBodyWriter::WriteMultiBuffer(buf::MultiBuffer mb) {
    return WriteEncrypted(std::move(mb));
}

net::awaitable<void> ResponseBodyWriter::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    return WriteEncrypted(buffers);
}

net::awaitable<void> ResponseBodyWriter::AsyncShutdownWrite() {
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
            constexpr std::span<const net::const_buffer> kEmptyBuffers{};
            const bool ok = Is2022Cipher(cipher_type_)
                ? InitResponseCipher2022(*this, kEmptyBuffers, skip_first_bytes_)
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

void ResponseBodyWriter::Finish() {
    write_finished_ = true;
    write_cipher_.reset();
    pending_prefix_.clear();
    ClearHandshakeKeys();
}

void ResponseBodyWriter::Retire() {
    auto* stream = std::exchange(stream_, nullptr);
    write_cipher_.reset();
    pending_prefix_.clear();
    ClearHandshakeKeys();
    if (stream) stream->CloseAbortive();
}

template <typename BufferRange>
net::awaitable<void> ResponseBodyWriter::WriteEncrypted(BufferRange buffers) {
    if (!stream_) {
        throw IoSystemError(io_error::not_connected, "Shadowsocks response writer has no stream");
    }
    if (write_finished_) throw transport::WriteClosed();
    AsyncStream& stream = *stream_;

    bool has_data = false;
    for (const auto& buffer : buffers) {
        if (!ChunkBytes(buffer).empty()) {
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
        if (!write_init_) {
            const bool ok = Is2022Cipher(cipher_type_)
                ? InitResponseCipher2022(*this, buffers, skip_first_bytes_)
                : InitResponseCipher(*this);
            if (!ok) {
                ThrowSsWriteError("Shadowsocks server init write cipher failed");
            }
        }

        buf::MultiBuffer out_mb;
        out_mb.reserve(buffers.size());
        for (const auto& buffer : buffers) {
            const auto bytes = ChunkBytes(buffer);
            if (bytes.empty()) continue;
            detail::EncryptToMultiBuffer(
                *write_cipher_,
                write_nonce_,
                bytes,
                out_mb,
                &skip_first_bytes_);
        }
        if constexpr (std::is_same_v<BufferRange, buf::MultiBuffer>) {
            buffers.clear();
        }

        co_await FlushPendingAndWrite(stream, std::move(out_mb));
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

net::awaitable<void> ResponseBodyWriter::FlushPendingAndWrite(
    AsyncStream& stream,
    buf::MultiBuffer out_mb) {
    if (out_mb.byte_size() == 0 && pending_prefix_.byte_size() == 0) {
        co_return;
    }
    if (pending_prefix_.byte_size() != 0) {
        out_mb.MoveTo(pending_prefix_);
        out_mb = std::move(pending_prefix_);
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
bool ResponseBodyWriter::InitResponseCipher(ResponseBodyWriter& state) {
    const size_t key_size = state.key_size_;
    if (!state.pending_handshake_ || key_size == 0 || key_size > 64) {
        return false;
    }

    std::array<uint8_t, 64> server_salt{};
    if (RAND_bytes(server_salt.data(), static_cast<int>(key_size)) != 1) {
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
    if (!DeriveSubkey(state.pending_handshake_->master_key.data(), key_size,
                      server_salt.data(), key_size,
                      write_subkey.data())) {
        return false;
    }

    state.write_cipher_.emplace(state.cipher_type_, write_subkey.data(), key_size,
                                 proxy::AeadDirection::Encrypt);
    OPENSSL_cleanse(write_subkey.data(), write_subkey.size());
    state.write_nonce_ = 0;

    if (!buf::AppendSpanToMultiBuffer(
            std::span<const uint8_t>(server_salt.data(), key_size),
            state.pending_prefix_)) {
        return false;
    }
    state.ClearHandshakeKeys();
    state.write_init_ = true;
    return true;
}

template <typename BufferRange>
bool ResponseBodyWriter::InitResponseCipher2022(
    ResponseBodyWriter& state,
    const BufferRange& buffers,
    size_t& first_payload_len) {
    size_t want = 0;
    for (const auto& buffer : buffers) {
        want += ChunkBytes(buffer).size();
        if (want >= kStreamChunkPayloadSize) {
            want = kStreamChunkPayloadSize;
            break;
        }
    }

    const size_t key_size = state.key_size_;
    if (!state.pending_handshake_ ||
        key_size == 0 ||
        key_size > KeyBytes::kMaxSize ||
        state.pending_handshake_->request_salt.size != key_size ||
        want > kSs2022MaxChunkPayload) {
        return false;
    }

    std::array<uint8_t, 32> server_salt{};
    if (RAND_bytes(server_salt.data(), static_cast<int>(key_size)) != 1) {
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
    if (!Derive2022Subkey(state.pending_handshake_->master_key.data(), key_size,
                          server_salt.data(), key_size,
                          write_subkey.data())) {
        return false;
    }

    state.write_cipher_.emplace(state.cipher_type_, write_subkey.data(), key_size,
                                 proxy::AeadDirection::Encrypt);
    OPENSSL_cleanse(write_subkey.data(), write_subkey.size());

    const size_t fixed_plain_size = 1 + 8 + key_size + 2;
    fixed_plain[0] = 1;
    StoreU64BE(fixed_plain.data() + 1, UnixSecondsNow());
    std::memcpy(fixed_plain.data() + 9,
                state.pending_handshake_->request_salt.data(), key_size);
    StoreU16BE(fixed_plain.data() + 9 + key_size,
             static_cast<uint16_t>(want));

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
            std::span<const uint8_t>(server_salt.data(), key_size),
            state.pending_prefix_) ||
        !buf::AppendSpanToMultiBuffer(
            std::span<const uint8_t>(fixed_cipher.data(), fixed_cipher_size),
            state.pending_prefix_)) {
        state.pending_prefix_.clear();
        return false;
    }

    if (want != 0) {
        buf::BufferGuard payload_cipher{buf::Buffer::New()};
        if (!payload_cipher ||
            want + SsAeadCipher::kTagSize > payload_cipher->Available()) {
            state.pending_prefix_.clear();
            return false;
        }
        uint8_t* dst = payload_cipher->Tail().data();
        size_t copied = 0;
        for (const auto& buffer : buffers) {
            const auto bytes = ChunkBytes(buffer);
            if (bytes.empty() || copied >= want) {
                continue;
            }
            const size_t n = std::min(bytes.size(), want - copied);
            std::memcpy(dst + copied, bytes.data(), n);
            copied += n;
        }
        auto nonce1 = MakeNonce(1);
        if (!state.write_cipher_->Encrypt(nonce1.data(), dst, want, dst)) {
            OPENSSL_cleanse(dst, want);
            state.pending_prefix_.clear();
            return false;
        }
        state.write_nonce_ = 2;
        payload_cipher->Produce(static_cast<uint32_t>(
            want + SsAeadCipher::kTagSize));
        state.pending_prefix_.push_back(std::move(payload_cipher));
    }
    first_payload_len = want;
    state.ClearHandshakeKeys();
    state.write_init_ = true;
    return true;
}

namespace {

bool DecryptIdentityHeader(
    const proxyman::inbound::PreparedKeyBytes& identity_key,
    const SsCipherInfo& cipher_info,
    std::span<const uint8_t> salt,
    std::span<const uint8_t, 16> encrypted_identity,
    std::array<uint8_t, 16>& identity_hash) {
    // BuildMasterKey/Decode2022Psk admit only the configured cipher's exact
    // key length; malformed prepared credentials are not identity groups.
    if (identity_key.size != cipher_info.key_size) return false;
    std::array<uint8_t, 32> block_key{};
    const bool ok =
        Derive2022IdentitySubkey(identity_key.data(), cipher_info.key_size,
                                 salt.data(), salt.size(), block_key.data()) &&
        AesBlocksCrypt<16>(
            std::span<const uint8_t>(block_key.data(), cipher_info.key_size),
            encrypted_identity, std::span<uint8_t, 16>(identity_hash), false);
    OPENSSL_cleanse(block_key.data(), block_key.size());
    return ok;
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

    const bool use_identity = Is2022AesCipher(cipher_info.type) &&
        users[users.size() - 1].identity_key.size >= key_size;
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

    if (use_identity) {
        std::array<uint8_t, 16> identity_hash{};
        struct CleanseIdentityHash {
            std::array<uint8_t, 16>& hash;
            ~CleanseIdentityHash() noexcept { OPENSSL_cleanse(hash.data(), hash.size()); }
        } cleanse_identity{identity_hash};
        const auto& list = *users.users;
        const auto try_candidates = [&](size_t begin, size_t end) {
            // The hash selects candidates, never authenticates a user:
            // collisions still require the fixed header's AEAD tag.
            for (size_t index = users.IdentityHashLowerBound(begin, end, identity_hash);
                 index != end &&
                 CRYPTO_memcmp(users[index].psk_hash.data(), identity_hash.data(),
                               identity_hash.size()) == 0; ++index) {
                if (index != hint && try_user(index)) break;
            }
        };
        size_t hinted_begin = users.size();
        size_t hinted_end = users.size();
        if (hint < list.size()) {
            const auto& key = list[hint].identity_key;
            const bool decoded = DecryptIdentityHeader(
                key, cipher_info, result.request_salt.span(), identity_header, identity_hash);
            if (decoded &&
                CRYPTO_memcmp(list[hint].psk_hash.data(), identity_hash.data(),
                              identity_hash.size()) == 0) {
                try_user(hint);
            }
            if (!result.user) {
                // A hit remains O(1). Only a miss needs to locate the hinted
                // group, whose identity work must not be repeated below.
                hinted_begin = static_cast<size_t>(std::partition_point(
                    list.begin(), list.begin() + hint, [&](const auto& user) {
                        return user.identity_key.size != key.size ||
                            CRYPTO_memcmp(user.identity_key.data(), key.data(), key.size) != 0;
                    }) - list.begin());
                hinted_end = users.IdentityGroupEnd(hint);
                if (decoded) try_candidates(hinted_begin, hinted_end);
            }
        }
        for (size_t group = 0; group != users.size() && !result.user;) {
            if (group == hinted_begin) {
                group = hinted_end;
                continue;
            }
            const size_t end = users.IdentityGroupEnd(group);
            if (DecryptIdentityHeader(users[group].identity_key, cipher_info,
                                      result.request_salt.span(), identity_header, identity_hash)) {
                try_candidates(group, end);
            }
            group = end;
        }
    } else if (hint >= users.size() || !try_user(hint)) {
        for (size_t i = 0; i < users.size(); ++i) {
            if (i != hint && try_user(i)) break;
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

    result.body_reader.emplace(
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

    result.body_reader.emplace(
        std::move(read_cipher), read_nonce, stream);
    co_return result;
    } catch (const std::bad_alloc&) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    } catch (const IoSystemError& error) {
        co_return tl::unexpected(
            proxy::ClassifyHandshakeReadException(stream, error));
    }
}

tl::expected<ResponseBodyWriter, ErrorCode> WriteTCPResponse(
    const proxyman::inbound::UserStore::ShadowsocksCredential& user,
    const SsCipherInfo& cipher_info,
    const KeyBytes& request_salt,
    AsyncStream& stream) {
    try {
        return ResponseBodyWriter(user, cipher_info, request_salt, stream);
    } catch (...) {
        return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
}

}  // namespace ss


namespace {



class ShadowsocksUdpResponseContext final : public InboundDatagramResponse {
public:
    ShadowsocksUdpResponseContext(ss::KeyBytes reply_key, ss::SsCipherInfo cipher_info)
        : state_(ClassicState{std::move(reply_key), cipher_info}) {}

    explicit ShadowsocksUdpResponseContext(ss::Ss2022UdpTxState session)
        : state_(std::move(session)) {}

    [[nodiscard]] buf::MultiBuffer Encode(UDPPacketView packet) override;

private:
    struct ClassicState {
        ss::KeyBytes reply_key;
        ss::SsCipherInfo cipher_info{};
    };

    [[nodiscard]] size_t EncodePacketTo(
        const TargetAddress& target,
        std::span<const uint8_t> payload,
        uint8_t* out,
        size_t out_capacity);

    std::variant<ClassicState, ss::Ss2022UdpTxState> state_;
};

struct PreparedSsTcpSession {
    ss::detail::BodyReader request_reader;
    ss::ResponseBodyWriter response_writer;
    InitialPayload initial_payload;
    UserOnlineSessionGuard user_session;
    std::optional<proxy::uot::Version> uot_version;
};

net::awaitable<tl::expected<PreparedSsTcpSession, ErrorCode>>
PrepareSsTcpSession(
    AsyncStream& stream,
    const ss::SsCipherInfo& cipher_info,
    size_t& last_matched_index,
    UserOnlineTracker& validator,
    ConnectionLimiter* limiter,
    session::Context& ctx,
    std::string_view tag,
    std::string_view client_ip) {
    auto session_result = co_await ss::ReadTCPSession(
        stream,
        cipher_info,
        tag,
        last_matched_index);
    if (!session_result) {
        const ErrorCode error = session_result.error();
        if (error == ErrorCode::PROTOCOL_AUTH_FAILED) {
            co_await proxy::RecordInboundAuthFailure(limiter, ctx, "no matching credential");
        } else if (error == ErrorCode::SOCKET_READ_FAILED) {
            // ReadTCPSession returns this code when ReadFull reaches EOF;
            // transport errors throw instead.
            LOG_CONN_DEBUG(ctx, "TCP session header ended before completion from {}:{} > {}",
                           client_ip, ctx.inbound.source_port, ErrorCodeToString(error));
        } else if (error != ErrorCode::SOCKET_EOF && error != ErrorCode::CONNECTION_CLOSED &&
                   error != ErrorCode::CANCELLED) {
            LOG_CONN_WARN(ctx, "TCP session handshake failed from {}:{} > {}",
                          client_ip, ctx.inbound.source_port, ErrorCodeToString(error));
        }
        co_return tl::unexpected(error);
    }

    auto request_reader = std::move(session_result->body_reader);
    const auto* matched = session_result->user.get();
    if (!matched) {
        co_await proxy::RecordInboundAuthFailure(limiter, ctx, "no authenticated user");
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    // UoT resolves its UDP destination only after admission; the magic address
    // is admitted as the TCP request target, as before.
    const auto uot_version = proxy::uot::VersionFromMagicAddress(session_result->target);
    proxy::BindAuthenticatedInbound(
        ctx, matched->profile,
        proxy::InboundRequestTarget{
            Network::TCP,
            std::move(session_result->target),
            std::move(session_result->forwarded)});
    auto user_session = co_await proxy::AdmitAuthenticatedInbound(
        validator, ctx, matched->profile);
    if (!user_session) {
        co_return tl::unexpected(ErrorCode::PERMISSION_DENIED);
    }

    auto response_writer_result = ss::WriteTCPResponse(
        *matched, cipher_info, session_result->request_salt, stream);
    if (!request_reader) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    if (!response_writer_result) {
        co_return tl::unexpected(response_writer_result.error());
    }
    // Both directions now own their cipher/key state, including the lazy
    // response header. Authentication ownership must end before UoT/relay waits.
    session_result->user.reset();

    co_return PreparedSsTcpSession{
        .request_reader = std::move(*request_reader),
        .response_writer = std::move(*response_writer_result),
        .initial_payload = std::move(session_result->initial_payload),
        .user_session = std::move(*user_session),
        .uot_version = uot_version,
    };
}

net::awaitable<RelayResult> DispatchSsUotSession(
    proxy::uot::Version uot_version,
    std::unique_ptr<AsyncStream> stream,
    transport::MultiBufferReader& request_reader,
    transport::MultiBufferWriter& response_writer,
    buf::MultiBuffer pending,
    routing::Dispatcher& dispatcher,
    const routing::DispatchPolicy& dispatch_policy,
    net::io_context& io_context,
    session::Context& ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts) {
    tl::expected<proxy::uot::PreparedRequest, ErrorCode> prepared =
        tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    try {
        prepared = co_await proxy::uot::ReadUotRequestHeader(
            uot_version, request_reader, std::move(pending));
    } catch (const transport::LinkError& e) {
        prepared = tl::unexpected(e.code());
    } catch (const IoSystemError& e) {
        prepared = tl::unexpected(
            stream ? proxy::ClassifyHandshakeReadException(*stream, e)
                   : MapAsioError(e.code()));
    }
    if (!prepared) {
        co_return proxy::RejectInbound(stats, stream.get(), prepared.error());
    }
    co_return co_await proxy::uot::DispatchPreparedUotRequest(
        std::move(*prepared),
        std::move(stream),
        request_reader,
        response_writer,
        dispatcher,
        dispatch_policy,
        io_context,
        ctx,
        stats,
        timeouts);
}

}  // namespace

// ============================================================================
// proxy/shadowsocks/inbound.Handler
// ============================================================================

proxy::shadowsocks::inbound::Handler::Handler(
    UserOnlineTracker& validator,
    StatsShard& stats,
    ConnectionLimiter* limiter,
    ss::SsCipherInfo cipher_info)
    : validator_(validator)
    , stats_(stats)
    , limiter_(limiter)
    , cipher_info_(cipher_info) {}

// ----------------------------------------------------------------------------
// Process
// 流程：
//   1. 读取 salt（salt_size 字节）
//   2. 遍历所有用户，尝试派生子密钥并解密首 chunk 长度字段
//   3. 找到匹配用户后解密首 chunk payload
//   4. 解析 SOCKS5 目标地址
//   5. 将剩余数据作为 initial_payload
//   6. 调用 dispatcher 进入出站处理
//
// 握手超时由底层 TcpStream 空闲超时保护（proxyman inbound 已在 Process
// 前设置 handshake 超时），无需额外守卫。
// ----------------------------------------------------------------------------
net::awaitable<RelayResult>
proxy::shadowsocks::inbound::Handler::Process(
    std::unique_ptr<AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    uint32_t /*pressure_idle_timeout*/) {

    const std::string_view tag   = ctx.inbound.tag;
    const std::string_view client_ip = ctx.inbound.source_ip;

    LOG_CONN_DEBUG(ctx, "processing connection from {}:{}", client_ip, ctx.inbound.source_port);

    if (proxy::BeginInboundAuthentication(limiter_, ctx) &&
        co_await proxy::CheckInboundIpBanned(*limiter_, ctx)) {
        co_return proxy::RejectInbound(stats_, stream.get(), ErrorCode::BLOCKED);
    }
    auto prepared = co_await PrepareSsTcpSession(
        *stream,
        cipher_info_,
        last_matched_index_,
        validator_,
        limiter_,
        ctx,
        tag,
        client_ip);
    if (!prepared) {
        co_return proxy::RejectInbound(stats_, stream.get(), prepared.error());
    }

    if (prepared->uot_version) {
        co_return co_await DispatchSsUotSession(
            *prepared->uot_version,
            std::move(stream),
            prepared->request_reader,
            prepared->response_writer,
            std::move(prepared->initial_payload).MoveToMultiBuffer(),
            dispatcher,
            receiver.dispatch_policy,
            io_context,
            ctx,
            stats_,
            timeouts);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{&prepared->request_reader, &prepared->response_writer},
        std::move(prepared->initial_payload),
        ctx,
        stats_,
        timeouts);
}

tl::expected<::InboundDatagramResult, ::ErrorCode>
proxy::shadowsocks::inbound::Handler::Process(
    const InboundDatagramRequest& request) {
    const auto tag = request.tag;

    auto users = proxyman::inbound::UserStore::ShadowsocksUsers(tag);
    if (users.empty()) {
        return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    auto decoded = ss::DecodeUdpPacket(
        request.payload.data(), request.payload.size(), users,
        cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size,
        udp_replay_cache_, request.associations != nullptr);
    if (!decoded) {
        // UDP datagrams use the socket peer address, never a PROXY protocol source.
        return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    const auto& user = users[decoded->user_index];

    InboundDatagramResult result;
    if (!result.session_owner.Assign(user.derived_key.span())) {
        return tl::unexpected(ErrorCode::INTERNAL);
    }
    result.target = std::move(decoded->target);
    result.payload = std::move(decoded->payload);
    result.forwarded = std::move(decoded->forwarded);
    result.session_id = decoded->session_id;
    result.packet_id = decoded->packet_id;
    if (request.associations && decoded->session_id && decoded->packet_id) {
        result.association_policy = &ss::Ss2022UdpAssociation::Policy();
        const auto found = request.associations->find(InboundDatagramAssociationKey{
            result.session_owner, *decoded->session_id, request.configuration});
        if (found != request.associations->end() && found->second) {
            auto* association = found->second;
            // The configuration/credential/session lookup and immutable policy
            // identity together establish the concrete protocol state type.
            if (&association->Policy() != result.association_policy)
                return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
            if (!association->claimed) {
                auto& state = static_cast<ss::Ss2022UdpAssociation&>(*association);
                if (!state.ss::Ss2022UdpAssociation::Check(*decoded->packet_id, request.worker_id,
                        request.client_endpoint, InboundDatagramCheck::Commit))
                    return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
                result.committed_association = association;
            }
        }
    }
    result.user = &user.profile;
    return result;
}

tl::expected<std::shared_ptr<InboundDatagramResponse>, ErrorCode>
proxy::shadowsocks::inbound::Handler::CreateDatagramResponse(
    const InboundDatagramResult& decoded) {
    ss::KeyBytes key;
    if (!key.assign(std::span(decoded.session_owner.bytes).first(decoded.session_owner.size))) {
        return tl::unexpected(ErrorCode::INTERNAL);
    }
    if (!ss::Is2022Cipher(cipher_info_.type)) {
        return memory::AllocateShared<ShadowsocksUdpResponseContext>(key, cipher_info_);
    }
    if (!decoded.session_id) return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    ss::Ss2022UdpTxState state;
    state.cipher_info = cipher_info_;
    state.key = key;
    StoreU64BE(state.client_session_id.data(), *decoded.session_id);
    if (RAND_bytes(state.server_session_id.data(), state.server_session_id.size()) != 1) {
        return tl::unexpected(ErrorCode::INTERNAL);
    }
    return memory::AllocateShared<ShadowsocksUdpResponseContext>(std::move(state));
}

size_t ShadowsocksUdpResponseContext::EncodePacketTo(
    const TargetAddress& target,
    std::span<const uint8_t> payload,
    uint8_t* out,
    size_t out_capacity) {
    if (auto* ss2022 = std::get_if<ss::Ss2022UdpTxState>(&state_)) {
        return ss::Encode2022UdpResponsePacketTo(
            target,
            payload.data(),
            payload.size(),
            *ss2022,
            out,
            out_capacity);
    }
    const auto& classic = std::get<ClassicState>(state_);
    return ss::EncodeUdpPacketTo(
        target,
        payload.data(),
        payload.size(),
        classic.reply_key.span(),
        classic.cipher_info.type,
        classic.cipher_info.key_size,
        classic.cipher_info.salt_size,
        out,
        out_capacity);
}

buf::MultiBuffer ShadowsocksUdpResponseContext::Encode(UDPPacketView packet) {
    const size_t encoded_len = EncodePacketTo(
        packet.target, packet.data, nullptr, 0);
    if (encoded_len == 0) {
        return {};
    }

    buf::ContiguousWriteBuffer encoded;
    uint8_t* dst = encoded.TryPrepare(encoded_len);
    if (!dst) {
        return {};
    }
    const size_t written = EncodePacketTo(
        packet.target,
        packet.data,
        dst,
        encoded_len);
    if (written != encoded_len) {
        return {};
    }

    buf::MultiBuffer payload;
    if (!encoded.TryAppendTo(written, payload)) {
        return {};
    }
    return payload;
}


// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
class ShadowsocksSettings final
    : public ::proxyman::inbound::ProtocolSettings {
public:
    ::ss::SsCipherInfo cipher;
    // SS2022-AES identity header key; empty when EIH is disabled.
    ::proxyman::inbound::PreparedKeyBytes identity_key;
    ::Ss2022UserKey user_key = ::Ss2022UserKey::Base64Psk;
};

[[nodiscard]] const ShadowsocksSettings* GetSettings(
    const ::proxyman::inbound::BuildRequest& req) noexcept {
    return dynamic_cast<const ShadowsocksSettings*>(req.settings.get());
}

const bool kSsInboundRegistered = [] {
    ::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = ::proxyman::inbound::UserProtocol::Shadowsocks;
    reg.datagram_transport =
        ::proxyman::inbound::DatagramTransport::Packet;

    reg.create_runtime = &::proxy::CreateUserOnlineProtocolRuntime;

    const auto create_handler =
        [](::proxyman::inbound::ProtocolRuntime& runtime,
           ::StatsShard& stats,
           ::ConnectionLimiter* limiter,
           const ::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<::Inbound> {
            auto* tracker = runtime.OnlineTracker();
            const auto* settings = GetSettings(req);
            if (!tracker || !settings) {
                return nullptr;
            }
            return std::make_unique<::proxy::shadowsocks::inbound::Handler>(
                *tracker,
                stats,
                limiter,
                settings->cipher);
        };
    reg.create_tcp_handler = create_handler;
    reg.create_datagram_handler = create_handler;

    reg.prepare_settings =
        [](std::string_view tag, const ::InboundProtocolSettings& config)
            -> std::optional<std::shared_ptr<
                const ::proxyman::inbound::ProtocolSettings>> {
            const std::string method = config.method.empty()
                ? std::string(::constants::protocol::kAes256Gcm)
                : config.method;
            auto cipher = ::ss::ParseCipherMethod(method);
            if (!cipher) {
                LOG_WARN("Inbound '{}': unknown SS cipher '{}'", tag, method);
                return std::nullopt;
            }
            auto settings = std::make_shared<ShadowsocksSettings>();
            settings->cipher = *cipher;
            settings->user_key = config.ss2022_user_key;
            if (::ss::Is2022AesCipher(cipher->type)) {
                if (!config.identity_password.empty()) {
                    settings->identity_key =
                        ::ss::BuildMasterKey(config.identity_password, *cipher);
                    if (settings->identity_key.empty()) {
                        LOG_WARN("Inbound '{}': invalid SS2022 identity password", tag);
                        return std::nullopt;
                    }
                } else if (config.ss2022_user_key == ::Ss2022UserKey::UuidDerived) {
                    LOG_WARN("Inbound '{}': SS2022 UUID users require server identity key", tag);
                    return std::nullopt;
                }
            }
            return settings;
        };

    reg.build_users =
        [](const ::proxyman::inbound::BuildRequest& req,
           std::span<const ::InboundUserSpec> specs)
            -> std::optional<::proxyman::inbound::UserSet> {
            const auto* settings = GetSettings(req);
            if (!settings) {
                LOG_WARN("Inbound '{}': missing prepared SS settings", req.tag);
                return std::nullopt;
            }
            const auto& cipher_info = settings->cipher;
            const bool uuid_derived =
                ::ss::Is2022Cipher(cipher_info.type) &&
                settings->user_key == ::Ss2022UserKey::UuidDerived;

            std::vector<::proxyman::inbound::PreparedShadowsocksUser> users;
            users.reserve(specs.size());
            for (const auto& spec : specs) {
                if (spec.credential.empty()) {
                    LOG_WARN("Inbound '{}': SS password is empty", req.tag);
                    return std::nullopt;
                }
                ::proxyman::inbound::PreparedShadowsocksUser info;
                info.profile = ::proxy::MakeUserProfile(spec);
                info.derived_key = uuid_derived
                    ? ::ss::Build2022UserKeyFromUuid(spec.credential, cipher_info)
                    : ::ss::BuildMasterKey(spec.credential, cipher_info);
                info.identity_key = settings->identity_key;
                if (info.derived_key.empty()) {
                    LOG_WARN("Inbound '{}': invalid SS password for user '{}'",
                             req.tag, spec.email);
                    return std::nullopt;
                }
                if (!info.identity_key.empty() &&
                    !::ss::Hash2022Psk(info.derived_key.span(), info.psk_hash)) {
                    return std::nullopt;
                }
                users.push_back(std::move(info));
            }

            return ::proxyman::inbound::UserSet{std::move(users)};
        };

    ::proxyman::inbound::RegisterProxy(
        ::constants::protocol::kShadowsocks, std::move(reg));
    return true;
}();
}  // namespace
