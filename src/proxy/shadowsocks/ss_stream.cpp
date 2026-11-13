#include "proxy/shadowsocks/ss_stream.hpp"
#include "common/scoped_cleanse.hpp"

#include <openssl/rand.h>
#include <asio/this_coro.hpp>

namespace proxy {
using common::ChunkBytes;

net::awaitable<void> SsStreamWriter::WriteMultiBuffer(common::MultiBuffer mb) {
    return WriteEncrypted({}, std::move(mb));
}

net::awaitable<void> SsStreamWriter::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    return WriteEncrypted(buffers);
}

net::awaitable<void> SsStreamWriter::AsyncShutdownWrite() {
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
                ? InitResponseCipher2022(kEmptyBuffers)
                : InitResponseCipher();
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

void SsStreamWriter::Finish() {
    write_finished_ = true;
    write_cipher_.reset();
    pending_prefix_.clear();
    ClearHandshakeKeys();
}

void SsStreamWriter::Retire() {
    auto* stream = std::exchange(stream_, nullptr);
    write_cipher_.reset();
    pending_prefix_.clear();
    ClearHandshakeKeys();
    if (stream) stream->CloseAbortive();
}

net::awaitable<void> SsStreamWriter::WriteEncrypted(
    std::span<const net::const_buffer> buffers,
    common::MultiBuffer owned) {
    if (!stream_) {
        throw IoSystemError(io_error::not_connected, "Shadowsocks response writer has no stream");
    }
    if (write_finished_) throw transport::WriteClosed();
    transport::AsyncStream& stream = *stream_;

    net::const_buffer single_owned;
    if (!owned.empty()) {
        const auto span = owned.FrontSpan();
        single_owned = net::buffer(span.data(), span.size());
        buffers = {&single_owned, span.empty() ? size_t{0} : size_t{1}};
    }
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
    bool write_started = false;
    try {
        if (!write_init_) {
            const bool ok = Is2022Cipher(cipher_type_)
                ? InitResponseCipher2022(buffers)
                : InitResponseCipher();
            if (!ok) {
                ThrowSsWriteError("Shadowsocks server init write cipher failed");
            }
        }

        common::MultiBuffer out_mb;
        for (const auto& buffer : buffers) {
            const auto bytes = ChunkBytes(buffer);
            if (bytes.empty()) continue;
            EncryptToMultiBuffer(
                *write_cipher_,
                write_nonce_,
                bytes,
                out_mb,
                &skip_first_bytes_);
        }
        owned.clear();

        write_started = true;
        co_await FlushPendingAndWrite(stream, std::move(out_mb));
    } catch (const transport::WriteClosed&) {
        Finish();
        throw;
    } catch (const std::bad_alloc&) {
        if (write_nonce_ != initial_nonce || write_started) Retire();
        throw;
    } catch (...) {
        Retire();
        throw;
    }
}

net::awaitable<void> SsStreamWriter::FlushPendingAndWrite(
    transport::AsyncStream& stream,
    common::MultiBuffer out_mb) {
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
bool SsStreamWriter::InitResponseCipher() {
    const size_t key_size = key_size_;
    if (!pending_handshake_ || key_size == 0 || key_size > 64) {
        return false;
    }

    std::array<uint8_t, 64> server_salt{};
    if (RAND_bytes(server_salt.data(), static_cast<int>(key_size)) != 1) {
        return false;
    }

    std::array<uint8_t, 64> write_subkey{};
    common::ScopedCleanse cleanse_init_legacy{server_salt, write_subkey};
    if (!DeriveSsSubkey(pending_handshake_->master_key.data(), key_size,
                      server_salt.data(), key_size,
                      write_subkey.data())) {
        return false;
    }

    write_cipher_.emplace(cipher_type_, write_subkey.data(), key_size);
    write_nonce_ = 0;

    if (!pending_prefix_.AppendSpan(
            std::span<const uint8_t>(server_salt.data(), key_size))) {
        return false;
    }
    ClearHandshakeKeys();
    write_init_ = true;
    return true;
}

bool SsStreamWriter::AppendFirstResponsePayload(
    std::span<const net::const_buffer> buffers, size_t want) {
    if (want == 0) return true;
    common::BufferGuard payload_cipher{common::Buffer::New()};
    if (!payload_cipher ||
        want + SsAeadCipher::kTagSize > payload_cipher->Available()) {
        pending_prefix_.clear();
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
    if (!write_cipher_->Encrypt(nonce1.data(), dst, want, dst)) {
        OPENSSL_cleanse(dst, want);
        pending_prefix_.clear();
        return false;
    }
    write_nonce_ = 2;
    payload_cipher->Produce(static_cast<uint32_t>(
        want + SsAeadCipher::kTagSize));
    pending_prefix_.push_back(std::move(payload_cipher));
    return true;
}

bool SsStreamWriter::InitResponseCipher2022(
    std::span<const net::const_buffer> buffers) {
    size_t want = 0;
    for (const auto& buffer : buffers) {
        want += ChunkBytes(buffer).size();
        if (want >= kStreamChunkPayloadSize) {
            want = kStreamChunkPayloadSize;
            break;
        }
    }

    const size_t key_size = key_size_;
    if (!pending_handshake_ ||
        key_size == 0 ||
        key_size > KeyBytes::kMaxSize ||
        pending_handshake_->request_salt.size != key_size ||
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
    common::ScopedCleanse cleanse_init_2022{server_salt, write_subkey, fixed_plain};
    if (!Derive2022Subkey(pending_handshake_->master_key.data(), key_size,
                          server_salt.data(), key_size,
                          write_subkey.data())) {
        return false;
    }

    write_cipher_.emplace(cipher_type_, write_subkey.data(), key_size);

    const size_t fixed_plain_size = 1 + 8 + key_size + 2;
    fixed_plain[0] = 1;
    common::StoreU64BE(fixed_plain.data() + 1, UnixSecondsNow());
    std::memcpy(fixed_plain.data() + 9,
                pending_handshake_->request_salt.data(), key_size);
    common::StoreU16BE(fixed_plain.data() + 9 + key_size,
             static_cast<uint16_t>(want));

    std::array<uint8_t, kFixedCipherMaxSize> fixed_cipher{};
    const size_t fixed_cipher_size = fixed_plain_size + SsAeadCipher::kTagSize;
    auto nonce0 = MakeNonce(0);
    if (!write_cipher_->Encrypt(nonce0.data(), fixed_plain.data(), fixed_plain_size,
                                      fixed_cipher.data())) {
        return false;
    }
    write_nonce_ = 1;

    pending_prefix_.clear();
    if (!pending_prefix_.AppendSpan(
            std::span<const uint8_t>(server_salt.data(), key_size)) ||
        !pending_prefix_.AppendSpan(
            std::span<const uint8_t>(fixed_cipher.data(), fixed_cipher_size))) {
        pending_prefix_.clear();
        return false;
    }

    if (!AppendFirstResponsePayload(buffers, want)) return false;
    skip_first_bytes_ = want;
    ClearHandshakeKeys();
    write_init_ = true;
    return true;
}
}  // namespace proxy
