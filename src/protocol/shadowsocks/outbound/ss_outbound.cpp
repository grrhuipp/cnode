#include "acppnode/protocol/shadowsocks/outbound/ss_outbound.hpp"
#include "acppnode/protocol/protocol_registry.hpp"
#include "acppnode/protocol/outbound_helpers.hpp"
#include "acppnode/transport/stream_helpers.hpp"
#include "acppnode/dns/dns_service.hpp"
#include "acppnode/infra/json_helpers.hpp"
#include "acppnode/infra/log.hpp"

#include <openssl/rand.h>

#include "acppnode/common/buffer_util.hpp"
#include <algorithm>
#include <cstring>

namespace acpp {

namespace {

constexpr size_t kSsLenHeaderSize = 2 + ss::SsAeadCipher::kTagSize;
constexpr size_t kStreamChunkPayloadSize =
    Buffer::kSize - kSsLenHeaderSize - ss::SsAeadCipher::kTagSize;
constexpr size_t kStreamFlushBufferCount = 8;
constexpr size_t kStreamFlushBytes = Buffer::kSize * kStreamFlushBufferCount;

[[noreturn]] void ThrowSsWriteError(const char* what) {
    throw boost::system::system_error(boost::asio::error::connection_reset, what);
}

const EVP_CIPHER* GetCipher(ss::SsCipherType type) noexcept {
    switch (type) {
        case ss::SsCipherType::AES_128_GCM:       return EVP_aes_128_gcm();
        case ss::SsCipherType::AES_256_GCM:       return EVP_aes_256_gcm();
        case ss::SsCipherType::CHACHA20_POLY1305:  return EVP_chacha20_poly1305();
    }
    return nullptr;
}

class SsAeadStreamEncryptor {
public:
    explicit SsAeadStreamEncryptor(const ss::SsAeadCipher& cipher)
        : type_(cipher.Type())
        , key_(cipher.Key().begin(), cipher.Key().end()) {
        ctx_ = EVP_CIPHER_CTX_new();
    }

    ~SsAeadStreamEncryptor() {
        if (ctx_) {
            EVP_CIPHER_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }

    SsAeadStreamEncryptor(const SsAeadStreamEncryptor&)            = delete;
    SsAeadStreamEncryptor& operator=(const SsAeadStreamEncryptor&) = delete;

    bool Init(const uint8_t* nonce) noexcept {
        if (!ctx_ || !nonce) return false;

        const EVP_CIPHER* cipher = GetCipher(type_);
        if (!cipher) return false;

        if (EVP_CIPHER_CTX_reset(ctx_) != 1) return false;
        if (EVP_EncryptInit_ex(ctx_, cipher, nullptr, nullptr, nullptr) != 1) return false;
        if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) return false;
        if (EVP_EncryptInit_ex(ctx_, nullptr, nullptr, key_.data(), nonce) != 1) return false;
        return true;
    }

    bool Update(const uint8_t* plaintext,
                size_t plaintext_len,
                uint8_t* output,
                int* out_len) noexcept {
        if (!ctx_ || !plaintext || !output || !out_len) return false;

        return EVP_EncryptUpdate(
            ctx_, output, out_len,
            plaintext, static_cast<int>(plaintext_len)) == 1;
    }

    bool Final(uint8_t* tag) noexcept {
        if (!ctx_ || !tag) return false;

        int final_len = 0;
        uint8_t dummy[16]{};
        if (EVP_EncryptFinal_ex(ctx_, dummy, &final_len) != 1) return false;
        if (final_len != 0) return false;
        if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) return false;
        return true;
    }

private:
    ss::SsCipherType         type_;
    std::vector<uint8_t>     key_;
    EVP_CIPHER_CTX*          ctx_ = nullptr;
};

size_t CountPrefixBytes(const MultiBuffer& mb, size_t limit) noexcept {
    size_t total = 0;
    if (limit == 0) {
        return 0;
    }

    for (auto* buf : mb) {
        if (total >= limit) break;

        auto bytes = buf->Bytes();
        if (bytes.empty()) continue;

        const size_t take = std::min(limit - total, bytes.size());
        total += take;
    }
    return total;
}

bool AppendEncryptedSpan(SsAeadStreamEncryptor& encryptor,
                         Buffer*& out,
                         MultiBuffer& out_mb,
                         const uint8_t* data,
                         size_t len) {
    size_t offset = 0;
    while (offset < len) {
        if (out->Available() == 0) {
            Buffer* next = Buffer::New();
            if (!next) {
                return false;
            }
            out = next;
            out_mb.push_back(out);
        }

        const size_t to_process =
            std::min(len - offset, static_cast<size_t>(out->Available()));
        int produced = 0;
        if (!encryptor.Update(data + offset, to_process,
                              out->Tail().data(), &produced)) {
            return false;
        }
        if (produced < 0 || static_cast<size_t>(produced) != to_process) {
            return false;
        }

        out->Produce(static_cast<uint32_t>(produced));
        offset += to_process;
    }
    return true;
}

bool AppendTag(Buffer*& out, MultiBuffer& out_mb, const uint8_t* tag, size_t tag_len) {
    if (out->Available() < tag_len) {
        Buffer* next = Buffer::New();
        if (!next) {
            return false;
        }
        out = next;
        out_mb.push_back(out);
    }

    std::memcpy(out->Tail().data(), tag, tag_len);
    out->Produce(static_cast<uint32_t>(tag_len));
    return true;
}

}  // namespace

// ============================================================================
// SsClientAsyncStream
// ============================================================================

SsClientAsyncStream::SsClientAsyncStream(
    std::unique_ptr<AsyncStream> inner,
    ss::SsCipherType cipher_type,
    size_t key_size,
    size_t salt_size,
    std::span<const uint8_t> master_key,
    TargetAddress target)
    : inner_(std::move(inner))
    , target_(std::move(target))
    , cipher_type_(cipher_type)
    , key_size_(key_size)
    , salt_size_(salt_size)
    , master_key_(master_key.begin(), master_key.end()) {
}

// ── 内部辅助 ─────────────────────────────────────────────────────────────────

cobalt::task<bool> SsClientAsyncStream::ReadFull(uint8_t* buf, size_t len) {
    co_return co_await acpp::ReadFull(*inner_, buf, len);
}

cobalt::task<bool> SsClientAsyncStream::WriteFull(const uint8_t* buf, size_t len) {
    co_return co_await acpp::WriteFull(*inner_, buf, len);
}

cobalt::task<bool> SsClientAsyncStream::EnsureReadCipherInitialized() {
    if (read_init_) {
        co_return true;
    }

    if (salt_size_ > 64 || key_size_ > 64) {
        co_return false;
    }

    std::array<uint8_t, 64> server_salt{};
    if (!co_await ReadFull(server_salt.data(), salt_size_)) co_return false;

    std::array<uint8_t, 64> read_subkey{};
    if (!ss::DeriveSubkey(master_key_.data(), key_size_,
                          server_salt.data(), salt_size_,
                          read_subkey.data())) {
        co_return false;
    }

    read_cipher_ = std::make_unique<ss::SsAeadCipher>(
        cipher_type_, read_subkey.data(), key_size_);
    read_nonce_ = 0;
    read_init_  = true;
    co_return true;
}

cobalt::task<bool> SsClientAsyncStream::ReadNextChunk() {
    if (!co_await EnsureReadCipherInitialized()) co_return false;

    // 读 [enc_len(2) + tag(16)]
    uint8_t enc_len_buf[2 + ss::SsAeadCipher::kTagSize];
    if (!co_await ReadFull(enc_len_buf, sizeof(enc_len_buf))) co_return false;

    uint8_t len_plain[2];
    auto nonce = ss::MakeNonce(read_nonce_);
    if (!read_cipher_->Decrypt(nonce.data(), enc_len_buf, sizeof(enc_len_buf), len_plain)) {
        co_return false;
    }
    ++read_nonce_;

    const uint16_t payload_len =
        static_cast<uint16_t>((len_plain[0] << 8) | len_plain[1]);

    if (payload_len == 0 || payload_len > ss::kMaxChunkPayload) co_return false;

    // 读 [enc_payload(payload_len) + tag(16)]
    if (!co_await ReadFull(read_chunk_buf_.data(),
                           payload_len + ss::SsAeadCipher::kTagSize)) co_return false;

    if (read_buf_offset_ >= read_buf_.size()) {
        read_buf_.clear();
        read_buf_offset_ = 0;
    }
    const size_t old_size = read_buf_.size();
    read_buf_.resize(old_size + payload_len);

    auto nonce2 = ss::MakeNonce(read_nonce_);
    if (!read_cipher_->Decrypt(nonce2.data(), read_chunk_buf_.data(),
                               payload_len + ss::SsAeadCipher::kTagSize,
                               read_buf_.data() + old_size)) {
        read_buf_.resize(old_size);
        co_return false;
    }
    ++read_nonce_;

    co_return true;
}

cobalt::task<MultiBuffer> SsClientAsyncStream::ReadMultiBuffer() {
    if (read_buf_offset_ < read_buf_.size()) {
        co_return co_await AsyncStream::ReadMultiBuffer();
    }

    if (!co_await EnsureReadCipherInitialized()) {
        co_return MultiBuffer{};
    }

    uint8_t enc_len_buf[2 + ss::SsAeadCipher::kTagSize];
    if (!co_await ReadFull(enc_len_buf, sizeof(enc_len_buf))) {
        co_return MultiBuffer{};
    }

    uint8_t len_plain[2];
    auto nonce = ss::MakeNonce(read_nonce_);
    if (!read_cipher_->Decrypt(nonce.data(), enc_len_buf, sizeof(enc_len_buf), len_plain)) {
        co_return MultiBuffer{};
    }
    ++read_nonce_;

    const uint16_t payload_len =
        static_cast<uint16_t>((len_plain[0] << 8) | len_plain[1]);
    if (payload_len == 0 || payload_len > ss::kMaxChunkPayload) {
        co_return MultiBuffer{};
    }

    const size_t enc_payload_len = payload_len + ss::SsAeadCipher::kTagSize;
    if (!co_await ReadFull(read_chunk_buf_.data(), enc_payload_len)) {
        co_return MultiBuffer{};
    }

    ss::SsAeadStreamDecryptor decryptor(*read_cipher_);
    auto nonce2 = ss::MakeNonce(read_nonce_);
    if (!decryptor.Init(nonce2.data())) {
        co_return MultiBuffer{};
    }

    MultiBuffer out_mb;
    MultiBufferGuard guard{out_mb};
    out_mb.reserve((payload_len + Buffer::kSize - 1) / Buffer::kSize);

    size_t remaining = payload_len;
    size_t offset = 0;
    while (remaining > 0) {
        Buffer* out = Buffer::New();
        if (!out) {
            co_return MultiBuffer{};
        }

        const size_t to_process = std::min(remaining, static_cast<size_t>(out->Available()));
        try {
            int produced = 0;
            if (!decryptor.Update(read_chunk_buf_.data() + offset, to_process,
                                  out->Tail().data(), &produced)) {
                Buffer::Free(out);
                co_return MultiBuffer{};
            }
            if (produced < 0 || static_cast<size_t>(produced) != to_process) {
                Buffer::Free(out);
                co_return MultiBuffer{};
            }

            out->Produce(static_cast<uint32_t>(produced));
            out_mb.push_back(out);
        } catch (...) {
            Buffer::Free(out);
            throw;
        }

        offset += to_process;
        remaining -= to_process;
    }

    if (!decryptor.Final(read_chunk_buf_.data() + payload_len)) {
        co_return MultiBuffer{};
    }

    ++read_nonce_;

    MultiBuffer result = std::move(out_mb);
    out_mb = MultiBuffer{};
    co_return result;
}

cobalt::task<void> SsClientAsyncStream::WriteMultiBuffer(MultiBuffer mb) {
    MultiBufferGuard guard{mb};

    if (mb.empty()) co_return;

    size_t consumed_prefix = 0;
    if (!handshake_sent_) {
        if (!co_await SendHandshake(mb, consumed_prefix)) {
            ThrowSsWriteError("Shadowsocks client send handshake failed");
        }
    }

    MultiBuffer out_mb;
    MultiBufferGuard out_guard{out_mb};
    size_t out_bytes = 0;

    auto flush_out = [this, &out_mb, &out_bytes]() -> cobalt::task<void> {
        if (out_mb.empty()) {
            co_return;
        }
        co_await inner_->WriteMultiBuffer(std::move(out_mb));
        out_mb = MultiBuffer{};
        out_bytes = 0;
    };

    size_t skip = consumed_prefix;
    for (auto* buf : mb) {
        auto bytes = buf->Bytes();
        if (bytes.empty()) continue;

        const uint8_t* data = bytes.data();
        size_t len = bytes.size();

        if (skip > 0) {
            if (skip >= len) {
                skip -= len;
                continue;
            }
            data += skip;
            len -= skip;
            skip = 0;
        }

        while (len > 0) {
            const size_t chunk_size = std::min(len, kStreamChunkPayloadSize);
            Buffer* out = Buffer::New();
            if (!out) {
                throw std::bad_alloc();
            }

            try {
                uint8_t* dst = out->Tail().data();

                const uint8_t len_plain[2] = {
                    static_cast<uint8_t>(chunk_size >> 8),
                    static_cast<uint8_t>(chunk_size & 0xFF)
                };
                auto nonce_l = ss::MakeNonce(write_nonce_);
                if (!write_cipher_->Encrypt(nonce_l.data(), len_plain, 2, dst)) {
                    ThrowSsWriteError("Shadowsocks client stream encrypt length failed");
                }
                ++write_nonce_;

                auto nonce_p = ss::MakeNonce(write_nonce_);
                if (!write_cipher_->Encrypt(nonce_p.data(), data, chunk_size,
                                            dst + kLenHeaderSize)) {
                    ThrowSsWriteError("Shadowsocks client stream encrypt payload failed");
                }
                ++write_nonce_;

                const size_t output_size =
                    kLenHeaderSize + chunk_size + ss::SsAeadCipher::kTagSize;
                out->Produce(static_cast<uint32_t>(output_size));
                out_bytes += output_size;
                out_mb.push_back(out);
            } catch (...) {
                Buffer::Free(out);
                throw;
            }

            data += chunk_size;
            len -= chunk_size;

            if (out_mb.size() >= kStreamFlushBufferCount || out_bytes >= kStreamFlushBytes) {
                co_await flush_out();
            }
        }
    }

    co_await flush_out();
}

// SendHandshake — 首次写：生成 client salt，发送 [salt][addr_chunk][data_chunk(可选)]
cobalt::task<bool> SsClientAsyncStream::SendHandshake(const MultiBuffer& mb,
                                                      size_t& consumed_prefix) {
    consumed_prefix = 0;

    if (salt_size_ > 64 || key_size_ > 64) {
        co_return false;
    }

    // 生成 client salt
    std::array<uint8_t, 64> client_salt{};
    if (RAND_bytes(client_salt.data(), static_cast<int>(salt_size_)) != 1) {
        co_return false;
    }

    // 派生写子密钥
    std::array<uint8_t, 64> write_subkey{};
    if (!ss::DeriveSubkey(master_key_.data(), key_size_,
                          client_salt.data(), salt_size_,
                          write_subkey.data())) {
        co_return false;
    }

    write_cipher_ = std::make_unique<ss::SsAeadCipher>(
        cipher_type_, write_subkey.data(), key_size_);
    write_nonce_ = 0;

    auto addr_bytes = ss::EncodeSocks5Address(target_);
    if (addr_bytes.empty() || addr_bytes.size() > ss::kMaxChunkPayload) {
        co_return false;
    }

    const size_t first_chunk_limit = ss::kMaxChunkPayload - addr_bytes.size();
    consumed_prefix = CountPrefixBytes(mb, first_chunk_limit);
    const size_t payload_size = addr_bytes.size() + consumed_prefix;

    MultiBuffer handshake_mb;
    MultiBufferGuard handshake_guard{handshake_mb};
    handshake_mb.reserve(4);

    Buffer* out = Buffer::New();
    if (!out) {
        co_return false;
    }
    handshake_mb.push_back(out);

    // [salt]
    std::memcpy(out->Tail().data(), client_salt.data(), salt_size_);
    out->Produce(static_cast<uint32_t>(salt_size_));

    // [enc_len]
    const uint8_t len_plain[2] = {
        static_cast<uint8_t>(payload_size >> 8),
        static_cast<uint8_t>(payload_size & 0xFF)
    };
    auto nonce_l = ss::MakeNonce(write_nonce_);
    if (!write_cipher_->Encrypt(nonce_l.data(), len_plain, 2, out->Tail().data())) {
        co_return false;
    }
    ++write_nonce_;
    out->Produce(static_cast<uint32_t>(kLenHeaderSize));

    // [enc_addr_payload + enc_prefix]
    SsAeadStreamEncryptor encryptor(*write_cipher_);
    auto nonce_p = ss::MakeNonce(write_nonce_);
    if (!encryptor.Init(nonce_p.data())) {
        co_return false;
    }

    if (!AppendEncryptedSpan(encryptor, out, handshake_mb,
                             addr_bytes.data(), addr_bytes.size())) {
        co_return false;
    }

    size_t remaining_prefix = consumed_prefix;
    for (auto* buf : mb) {
        if (remaining_prefix == 0) break;

        auto bytes = buf->Bytes();
        if (bytes.empty()) continue;

        const size_t take = std::min(remaining_prefix, bytes.size());
        if (!AppendEncryptedSpan(encryptor, out, handshake_mb, bytes.data(), take)) {
            co_return false;
        }
        remaining_prefix -= take;
    }

    std::array<uint8_t, ss::SsAeadCipher::kTagSize> payload_tag{};
    if (!encryptor.Final(payload_tag.data())) {
        co_return false;
    }

    if (!AppendTag(out, handshake_mb, payload_tag.data(), payload_tag.size())) {
        co_return false;
    }

    MultiBuffer send_mb = std::move(handshake_mb);
    handshake_mb = MultiBuffer{};
    co_await inner_->WriteMultiBuffer(std::move(send_mb));

    ++write_nonce_;
    handshake_sent_ = true;
    co_return true;
}

// SendHandshake — 首次写：生成 client salt，发送 [salt][addr_chunk][data_chunk(可选)]
cobalt::task<bool> SsClientAsyncStream::SendHandshake(const uint8_t* data, size_t data_len) {
    if (salt_size_ > 64 || key_size_ > 64) {
        co_return false;
    }

    // 生成 client salt
    std::array<uint8_t, 64> client_salt{};
    if (RAND_bytes(client_salt.data(), static_cast<int>(salt_size_)) != 1) {
        co_return false;
    }

    // 派生写子密钥
    std::array<uint8_t, 64> write_subkey{};
    if (!ss::DeriveSubkey(master_key_.data(), key_size_,
                          client_salt.data(), salt_size_,
                          write_subkey.data())) {
        co_return false;
    }

    write_cipher_ = std::make_unique<ss::SsAeadCipher>(
        cipher_type_, write_subkey.data(), key_size_);
    write_nonce_ = 0;

    auto addr_bytes = ss::EncodeSocks5Address(target_);
    if (addr_bytes.empty() || addr_bytes.size() > ss::kMaxChunkPayload) {
        co_return false;
    }

    const size_t first_chunk_data = std::min(data_len, ss::kMaxChunkPayload - addr_bytes.size());
    const size_t payload_size = addr_bytes.size() + first_chunk_data;

    MultiBuffer handshake_mb;
    MultiBufferGuard handshake_guard{handshake_mb};
    handshake_mb.reserve(4);

    Buffer* out = Buffer::New();
    if (!out) {
        co_return false;
    }
    handshake_mb.push_back(out);

    std::memcpy(out->Tail().data(), client_salt.data(), salt_size_);
    out->Produce(static_cast<uint32_t>(salt_size_));

    const uint8_t len_plain[2] = {
        static_cast<uint8_t>(payload_size >> 8),
        static_cast<uint8_t>(payload_size & 0xFF)
    };
    auto nonce_l = ss::MakeNonce(write_nonce_);
    if (!write_cipher_->Encrypt(nonce_l.data(), len_plain, 2, out->Tail().data())) {
        co_return false;
    }
    ++write_nonce_;
    out->Produce(static_cast<uint32_t>(kLenHeaderSize));

    SsAeadStreamEncryptor encryptor(*write_cipher_);
    auto nonce_p = ss::MakeNonce(write_nonce_);
    if (!encryptor.Init(nonce_p.data())) {
        co_return false;
    }

    if (!AppendEncryptedSpan(encryptor, out, handshake_mb,
                             addr_bytes.data(), addr_bytes.size())) {
        co_return false;
    }
    if (first_chunk_data > 0 &&
        !AppendEncryptedSpan(encryptor, out, handshake_mb, data, first_chunk_data)) {
        co_return false;
    }

    std::array<uint8_t, ss::SsAeadCipher::kTagSize> payload_tag{};
    if (!encryptor.Final(payload_tag.data())) {
        co_return false;
    }
    if (!AppendTag(out, handshake_mb, payload_tag.data(), payload_tag.size())) {
        co_return false;
    }

    MultiBuffer send_mb = std::move(handshake_mb);
    handshake_mb = MultiBuffer{};
    co_await inner_->WriteMultiBuffer(std::move(send_mb));

    ++write_nonce_;
    handshake_sent_ = true;

    // 剩余数据用常规 WriteChunk（已优化为单次写入）
    if (data_len > first_chunk_data) {
        if (!co_await WriteChunk(data + first_chunk_data, data_len - first_chunk_data)) {
            co_return false;
        }
    }
    co_return true;
}

cobalt::task<bool> SsClientAsyncStream::WriteChunk(const uint8_t* data, size_t data_len) {
    size_t offset = 0;
    while (offset < data_len) {
        const size_t chunk_size = std::min(data_len - offset, ss::kMaxChunkPayload);

        // enc_len → write_chunk_buf_[0..17]
        uint8_t len_plain[2] = {
            static_cast<uint8_t>(chunk_size >> 8),
            static_cast<uint8_t>(chunk_size & 0xFF)
        };
        auto nonce_l = ss::MakeNonce(write_nonce_);
        if (!write_cipher_->Encrypt(nonce_l.data(), len_plain, 2,
                                    write_chunk_buf_.data())) {
            co_return false;
        }
        ++write_nonce_;

        // enc_payload → write_chunk_buf_[18..]
        auto nonce_p = ss::MakeNonce(write_nonce_);
        if (!write_cipher_->Encrypt(nonce_p.data(), data + offset, chunk_size,
                                    write_chunk_buf_.data() + kLenHeaderSize)) {
            co_return false;
        }
        ++write_nonce_;

        // 单次写入 enc_len + enc_payload
        const size_t total = kLenHeaderSize + chunk_size + ss::SsAeadCipher::kTagSize;
        if (!co_await WriteFull(write_chunk_buf_.data(), total)) {
            co_return false;
        }

        offset += chunk_size;
    }
    co_return true;
}

cobalt::task<size_t> SsClientAsyncStream::AsyncRead(net::mutable_buffer buf) {
    if (read_buf_offset_ >= read_buf_.size()) {
        read_buf_.clear();
        read_buf_offset_ = 0;
        if (!co_await ReadNextChunk()) co_return 0;
    }

    const size_t available = read_buf_.size() - read_buf_offset_;
    const size_t to_copy = std::min(buf.size(), available);
    std::memcpy(buf.data(), read_buf_.data() + read_buf_offset_, to_copy);
    read_buf_offset_ += to_copy;

    if (read_buf_offset_ >= read_buf_.size()) {
        read_buf_.clear();
        read_buf_offset_ = 0;
        ReleaseIdleBuffer(read_buf_, 8 * 1024);
    }
    co_return to_copy;
}

cobalt::task<size_t> SsClientAsyncStream::AsyncWrite(net::const_buffer buf) {
    const uint8_t* data = static_cast<const uint8_t*>(buf.data());
    const size_t   len  = buf.size();

    if (!handshake_sent_) {
        if (!co_await SendHandshake(data, len)) {
            ThrowSsWriteError("Shadowsocks client send handshake failed");
        }
        co_return len;
    }

    if (!co_await WriteChunk(data, len)) {
        ThrowSsWriteError("Shadowsocks client write chunk failed");
    }
    co_return len;
}

// ============================================================================
// SsOutboundHandler
// ============================================================================

SsOutboundHandler::SsOutboundHandler(ss::SsCipherType cipher_type,
                                     size_t key_size,
                                     size_t salt_size,
                                     std::span<const uint8_t> master_key)
    : cipher_type_(cipher_type)
    , key_size_(key_size)
    , salt_size_(salt_size)
    , master_key_(master_key.begin(), master_key.end()) {
}

cobalt::task<OutboundWrapResult> SsOutboundHandler::WrapStream(
    std::unique_ptr<AsyncStream> stream,
    const SessionContext& ctx) {

    const auto& target = ctx.EffectiveTarget();

    co_return OutboundWrapResult(std::make_unique<SsClientAsyncStream>(
        std::move(stream),
        cipher_type_,
        key_size_,
        salt_size_,
        master_key_,
        target));
}

// ============================================================================
// SsOutbound
// ============================================================================

SsOutbound::SsOutbound(net::any_io_executor executor,
                       const SsOutboundConfig& config,
                       IDnsService* dns_service)
    : config_(config)
    , dns_service_(dns_service) {
    (void)executor;

    auto info = ss::ParseCipherMethod(config_.method);
    if (info) {
        cipher_info_ = *info;
    } else {
        LOG_WARN("[SsOutbound] Unknown cipher '{}', fallback to {}",
                 config_.method,
                 acpp::constants::protocol::kAes256Gcm);
        cipher_info_ = ss::SsCipherInfo{ss::SsCipherType::AES_256_GCM, 32, 32};
    }

    {
        auto derived_key = ss::DeriveKey(config_.password, cipher_info_.key_size);
        master_key_.assign(derived_key.begin(), derived_key.end());
    }
    stream_settings_ = config_.stream_settings;
    stream_settings_.RecomputeModes();
    if (stream_settings_.network.empty()) {
        stream_settings_.network = std::string(acpp::constants::protocol::kTcp);
        stream_settings_.security = std::string(acpp::constants::protocol::kNone);
        stream_settings_.RecomputeModes();
    }

    handler_ = std::make_unique<SsOutboundHandler>(
        cipher_info_.type,
        cipher_info_.key_size,
        cipher_info_.salt_size,
        master_key_);
}

cobalt::task<std::expected<OutboundTransportTarget, ErrorCode>>
SsOutbound::ResolveTransportTarget(SessionContext& ctx) {
    try {
        auto addrs_result = co_await ResolveOutboundAddresses(config_.address, dns_service_);
        if (!addrs_result || addrs_result->empty()) {
            co_return std::unexpected(addrs_result ? ErrorCode::DNS_RESOLVE_FAILED : addrs_result.error());
        }

        OutboundTransportTarget target;
        target.host = config_.address;
        target.port = config_.port;
        target.timeout = config_.timeout;
        target.stream_settings = &stream_settings_;
        target.candidates.reserve(addrs_result->size());
        for (const auto& addr : *addrs_result) {
            target.candidates.push_back(OutboundDialCandidate{
                .endpoint = tcp::endpoint(addr, config_.port),
                .bind_local = std::nullopt
            });
        }
        co_return target;

    } catch (const std::exception& e) {
        LOG_CONN_FAIL_CTX(ctx, "[SsOutbound] resolve target failed: {}", e.what());
        co_return std::unexpected(ErrorCode::OUTBOUND_CONNECTION_FAILED);
    }
}

std::unique_ptr<IOutbound> CreateSsOutbound(
    net::any_io_executor executor,
    const SsOutboundConfig& config,
    IDnsService* dns_service) {
    return std::make_unique<SsOutbound>(executor, config, dns_service);
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kSsRegistered = (acpp::OutboundFactory::Instance().Register(
    acpp::constants::protocol::kShadowsocks,
    [](const acpp::OutboundConfig& cfg,
       acpp::net::any_io_executor executor,
       acpp::IDnsService* dns,
       acpp::UDPSessionManager* /*udp_mgr*/,
       std::chrono::seconds timeout) -> std::unique_ptr<acpp::IOutbound> {

        const auto& s = cfg.settings;

        acpp::SsOutboundConfig ss_config;
        ss_config.tag     = cfg.tag;
        ss_config.timeout = timeout;

        // Xray 格式: servers[0] 包含 address/port/method/password
        const auto* servers_p = s.if_contains("servers");
        if (servers_p && servers_p->is_array() && !servers_p->as_array().empty()) {
            const auto& srv = servers_p->as_array()[0].as_object();
            ss_config.address  = acpp::json::GetString(srv, "address", "");
            ss_config.port     = static_cast<uint16_t>(acpp::json::GetInt(srv, "port", 8388));
            ss_config.password = acpp::json::GetString(srv, "password", "");
            ss_config.method   = acpp::json::GetString(
                srv, "method", std::string(acpp::constants::protocol::kAes256Gcm));
        } else {
            // 兼容旧扁平格式
            ss_config.address  = acpp::json::GetString(s, "Address",  "address",  "");
            ss_config.port     = static_cast<uint16_t>(acpp::json::GetInt(s, "Port", "port", 8388));
            ss_config.password = acpp::json::GetString(s, "Password", "password", "");
            ss_config.method   = acpp::json::GetString(
                s, "Method", "method", std::string(acpp::constants::protocol::kAes256Gcm));
        }

        ss_config.stream_settings = cfg.stream_settings;
        ss_config.stream_settings.RecomputeModes();

        if (ss_config.address.empty() || ss_config.password.empty()) {
            return nullptr;
        }

        return acpp::CreateSsOutbound(executor, ss_config, dns);
    }), true);
}  // namespace
