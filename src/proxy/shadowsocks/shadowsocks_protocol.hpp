#pragma once

#include "app/proxyman/inbound/user_store.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/buffer_util.hpp"
#include "common/byte_reader.hpp"
#include "common/unsafe.hpp"
#include "proxy/aead.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <tl/expected.hpp>
namespace ss {

// ============================================================================
// 密码类型
// ============================================================================
enum class SsCipherType : uint8_t {
    AES_128_GCM                  = 0,
    AES_256_GCM                  = 1,
    CHACHA20_POLY1305            = 2,
    AES_128_GCM_2022             = 3,
    AES_256_GCM_2022             = 4,
    CHACHA20_POLY1305_2022       = 5,
};

struct SsCipherInfo {
    SsCipherType type;
    size_t key_size;   // bytes（主密钥长度 == 子密钥长度 == salt 长度）
    size_t salt_size;  // bytes
};

// 根据方法名获取密码参数（不区分大小写），含 AEAD 与 2022-blake3 方法。
[[nodiscard]] std::optional<SsCipherInfo> ParseCipherMethod(std::string_view method);
[[nodiscard]] bool Is2022Cipher(SsCipherType type) noexcept;
[[nodiscard]] bool Is2022AesCipher(SsCipherType type) noexcept;
[[nodiscard]] SsCipherType BaseCipherType(SsCipherType type) noexcept;
// TCP 流与 UDP 包共用的 2022/legacy → BoringSSL AEAD 映射；未知类型返回 nullptr。
[[nodiscard]] const EVP_AEAD* AeadAlgorithm(SsCipherType type) noexcept;

// ============================================================================
// 密钥派生
// ============================================================================

using KeyBytes = ::proxyman::inbound::PreparedKeyBytes;

// 从密码派生主密钥（EVP_BytesToKey + MD5，Shadowsocks 标准）
[[nodiscard]] KeyBytes DeriveKey(std::string_view password, size_t key_size);
[[nodiscard]] KeyBytes Decode2022Psk(std::string_view password, size_t key_size);
[[nodiscard]] KeyBytes Build2022UserKeyFromUuid(
    std::string_view uuid,
    const SsCipherInfo& info);
[[nodiscard]] KeyBytes BuildMasterKey(std::string_view password, const SsCipherInfo& info);

[[nodiscard]] bool Derive2022Subkey(const uint8_t* key, size_t key_size,
                                    const uint8_t* salt, size_t salt_size,
                                    uint8_t* out_subkey);
[[nodiscard]] bool Derive2022IdentitySubkey(const uint8_t* key, size_t key_size,
                                            const uint8_t* salt, size_t salt_size,
                                            uint8_t* out_key);
[[nodiscard]] bool Hash2022Psk(std::span<const uint8_t> key,
                               std::span<uint8_t, 16> out_hash);

// 从主密钥 + 随机 salt 派生子密钥（HKDF-SHA1，ss-subkey）
[[nodiscard]] bool DeriveSubkey(const uint8_t* key, size_t key_size,
                                const uint8_t* salt, size_t salt_size,
                                uint8_t* out_subkey);

// 每次 Encrypt/Decrypt 后由调用方自增 nonce 计数器。
class SsAeadCipher {
public:
    // Authentication trials bind the first candidate key through ResetKey.
    SsAeadCipher(SsCipherType type, proxy::AeadDirection direction);
    SsAeadCipher(SsCipherType type, const uint8_t* key, size_t key_size,
                 proxy::AeadDirection direction);
    ~SsAeadCipher() = default;

    SsAeadCipher(const SsAeadCipher&) = delete;
    SsAeadCipher& operator=(const SsAeadCipher&) = delete;
    SsAeadCipher(SsAeadCipher&& other) noexcept = default;
    SsAeadCipher& operator=(SsAeadCipher&& other) noexcept = default;

    [[nodiscard]] bool Encrypt(const uint8_t* nonce,
                               const uint8_t* plaintext,
                               size_t plaintext_len,
                               uint8_t* output) noexcept;

    [[nodiscard]] bool Decrypt(const uint8_t* nonce,
                               const uint8_t* ciphertext,
                               size_t ciphertext_len,
                               uint8_t* output) noexcept;

    [[nodiscard]] bool ResetKey(const uint8_t* key, size_t key_size);

    static constexpr size_t kTagSize = 16;

private:
    SsCipherType type_;
    std::variant<proxy::AeadEncryptor, proxy::AeadDecryptor> context_;
};

static constexpr size_t kMaxChunkPayload = 0x3FFF;

// ============================================================================
// SS2022 (AEAD-2022) 共享原语
//
// Unix 时间戳、AES-ECB 头块等握手辅助逻辑，
// 客户端（client.cpp）与服务端（server.cpp）完全一致，集中在协议私有头里避免
// 两份逐字复制。仅服务握手语义，不对外暴露为请求链路对象。
// ============================================================================
static constexpr size_t kSs2022MaxChunkPayload = 0xFFFF;
static constexpr size_t kSs2022RequestFixedHeaderSize = 1 + 8 + 2;

inline uint64_t UnixSecondsNow() noexcept {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

inline bool TimestampFresh(uint64_t remote, uint64_t now) noexcept {
    constexpr uint64_t kMaxSkew = 30;
    return remote <= now + kMaxSkew && remote + kMaxSkew >= now;
}

template<size_t Size>
    requires (Size == 16 || Size == 32)
inline bool AesBlocksCrypt(std::span<const uint8_t> key,
                           std::span<const uint8_t, Size> input,
                           std::span<uint8_t, Size> output,
                           bool encrypt) {
    if (key.size() != 16 && key.size() != 32) return false;
    // BoringSSL 保证单块可重叠；双块只能原地或不重叠，防止覆盖尚未读取的块。
    if constexpr (Size == 32) {
        const auto source = reinterpret_cast<uintptr_t>(input.data());
        const auto destination = reinterpret_cast<uintptr_t>(output.data());
        if (source != destination &&
            (source < destination ? destination - source : source - destination) < Size)
            return false;
    }

    // 同一同步操作内的同密钥头块只展开一次；密钥表用毕擦除，不进入连接或用户快照。
    // BoringSSL 保留软硬件分派。
    AES_KEY schedule;
    const auto bits = static_cast<unsigned>(key.size() * 8);
    const int status = encrypt
        ? AES_set_encrypt_key(key.data(), bits, &schedule)
        : AES_set_decrypt_key(key.data(), bits, &schedule);
    if (status == 0) {
        for (size_t offset = 0; offset < Size; offset += AES_BLOCK_SIZE) {
            if (encrypt) AES_encrypt(input.data() + offset, output.data() + offset, &schedule);
            else AES_decrypt(input.data() + offset, output.data() + offset, &schedule);
        }
    }
    OPENSSL_cleanse(&schedule, sizeof(schedule));
    return status == 0;
}

namespace detail {

inline constexpr size_t kStreamChunkPayloadSize =
    buf::Buffer::kSize - (2 + SsAeadCipher::kTagSize) - SsAeadCipher::kTagSize;

[[noreturn]] inline void ThrowSsWriteError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

// Returns false on EOF before len bytes arrived.
inline net::awaitable<bool> ReadFull(AsyncStream& stream, uint8_t* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        const size_t r = co_await stream.AsyncRead(net::buffer(buf + got, len - got));
        if (r == 0) {
            co_return false;
        }
        got += r;
    }
    co_return true;
}

inline std::array<uint8_t, 12> MakeNonce(uint64_t counter) noexcept {
    std::array<uint8_t, 12> nonce{};
    for (size_t i = 0; i < 8; ++i)
        nonce[i] = static_cast<uint8_t>(counter >> (8 * i));
    return nonce;
}

inline void EncryptToMultiBuffer(SsAeadCipher& cipher,
                                 uint64_t& nonce,
                                 std::span<const uint8_t> bytes,
                                 buf::MultiBuffer& out_mb,
                                 size_t* skip_first_bytes) {
    static constexpr size_t kLenHeaderSize = 2 + SsAeadCipher::kTagSize;

    const uint8_t* data = bytes.data();
    size_t remaining = bytes.size();
    if (skip_first_bytes && *skip_first_bytes > 0) {
        const size_t skip = std::min(*skip_first_bytes, remaining);
        data += skip;
        remaining -= skip;
        *skip_first_bytes -= skip;
        if (remaining == 0) {
            return;
        }
    }

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
        const auto nonce_l = MakeNonce(nonce);
        if (!cipher.Encrypt(nonce_l.data(), len_plain, 2, dst)) {
            throw IoSystemError(
                io_error::connection_reset,
                "Shadowsocks stream encrypt length failed");
        }
        ++nonce;

        const auto nonce_p = MakeNonce(nonce);
        if (!cipher.Encrypt(
                nonce_p.data(), data, chunk_size,
                dst + kLenHeaderSize)) {
            throw IoSystemError(
                io_error::connection_reset,
                "Shadowsocks stream encrypt payload failed");
        }
        ++nonce;

        const size_t output_size =
            kLenHeaderSize +
            chunk_size +
            SsAeadCipher::kTagSize;
        out->Produce(static_cast<uint32_t>(output_size));
        out_mb.push_back(std::move(out));

        data += chunk_size;
        remaining -= chunk_size;
    }
}

// BoringSSL authenticates one complete record. Reuse a single input block in
// place; fragmented records borrow contiguous storage only for this operation.
[[nodiscard]] inline bool DecryptStreamPayload(
    SsAeadCipher& cipher, std::span<const uint8_t, 12> nonce,
    buf::MultiBuffer ciphertext, buf::MultiBuffer& output) {
    const size_t wire_size = ciphertext.byte_size();
    if (wire_size < SsAeadCipher::kTagSize) return false;
    const size_t payload_len = wire_size - SsAeadCipher::kTagSize;
    if (auto block = ciphertext.TakeFrontIfLen(wire_size)) {
        auto bytes = block->Bytes();
        if (!cipher.Decrypt(nonce.data(), bytes.data(), bytes.size(), bytes.data())) return false;
        block->end -= SsAeadCipher::kTagSize;
        if (payload_len != 0) output.push_back(std::move(block));
        return true;
    }
    buf::ContiguousWriteBuffer plaintext;
    auto* bytes = plaintext.Prepare(wire_size);
    ciphertext.CopyPrefixTo({bytes, wire_size});
    ciphertext.clear();
    if (!cipher.Decrypt(nonce.data(), bytes, wire_size, bytes)) return false;
    if (payload_len != 0) plaintext.AppendTo(payload_len, output);
    return true;
}

[[nodiscard]] inline net::awaitable<tl::expected<void, ErrorCode>>
ReadAndDecryptStreamPayload(
    AsyncStream& stream,
    SsAeadCipher& cipher,
    std::span<const uint8_t, 12> nonce,
    size_t payload_len,
    buf::MultiBuffer& output) {
    buf::MultiBuffer ciphertext;
    size_t remaining = payload_len;
    while (remaining > 0) {
        buf::BufferGuard block{buf::Buffer::New()};
        if (!block) co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        const size_t count = std::min(remaining, size_t(block->Available()));
        if (!co_await ReadFull(stream, block->Tail().data(), count))
            co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
        block->Produce(static_cast<uint32_t>(count));
        ciphertext.push_back(std::move(block));
        remaining -= count;
    }
    std::array<uint8_t, SsAeadCipher::kTagSize> tag{};
    if (!co_await ReadFull(stream, tag.data(), tag.size()))
        co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
    if (!buf::AppendSpanToMultiBuffer(tag, ciphertext))
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    if (!DecryptStreamPayload(cipher, nonce, std::move(ciphertext), output))
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    co_return tl::expected<void, ErrorCode>{};
}

// Both TCP directions use this state machine. A length is authenticated and
// consumed once; partial ciphertext remains owned across cancellation. Return
// one record at a time, leaving a subsequent corrupt record for the next read
// rather than discarding its error after producing earlier plaintext.
class BodyReader final : public transport::MultiBufferReader {
public:
    BodyReader(SsAeadCipher cipher, uint64_t nonce, transport::MultiBufferReader& stream,
               size_t max_payload = kMaxChunkPayload)
        : cipher_(std::move(cipher)), nonce_(nonce), stream_(&stream),
          max_payload_(max_payload) {}

    BodyReader(const BodyReader&) = delete;
    BodyReader& operator=(const BodyReader&) = delete;
    BodyReader(BodyReader&&) noexcept = default;
    BodyReader& operator=(BodyReader&&) noexcept = default;

    transport::CancellationSource& Cancellation() noexcept override { return stream_->Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return stream_->ReadEofAction(); }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (failure_) std::rethrow_exception(failure_);
        for (;;) {
            try {
                auto record = DecodePending();
                if (record.byte_size() != 0) co_return record;
            } catch (...) {
                Fail();
            }
            ciphertext_.ReleaseIfIdle();
            auto raw = co_await stream_->ReadMultiBuffer();
            if (raw.byte_size() == 0) {
                co_await ThrowIfCancelledOnEof();
                if (length_ || ciphertext_.byte_size() != 0) {
                    try { throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED); }
                    catch (...) { Fail(); }
                }
                co_return buf::MultiBuffer{};
            }
            try { buf::AppendCoalescedStreamInput(ciphertext_, std::move(raw)); }
            catch (...) { Fail(); }
        }
    }

private:
    // Call only from a catch handler: latches and rethrows the active exception.
    [[noreturn]] void Fail() {
        ciphertext_.clear();
        failure_ = std::current_exception();
        throw;
    }

    buf::MultiBuffer DecodePending() {
        for (;;) {
            if (!length_) {
                std::array<uint8_t, 2 + SsAeadCipher::kTagSize> header{};
                if (ciphertext_.byte_size() < header.size()) return {};
                ciphertext_.CopyPrefixTo(header);
                std::array<uint8_t, 2> plain{};
                const auto nonce = MakeNonce(nonce_);
                if (!cipher_.Decrypt(nonce.data(), header.data(), header.size(), plain.data()))
                    throw transport::LinkError(ErrorCode::PROTOCOL_AUTH_FAILED);
                const size_t length = (size_t(plain[0]) << 8) | plain[1];
                if (length > max_payload_)
                    throw transport::LinkError(ErrorCode::PROTOCOL_DECODE_FAILED);
                length_ = length;
                ciphertext_.DropPrefixBytes(header.size());
                ++nonce_;
            }
            if (ciphertext_.byte_size() < *length_ + SsAeadCipher::kTagSize) return {};
            buf::MultiBuffer record;
            if (!ciphertext_.MovePrefixTo(record, *length_ + SsAeadCipher::kTagSize))
                throw std::bad_alloc();
            buf::MultiBuffer decoded;
            const auto nonce = MakeNonce(nonce_);
            if (!DecryptStreamPayload(cipher_, nonce, std::move(record), decoded))
                throw transport::LinkError(ErrorCode::PROTOCOL_AUTH_FAILED);
            length_.reset();
            ++nonce_;
            if (decoded.byte_size() != 0) return decoded;
            // An authenticated zero-length record carries no application data;
            // it is not transport EOF and cannot hide later malformed bytes.
        }
    }

    SsAeadCipher cipher_;
    uint64_t nonce_;
    transport::MultiBufferReader* stream_ = nullptr;
    size_t max_payload_;
    buf::MultiBuffer ciphertext_;
    std::optional<size_t> length_;
    std::exception_ptr failure_;
};

} // namespace detail

}  // namespace ss
