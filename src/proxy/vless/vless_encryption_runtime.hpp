#pragma once

#include "vless_encryption.hpp"

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"
#include "transport/link.hpp"
#include <tl/expected.hpp>
#include <openssl/mem.h>
#include <openssl/siphash.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <variant>

namespace vless {

class VlessBufferedReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return src_.ReadEofAction(); }
    [[nodiscard]] bool EnableRawRead() noexcept override { return src_.EnableRawRead(); }

    explicit VlessBufferedReader(transport::MultiBufferReader& src) noexcept
        : src_(src) {}

    net::awaitable<bool> ReadExact(uint8_t* data,
                                   size_t len,
                                   bool eof_ok_at_start = false,
                                   size_t* progress = nullptr) {
        size_t local_done = 0;
        size_t& done = progress ? *progress : local_done;
        while (done < len) {
            if (pending_.byte_size() != 0) {
                const size_t n = pending_.ConsumePrefixTo(
                    std::span<uint8_t>(data + done, len - done));
                if (pending_.empty()) {
                    pending_.ReleaseIfIdle();
                }
                done += n;
                if (n > 0) {
                    continue;
                }
            }

            buf::MultiBuffer mb = co_await src_.ReadMultiBuffer();
            const bool received = mb.byte_size() != 0;
            if (received) mb.MoveTo(pending_);
            // Retain concurrently received bytes before observing cancellation.
            if ((co_await net::this_coro::cancellation_state).cancelled() !=
                net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            if (!received) {
                co_return done == 0 && eof_ok_at_start ? false : done == len;
            }
        }
        co_return true;
    }

    net::awaitable<bool> DiscardExact(size_t len, size_t* progress = nullptr) {
        size_t local_done = 0;
        size_t& done = progress ? *progress : local_done;
        while (done < len) {
            if (pending_.byte_size() != 0) {
                const size_t n = pending_.DropPrefixBytes(len - done);
                if (pending_.empty()) {
                    pending_.ReleaseIfIdle();
                }
                done += n;
                if (n > 0) {
                    continue;
                }
            }

            buf::MultiBuffer mb = co_await src_.ReadMultiBuffer();
            const bool received = mb.byte_size() != 0;
            if (received) mb.MoveTo(pending_);
            // Retain concurrently received bytes before observing cancellation.
            if ((co_await net::this_coro::cancellation_state).cancelled() !=
                net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            if (!received) {
                co_return done == len;
            }
        }
        co_return true;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (pending_.byte_size() != 0) {
            return TakePending();
        }
        return src_.ReadMultiBuffer();
    }

private:
    net::awaitable<buf::MultiBuffer> TakePending() {
        co_return std::move(pending_);
    }

    transport::MultiBufferReader& src_;
    buf::MultiBuffer pending_;
};

inline net::awaitable<void> WriteVlessBytes(
    transport::MultiBufferWriter& writer,
    std::span<const uint8_t> data) {
    net::const_buffer buffer{data.data(), data.size()};
    co_await writer.WriteBuffers(std::span<const net::const_buffer>{&buffer, 1});
}

// 记录层只报告首个认证响应前的拒绝，不借用握手凭据。
// 宿主必须地址稳定，并比延迟读端活得更久；取消本身不构成拒绝。
struct VlessEncryptionTicketRejection {
    VlessEncryptionTicketRejection() noexcept = default;
    VlessEncryptionTicketRejection(const VlessEncryptionTicketRejection&) = delete;
    VlessEncryptionTicketRejection& operator=(const VlessEncryptionTicketRejection&) = delete;
    VlessEncryptionTicketRejection(VlessEncryptionTicketRejection&&) = delete;
    VlessEncryptionTicketRejection& operator=(VlessEncryptionTicketRejection&&) = delete;

    bool rejected = false;
};

// 0-RTT client read side: it is keyed by the server random that prefixes the
// first response bytes, which also seeds the header XOR when enabled.
struct VlessEncryptionDeferredRead {
    VlessEncryptionAeadCipher cipher = VlessEncryptionAeadCipher::Aes256Gcm;
    bool header_xor = false;
    VlessEncryptionTicketRejection* ticket_rejection = nullptr;
};
using VlessEncryptionReadKeys =
    std::variant<VlessEncryptionAead, VlessEncryptionDeferredRead>;

class VlessEncryptionReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return src_.ReadEofAction(); }

    // A deferred read side must not come with a header XOR; it derives its own.
    VlessEncryptionReader(transport::MultiBufferReader& src,
                          VlessEncryptionReadKeys keys,
                          const VlessEncryptionUnitedKey& united_key,
                          std::optional<VlessEncryptionHeaderXor>
                              header_xor) noexcept;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    [[nodiscard]] bool EnableRawRead() noexcept override;
    void RejectDeferredTicket() noexcept;

private:
    [[nodiscard]] VlessEncryptionAead& KeyDeferredRead(
        const VlessEncryptionDeferredRead& deferred);

    VlessBufferedReader src_;
    VlessEncryptionReadKeys keys_;
    VlessEncryptionUnitedKey united_key_;
    std::optional<VlessEncryptionHeaderXor> header_xor_;
    // Read progress survives a cancelled sniff continuation. Header XOR is
    // applied once, before waiting for the rest of the encrypted record.
    // `bytes_read_` tracks the server random until the read side is keyed.
    std::array<uint8_t, kVlessEncryptionCtrIvSize> server_random_{};
    std::array<uint8_t, kVlessEncryptionRecordHeaderSize> read_header_{};
    buf::ContiguousWriteBuffer read_record_;
    size_t header_read_ = 0;
    size_t bytes_read_ = 0;
    size_t encrypted_size_ = 0;
    bool raw_read_ = false;
    VlessEncryptionTicketRejection* unverified_ticket_ = nullptr;
};

class VlessEncryptionWriter final : public transport::MultiBufferWriter {
public:
    VlessEncryptionWriter(transport::MultiBufferWriter& dst,
                          VlessEncryptionAead aead,
                          const VlessEncryptionUnitedKey& united_key,
                          std::optional<VlessEncryptionHeaderXor>
                              header_xor) noexcept;
    VlessEncryptionWriter(const VlessEncryptionWriter&) = delete;
    VlessEncryptionWriter& operator=(const VlessEncryptionWriter&) = delete;
    VlessEncryptionWriter(VlessEncryptionWriter&&) = delete;
    VlessEncryptionWriter& operator=(VlessEncryptionWriter&&) = delete;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;
    bool WriteShutdownClosesLink() const noexcept override {
        return dst_.WriteShutdownClosesLink();
    }

private:
    enum class State : uint8_t { Active, Finished, Failed };

    void CheckWritable() const;
    net::awaitable<void> WritePlaintext(std::span<const uint8_t> data,
                                       bool& record_started);

    transport::MultiBufferWriter& dst_;
    VlessEncryptionAead aead_;
    VlessEncryptionUnitedKey united_key_;
    std::optional<VlessEncryptionHeaderXor> header_xor_;
    State state_ = State::Active;
};

struct VlessEncryptionIssuedTicket {
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
    VlessEncryptionPfsKey pfs_key;
    uint16_t seconds = 0;
    std::chrono::steady_clock::time_point issued_at{};
};

struct VlessEncryptionRuntime {
    VlessEncryptionUnitedKey united_key;
    VlessEncryptionReadKeys read_keys;
    VlessEncryptionAead write_aead;
    std::optional<VlessEncryptionHeaderXor> read_xor;
    std::optional<VlessEncryptionHeaderXor> write_xor;
    // Server-only authentication binding; never changes the wire ticket format.
    std::optional<VlessEncryptionIssuedTicket> issued_ticket;
    std::optional<std::array<uint8_t, 16>> resumed_identity;
};

enum class VlessEncryptionHandshakeFailure {
    Closed,
    Truncated,
    Rejected,
};

// Transport failures (including cancellation) propagate as IoSystemError; only
// a server receiving no handshake bytes can report a normal Closed result.
using VlessEncryptionHandshakeResult =
    tl::expected<VlessEncryptionRuntime, VlessEncryptionHandshakeFailure>;

// Record layer installed over the raw connection after a completed handshake.
// `plain_reader` borrows `reader` and both borrow the raw endpoints, so the
// owner is address-stable and must outlive every borrowed raw endpoint use.
struct VlessEncryptedIo : memory::ThreadAllocated {
    VlessEncryptedIo(VlessBufferedReader& raw_reader,
                     transport::MultiBufferWriter& raw_writer,
                     VlessEncryptionRuntime runtime);

    VlessEncryptedIo(const VlessEncryptedIo&) = delete;
    VlessEncryptedIo& operator=(const VlessEncryptedIo&) = delete;
    VlessEncryptedIo(VlessEncryptedIo&&) = delete;
    VlessEncryptedIo& operator=(VlessEncryptedIo&&) = delete;

    VlessEncryptionReader reader;
    VlessEncryptionWriter writer;
    VlessBufferedReader plain_reader;
};

struct VlessEncryptionClientTicketCache {
    VlessEncryptionPfsKey pfs_key;
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
    std::chrono::steady_clock::time_point expires_at{};

    [[nodiscard]] bool Valid(std::chrono::steady_clock::time_point now) const noexcept;
    void Store(const VlessEncryptionClientPfsOpenResult& open,
               std::chrono::steady_clock::time_point now) noexcept;
    void Clear() noexcept {
        pfs_key = {};
        ticket = {};
        expires_at = {};
    }
};

// Executor-local 0-RTT ticket table. Tickets are server-chosen, but lookups and
// replay keys are peer-chosen, so buckets use a per-store SipHash key and key
// equality is constant time.
class VlessEncryptionServerTicketStore {
public:
    VlessEncryptionServerTicketStore();
    struct ResumedSession {
        VlessEncryptionPfsKey pfs_key;
        std::array<uint8_t, 16> identity;
    };

    // Records `nfs_key` against the ticket and refuses a repeated one.
    [[nodiscard]] std::optional<ResumedSession> Lookup(
        std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
        const VlessEncryptionNfsKey& nfs_key,
        std::chrono::steady_clock::time_point now);

    void Store(std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
               const VlessEncryptionPfsKey& pfs_key,
               uint16_t seconds,
               std::chrono::steady_clock::time_point now);
    [[nodiscard]] bool BindIdentity(
        std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
        const std::array<uint8_t, 16>& identity,
        std::chrono::steady_clock::time_point now);
    void Erase(std::span<const uint8_t, kVlessEncryptionTicketSize> ticket) noexcept;

private:
    static constexpr size_t kMaxSessions = 1024;
    // Upper bound of replay keys held across all sessions; reaching it evicts
    // the oldest sessions, the same policy as the session bound.
    static constexpr size_t kMaxSeenNfsKeys = 65536;
    static constexpr size_t kMaxSeenNfsKeysPerSession = 256;

    using TicketArray = std::array<uint8_t, kVlessEncryptionTicketSize>;
    // Replay keys are BLAKE3 digests so no NFS secret outlives its handshake.
    using NfsKeyDigest = std::array<uint8_t, 32>;

    struct KeyedHash {
        std::array<uint64_t, 2> key{};

        template <size_t N>
        [[nodiscard]] size_t operator()(const std::array<uint8_t, N>& value) const noexcept {
            return static_cast<size_t>(SIPHASH_24(key.data(), value.data(), N));
        }
    };

    struct ConstantTimeEqual {
        template <size_t N>
        [[nodiscard]] bool operator()(const std::array<uint8_t, N>& a,
                                      const std::array<uint8_t, N>& b) const noexcept {
            return CRYPTO_memcmp(a.data(), b.data(), N) == 0;
        }
    };

    struct Session {
        VlessEncryptionPfsKey pfs_key;
        std::chrono::steady_clock::time_point expires_at{};
        std::optional<std::array<uint8_t, 16>> identity;
        memory::ThreadLocalUnorderedSet<NfsKeyDigest, KeyedHash, ConstantTimeEqual>
            seen_nfs_keys;
    };

    using SessionMap =
        memory::ThreadLocalUnorderedMap<TicketArray, Session, KeyedHash, ConstantTimeEqual>;

    void Prune(std::chrono::steady_clock::time_point now);
    void EraseOldest();
    void Erase(SessionMap::iterator it) noexcept;

    SessionMap sessions_;
    memory::ThreadLocalDeque<std::pair<TicketArray, std::chrono::steady_clock::time_point>> order_;
    size_t seen_nfs_keys_ = 0;
};

[[nodiscard]] net::awaitable<VlessEncryptionHandshakeResult>
RunVlessEncryptionClientHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config,
    VlessEncryptionClientTicketCache* ticket_cache,
    VlessEncryptionTicketRejection& ticket_rejection);

[[nodiscard]] net::awaitable<VlessEncryptionHandshakeResult>
RunVlessEncryptionServerHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    std::shared_ptr<const VlessEncryptionConfig> config,
    std::string_view inbound_tag);

// Directory entries carry only routing/lifetime metadata. PFS secrets and the
// mutable replay set are accessed exclusively on the ticket owner's domain.

[[nodiscard]] net::awaitable<bool> AuthenticateVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config,
    std::string_view inbound_tag,
    VlessEncryptionIssuedTicket ticket,
    std::array<uint8_t, 16> identity);

[[nodiscard]] net::awaitable<std::optional<VlessEncryptionServerTicketStore::ResumedSession>>
LookupVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config,
    std::string_view inbound_tag,
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket,
    VlessEncryptionNfsKey nfs_key);

}  // namespace vless
