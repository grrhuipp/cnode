#pragma once

#include "vless_buffered_reader.hpp"
#include "vless_encryption.hpp"
#include "vless_encryption_handshake.hpp"
#include "vless_encryption_io.hpp"
#include "vless_encryption_record.hpp"
#include "vless_encryption_xor.hpp"

#include "common/allocator.hpp"
#include "common/asio_types.hpp"

#include <tl/expected.hpp>
#include <openssl/mem.h>
#include <openssl/siphash.h>

#include <array>
#include <chrono>
#include <optional>
#include <memory>
#include <string_view>
#include <utility>

namespace vless {

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
    VlessEncryptionClientTicketCache* ticket_cache = nullptr);

[[nodiscard]] net::awaitable<VlessEncryptionHandshakeResult>
RunVlessEncryptionServerHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    std::shared_ptr<const VlessEncryptionConfig> config,
    std::string_view inbound_tag);

}  // namespace vless
