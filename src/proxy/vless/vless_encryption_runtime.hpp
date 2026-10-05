#pragma once

#include "vless_encryption.hpp"
#include "vless_encryption_handshake.hpp"
#include "vless_encryption_record.hpp"
#include "vless_encryption_xor.hpp"
#include "vless_io_util.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/runtime/channel.hpp"

#include <array>
#include <chrono>
#include <optional>
#include <vector>

namespace acpp::vless {

struct VlessEncryptionRuntime {
    memory::ByteVector united_key;
    VlessEncryptionAead read_aead;
    VlessEncryptionAead write_aead;
    std::optional<VlessEncryptionHeaderXor> read_xor;
    std::optional<VlessEncryptionHeaderXor> write_xor;
    bool read_aead_ready = true;
    size_t lazy_read_context_size = 0;
    bool lazy_read_xor_from_context = false;
    VlessEncryptionAeadCipher cipher = VlessEncryptionAeadCipher::Aes256Gcm;
};

class VlessEncryptionClientTicketCache : public memory::DataAllocated {
public:
    explicit VlessEncryptionClientTicketCache(net::any_io_executor executor)
        : channel_(std::move(executor), 4096) {}
    struct Ticket {
        memory::ByteVector pfs_key;
        std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
        std::chrono::steady_clock::time_point expires_at{};
        uint64_t generation = 0;
    };
    net::awaitable<std::optional<Ticket>> Snapshot(std::chrono::steady_clock::time_point now);
    net::awaitable<void> Store(std::array<uint8_t, kVlessEncryptionTicketSize> ticket,
        memory::ByteVector pfs_key, uint16_t seconds, std::chrono::steady_clock::time_point now);
    net::awaitable<void> Clear(uint64_t generation);
private:
    ServiceChannel channel_;
    Ticket ticket_;
};

class VlessEncryptionServerTicketStore {
public:
    explicit VlessEncryptionServerTicketStore(net::any_io_executor executor)
        : channel_(std::move(executor), 4096) {}
    [[nodiscard]] net::awaitable<std::optional<memory::ByteVector>> Lookup(
        std::array<uint8_t, kVlessEncryptionTicketSize> ticket,
        memory::ByteVector nfs_key,
        std::chrono::steady_clock::time_point now);
    net::awaitable<void> Store(std::array<uint8_t, kVlessEncryptionTicketSize> ticket,
        memory::ByteVector pfs_key, uint16_t seconds,
        std::chrono::steady_clock::time_point now);

private:
    struct Session {
        std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
        memory::ByteVector pfs_key;
        std::chrono::steady_clock::time_point expires_at{};
        std::vector<std::array<uint8_t, kVlessMlKem768SharedSecretSize>>
            seen_nfs_keys;
    };

    void Prune(std::chrono::steady_clock::time_point now);

    ServiceChannel channel_;
    std::vector<Session> sessions_;
};

[[nodiscard]] net::awaitable<std::optional<VlessEncryptionRuntime>>
RunVlessEncryptionClientHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config,
    VlessEncryptionClientTicketCache* ticket_cache = nullptr);

[[nodiscard]] net::awaitable<std::optional<VlessEncryptionRuntime>>
RunVlessEncryptionServerHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config,
    VlessEncryptionServerTicketStore* ticket_store = nullptr);

}  // namespace acpp::vless
