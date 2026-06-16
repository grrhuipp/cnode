#pragma once

#include "vless_encryption.hpp"
#include "vless_encryption_handshake.hpp"
#include "vless_encryption_record.hpp"
#include "vless_encryption_xor.hpp"
#include "vless_io_util.hpp"

#include "acppnode/common/asio_types.hpp"

#include <array>
#include <chrono>
#include <optional>
#include <vector>

namespace acpp::vless {

struct VlessEncryptionRuntime {
    std::vector<uint8_t> united_key;
    VlessEncryptionAead read_aead;
    VlessEncryptionAead write_aead;
    std::optional<VlessEncryptionHeaderXor> read_xor;
    std::optional<VlessEncryptionHeaderXor> write_xor;
    bool read_aead_ready = true;
    size_t lazy_read_context_size = 0;
    bool lazy_read_xor_from_context = false;
    VlessEncryptionAeadCipher cipher = VlessEncryptionAeadCipher::Aes256Gcm;
};

struct VlessEncryptionClientTicketCache {
    std::vector<uint8_t> pfs_key;
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
    std::chrono::steady_clock::time_point expires_at{};

    [[nodiscard]] bool Valid(std::chrono::steady_clock::time_point now) const noexcept;
    void Store(const VlessEncryptionClientPfsOpenResult& open,
               std::chrono::steady_clock::time_point now);
    void Clear() noexcept;
};

class VlessEncryptionServerTicketStore {
public:
    [[nodiscard]] std::optional<std::vector<uint8_t>> Lookup(
        std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
        std::span<const uint8_t> nfs_key,
        std::chrono::steady_clock::time_point now);

    void Store(std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
               std::span<const uint8_t> pfs_key,
               uint16_t seconds,
               std::chrono::steady_clock::time_point now);

private:
    struct Session {
        std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
        std::vector<uint8_t> pfs_key;
        std::chrono::steady_clock::time_point expires_at{};
        std::vector<std::array<uint8_t, kVlessMlKem768SharedSecretSize>>
            seen_nfs_keys;
    };

    void Prune(std::chrono::steady_clock::time_point now);

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
