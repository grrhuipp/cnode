#include "vless_encryption_runtime.hpp"
#include "vless_ticket_service.hpp"

#include "common/allocator.hpp"
#include "common/container_util.hpp"

#include <blake3.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>

namespace vless {
namespace {

static_assert(kVlessEncryptionServerRandomSize == kVlessEncryptionCtrIvSize,
              "the 0-RTT server random keys the deferred read side and its header XOR");

constexpr VlessEncryptionAeadCipher kPreferredCipher =
    VlessEncryptionAeadCipher::Aes256Gcm;

[[nodiscard]] std::optional<VlessEncryptionAead> CreateNfsAead(
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    const VlessEncryptionNfsKey& nfs_key,
    VlessEncryptionAeadCipher cipher) noexcept {
    return VlessEncryptionAead::Create(iv, nfs_key.bytes, cipher);
}

[[nodiscard]] std::optional<
    std::array<uint8_t, kVlessEncryptionTicketSize>>
OpenEncryptedTicketAfterLength(
    VlessEncryptionAead& nfs_aead,
    std::span<const uint8_t, kVlessEncryptionEncryptedTicketSize>
        encrypted_ticket) noexcept {
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
    const auto opened = nfs_aead.Open(encrypted_ticket, {}, ticket);
    if (!opened || *opened != ticket.size()) {
        return std::nullopt;
    }
    return ticket;
}

[[nodiscard]] std::optional<size_t> OpenEncryptedPaddingLength(
    VlessEncryptionAead& aead,
    std::span<const uint8_t, kVlessEncryptionEncryptedLengthSize>
        encrypted_length) noexcept {
    std::array<uint8_t, kVlessEncryptionLengthSize> plain{};
    auto opened = aead.Open(encrypted_length, {}, plain);
    if (!opened || *opened != plain.size()) {
        return std::nullopt;
    }
    return DecodeVlessEncryptionLength(plain);
}

[[nodiscard]] std::optional<
    std::array<uint8_t, kVlessEncryptionClientPfsPublicSize>>
OpenEncryptedClientPfsPublic(
    VlessEncryptionAead& aead,
    std::span<const uint8_t, kVlessEncryptionEncryptedClientPfsPublicSize>
        encrypted_client_public) noexcept {
    std::array<uint8_t, kVlessEncryptionClientPfsPublicSize> client_public{};
    const auto opened = aead.Open(encrypted_client_public, {}, client_public);
    if (!opened || *opened != client_public.size()) {
        return std::nullopt;
    }
    return client_public;
}

net::awaitable<tl::expected<void, VlessEncryptionHandshakeFailure>> ReadAndOpenPadding(VlessBufferedReader& reader,
                                        VlessEncryptionAead& aead) {
    std::array<uint8_t, kVlessEncryptionEncryptedLengthSize>
        encrypted_length{};
    if (!co_await reader.ReadExact(
            encrypted_length.data(),
            encrypted_length.size())) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Truncated);
    }

    // The length is authenticated and capped below 64 KiB before allocation.
    const auto encrypted_body_length =
        OpenEncryptedPaddingLength(aead, encrypted_length);
    if (!encrypted_body_length ||
        *encrypted_body_length < kVlessEncryptionTagSize ||
        *encrypted_body_length >
            kVlessEncryptionMaxPaddingLength -
                kVlessEncryptionEncryptedLengthSize) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    memory::ByteVector padding(*encrypted_body_length);
    if (!co_await reader.ReadExact(padding.data(), padding.size())) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Truncated);
    }
    const size_t plain_size = padding.size() - kVlessEncryptionTagSize;
    const auto opened = aead.Open(
        padding, {}, std::span<uint8_t>(padding).first(plain_size));
    if (!opened || *opened != plain_size) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }
    co_return tl::expected<void, VlessEncryptionHandshakeFailure>{};
}

[[nodiscard]] std::optional<VlessEncryptionHeaderXor> MakeHeaderXor(
    const VlessEncryptionConfig& config,
    const VlessEncryptionUnitedKey& united_key,
    std::span<const uint8_t, kVlessEncryptionIvSize> iv) noexcept {
    if (config.mode != VlessEncryptionMode::Random) {
        return std::nullopt;
    }
    return VlessEncryptionHeaderXor::Create(united_key.bytes, iv);
}

// Random mode requires every installed header XOR to exist.
[[nodiscard]] bool HeaderXorComplete(const VlessEncryptionConfig& config,
                                     const VlessEncryptionRuntime& runtime) noexcept {
    if (config.mode != VlessEncryptionMode::Random) {
        return true;
    }
    return runtime.write_xor &&
           (runtime.read_xor ||
            std::holds_alternative<VlessEncryptionDeferredRead>(runtime.read_keys));
}

[[nodiscard]] VlessEncryptionHandshakeResult BuildClientRuntime(
    const VlessEncryptionConfig& config,
    const VlessEncryptionClientPfsHello& client_pfs,
    VlessEncryptionClientPfsOpenResult server_open,
    VlessEncryptionAeadCipher cipher,
    std::span<const uint8_t, kVlessEncryptionIvSize> client_iv) noexcept {
    auto write_aead = VlessEncryptionAead::Create(
        client_pfs.public_key,
        server_open.united_key.bytes,
        cipher);
    if (!write_aead) {
        return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    VlessEncryptionRuntime runtime;
    runtime.united_key = server_open.united_key;
    runtime.read_keys = std::move(server_open.read_aead);
    runtime.write_aead = std::move(*write_aead);
    runtime.write_xor = MakeHeaderXor(config, runtime.united_key, client_iv);
    runtime.read_xor = MakeHeaderXor(config, runtime.united_key,
                                     server_open.ticket);
    if (!HeaderXorComplete(config, runtime)) {
        return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }
    return runtime;
}

[[nodiscard]] VlessEncryptionHandshakeResult BuildServerRuntime(
    const VlessEncryptionConfig& config,
    std::span<const uint8_t, kVlessEncryptionClientPfsPublicSize>
        client_public_key,
    VlessEncryptionServerPfsResponse response,
    VlessEncryptionAeadCipher cipher,
    std::span<const uint8_t, kVlessEncryptionIvSize> client_iv) noexcept {
    auto read_aead = VlessEncryptionAead::Create(
        client_public_key,
        response.united_key.bytes,
        cipher);
    if (!read_aead) {
        return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    VlessEncryptionRuntime runtime;
    runtime.united_key = response.united_key;
    runtime.read_keys = std::move(*read_aead);
    runtime.write_aead = std::move(response.write_aead);
    runtime.read_xor = MakeHeaderXor(config, runtime.united_key, client_iv);
    runtime.write_xor = MakeHeaderXor(config, runtime.united_key,
                                      response.ticket);
    if (response.ticket_seconds != 0) {
        runtime.issued_ticket = VlessEncryptionIssuedTicket{
            response.ticket, response.pfs_key, response.ticket_seconds,
            std::chrono::steady_clock::now()};
    }
    if (!HeaderXorComplete(config, runtime)) {
        return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }
    return runtime;
}

[[nodiscard]] VlessEncryptionHandshakeResult BuildClientZeroRttRuntime(
    const VlessEncryptionConfig& config,
    const VlessEncryptionClientZeroRttRequest& request,
    std::span<const uint8_t, kVlessEncryptionIvSize> client_iv,
    VlessEncryptionAeadCipher cipher,
    VlessEncryptionClientTicketCache* ticket_cache) noexcept {
    auto write_aead = VlessEncryptionAead::Create(
        request.EncryptedTicket(),
        request.united_key.bytes,
        cipher);
    if (!write_aead) {
        return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    VlessEncryptionRuntime runtime;
    runtime.united_key = request.united_key;
    runtime.read_keys = VlessEncryptionDeferredRead{
        .cipher = cipher,
        .header_xor = config.mode == VlessEncryptionMode::Random,
        .ticket_cache = ticket_cache,
    };
    runtime.write_aead = std::move(*write_aead);
    runtime.write_xor = MakeHeaderXor(config, runtime.united_key, client_iv);
    if (!HeaderXorComplete(config, runtime)) {
        return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }
    return runtime;
}

[[nodiscard]] VlessEncryptionHandshakeResult BuildServerZeroRttRuntime(
    const VlessEncryptionConfig& config,
    const VlessEncryptionServerZeroRttAccept& accept,
    std::span<const uint8_t, kVlessEncryptionIvSize> client_iv,
    std::span<const uint8_t, kVlessEncryptionEncryptedTicketSize>
        encrypted_ticket,
    VlessEncryptionAeadCipher cipher) noexcept {
    auto read_aead = VlessEncryptionAead::Create(
        encrypted_ticket,
        accept.united_key.bytes,
        cipher);
    auto write_aead = VlessEncryptionAead::Create(
        accept.server_random,
        accept.united_key.bytes,
        cipher);
    if (!read_aead || !write_aead) {
        return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    VlessEncryptionRuntime runtime;
    runtime.united_key = accept.united_key;
    runtime.read_keys = std::move(*read_aead);
    runtime.write_aead = std::move(*write_aead);
    runtime.read_xor = MakeHeaderXor(config, runtime.united_key, client_iv);
    runtime.write_xor = MakeHeaderXor(config, runtime.united_key,
                                      accept.server_random);
    if (!HeaderXorComplete(config, runtime)) {
        return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }
    return runtime;
}

[[nodiscard]] std::array<uint8_t, 32> DigestNfsKey(
    const VlessEncryptionNfsKey& nfs_key) noexcept {
    std::array<uint8_t, 32> out{};
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, nfs_key.bytes.data(), nfs_key.bytes.size());
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    OPENSSL_cleanse(&hasher, sizeof(hasher));
    return out;
}

}  // namespace

bool VlessEncryptionClientTicketCache::Valid(
    std::chrono::steady_clock::time_point now) const noexcept {
    return expires_at > now;
}

void VlessEncryptionClientTicketCache::Store(
    const VlessEncryptionClientPfsOpenResult& open,
    std::chrono::steady_clock::time_point now) noexcept {
    if (open.ticket_seconds == 0) {
        Clear();
        return;
    }
    pfs_key = open.pfs_key;
    ticket = open.ticket;
    expires_at = now + std::chrono::seconds(open.ticket_seconds);
}

VlessEncryptionServerTicketStore::VlessEncryptionServerTicketStore()
    : sessions_(0, [] {
          KeyedHash hash;
          if (RAND_bytes(reinterpret_cast<uint8_t*>(hash.key.data()),
                         sizeof(hash.key)) != 1) {
              std::abort();
          }
          return hash;
      }()) {}

void VlessEncryptionServerTicketStore::Erase(SessionMap::iterator it) noexcept {
    seen_nfs_keys_ -= it->second.seen_nfs_keys.size();
    sessions_.erase(it);
}

void VlessEncryptionServerTicketStore::EraseOldest() {
    const auto& [ticket, expires_at] = order_.front();
    auto it = sessions_.find(ticket);
    if (it != sessions_.end() && it->second.expires_at == expires_at) {
        Erase(it);
    }
    order_.pop_front();
}

void VlessEncryptionServerTicketStore::Prune(
    std::chrono::steady_clock::time_point now) {
    while (!order_.empty()) {
        const auto& [ticket, expires_at] = order_.front();
        auto it = sessions_.find(ticket);
        if (it != sessions_.end() && it->second.expires_at == expires_at &&
            expires_at > now) {
            break;
        }
        EraseOldest();
    }
    MaybeShrinkHashContainer(sessions_);
    order_.shrink_to_fit();
}

std::optional<VlessEncryptionServerTicketStore::ResumedSession>
VlessEncryptionServerTicketStore::Lookup(
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    const VlessEncryptionNfsKey& nfs_key,
    std::chrono::steady_clock::time_point now) {
    Prune(now);
    while (seen_nfs_keys_ >= kMaxSeenNfsKeys && !order_.empty()) {
        EraseOldest();
    }
    TicketArray ticket_array{};
    std::copy(ticket.begin(), ticket.end(), ticket_array.begin());
    auto it = sessions_.find(ticket_array);
    if (it == sessions_.end() || it->second.expires_at <= now ||
        !it->second.identity ||
        it->second.seen_nfs_keys.size() >= kMaxSeenNfsKeysPerSession) {
        return std::nullopt;
    }

    if (!it->second.seen_nfs_keys.insert(DigestNfsKey(nfs_key)).second) {
        return std::nullopt;
    }
    ++seen_nfs_keys_;
    return ResumedSession{it->second.pfs_key, *it->second.identity};
}

bool VlessEncryptionServerTicketStore::BindIdentity(
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    const std::array<uint8_t, 16>& identity,
    std::chrono::steady_clock::time_point now) {
    TicketArray key{};
    std::copy(ticket.begin(), ticket.end(), key.begin());
    auto it = sessions_.find(key);
    if (it == sessions_.end() || it->second.expires_at <= now) {
        return false;
    }
    if (it->second.identity) {
        return CRYPTO_memcmp(it->second.identity->data(), identity.data(), identity.size()) == 0;
    }
    it->second.identity = identity;
    return true;
}

void VlessEncryptionServerTicketStore::Erase(
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket) noexcept {
    TicketArray ticket_array{};
    std::copy(ticket.begin(), ticket.end(), ticket_array.begin());
    if (auto it = sessions_.find(ticket_array); it != sessions_.end()) {
        Erase(it);
    }
}

void VlessEncryptionServerTicketStore::Store(
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    const VlessEncryptionPfsKey& pfs_key,
    uint16_t seconds,
    std::chrono::steady_clock::time_point now) {
    if (seconds == 0) {
        return;
    }
    Prune(now);
    TicketArray ticket_array{};
    std::copy(ticket.begin(), ticket.end(), ticket_array.begin());
    if (auto existing = sessions_.find(ticket_array);
        existing != sessions_.end()) {
        // A duplicate ticket must never erase its replay history or change its
        // identity/PFS key. A random collision therefore fails closed.
        return;
    }
    while (sessions_.size() >= kMaxSessions && !order_.empty()) {
        EraseOldest();
    }
    const auto expires_at = now + std::chrono::seconds(seconds);
    auto [inserted_it, inserted] = sessions_.try_emplace(
        ticket_array,
        Session{
            .pfs_key = pfs_key,
            .expires_at = expires_at,
            .identity = std::nullopt,
            .seen_nfs_keys = decltype(Session::seen_nfs_keys)(
                0, sessions_.hash_function(), sessions_.key_eq()),
        });
    try {
        order_.emplace_back(ticket_array, expires_at);
    } catch (...) {
        if (inserted) {
            sessions_.erase(inserted_it);
        }
        throw;
    }
}

net::awaitable<VlessEncryptionHandshakeResult>
RunVlessEncryptionClientHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config,
    VlessEncryptionClientTicketCache* ticket_cache) {
    auto nfs = BuildVlessEncryptionClientNfsHello(config);
    if (!nfs) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    const auto cipher = kPreferredCipher;
    auto nfs_aead = CreateNfsAead(nfs->iv, nfs->nfs_key, cipher);
    if (!nfs_aead) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    const auto now = std::chrono::steady_clock::now();
    if (config.zero_rtt && ticket_cache && ticket_cache->Valid(now)) {
        auto zero = BuildVlessEncryptionClientZeroRttRequest(
            nfs->iv,
            nfs->nfs_key,
            ticket_cache->pfs_key,
            ticket_cache->ticket,
            cipher);
        if (zero) {
            try {
                co_await WriteVlessBytes(raw_writer, nfs->bytes);
                memory::ByteVector{}.swap(nfs->bytes);
                co_await WriteVlessBytes(raw_writer, zero->bytes);
            } catch (...) {
                ticket_cache->Clear();
                throw;
            }
            auto runtime = BuildClientZeroRttRuntime(
                config, *zero, nfs->iv, cipher, ticket_cache);
            if (!runtime) {
                ticket_cache->Clear();
            }
            co_return runtime;
        }
        ticket_cache->Clear();
    }

    auto pfs = BuildVlessEncryptionClientPfsHello(*nfs_aead);
    if (!pfs) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }
    auto padding = BuildVlessEncryptionPadding(config, *nfs_aead);
    if (!padding) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    co_await WriteVlessBytes(raw_writer, nfs->bytes);
    memory::ByteVector{}.swap(nfs->bytes);
    co_await WriteVlessBytes(raw_writer, pfs->encrypted);
    memory::ByteVector{}.swap(pfs->encrypted);
    co_await WriteVlessBytes(raw_writer, *padding);
    memory::ByteVector{}.swap(*padding);
    padding.reset();

    memory::ByteVector encrypted_server_public(
        kVlessEncryptionEncryptedServerPfsPublicSize);
    if (!co_await raw_reader.ReadExact(
            encrypted_server_public.data(),
            encrypted_server_public.size())) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Truncated);
    }
    std::array<uint8_t, kVlessEncryptionEncryptedTicketSize>
        encrypted_ticket{};
    if (!co_await raw_reader.ReadExact(
            encrypted_ticket.data(),
            encrypted_ticket.size())) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Truncated);
    }

    auto server_open = OpenVlessEncryptionServerPfsResponse(
        *pfs,
        nfs->iv,
        nfs->nfs_key,
        std::span<const uint8_t, kVlessEncryptionEncryptedServerPfsPublicSize>(
            encrypted_server_public.data(),
            kVlessEncryptionEncryptedServerPfsPublicSize),
        encrypted_ticket,
        cipher);
    memory::ByteVector{}.swap(encrypted_server_public);
    if (!server_open) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    if (auto padding_result = co_await ReadAndOpenPadding(raw_reader, server_open->read_aead);
        !padding_result) {
        co_return tl::unexpected(padding_result.error());
    }

    if (ticket_cache) {
        ticket_cache->Store(*server_open, std::chrono::steady_clock::now());
    }

    co_return BuildClientRuntime(
        config,
        *pfs,
        std::move(*server_open),
        cipher,
        nfs->iv);
}

net::awaitable<VlessEncryptionHandshakeResult>
RunVlessEncryptionServerHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    std::shared_ptr<const VlessEncryptionConfig> namespace_config,
    std::string_view inbound_tag) {
    if (!namespace_config) co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    const auto& config = *namespace_config;
    const auto relays_len = VlessEncryptionRelaysLength(config);
    if (!relays_len) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    memory::ByteVector iv_and_relays(kVlessEncryptionIvSize + *relays_len);
    size_t progress = 0;
    if (!co_await raw_reader.ReadExact(
            iv_and_relays.data(),
            iv_and_relays.size(), true, &progress)) {
        co_return tl::unexpected(progress == 0
            ? VlessEncryptionHandshakeFailure::Closed
            : VlessEncryptionHandshakeFailure::Truncated);
    }
    auto nfs = OpenVlessEncryptionClientNfsHello(config, iv_and_relays);
    memory::ByteVector{}.swap(iv_and_relays);
    if (!nfs) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    std::array<uint8_t, kVlessEncryptionEncryptedLengthSize>
        encrypted_length{};
    if (!co_await raw_reader.ReadExact(
            encrypted_length.data(),
            encrypted_length.size())) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Truncated);
    }

    auto cipher = kPreferredCipher;
    auto nfs_aead = CreateNfsAead(nfs->iv, nfs->nfs_key, cipher);
    auto client_pfs_length = nfs_aead
        ? OpenEncryptedPaddingLength(*nfs_aead, encrypted_length)
        : std::nullopt;
    if (!client_pfs_length) {
        cipher = VlessEncryptionAeadCipher::Chacha20Poly1305;
        nfs_aead = CreateNfsAead(nfs->iv, nfs->nfs_key, cipher);
        client_pfs_length = nfs_aead
            ? OpenEncryptedPaddingLength(*nfs_aead, encrypted_length)
            : std::nullopt;
    }
    if (!nfs_aead || !client_pfs_length ||
        (*client_pfs_length != kVlessEncryptionEncryptedClientPfsPublicSize &&
         *client_pfs_length != kVlessEncryptionEncryptedTicketSize)) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    if (*client_pfs_length == kVlessEncryptionEncryptedTicketSize) {
        std::array<uint8_t, kVlessEncryptionEncryptedTicketSize>
            encrypted_ticket{};
        if (!co_await raw_reader.ReadExact(
                encrypted_ticket.data(),
                encrypted_ticket.size())) {
            co_return tl::unexpected(VlessEncryptionHandshakeFailure::Truncated);
        }
        auto ticket = OpenEncryptedTicketAfterLength(
            *nfs_aead,
            encrypted_ticket);
        if (!ticket ||
            (config.seconds_from == 0 && config.seconds_to == 0)) {
            co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
        }

        auto pfs_key = co_await LookupVlessTicket(
            namespace_config, inbound_tag, *ticket, nfs->nfs_key);
        if (!pfs_key) {
            co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
        }
        const auto identity = pfs_key->identity;
        auto accept = AcceptVlessEncryptionClientZeroRtt(nfs->nfs_key, pfs_key->pfs_key);
        pfs_key.reset();  // The returned PFS copy is cleansed before any socket write.
        if (!accept) {
            co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
        }
        auto runtime = BuildServerZeroRttRuntime(
            config,
            *accept,
            nfs->iv,
            encrypted_ticket,
            cipher);
        if (!runtime) {
            co_return tl::unexpected(runtime.error());
        }
        runtime->resumed_identity = identity;
        co_await WriteVlessBytes(raw_writer, accept->server_random);
        co_return runtime;
    }

    memory::ByteVector encrypted_client_public(
        kVlessEncryptionEncryptedClientPfsPublicSize);
    if (!co_await raw_reader.ReadExact(
            encrypted_client_public.data(),
            encrypted_client_public.size())) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Truncated);
    }

    auto client_public = OpenEncryptedClientPfsPublic(
        *nfs_aead,
        std::span<const uint8_t, kVlessEncryptionEncryptedClientPfsPublicSize>(
            encrypted_client_public.data(),
            kVlessEncryptionEncryptedClientPfsPublicSize));
    memory::ByteVector{}.swap(encrypted_client_public);
    if (!client_public) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    auto response = BuildVlessEncryptionServerPfsResponse(
        config,
        nfs->iv,
        nfs->nfs_key,
        *client_public,
        cipher);
    if (!response) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }
    auto padding = BuildVlessEncryptionPadding(
        config,
        response->write_aead);
    if (!padding) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    co_await WriteVlessBytes(raw_writer, response->encrypted_public_key);
    memory::ByteVector{}.swap(response->encrypted_public_key);
    co_await WriteVlessBytes(raw_writer, response->encrypted_ticket);
    co_await WriteVlessBytes(raw_writer, *padding);
    memory::ByteVector{}.swap(*padding);
    padding.reset();

    if (auto padding_result = co_await ReadAndOpenPadding(raw_reader, *nfs_aead);
        !padding_result) {
        co_return tl::unexpected(padding_result.error());
    }


    co_return BuildServerRuntime(
        config,
        *client_public,
        std::move(*response),
        cipher,
        nfs->iv);
}

VlessEncryptedIo::VlessEncryptedIo(VlessBufferedReader& raw_reader,
                                   transport::MultiBufferWriter& raw_writer,
                                   VlessEncryptionRuntime runtime)
    : reader(raw_reader,
             std::move(runtime.read_keys),
             runtime.united_key,
             std::move(runtime.read_xor))
    , writer(raw_writer,
             std::move(runtime.write_aead),
             runtime.united_key,
             std::move(runtime.write_xor))
    , plain_reader(reader) {}

}  // namespace vless
