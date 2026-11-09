#include "vless_encryption_runtime.hpp"

#include "app/session_group_executor.hpp"
#include "common/allocator.hpp"
#include "common/buffer_util.hpp"
#include "common/container_util.hpp"
#include "common/error.hpp"
#include "infra/log.hpp"

#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <blake3.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <string>
#include <string_view>
#include <unordered_map>
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
    VlessEncryptionClientPfsOpenResult& server_open,
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
    VlessEncryptionServerPfsResponse& response,
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
    VlessEncryptionTicketRejection& ticket_rejection) noexcept {
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
        .ticket_rejection = &ticket_rejection,
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
    VlessEncryptionClientTicketCache* ticket_cache,
    VlessEncryptionTicketRejection& ticket_rejection) {
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
                config, *zero, nfs->iv, cipher, ticket_rejection);
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
    co_await WriteVlessBytes(raw_writer, *padding);
    memory::ByteVector{}.swap(*padding);
    padding.reset();

    std::array<uint8_t, kVlessEncryptionEncryptedServerPfsPublicSize>
        encrypted_server_public{};
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
        encrypted_server_public,
        encrypted_ticket,
        cipher);
    if (!server_open) {
        pfs.reset();
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }
    auto runtime = BuildClientRuntime(
        config,
        *pfs,
        *server_open,
        cipher,
        nfs->iv);
    pfs.reset();
    if (!runtime) {
        co_return tl::unexpected(runtime.error());
    }

    if (auto padding_result = co_await ReadAndOpenPadding(
            raw_reader, std::get<VlessEncryptionAead>(runtime->read_keys));
        !padding_result) {
        co_return tl::unexpected(padding_result.error());
    }

    if (ticket_cache) {
        ticket_cache->Store(*server_open, std::chrono::steady_clock::now());
    }

    co_return runtime;
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

    std::array<uint8_t, kVlessEncryptionEncryptedClientPfsPublicSize>
        encrypted_client_public{};
    if (!co_await raw_reader.ReadExact(
            encrypted_client_public.data(),
            encrypted_client_public.size())) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Truncated);
    }

    auto client_public = OpenEncryptedClientPfsPublic(
        *nfs_aead, encrypted_client_public);
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
        OPENSSL_cleanse(client_public->data(), client_public->size());
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }
    auto runtime = BuildServerRuntime(
        config,
        *client_public,
        *response,
        cipher,
        nfs->iv);
    OPENSSL_cleanse(client_public->data(), client_public->size());
    client_public.reset();
    if (!runtime) {
        co_return tl::unexpected(runtime.error());
    }
    auto padding = BuildVlessEncryptionPadding(
        config,
        runtime->write_aead);
    if (!padding) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    co_await WriteVlessBytes(raw_writer, response->encrypted_public_key);
    co_await WriteVlessBytes(raw_writer, response->encrypted_ticket);
    response.reset();
    co_await WriteVlessBytes(raw_writer, *padding);
    memory::ByteVector{}.swap(*padding);
    padding.reset();

    if (auto padding_result = co_await ReadAndOpenPadding(raw_reader, *nfs_aead);
        !padding_result) {
        co_return tl::unexpected(padding_result.error());
    }

    co_return runtime;
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

namespace {
using Clock = std::chrono::steady_clock;
using Ticket = std::array<uint8_t, kVlessEncryptionTicketSize>;
using Resumed = VlessEncryptionServerTicketStore::ResumedSession;

struct StoreKey {
    const VlessEncryptionConfig* config = nullptr;
    std::string tag;
    bool operator==(const StoreKey&) const = default;
};

struct StoreKeyView {
    const VlessEncryptionConfig* config = nullptr;
    std::string_view tag;
};

struct StoreKeyHash {
    using is_transparent = void;

    size_t operator()(const StoreKey& key) const noexcept {
        return (*this)(StoreKeyView{key.config, key.tag});
    }
    size_t operator()(const StoreKeyView& key) const noexcept {
        return std::hash<const void*>{}(key.config) ^
               std::hash<std::string_view>{}(key.tag);
    }
};

struct StoreKeyEqual {
    using is_transparent = void;

    bool operator()(const StoreKey& a, const StoreKey& b) const noexcept {
        return a == b;
    }
    bool operator()(const StoreKey& a, const StoreKeyView& b) const noexcept {
        return a.config == b.config && std::string_view(a.tag) == b.tag;
    }
    bool operator()(const StoreKeyView& a, const StoreKey& b) const noexcept {
        return a.config == b.config && a.tag == std::string_view(b.tag);
    }
};

struct StoreEntry {
    std::shared_ptr<const VlessEncryptionConfig> config;
    VlessEncryptionServerTicketStore tickets;
};

class TicketDirectoryService final : public net::execution_context::service {
public:
    inline static net::execution_context::id id;
    explicit TicketDirectoryService(net::execution_context& context) : service(context) {}

    VlessEncryptionServerTicketStore& GetOrCreate(
        std::shared_ptr<const VlessEncryptionConfig> config, std::string_view tag) {
        if (auto it = stores_.find(StoreKeyView{config.get(), tag}); it != stores_.end()) {
            return it->second.tickets;
        }
        StoreKey key{config.get(), std::string(tag)};
        auto [it, inserted] = stores_.try_emplace(std::move(key));
        if (inserted) it->second.config = std::move(config);
        return it->second.tickets;
    }

    VlessEncryptionServerTicketStore* Find(
        const VlessEncryptionConfig* config, std::string_view tag) {
        auto it = stores_.find(StoreKeyView{config, tag});
        return it == stores_.end() ? nullptr : &it->second.tickets;
    }

private:
    void shutdown() override { stores_.clear(); }
    std::unordered_map<StoreKey, StoreEntry, StoreKeyHash, StoreKeyEqual> stores_;
};

} // namespace

net::awaitable<bool> AuthenticateVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config, std::string_view tag,
    VlessEncryptionIssuedTicket ticket, std::array<uint8_t, 16> identity) {
    if (!config) co_return false;
    auto executor = co_await net::this_coro::executor;
    auto* coordinator = GroupCoordinator::ForContext(
        net::query(executor, net::execution::context));
    if (!coordinator) co_return false;
    std::string owned_tag(tag);
    co_return co_await coordinator->PostCall(
        [coordinator, config = std::move(config), tag = std::move(owned_tag),
         ticket = std::move(ticket), identity]() mutable -> bool {
            const auto now = Clock::now();
            const auto expires = ticket.issued_at + std::chrono::seconds(ticket.seconds);
            if (ticket.seconds == 0 || expires <= now) return false;
            auto& store = net::use_service<TicketDirectoryService>(
                coordinator->Services()).GetOrCreate(std::move(config), tag);
            store.Store(ticket.ticket, ticket.pfs_key, ticket.seconds, ticket.issued_at);
            return store.BindIdentity(ticket.ticket, identity, now);
        });
}

net::awaitable<std::optional<Resumed>> LookupVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config, std::string_view tag,
    Ticket ticket, VlessEncryptionNfsKey nfs) {
    if (!config) co_return std::nullopt;
    auto executor = co_await net::this_coro::executor;
    auto* coordinator = GroupCoordinator::ForContext(
        net::query(executor, net::execution::context));
    if (!coordinator) co_return std::nullopt;
    std::string owned_tag(tag);
    co_return co_await coordinator->PostCall(
        [coordinator, config = std::move(config), tag = std::move(owned_tag),
         ticket, nfs = std::move(nfs)]() -> std::optional<Resumed> {
            auto* store = net::use_service<TicketDirectoryService>(
                coordinator->Services()).Find(config.get(), tag);
            auto result = store ? store->Lookup(ticket, nfs, Clock::now()) : std::nullopt;
            LOG_NET_DEBUG("inbound '{}' ticket lookup accepted={}",
                          tag, result.has_value());
            return result;
        });
}

namespace {

[[noreturn]] void ThrowVlessEncryptionIoError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

// Replaces the AEAD after the record sealed or opened at the maximum nonce;
// `context` is that complete wire record.
[[nodiscard]] bool RekeyAead(VlessEncryptionAead& aead,
                             std::span<const uint8_t> context,
                             const VlessEncryptionUnitedKey& united_key) noexcept {
    auto next = VlessEncryptionAead::Create(
        context,
        united_key.bytes,
        aead.Cipher());
    if (!next) {
        return false;
    }
    aead = std::move(*next);
    return true;
}

[[nodiscard]] bool WillReachVlessEncryptionMaxNonce(
    const VlessEncryptionNonce& nonce) noexcept {
    auto next = nonce;
    IncreaseVlessEncryptionNonce(next);
    return IsVlessEncryptionMaxNonce(next);
}

}  // namespace

VlessEncryptionReader::VlessEncryptionReader(
    transport::MultiBufferReader& src,
    VlessEncryptionReadKeys keys,
    const VlessEncryptionUnitedKey& united_key,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept
    : src_(src)
    , keys_(std::move(keys))
    , united_key_(united_key)
    , header_xor_(std::move(header_xor)) {
    if (const auto* deferred = std::get_if<VlessEncryptionDeferredRead>(&keys_)) {
        unverified_ticket_ = deferred->ticket_rejection;
    }
}

void VlessEncryptionReader::RejectDeferredTicket() noexcept {
    if (unverified_ticket_) {
        unverified_ticket_->rejected = true;
        unverified_ticket_ = nullptr;
    }
}

VlessEncryptionAead& VlessEncryptionReader::KeyDeferredRead(
    const VlessEncryptionDeferredRead& deferred) {
    auto aead = VlessEncryptionAead::Create(
        server_random_, united_key_.bytes, deferred.cipher);
    if (!aead) {
        ThrowVlessEncryptionIoError("VLESS Encryption server random invalid");
    }
    if (deferred.header_xor) {
        header_xor_ = VlessEncryptionHeaderXor::Create(
            united_key_.bytes, server_random_);
        if (!header_xor_) {
            ThrowVlessEncryptionIoError("VLESS Encryption lazy xor failed");
        }
    }
    bytes_read_ = 0;
    return keys_.emplace<VlessEncryptionAead>(std::move(*aead));
}

bool VlessEncryptionReader::EnableRawRead() noexcept {
    if (header_read_ != 0 || bytes_read_ != 0 || encrypted_size_ != 0 ||
        !std::holds_alternative<VlessEncryptionAead>(keys_)) {
        return false;
    }
    // Xray unwraps CommonConn, not its underlying TLS transport a second time.
    // In random mode XorConn stays in place across the transition.
    raw_read_ = true;
    return true;
}

net::awaitable<buf::MultiBuffer> VlessEncryptionReader::ReadMultiBuffer() {
    if (raw_read_) {
        auto out = co_await ReadMultiBufferOrThrowOnCancel(
            src_, "VLESS Encryption read cancelled");
        if (header_xor_) {
            for (auto* buffer : out) {
                if (!header_xor_->XorInboundInPlace(buffer->Bytes())) {
                    ThrowVlessEncryptionIoError("VLESS Encryption direct header xor failed");
                }
            }
        }
        co_return out;
    }
    try {
        auto* aead = std::get_if<VlessEncryptionAead>(&keys_);
        if (!aead) {
            if (!co_await src_.ReadExact(server_random_.data(),
                                         server_random_.size(),
                                         false, &bytes_read_)) {
                ThrowVlessEncryptionIoError("VLESS Encryption server random missing");
            }
            aead = &KeyDeferredRead(std::get<VlessEncryptionDeferredRead>(keys_));
        }

        for (;;) {
            auto& header = read_header_;
            if (encrypted_size_ == 0) {
                const bool have_header = co_await src_.ReadExact(
                    header.data(), header.size(), true, &header_read_);
                if (!have_header) {
                    if (header_read_ != 0) {
                        ThrowVlessEncryptionIoError("VLESS Encryption record header truncated");
                    }
                    const auto cancellation =
                        co_await net::this_coro::cancellation_state;
                    if (cancellation.cancelled() !=
                        net::cancellation_type::none) {
                        throw IoSystemError(
                            io_error::operation_aborted,
                            "VLESS Encryption read cancelled");
                    }
                    RejectDeferredTicket();
                    read_record_.Reset();
                    co_return buf::MultiBuffer{};
                }
                if (header_xor_ && !header_xor_->XorInboundInPlace(header)) {
                    ThrowVlessEncryptionIoError("VLESS Encryption header xor failed");
                }
                const auto encrypted_len = DecodeVlessEncryptionRecordHeader(header);
                if (!encrypted_len) {
                    ThrowVlessEncryptionIoError("VLESS Encryption record header invalid");
                }
                encrypted_size_ = *encrypted_len;
            }

            // `encrypted_size_` is bounded by kVlessEncryptionMaxRecordCiphertextSize.
            if (bytes_read_ == 0 && read_record_.Empty()) {
                (void)read_record_.Prepare(encrypted_size_);
            }
            uint8_t* record_bytes = read_record_.Data();
            if (!co_await src_.ReadExact(record_bytes, encrypted_size_,
                                         false, &bytes_read_)) {
                ThrowVlessEncryptionIoError("VLESS Encryption record truncated");
            }
            auto encrypted_span = std::span<uint8_t>(record_bytes, encrypted_size_);
            if (header_xor_ && !header_xor_->XorInboundInPlace(encrypted_span)) {
                ThrowVlessEncryptionIoError("VLESS Encryption body xor state failed");
            }

            memory::ByteVector rekey_context;
            if (WillReachVlessEncryptionMaxNonce(aead->Nonce())) {
                rekey_context.resize(header.size() + encrypted_span.size());
                auto next = std::copy(header.begin(), header.end(), rekey_context.begin());
                std::copy(encrypted_span.begin(), encrypted_span.end(), next);
            }

            const auto opened = OpenVlessEncryptionRecord(
                *aead,
                header,
                encrypted_span,
                encrypted_span);
            if (!opened) {
                ThrowVlessEncryptionIoError("VLESS Encryption record decrypt failed");
            }
            unverified_ticket_ = nullptr;

            if (!rekey_context.empty() &&
                !RekeyAead(*aead, rekey_context, united_key_)) {
                ThrowVlessEncryptionIoError("VLESS Encryption read rekey failed");
            }

            header_read_ = 0;
            bytes_read_ = 0;
            encrypted_size_ = 0;
            if (*opened == 0) {
                read_record_.Reset();
                continue;
            }
            buf::MultiBuffer out;
            if (!read_record_.TryAppendTo(*opened, out)) {
                throw IoSystemError(io_error::fault,
                                    "VLESS Encryption buffer allocation failed");
            }
            co_return out;
        }
    } catch (const IoSystemError& error) {
        if (error.code() != io_error::operation_aborted) {
            RejectDeferredTicket();
            header_read_ = 0;
            bytes_read_ = 0;
            encrypted_size_ = 0;
            read_record_.Reset();
        }
        throw;
    } catch (...) {
        RejectDeferredTicket();
        header_read_ = 0;
        bytes_read_ = 0;
        encrypted_size_ = 0;
        read_record_.Reset();
        throw;
    }
}

VlessEncryptionWriter::VlessEncryptionWriter(
    transport::MultiBufferWriter& dst,
    VlessEncryptionAead aead,
    const VlessEncryptionUnitedKey& united_key,
    std::optional<VlessEncryptionHeaderXor> header_xor) noexcept
    : dst_(dst)
    , aead_(std::move(aead))
    , united_key_(united_key)
    , header_xor_(std::move(header_xor)) {}

void VlessEncryptionWriter::CheckWritable() const {
    if (state_ == State::Failed) {
        ThrowVlessEncryptionIoError("VLESS Encryption writer failed");
    }
    if (state_ == State::Finished) {
        throw transport::WriteClosed();
    }
}

net::awaitable<void> VlessEncryptionWriter::WriteMultiBuffer(
    buf::MultiBuffer mb) {
    CheckWritable();
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(io_error::operation_aborted,
                            "VLESS Encryption write cancelled");
    }
    if (mb.empty()) {
        co_return;
    }
    ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> buffers;
    buffers.AppendMultiBuffer(mb);
    if (!buffers.empty()) {
        co_await WriteBuffers(buffers.Span());
    }
    mb.clear();
}

net::awaitable<void> VlessEncryptionWriter::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    CheckWritable();
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(io_error::operation_aborted,
                            "VLESS Encryption write cancelled");
    }
    bool record_started = false;
    try {
        size_t idx = 0;
        size_t offset = 0;
        auto skip_empty = [&]() noexcept {
            while (idx < buffers.size()) {
                const auto* data = static_cast<const uint8_t*>(buffers[idx].data());
                if (data && offset < buffers[idx].size()) {
                    return;
                }
                ++idx;
                offset = 0;
            }
        };

        skip_empty();
        while (idx < buffers.size()) {
            const auto* first_data =
                static_cast<const uint8_t*>(buffers[idx].data()) + offset;
            const size_t first_rem = buffers[idx].size() - offset;

            size_t planned_len = std::min(first_rem, kVlessEncryptionMaxPlaintextSize);
            if (planned_len < kVlessEncryptionMaxPlaintextSize) {
                for (size_t j = idx + 1;
                     j < buffers.size() && planned_len < kVlessEncryptionMaxPlaintextSize;
                     ++j) {
                    if (buffers[j].data() && buffers[j].size() > 0) {
                        planned_len += std::min(
                            buffers[j].size(),
                            kVlessEncryptionMaxPlaintextSize - planned_len);
                    }
                }
            }

            if (planned_len <= first_rem) {
                offset += planned_len;
                skip_empty();
                co_await WritePlaintext(
                    std::span<const uint8_t>{first_data, planned_len}, record_started);
                continue;
            }

            const auto step_cancellation = co_await net::this_coro::cancellation_state;
            if (step_cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted,
                                    "VLESS Encryption write cancelled");
            }
            const size_t frame_capacity =
                kVlessEncryptionRecordHeaderSize + planned_len + kVlessEncryptionTagSize;
            buf::ContiguousWriteBuffer frame_buffer;
            uint8_t* frame_ptr = frame_buffer.TryPrepare(frame_capacity);
            if (!frame_ptr) {
                ThrowVlessEncryptionIoError("VLESS Encryption buffer allocation failed");
            }
            uint8_t* dst = frame_ptr + kVlessEncryptionRecordHeaderSize;
            size_t filled = 0;
            while (idx < buffers.size() && filled < planned_len) {
                const auto* data =
                    static_cast<const uint8_t*>(buffers[idx].data()) + offset;
                const size_t rem = buffers[idx].size() - offset;
                const size_t copy_len = std::min(rem, planned_len - filled);
                std::memcpy(dst + filled, data, copy_len);
                filled += copy_len;
                offset += copy_len;
                skip_empty();
            }
            std::span<uint8_t> frame{frame_ptr, frame_capacity};
            record_started = true;
            const auto written = SealVlessEncryptionRecord(
                aead_,
                std::span<const uint8_t>{frame_ptr + kVlessEncryptionRecordHeaderSize, filled},
                frame);
            if (!written) {
                ThrowVlessEncryptionIoError("VLESS Encryption record encrypt failed");
            }
            auto frame_view = frame.first(*written);
            if (IsVlessEncryptionMaxNonce(aead_.Nonce()) &&
                !RekeyAead(aead_, frame_view, united_key_)) {
                ThrowVlessEncryptionIoError("VLESS Encryption write rekey failed");
            }
            if (header_xor_ &&
                !header_xor_->XorOutboundInPlace(frame_view)) {
                ThrowVlessEncryptionIoError("VLESS Encryption write xor failed");
            }
            net::const_buffer buffer{frame_view.data(), frame_view.size()};
            co_await dst_.WriteBuffers(
                std::span<const net::const_buffer>{&buffer, 1});
        }
    } catch (const transport::WriteClosed&) {
        state_ = State::Finished;
        throw;
    } catch (...) {
        if (record_started) {
            state_ = State::Failed;
        }
        throw;
    }
}

net::awaitable<void> VlessEncryptionWriter::AsyncShutdownWrite() {
    if (state_ == State::Finished) {
        co_return;
    }
    CheckWritable();
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(io_error::operation_aborted,
                            "VLESS Encryption write shutdown cancelled");
    }
    try {
        co_await dst_.AsyncShutdownWrite();
        state_ = State::Finished;
    } catch (const transport::WriteClosed&) {
        state_ = State::Finished;
        throw;
    } catch (...) {
        state_ = State::Failed;
        throw;
    }
}

net::awaitable<void> VlessEncryptionWriter::WritePlaintext(
    std::span<const uint8_t> data, bool& record_started) {
    while (!data.empty()) {
        const auto cancellation = co_await net::this_coro::cancellation_state;
        if (cancellation.cancelled() != net::cancellation_type::none) {
            throw IoSystemError(io_error::operation_aborted,
                                "VLESS Encryption write cancelled");
        }
        const size_t n = std::min<size_t>(
            data.size(),
            kVlessEncryptionMaxPlaintextSize);
        const size_t frame_capacity =
            kVlessEncryptionRecordHeaderSize + n + kVlessEncryptionTagSize;
        buf::ContiguousWriteBuffer frame_buffer;
        uint8_t* frame_ptr = frame_buffer.TryPrepare(frame_capacity);
        if (!frame_ptr) {
            ThrowVlessEncryptionIoError("VLESS Encryption buffer allocation failed");
        }
        std::span<uint8_t> frame{frame_ptr, frame_capacity};

        // Seal advances the nonce even if record encryption subsequently fails.
        // Keep this set across every record in the public write request.
        record_started = true;
        const auto written = SealVlessEncryptionRecord(
            aead_,
            data.first(n),
            frame);
        if (!written) {
            ThrowVlessEncryptionIoError("VLESS Encryption record encrypt failed");
        }
        auto frame_view = frame.first(*written);
        if (IsVlessEncryptionMaxNonce(aead_.Nonce()) &&
            !RekeyAead(aead_, frame_view, united_key_)) {
            ThrowVlessEncryptionIoError("VLESS Encryption write rekey failed");
        }
        if (header_xor_ &&
            !header_xor_->XorOutboundInPlace(frame_view)) {
            ThrowVlessEncryptionIoError("VLESS Encryption write xor failed");
        }

        net::const_buffer buffer{frame_view.data(), frame_view.size()};
        co_await dst_.WriteBuffers(
            std::span<const net::const_buffer>{&buffer, 1});
        data = data.subspan(n);
    }
}

}  // namespace vless
