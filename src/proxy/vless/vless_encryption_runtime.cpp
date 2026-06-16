#include "vless_encryption_runtime.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <ranges>

namespace acpp::vless {
namespace {

[[nodiscard]] std::span<const uint8_t, kVlessEncryptionIvSize> IvSpan(
    const std::array<uint8_t, kVlessEncryptionIvSize>& iv) noexcept {
    return std::span<const uint8_t, kVlessEncryptionIvSize>(
        iv.data(),
        iv.size());
}

[[nodiscard]] std::span<const uint8_t, kVlessEncryptionTicketSize> TicketSpan(
    const std::array<uint8_t, kVlessEncryptionTicketSize>& ticket) noexcept {
    return std::span<const uint8_t, kVlessEncryptionTicketSize>(
        ticket.data(),
        ticket.size());
}

[[nodiscard]] VlessEncryptionAeadCipher PreferredCipher() noexcept {
    return VlessEncryptionAeadCipher::Aes256Gcm;
}

[[nodiscard]] std::optional<VlessEncryptionAead> CreateNfsAead(
    const std::array<uint8_t, kVlessEncryptionIvSize>& iv,
    std::span<const uint8_t> nfs_key,
    VlessEncryptionAeadCipher cipher) noexcept {
    return VlessEncryptionAead::Create(IvSpan(iv), nfs_key, cipher);
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
    if (!ValidateVlessMlKem768PublicKey(std::span<const uint8_t>(
            client_public.data(),
            kVlessMlKem768PublicKeySize))) {
        return std::nullopt;
    }
    return client_public;
}

net::awaitable<bool> ReadAndOpenPadding(VlessBufferedReader& reader,
                                        VlessEncryptionAead& aead) {
    std::array<uint8_t, kVlessEncryptionEncryptedLengthSize>
        encrypted_length{};
    if (!co_await reader.ReadExact(
            encrypted_length.data(),
            encrypted_length.size())) {
        co_return false;
    }

    const auto encrypted_body_length =
        OpenEncryptedPaddingLength(aead, encrypted_length);
    if (!encrypted_body_length ||
        *encrypted_body_length < kVlessEncryptionTagSize ||
        *encrypted_body_length >
            kVlessEncryptionMaxPaddingLength -
                kVlessEncryptionEncryptedLengthSize) {
        co_return false;
    }

    std::vector<uint8_t> encrypted_padding(*encrypted_body_length);
    if (!co_await reader.ReadExact(
            encrypted_padding.data(),
            encrypted_padding.size())) {
        co_return false;
    }
    std::vector<uint8_t> plain(
        encrypted_padding.size() - kVlessEncryptionTagSize);
    const auto opened = aead.Open(encrypted_padding, {}, plain);
    co_return opened.has_value() && *opened == plain.size();
}

net::awaitable<bool> WriteBytes(transport::MultiBufferWriter& writer,
                               std::span<const uint8_t> data) {
    co_await WriteVlessBytes(writer, data);
    co_return true;
}

[[nodiscard]] std::optional<VlessEncryptionHeaderXor> MakeHeaderXor(
    const VlessEncryptionConfig& config,
    std::span<const uint8_t> united_key,
    std::span<const uint8_t, kVlessEncryptionIvSize> iv) noexcept {
    if (config.mode != VlessEncryptionMode::Random) {
        return std::nullopt;
    }
    return VlessEncryptionHeaderXor::Create(united_key, iv);
}

[[nodiscard]] std::optional<VlessEncryptionRuntime> BuildClientRuntime(
    const VlessEncryptionConfig& config,
    const VlessEncryptionClientPfsHello& client_pfs,
    VlessEncryptionClientPfsOpenResult server_open,
    VlessEncryptionAeadCipher cipher,
    std::span<const uint8_t, kVlessEncryptionIvSize> client_iv) noexcept {
    auto write_aead = VlessEncryptionAead::Create(
        client_pfs.public_key,
        server_open.united_key,
        cipher);
    if (!write_aead) {
        return std::nullopt;
    }

    VlessEncryptionRuntime runtime;
    runtime.united_key = server_open.united_key;
    runtime.read_aead = std::move(server_open.read_aead);
    runtime.write_aead = std::move(*write_aead);
    runtime.cipher = cipher;
    runtime.write_xor = MakeHeaderXor(
        config,
        runtime.united_key,
        client_iv);
    runtime.read_xor = MakeHeaderXor(
        config,
        runtime.united_key,
        TicketSpan(server_open.ticket));
    if (config.mode == VlessEncryptionMode::Random &&
        (!runtime.write_xor || !runtime.read_xor)) {
        return std::nullopt;
    }
    return runtime;
}

[[nodiscard]] std::optional<VlessEncryptionRuntime> BuildServerRuntime(
    const VlessEncryptionConfig& config,
    std::span<const uint8_t, kVlessEncryptionClientPfsPublicSize>
        client_public_key,
    VlessEncryptionServerPfsResponse response,
    VlessEncryptionAeadCipher cipher,
    std::span<const uint8_t, kVlessEncryptionIvSize> client_iv) noexcept {
    auto read_aead = VlessEncryptionAead::Create(
        client_public_key,
        response.united_key,
        cipher);
    if (!read_aead) {
        return std::nullopt;
    }

    VlessEncryptionRuntime runtime;
    runtime.united_key = response.united_key;
    runtime.read_aead = std::move(*read_aead);
    runtime.write_aead = std::move(response.write_aead);
    runtime.cipher = cipher;
    runtime.read_xor = MakeHeaderXor(
        config,
        runtime.united_key,
        client_iv);
    runtime.write_xor = MakeHeaderXor(
        config,
        runtime.united_key,
        TicketSpan(response.ticket));
    if (config.mode == VlessEncryptionMode::Random &&
        (!runtime.write_xor || !runtime.read_xor)) {
        return std::nullopt;
    }
    return runtime;
}

[[nodiscard]] std::optional<VlessEncryptionRuntime> BuildClientZeroRttRuntime(
    const VlessEncryptionConfig& config,
    const VlessEncryptionClientZeroRttRequest& request,
    std::span<const uint8_t, kVlessEncryptionIvSize> client_iv,
    VlessEncryptionAeadCipher cipher) noexcept {
    auto write_aead = VlessEncryptionAead::Create(
        request.encrypted_ticket,
        request.united_key,
        cipher);
    if (!write_aead) {
        return std::nullopt;
    }

    VlessEncryptionRuntime runtime;
    runtime.united_key = request.united_key;
    runtime.write_aead = std::move(*write_aead);
    runtime.read_aead_ready = false;
    runtime.lazy_read_context_size = kVlessEncryptionServerRandomSize;
    runtime.lazy_read_xor_from_context =
        config.mode == VlessEncryptionMode::Random;
    runtime.cipher = cipher;
    runtime.write_xor = MakeHeaderXor(
        config,
        runtime.united_key,
        client_iv);
    if (config.mode == VlessEncryptionMode::Random &&
        !runtime.write_xor) {
        return std::nullopt;
    }
    return runtime;
}

[[nodiscard]] std::optional<VlessEncryptionRuntime> BuildServerZeroRttRuntime(
    const VlessEncryptionConfig& config,
    std::span<const uint8_t> united_key,
    std::span<const uint8_t, kVlessEncryptionIvSize> client_iv,
    std::span<const uint8_t, kVlessEncryptionEncryptedTicketSize>
        encrypted_ticket,
    std::span<const uint8_t, kVlessEncryptionServerRandomSize> server_random,
    VlessEncryptionAeadCipher cipher) noexcept {
    auto read_aead = VlessEncryptionAead::Create(
        encrypted_ticket,
        united_key,
        cipher);
    auto write_aead = VlessEncryptionAead::Create(
        server_random,
        united_key,
        cipher);
    if (!read_aead || !write_aead) {
        return std::nullopt;
    }

    VlessEncryptionRuntime runtime;
    runtime.united_key.assign(united_key.begin(), united_key.end());
    runtime.read_aead = std::move(*read_aead);
    runtime.write_aead = std::move(*write_aead);
    runtime.cipher = cipher;
    runtime.read_xor = MakeHeaderXor(
        config,
        runtime.united_key,
        client_iv);
    runtime.write_xor = MakeHeaderXor(
        config,
        runtime.united_key,
        server_random);
    if (config.mode == VlessEncryptionMode::Random &&
        (!runtime.write_xor || !runtime.read_xor)) {
        return std::nullopt;
    }
    return runtime;
}

}  // namespace

bool VlessEncryptionClientTicketCache::Valid(
    std::chrono::steady_clock::time_point now) const noexcept {
    return pfs_key.size() == kVlessEncryptionPfsKeySize &&
           expires_at > now &&
           std::ranges::any_of(ticket, [](uint8_t value) {
               return value != 0;
           });
}

void VlessEncryptionClientTicketCache::Store(
    const VlessEncryptionClientPfsOpenResult& open,
    std::chrono::steady_clock::time_point now) {
    if (open.ticket_seconds == 0 ||
        open.pfs_key.size() != kVlessEncryptionPfsKeySize) {
        Clear();
        return;
    }
    pfs_key = open.pfs_key;
    ticket = open.ticket;
    expires_at = now + std::chrono::seconds(open.ticket_seconds);
}

void VlessEncryptionClientTicketCache::Clear() noexcept {
    pfs_key.clear();
    ticket = {};
    expires_at = {};
}

void VlessEncryptionServerTicketStore::Prune(
    std::chrono::steady_clock::time_point now) {
    std::erase_if(sessions_, [now](const Session& session) {
        return session.expires_at <= now;
    });
}

std::optional<std::vector<uint8_t>> VlessEncryptionServerTicketStore::Lookup(
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    std::span<const uint8_t> nfs_key,
    std::chrono::steady_clock::time_point now) {
    if (nfs_key.size() != kVlessMlKem768SharedSecretSize) {
        return std::nullopt;
    }
    Prune(now);
    auto it = std::ranges::find_if(sessions_, [&](const Session& session) {
        return std::ranges::equal(session.ticket, ticket);
    });
    if (it == sessions_.end()) {
        return std::nullopt;
    }

    std::array<uint8_t, kVlessMlKem768SharedSecretSize> nfs_key_array{};
    std::copy(nfs_key.begin(), nfs_key.end(), nfs_key_array.begin());
    if (std::ranges::find(it->seen_nfs_keys, nfs_key_array) !=
        it->seen_nfs_keys.end()) {
        return std::nullopt;
    }
    it->seen_nfs_keys.push_back(nfs_key_array);
    return it->pfs_key;
}

void VlessEncryptionServerTicketStore::Store(
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    std::span<const uint8_t> pfs_key,
    uint16_t seconds,
    std::chrono::steady_clock::time_point now) {
    if (seconds == 0 || pfs_key.size() != kVlessEncryptionPfsKeySize) {
        return;
    }
    Prune(now);
    if (sessions_.size() >= 1024) {
        sessions_.erase(sessions_.begin());
    }
    Session session;
    std::copy(ticket.begin(), ticket.end(), session.ticket.begin());
    session.pfs_key.assign(pfs_key.begin(), pfs_key.end());
    session.expires_at = now + std::chrono::seconds(seconds);
    sessions_.push_back(std::move(session));
}

net::awaitable<std::optional<VlessEncryptionRuntime>>
RunVlessEncryptionClientHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config,
    VlessEncryptionClientTicketCache* ticket_cache) {
    auto nfs = BuildVlessEncryptionClientNfsHello(config);
    if (!nfs) {
        co_return std::nullopt;
    }

    const auto cipher = PreferredCipher();
    auto nfs_aead = CreateNfsAead(nfs->iv, nfs->nfs_key, cipher);
    if (!nfs_aead) {
        co_return std::nullopt;
    }

    const auto now = std::chrono::steady_clock::now();
    if (config.zero_rtt && ticket_cache && ticket_cache->Valid(now)) {
        auto zero = BuildVlessEncryptionClientZeroRttRequest(
            IvSpan(nfs->iv),
            nfs->nfs_key,
            ticket_cache->pfs_key,
            TicketSpan(ticket_cache->ticket),
            cipher);
        if (zero) {
            co_await WriteBytes(raw_writer, nfs->bytes);
            co_await WriteBytes(raw_writer, zero->bytes);
            co_return BuildClientZeroRttRuntime(
                config,
                *zero,
                IvSpan(nfs->iv),
                cipher);
        }
        ticket_cache->Clear();
    }

    auto pfs = BuildVlessEncryptionClientPfsHello(*nfs_aead);
    if (!pfs) {
        co_return std::nullopt;
    }
    auto padding = BuildVlessEncryptionPadding(config, *nfs_aead);
    if (!padding) {
        co_return std::nullopt;
    }

    co_await WriteBytes(raw_writer, nfs->bytes);
    co_await WriteBytes(raw_writer, pfs->encrypted);
    co_await WriteBytes(raw_writer, padding->bytes);

    std::array<uint8_t, kVlessEncryptionEncryptedServerPfsPublicSize>
        encrypted_server_public{};
    if (!co_await raw_reader.ReadExact(
            encrypted_server_public.data(),
            encrypted_server_public.size())) {
        co_return std::nullopt;
    }
    std::array<uint8_t, kVlessEncryptionEncryptedTicketSize>
        encrypted_ticket{};
    if (!co_await raw_reader.ReadExact(
            encrypted_ticket.data(),
            encrypted_ticket.size())) {
        co_return std::nullopt;
    }

    auto server_open = OpenVlessEncryptionServerPfsResponse(
        *pfs,
        IvSpan(nfs->iv),
        nfs->nfs_key,
        encrypted_server_public,
        encrypted_ticket,
        cipher);
    if (!server_open) {
        co_return std::nullopt;
    }

    if (!co_await ReadAndOpenPadding(raw_reader, server_open->read_aead)) {
        co_return std::nullopt;
    }

    if (ticket_cache) {
        ticket_cache->Store(*server_open, std::chrono::steady_clock::now());
    }

    co_return BuildClientRuntime(
        config,
        *pfs,
        std::move(*server_open),
        cipher,
        IvSpan(nfs->iv));
}

net::awaitable<std::optional<VlessEncryptionRuntime>>
RunVlessEncryptionServerHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config,
    VlessEncryptionServerTicketStore* ticket_store) {
    const auto relays_len = VlessEncryptionRelaysLength(config);
    if (!relays_len) {
        co_return std::nullopt;
    }

    std::vector<uint8_t> iv_and_relays(kVlessEncryptionIvSize + *relays_len);
    if (!co_await raw_reader.ReadExact(
            iv_and_relays.data(),
            iv_and_relays.size())) {
        co_return std::nullopt;
    }
    auto nfs = OpenVlessEncryptionClientNfsHello(config, iv_and_relays);
    if (!nfs) {
        co_return std::nullopt;
    }

    std::array<uint8_t, kVlessEncryptionEncryptedLengthSize>
        encrypted_length{};
    if (!co_await raw_reader.ReadExact(
            encrypted_length.data(),
            encrypted_length.size())) {
        co_return std::nullopt;
    }

    auto cipher = PreferredCipher();
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
        co_return std::nullopt;
    }

    if (*client_pfs_length == kVlessEncryptionEncryptedTicketSize) {
        std::array<uint8_t, kVlessEncryptionEncryptedTicketSize>
            encrypted_ticket{};
        if (!co_await raw_reader.ReadExact(
                encrypted_ticket.data(),
                encrypted_ticket.size())) {
            co_return std::nullopt;
        }
        auto ticket = OpenEncryptedTicketAfterLength(
            *nfs_aead,
            encrypted_ticket);
        if (!ticket || !ticket_store ||
            (config.seconds_from == 0 && config.seconds_to == 0)) {
            co_return std::nullopt;
        }

        const auto now = std::chrono::steady_clock::now();
        auto pfs_key = ticket_store->Lookup(
            TicketSpan(*ticket),
            nfs->nfs_key,
            now);
        if (!pfs_key) {
            co_return std::nullopt;
        }
        auto zero = OpenVlessEncryptionClientZeroRttRequest(
            IvSpan(nfs->iv),
            nfs->nfs_key,
            *pfs_key,
            encrypted_length,
            encrypted_ticket,
            cipher);
        if (!zero) {
            co_return std::nullopt;
        }
        auto runtime = BuildServerZeroRttRuntime(
            config,
            zero->united_key,
            IvSpan(nfs->iv),
            encrypted_ticket,
            zero->server_random,
            cipher);
        if (!runtime) {
            co_return std::nullopt;
        }
        co_await WriteBytes(raw_writer, zero->server_random);
        co_return runtime;
    }

    std::array<uint8_t, kVlessEncryptionEncryptedClientPfsPublicSize>
        encrypted_client_public{};
    if (!co_await raw_reader.ReadExact(
            encrypted_client_public.data(),
            encrypted_client_public.size())) {
        co_return std::nullopt;
    }

    auto client_public = OpenEncryptedClientPfsPublic(
        *nfs_aead,
        encrypted_client_public);
    if (!client_public) {
        co_return std::nullopt;
    }

    auto response = BuildVlessEncryptionServerPfsResponse(
        config,
        IvSpan(nfs->iv),
        nfs->nfs_key,
        *client_public,
        cipher);
    if (!response) {
        co_return std::nullopt;
    }
    auto padding = BuildVlessEncryptionPadding(
        config,
        response->write_aead);
    if (!padding) {
        co_return std::nullopt;
    }

    co_await WriteBytes(raw_writer, response->encrypted_public_key);
    co_await WriteBytes(raw_writer, response->encrypted_ticket);
    co_await WriteBytes(raw_writer, padding->bytes);

    if (!co_await ReadAndOpenPadding(raw_reader, *nfs_aead)) {
        co_return std::nullopt;
    }

    if (ticket_store) {
        ticket_store->Store(
            TicketSpan(response->ticket),
            response->pfs_key,
            response->ticket_seconds,
            std::chrono::steady_clock::now());
    }

    co_return BuildServerRuntime(
        config,
        *client_public,
        std::move(*response),
        cipher,
        IvSpan(nfs->iv));
}

}  // namespace acpp::vless
