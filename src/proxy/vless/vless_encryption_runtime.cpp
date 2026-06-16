#include "vless_encryption_runtime.hpp"

#include "vless_encryption_handshake.hpp"

#include <algorithm>
#include <array>

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

}  // namespace

net::awaitable<std::optional<VlessEncryptionRuntime>>
RunVlessEncryptionClient1RttHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config) {
    auto nfs = BuildVlessEncryptionClientNfsHello(config);
    if (!nfs) {
        co_return std::nullopt;
    }

    const auto cipher = PreferredCipher();
    auto nfs_aead = CreateNfsAead(nfs->iv, nfs->nfs_key, cipher);
    if (!nfs_aead) {
        co_return std::nullopt;
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

    co_return BuildClientRuntime(
        config,
        *pfs,
        std::move(*server_open),
        cipher,
        IvSpan(nfs->iv));
}

net::awaitable<std::optional<VlessEncryptionRuntime>>
RunVlessEncryptionServer1RttHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config) {
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
        *client_pfs_length != kVlessEncryptionEncryptedClientPfsPublicSize) {
        co_return std::nullopt;
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

    auto server_config = config;
    server_config.seconds_from = 0;
    server_config.seconds_to = 0;
    auto response = BuildVlessEncryptionServerPfsResponse(
        server_config,
        IvSpan(nfs->iv),
        nfs->nfs_key,
        *client_public,
        cipher);
    if (!response) {
        co_return std::nullopt;
    }
    auto padding = BuildVlessEncryptionPadding(
        server_config,
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

    co_return BuildServerRuntime(
        server_config,
        *client_public,
        std::move(*response),
        cipher,
        IvSpan(nfs->iv));
}

}  // namespace acpp::vless
