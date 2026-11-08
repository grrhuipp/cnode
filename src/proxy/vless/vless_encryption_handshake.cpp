#include "vless_encryption_handshake.hpp"

#include "common/allocator.hpp"

#include <blake3.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <utility>

namespace vless {
namespace {

constexpr size_t kHashSize = 32;
constexpr size_t kX25519RelaySize = kVlessX25519KeySize;
constexpr size_t kMlKem768RelaySize = kVlessMlKem768CiphertextSize;
constexpr VlessEncryptionPadding kDefaultPaddingLens[] = {
    {100, 111, 1111},
    {50, 0, 3333},
};

[[nodiscard]] bool RandomBytes(std::span<uint8_t> out) noexcept {
    return out.empty() ||
           RAND_bytes(out.data(), static_cast<int>(out.size())) == 1;
}

[[nodiscard]] uint64_t RandomU64() noexcept {
    uint64_t out = 0;
    if (RAND_bytes(reinterpret_cast<uint8_t*>(&out), sizeof(out)) != 1) {
        return 0;
    }
    return out;
}

[[nodiscard]] int64_t RandomBetween(int64_t from, int64_t to) noexcept {
    if (from == to) {
        return from;
    }
    if (from > to) {
        std::swap(from, to);
    }
    const uint64_t diff =
        static_cast<uint64_t>(to) - static_cast<uint64_t>(from);
    if (diff == std::numeric_limits<uint64_t>::max()) {
        return static_cast<int64_t>(RandomU64());
    }
    return from + static_cast<int64_t>(RandomU64() % (diff + 1));
}

[[nodiscard]] std::optional<uint32_t> PickPaddingValue(
    const VlessEncryptionPadding& padding) noexcept {
    if (padding.probability < 0 || padding.from < 0 || padding.to < 0) {
        return std::nullopt;
    }
    if (padding.probability == 0 || padding.probability <= RandomBetween(0, 99)) {
        return 0;
    }
    const int64_t value = RandomBetween(padding.from, padding.to);
    if (value < 0 ||
        value > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
        return std::nullopt;
    }
    return static_cast<uint32_t>(value);
}

[[nodiscard]] bool IsClientKey(const VlessClientPfsKey& key) noexcept {
    if (key.public_key.size() == kVlessX25519KeySize) {
        return !key.mlkem_key;
    }
    if (key.public_key.size() == kVlessMlKem768PublicKeySize) {
        return key.mlkem_key != nullptr;
    }
    return false;
}

[[nodiscard]] bool IsServerKey(const VlessServerPfsKey& key) noexcept {
    if (key.private_key.size() == kVlessX25519KeySize) {
        return key.public_key.size() == kVlessX25519KeySize &&
               !key.mlkem_key;
    }
    if (key.private_key.size() == kVlessMlKem768SeedSize) {
        return key.public_key.size() == kVlessMlKem768PublicKeySize &&
               key.mlkem_key != nullptr;
    }
    return false;
}

template <typename Key>
[[nodiscard]] size_t RelaySize(const Key& key) noexcept {
    return key.mlkem_key ? kMlKem768RelaySize : kX25519RelaySize;
}

[[nodiscard]] std::array<uint8_t, kHashSize> Hash32(
    std::span<const uint8_t> data) noexcept {
    std::array<uint8_t, kHashSize> out{};
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (!data.empty()) {
        blake3_hasher_update(&hasher, data.data(), data.size());
    }
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    return out;
}

[[nodiscard]] std::span<const uint8_t, kVlessEncryptionIvSize>
IvSpan(const std::array<uint8_t, kVlessEncryptionIvSize>& iv) noexcept {
    return std::span<const uint8_t, kVlessEncryptionIvSize>(iv);
}

[[nodiscard]] const VlessEncryptionNonce& MaxNonce() noexcept {
    static constexpr VlessEncryptionNonce kMaxNonce = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    return kMaxNonce;
}

[[nodiscard]] uint16_t TicketSeconds(
    const VlessEncryptionConfig& config) noexcept {
    if (config.seconds_from <= 0 && config.seconds_to <= 0) {
        return 0;
    }
    int64_t seconds = 0;
    if (config.seconds_to == 0) {
        seconds = config.seconds_from * RandomBetween(50, 100) / 100;
    } else {
        seconds = RandomBetween(config.seconds_from, config.seconds_to);
    }
    return static_cast<uint16_t>(std::clamp<int64_t>(seconds, 1, 65535));
}

// PFS key layout: ML-KEM-768 shared secret followed by X25519 shared secret.
[[nodiscard]] std::span<uint8_t, kVlessMlKem768SharedSecretSize>
PfsMlKemPart(VlessEncryptionPfsKey& key) noexcept {
    return std::span<uint8_t, kVlessEncryptionPfsKeySize>(key.bytes)
        .first<kVlessMlKem768SharedSecretSize>();
}

[[nodiscard]] std::span<uint8_t, kVlessX25519KeySize>
PfsX25519Part(VlessEncryptionPfsKey& key) noexcept {
    return std::span<uint8_t, kVlessEncryptionPfsKeySize>(key.bytes)
        .subspan<kVlessMlKem768SharedSecretSize>();
}

[[nodiscard]] VlessEncryptionUnitedKey BuildUnitedKey(
    const VlessEncryptionPfsKey& pfs_key,
    const VlessEncryptionNfsKey& nfs_key) noexcept {
    VlessEncryptionUnitedKey out;
    auto next = std::copy(pfs_key.bytes.begin(), pfs_key.bytes.end(),
                          out.bytes.begin());
    std::copy(nfs_key.bytes.begin(), nfs_key.bytes.end(), next);
    return out;
}

[[nodiscard]] std::optional<size_t> PickPaddingLength(
    const VlessEncryptionConfig& config) noexcept {
    const auto lens = config.padding_lens.empty()
        ? std::span<const VlessEncryptionPadding>(kDefaultPaddingLens)
        : std::span<const VlessEncryptionPadding>(config.padding_lens);
    size_t total = 0;
    for (const auto& item : lens) {
        auto length = PickPaddingValue(item);
        if (!length) {
            return std::nullopt;
        }
        total += *length;
        if (total > kVlessEncryptionMaxPaddingLength) {
            return std::nullopt;
        }
    }
    if (total < kVlessEncryptionMinPaddingLength) {
        return std::nullopt;
    }
    return total;
}

}  // namespace

std::optional<size_t> VlessEncryptionRelaysLength(
    const VlessEncryptionConfig& config) noexcept {
    if (config.role == VlessEncryptionRole::Client) {
        if (config.client_keys.empty()) {
            return std::nullopt;
        }
        size_t length = 0;
        for (size_t i = 0; i < config.client_keys.size(); ++i) {
            const auto& key = config.client_keys[i];
            if (!IsClientKey(key)) {
                return std::nullopt;
            }
            length += RelaySize(key);
            if (i + 1 < config.client_keys.size()) {
                length += kHashSize;
            }
        }
        return length;
    }

    if (config.server_keys.empty()) {
        return std::nullopt;
    }
    size_t length = 0;
    for (size_t i = 0; i < config.server_keys.size(); ++i) {
        const auto& key = config.server_keys[i];
        if (!IsServerKey(key)) {
            return std::nullopt;
        }
        length += RelaySize(key);
        if (i + 1 < config.server_keys.size()) {
            length += kHashSize;
        }
    }
    return length;
}

std::optional<VlessEncryptionClientNfsHello>
BuildVlessEncryptionClientNfsHello(
    const VlessEncryptionConfig& config) noexcept {
    if (config.role != VlessEncryptionRole::Client) {
        return std::nullopt;
    }

    const auto relays_length = VlessEncryptionRelaysLength(config);
    if (!relays_length) {
        return std::nullopt;
    }

    VlessEncryptionClientNfsHello hello;
    if (!RandomBytes(hello.iv)) {
        return std::nullopt;
    }
    hello.bytes.resize(hello.iv.size() + *relays_length);
    std::copy(hello.iv.begin(), hello.iv.end(), hello.bytes.begin());

    std::optional<VlessEncryptionCtr> last_ctr;
    auto relays = std::span<uint8_t>(hello.bytes).subspan(hello.iv.size());
    for (size_t i = 0; i < config.client_keys.size(); ++i) {
        const auto& client_key = config.client_keys[i];
        const auto& public_key = client_key.public_key;
        const size_t relay_size = RelaySize(client_key);
        if (relays.size() < relay_size) {
            return std::nullopt;
        }

        std::span<uint8_t> current = relays.first(relay_size);
        if (!client_key.mlkem_key &&
            public_key.size() == kVlessX25519KeySize) {
            const auto pair = GenerateVlessX25519KeyPair();
            std::copy(pair.public_key.begin(), pair.public_key.end(),
                      current.begin());
            if (!ComputeVlessX25519SharedKey(
                    pair.private_key.bytes,
                    public_key,
                    hello.nfs_key.bytes)) {
                return std::nullopt;
            }
        } else if (client_key.mlkem_key &&
                   public_key.size() == kVlessMlKem768PublicKeySize) {
            auto enc = EncapsulateVlessMlKem768(client_key.mlkem_key.get());
            if (!enc) {
                return std::nullopt;
            }
            std::copy(enc->ciphertext.begin(), enc->ciphertext.end(),
                      current.begin());
            hello.nfs_key.bytes = enc->shared_secret.bytes;
        } else {
            return std::nullopt;
        }

        if (config.mode != VlessEncryptionMode::Native &&
            !XorVlessEncryptionInPlace(public_key, IvSpan(hello.iv), current)) {
            return std::nullopt;
        }
        if (last_ctr &&
            !last_ctr->XorInPlace(current.first(kHashSize))) {
            return std::nullopt;
        }
        if (i + 1 == config.client_keys.size()) {
            break;
        }

        relays = relays.subspan(relay_size);
        if (relays.size() < kHashSize) {
            return std::nullopt;
        }

        auto hash = Hash32(config.client_keys[i + 1].public_key);
        std::copy(hash.begin(), hash.end(), relays.begin());
        last_ctr = VlessEncryptionCtr::Create(hello.nfs_key.bytes,
                                              IvSpan(hello.iv));
        if (!last_ctr ||
            !last_ctr->XorInPlace(relays.first(kHashSize))) {
            return std::nullopt;
        }
        relays = relays.subspan(kHashSize);
    }
    return hello;
}

std::optional<VlessEncryptionServerNfsOpenResult>
OpenVlessEncryptionClientNfsHello(
    const VlessEncryptionConfig& config,
    std::span<uint8_t> iv_and_relays) noexcept {
    if (config.role != VlessEncryptionRole::Server ||
        iv_and_relays.size() < kVlessEncryptionIvSize) {
        return std::nullopt;
    }

    const auto relays_length = VlessEncryptionRelaysLength(config);
    if (!relays_length ||
        iv_and_relays.size() != kVlessEncryptionIvSize + *relays_length) {
        return std::nullopt;
    }

    VlessEncryptionServerNfsOpenResult result;
    std::copy_n(iv_and_relays.begin(), result.iv.size(), result.iv.begin());

    std::optional<VlessEncryptionCtr> last_ctr;
    auto relays = iv_and_relays.subspan(result.iv.size());
    for (size_t i = 0; i < config.server_keys.size(); ++i) {
        const auto& server_key = config.server_keys[i];
        const auto& secret_key = server_key.private_key;
        const auto& public_key = server_key.public_key;
        const size_t relay_size = RelaySize(server_key);
        if (relays.size() < relay_size) {
            return std::nullopt;
        }

        std::span<uint8_t> current = relays.first(relay_size);
        if (last_ctr &&
            !last_ctr->XorInPlace(current.first(kHashSize))) {
            return std::nullopt;
        }
        if (config.mode != VlessEncryptionMode::Native &&
            !XorVlessEncryptionInPlace(public_key, IvSpan(result.iv), current)) {
            return std::nullopt;
        }

        if (!server_key.mlkem_key &&
            secret_key.size() == kVlessX25519KeySize) {
            if (current[kVlessX25519KeySize - 1] > 127 ||
                !ComputeVlessX25519SharedKey(secret_key, current,
                                             result.nfs_key.bytes)) {
                return std::nullopt;
            }
        } else if (server_key.mlkem_key &&
                   secret_key.size() == kVlessMlKem768SeedSize) {
            if (!DecapsulateVlessMlKem768(server_key.mlkem_key.get(), current,
                                          result.nfs_key.bytes)) {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }

        if (i + 1 == config.server_keys.size()) {
            break;
        }

        relays = relays.subspan(relay_size);
        if (relays.size() < kHashSize) {
            return std::nullopt;
        }
        last_ctr = VlessEncryptionCtr::Create(result.nfs_key.bytes,
                                              IvSpan(result.iv));
        if (!last_ctr ||
            !last_ctr->XorInPlace(relays.first(kHashSize))) {
            return std::nullopt;
        }
        const auto expected_hash = Hash32(config.server_keys[i + 1].public_key);
        if (!std::ranges::equal(expected_hash, relays.first(kHashSize))) {
            return std::nullopt;
        }
        relays = relays.subspan(kHashSize);
    }
    return result;
}

std::optional<VlessEncryptionClientPfsHello>
BuildVlessEncryptionClientPfsHello(
    VlessEncryptionAead& nfs_aead) noexcept {
    VlessEncryptionClientPfsHello hello;
    hello.mlkem_private_key = GenerateVlessMlKem768PrivateKey();
    auto mlkem_public = DeriveVlessMlKem768PublicKey(
        hello.mlkem_private_key.get());
    if (!mlkem_public) {
        return std::nullopt;
    }

    const auto x25519 = GenerateVlessX25519KeyPair();
    hello.x25519_private_key = x25519.private_key;
    std::copy(mlkem_public->begin(), mlkem_public->end(),
              hello.public_key.begin());
    std::copy(x25519.public_key.begin(), x25519.public_key.end(),
              hello.public_key.begin() +
                  static_cast<std::ptrdiff_t>(kVlessMlKem768PublicKeySize));

    const auto encrypted_len = EncodeVlessEncryptionLength(
        kVlessEncryptionEncryptedClientPfsPublicSize);
    hello.encrypted.resize(kVlessEncryptionClientPfsHelloSize);
    auto encrypted = std::span<uint8_t, kVlessEncryptionClientPfsHelloSize>(
        hello.encrypted.data(), kVlessEncryptionClientPfsHelloSize);
    auto sealed_len = nfs_aead.Seal(
        encrypted_len,
        {},
        encrypted.first(kVlessEncryptionEncryptedLengthSize));
    if (!sealed_len || *sealed_len != kVlessEncryptionEncryptedLengthSize) {
        return std::nullopt;
    }

    auto sealed_key = nfs_aead.Seal(
        hello.public_key,
        {},
        encrypted.subspan(kVlessEncryptionEncryptedLengthSize));
    if (!sealed_key ||
        *sealed_key != kVlessEncryptionEncryptedClientPfsPublicSize) {
        return std::nullopt;
    }
    return hello;
}

std::optional<VlessEncryptionServerPfsResponse>
BuildVlessEncryptionServerPfsResponse(
    const VlessEncryptionConfig& config,
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    const VlessEncryptionNfsKey& nfs_key,
    std::span<const uint8_t, kVlessEncryptionClientPfsPublicSize>
        client_public_key,
    VlessEncryptionAeadCipher cipher) noexcept {
    if (config.role != VlessEncryptionRole::Server) {
        return std::nullopt;
    }

    // Parsing the client's ML-KEM key here is also its validation.
    auto mlkem_enc = EncapsulateVlessMlKem768(
        client_public_key.first(kVlessMlKem768PublicKeySize));
    if (!mlkem_enc) {
        return std::nullopt;
    }

    VlessEncryptionServerPfsResponse response;
    const auto x25519 = GenerateVlessX25519KeyPair();
    if (!ComputeVlessX25519SharedKey(
            x25519.private_key.bytes,
            client_public_key.subspan(kVlessMlKem768PublicKeySize),
            PfsX25519Part(response.pfs_key))) {
        return std::nullopt;
    }
    std::copy(mlkem_enc->shared_secret.bytes.begin(),
              mlkem_enc->shared_secret.bytes.end(),
              PfsMlKemPart(response.pfs_key).begin());

    std::array<uint8_t, kVlessEncryptionServerPfsPublicSize> public_key{};
    std::copy(mlkem_enc->ciphertext.begin(), mlkem_enc->ciphertext.end(),
              public_key.begin());
    std::copy(x25519.public_key.begin(), x25519.public_key.end(),
              public_key.begin() +
                  static_cast<std::ptrdiff_t>(
                      kVlessMlKem768CiphertextSize));
    response.united_key = BuildUnitedKey(response.pfs_key, nfs_key);

    auto nfs_aead = VlessEncryptionAead::Create(iv, nfs_key.bytes, cipher);
    if (!nfs_aead) {
        return std::nullopt;
    }
    response.encrypted_public_key.resize(
        kVlessEncryptionEncryptedServerPfsPublicSize);
    auto sealed_public = nfs_aead->SealWithNonce(
        MaxNonce(),
        public_key,
        {},
        response.encrypted_public_key);
    if (!sealed_public ||
        *sealed_public != kVlessEncryptionEncryptedServerPfsPublicSize) {
        return std::nullopt;
    }

    if (!RandomBytes(response.ticket)) {
        return std::nullopt;
    }
    response.ticket_seconds = TicketSeconds(config);
    const auto encoded_seconds =
        EncodeVlessEncryptionLength(response.ticket_seconds);
    std::copy(encoded_seconds.begin(), encoded_seconds.end(),
              response.ticket.begin());

    auto ticket_aead = VlessEncryptionAead::Create(
        public_key,
        response.united_key.bytes,
        cipher);
    if (!ticket_aead) {
        return std::nullopt;
    }
    auto sealed_ticket = ticket_aead->Seal(
        response.ticket,
        {},
        response.encrypted_ticket);
    if (!sealed_ticket ||
        *sealed_ticket != kVlessEncryptionEncryptedTicketSize) {
        return std::nullopt;
    }
    response.write_aead = std::move(*ticket_aead);
    return response;
}

std::optional<VlessEncryptionClientPfsOpenResult>
OpenVlessEncryptionServerPfsResponse(
    const VlessEncryptionClientPfsHello& client_hello,
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    const VlessEncryptionNfsKey& nfs_key,
    std::span<const uint8_t, kVlessEncryptionEncryptedServerPfsPublicSize>
        encrypted_public_key,
    std::span<const uint8_t, kVlessEncryptionEncryptedTicketSize>
        encrypted_ticket,
    VlessEncryptionAeadCipher cipher) noexcept {
    auto nfs_aead = VlessEncryptionAead::Create(iv, nfs_key.bytes, cipher);
    if (!nfs_aead) {
        return std::nullopt;
    }

    std::array<uint8_t, kVlessEncryptionServerPfsPublicSize> server_public_key{};
    auto opened_public = nfs_aead->OpenWithNonce(
        MaxNonce(),
        encrypted_public_key,
        {},
        server_public_key);
    if (!opened_public ||
        *opened_public != kVlessEncryptionServerPfsPublicSize) {
        return std::nullopt;
    }

    VlessEncryptionClientPfsOpenResult result;
    const auto server_public = std::span<const uint8_t>(server_public_key);
    if (!DecapsulateVlessMlKem768(
            client_hello.mlkem_private_key.get(),
            server_public.first(kVlessMlKem768CiphertextSize),
            PfsMlKemPart(result.pfs_key)) ||
        !ComputeVlessX25519SharedKey(
            client_hello.x25519_private_key.bytes,
            server_public.subspan(kVlessMlKem768CiphertextSize),
            PfsX25519Part(result.pfs_key))) {
        return std::nullopt;
    }
    result.united_key = BuildUnitedKey(result.pfs_key, nfs_key);

    auto ticket_aead = VlessEncryptionAead::Create(
        server_public_key,
        result.united_key.bytes,
        cipher);
    if (!ticket_aead) {
        return std::nullopt;
    }
    auto opened_ticket = ticket_aead->Open(
        encrypted_ticket,
        {},
        result.ticket);
    if (!opened_ticket || *opened_ticket != result.ticket.size()) {
        return std::nullopt;
    }
    result.ticket_seconds = DecodeVlessEncryptionLength(
        std::span<const uint8_t, kVlessEncryptionTicketSize>(result.ticket)
            .first<kVlessEncryptionLengthSize>());
    result.read_aead = std::move(*ticket_aead);
    return result;
}

std::optional<memory::ByteVector> BuildVlessEncryptionPadding(
    const VlessEncryptionConfig& config,
    VlessEncryptionAead& aead) noexcept {
    const auto padding_length = PickPaddingLength(config);
    if (!padding_length) {
        return std::nullopt;
    }

    const size_t encrypted_body_length =
        *padding_length - kVlessEncryptionEncryptedLengthSize;
    const size_t plaintext_body_length =
        encrypted_body_length - kVlessEncryptionTagSize;
    auto encoded_length = EncodeVlessEncryptionLength(encrypted_body_length);

    memory::ByteVector out(*padding_length);
    auto sealed_length = aead.Seal(
        encoded_length,
        {},
        std::span<uint8_t>(out).first(kVlessEncryptionEncryptedLengthSize));
    if (!sealed_length ||
        *sealed_length != kVlessEncryptionEncryptedLengthSize) {
        return std::nullopt;
    }

    // The body is sealed in place over the zero-filled plaintext.
    auto body = std::span<uint8_t>(out).subspan(
        kVlessEncryptionEncryptedLengthSize);
    auto sealed_body = aead.Seal(body.first(plaintext_body_length), {}, body);
    if (!sealed_body || *sealed_body != encrypted_body_length) {
        return std::nullopt;
    }
    return out;
}

std::optional<VlessEncryptionClientZeroRttRequest>
BuildVlessEncryptionClientZeroRttRequest(
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    const VlessEncryptionNfsKey& nfs_key,
    const VlessEncryptionPfsKey& pfs_key,
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    VlessEncryptionAeadCipher cipher) noexcept {
    auto nfs_aead = VlessEncryptionAead::Create(iv, nfs_key.bytes, cipher);
    if (!nfs_aead) {
        return std::nullopt;
    }

    VlessEncryptionClientZeroRttRequest request;
    request.united_key = BuildUnitedKey(pfs_key, nfs_key);
    auto bytes = std::span<uint8_t, kVlessEncryptionZeroRttRequestSize>(
        request.bytes);
    const auto encoded_ticket_len =
        EncodeVlessEncryptionLength(kVlessEncryptionEncryptedTicketSize);
    auto sealed_len = nfs_aead->Seal(
        encoded_ticket_len,
        {},
        bytes.first<kVlessEncryptionEncryptedLengthSize>());
    if (!sealed_len || *sealed_len != kVlessEncryptionEncryptedLengthSize) {
        return std::nullopt;
    }

    auto sealed_ticket = nfs_aead->Seal(
        ticket,
        {},
        bytes.subspan<kVlessEncryptionEncryptedLengthSize>());
    if (!sealed_ticket ||
        *sealed_ticket != kVlessEncryptionEncryptedTicketSize) {
        return std::nullopt;
    }
    return request;
}

std::optional<VlessEncryptionServerZeroRttAccept>
AcceptVlessEncryptionClientZeroRtt(
    const VlessEncryptionNfsKey& nfs_key,
    const VlessEncryptionPfsKey& pfs_key) noexcept {
    VlessEncryptionServerZeroRttAccept accept;
    if (!RandomBytes(accept.server_random)) {
        return std::nullopt;
    }
    accept.united_key = BuildUnitedKey(pfs_key, nfs_key);
    return accept;
}

}  // namespace vless
