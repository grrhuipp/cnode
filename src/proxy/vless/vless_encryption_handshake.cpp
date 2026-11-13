#include "proxy/vless/vless_encryption.hpp"
#include "common/scoped_cleanse.hpp"

#include <blake3.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>
namespace proxy {
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

std::optional<std::vector<uint8_t>> BuildVlessEncryptionPadding(
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

    std::vector<uint8_t> out(*padding_length);
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

net::awaitable<tl::expected<void, VlessEncryptionHandshakeFailure>> ReadAndOpenPadding(proxy::BufferedStreamReader& reader,
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

    std::vector<uint8_t> padding(*encrypted_body_length);
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
}  // namespace
net::awaitable<VlessEncryptionHandshakeResult>
RunVlessEncryptionClientHandshake(
    proxy::BufferedStreamReader& raw_reader,
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
                std::vector<uint8_t>{}.swap(nfs->bytes);
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
    std::vector<uint8_t>{}.swap(nfs->bytes);
    co_await WriteVlessBytes(raw_writer, pfs->encrypted);
    co_await WriteVlessBytes(raw_writer, *padding);
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

namespace {
net::awaitable<VlessEncryptionHandshakeResult> ResumeServerTicket(
    app::GroupCoordinator& coordinator,
    proxy::BufferedStreamReader& raw_reader, transport::MultiBufferWriter& raw_writer,
    const std::shared_ptr<const VlessEncryptionConfig>& namespace_config,
    std::string_view inbound_tag, const VlessEncryptionServerNfsOpenResult& nfs,
    VlessEncryptionAead& nfs_aead, VlessEncryptionAeadCipher cipher) {
    const auto& config = *namespace_config;
        std::array<uint8_t, kVlessEncryptionEncryptedTicketSize>
            encrypted_ticket{};
        if (!co_await raw_reader.ReadExact(
                encrypted_ticket.data(),
                encrypted_ticket.size())) {
            co_return tl::unexpected(VlessEncryptionHandshakeFailure::Truncated);
        }
        auto ticket = OpenEncryptedTicketAfterLength(
            nfs_aead,
            encrypted_ticket);
        if (!ticket ||
            (config.seconds_from == 0 && config.seconds_to == 0)) {
            co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
        }

        auto pfs_key = co_await LookupVlessTicket(
            coordinator, namespace_config, inbound_tag, *ticket, nfs.nfs_key);
        if (!pfs_key) {
            co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
        }
        const auto identity = pfs_key->identity;
        auto accept = AcceptVlessEncryptionClientZeroRtt(nfs.nfs_key, pfs_key->pfs_key);
        pfs_key.reset();  // The returned PFS copy is cleansed before any socket write.
        if (!accept) {
            co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
        }
        auto runtime = BuildServerZeroRttRuntime(
            config,
            *accept,
            nfs.iv,
            encrypted_ticket,
            cipher);
        if (!runtime) {
            co_return tl::unexpected(runtime.error());
        }
        runtime->resumed_identity = identity;
        co_await WriteVlessBytes(raw_writer, accept->server_random);
        co_return runtime;
}

net::awaitable<VlessEncryptionHandshakeResult> CompleteServerPfs(
    proxy::BufferedStreamReader& raw_reader, transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config, const VlessEncryptionServerNfsOpenResult& nfs,
    VlessEncryptionAead& nfs_aead, VlessEncryptionAeadCipher cipher) {
    std::array<uint8_t, kVlessEncryptionEncryptedClientPfsPublicSize>
        encrypted_client_public{};
    if (!co_await raw_reader.ReadExact(
            encrypted_client_public.data(),
            encrypted_client_public.size())) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Truncated);
    }

    auto client_public = OpenEncryptedClientPfsPublic(
        nfs_aead, encrypted_client_public);
    if (!client_public) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    auto response = BuildVlessEncryptionServerPfsResponse(
        config,
        nfs.iv,
        nfs.nfs_key,
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
        nfs.iv);
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
    padding.reset();

    if (auto padding_result = co_await ReadAndOpenPadding(raw_reader, nfs_aead);
        !padding_result) {
        co_return tl::unexpected(padding_result.error());
    }

    co_return runtime;
}
}  // namespace

net::awaitable<VlessEncryptionHandshakeResult>
RunVlessEncryptionServerHandshake(
    app::GroupCoordinator& coordinator,
    proxy::BufferedStreamReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    std::shared_ptr<const VlessEncryptionConfig> namespace_config,
    std::string_view inbound_tag) {
    if (!namespace_config) co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    const auto& config = *namespace_config;
    const auto relays_len = VlessEncryptionRelaysLength(config);
    if (!relays_len) {
        co_return tl::unexpected(VlessEncryptionHandshakeFailure::Rejected);
    }

    std::vector<uint8_t> iv_and_relays(
        kVlessEncryptionIvSize + *relays_len);
    size_t progress = 0;
    if (!co_await raw_reader.ReadExact(
            iv_and_relays.data(),
            iv_and_relays.size(), &progress)) {
        co_return tl::unexpected(progress == 0
            ? VlessEncryptionHandshakeFailure::Closed
            : VlessEncryptionHandshakeFailure::Truncated);
    }
    auto nfs = OpenVlessEncryptionClientNfsHello(config, iv_and_relays);
    std::vector<uint8_t>{}.swap(iv_and_relays);
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
        co_return co_await ResumeServerTicket(coordinator, raw_reader, raw_writer, namespace_config,
            inbound_tag, *nfs, *nfs_aead, cipher);
    }
    co_return co_await CompleteServerPfs(raw_reader, raw_writer, config, *nfs, *nfs_aead, cipher);
}
}  // namespace proxy
