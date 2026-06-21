#include "vless_encryption_handshake.hpp"

#include "acppnode/common/allocator.hpp"

#include <blake3.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <utility>

namespace acpp::vless {
namespace {

constexpr size_t kHashSize = 32;
constexpr size_t kX25519RelaySize = kVlessX25519KeySize;
constexpr size_t kMlKem768RelaySize = kVlessMlKem768CiphertextSize;
constexpr VlessEncryptionPadding kDefaultPaddingLens[] = {
    {100, 111, 1111},
    {50, 0, 3333},
};
constexpr VlessEncryptionPadding kDefaultPaddingGaps[] = {
    {75, 0, 111},
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
    const uint64_t width = static_cast<uint64_t>(to - from);
    if (width == 0) {
        return from;
    }
    return from + static_cast<int64_t>(RandomU64() % width);
}

[[nodiscard]] std::optional<uint32_t> PickPaddingValue(
    const VlessEncryptionPadding& padding) noexcept {
    if (padding.probability < 0 || padding.from < 0 || padding.to < 0) {
        return std::nullopt;
    }
    if (padding.probability < RandomBetween(0, 100)) {
        return 0;
    }
    const int64_t value = RandomBetween(padding.from, padding.to);
    if (value < 0 ||
        value > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
        return std::nullopt;
    }
    return static_cast<uint32_t>(value);
}

[[nodiscard]] bool IsClientKey(std::span<const uint8_t> key) noexcept {
    return key.size() == kVlessX25519KeySize ||
           key.size() == kVlessMlKem768PublicKeySize;
}

[[nodiscard]] bool IsServerKey(std::span<const uint8_t> key) noexcept {
    return key.size() == kVlessX25519KeySize ||
           key.size() == kVlessMlKem768SeedSize;
}

[[nodiscard]] size_t RelaySizeForClientKey(
    std::span<const uint8_t> key) noexcept {
    return key.size() == kVlessMlKem768PublicKeySize
        ? kMlKem768RelaySize
        : kX25519RelaySize;
}

[[nodiscard]] size_t RelaySizeForServerKey(
    std::span<const uint8_t> key) noexcept {
    return key.size() == kVlessMlKem768SeedSize
        ? kMlKem768RelaySize
        : kX25519RelaySize;
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

[[nodiscard]] std::optional<std::vector<std::vector<uint8_t>>>
ServerPublicKeys(const VlessEncryptionConfig& config) noexcept {
    std::vector<std::vector<uint8_t>> public_keys;
    public_keys.reserve(config.keys.size());
    for (const auto& key : config.keys) {
        if (key.size() == kVlessX25519KeySize) {
            std::array<uint8_t, kVlessX25519KeySize> public_key{};
            if (!DeriveVlessX25519PublicKey(key, public_key)) {
                return std::nullopt;
            }
            public_keys.emplace_back(public_key.begin(), public_key.end());
            continue;
        }
        if (key.size() == kVlessMlKem768SeedSize) {
            auto public_key = DeriveVlessMlKem768PublicKeyFromSeed(key);
            if (!public_key) {
                return std::nullopt;
            }
            public_keys.emplace_back(public_key->begin(), public_key->end());
            continue;
        }
        return std::nullopt;
    }
    return public_keys;
}

[[nodiscard]] std::optional<size_t> RelaysLengthForKeys(
    const VlessEncryptionConfig& config) noexcept {
    if (config.keys.empty()) {
        return std::nullopt;
    }

    size_t length = 0;
    for (size_t i = 0; i < config.keys.size(); ++i) {
        const auto& key = config.keys[i];
        if (config.role == VlessEncryptionRole::Client) {
            if (!IsClientKey(key)) {
                return std::nullopt;
            }
            length += RelaySizeForClientKey(key);
        } else {
            if (!IsServerKey(key)) {
                return std::nullopt;
            }
            length += RelaySizeForServerKey(key);
        }
        if (i + 1 < config.keys.size()) {
            length += kHashSize;
        }
    }
    return length;
}

[[nodiscard]] std::span<const uint8_t, kVlessEncryptionIvSize>
IvSpan(const std::array<uint8_t, kVlessEncryptionIvSize>& iv) noexcept {
    return std::span<const uint8_t, kVlessEncryptionIvSize>(
        iv.data(),
        iv.size());
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
    int64_t seconds = 0;
    if (config.seconds_to == 0) {
        seconds = config.seconds_from * RandomBetween(50, 100) / 100;
    } else {
        seconds = RandomBetween(config.seconds_from, config.seconds_to);
    }
    return static_cast<uint16_t>(seconds & 0xffff);
}

[[nodiscard]] bool AppendPfsKey(memory::ByteVector& out,
                                std::span<const uint8_t> mlkem_shared,
                                std::span<const uint8_t> x25519_shared) {
    if (mlkem_shared.size() != kVlessMlKem768SharedSecretSize ||
        x25519_shared.size() != kVlessX25519KeySize) {
        return false;
    }
    out.clear();
    out.reserve(kVlessEncryptionPfsKeySize);
    out.insert(out.end(), mlkem_shared.begin(), mlkem_shared.end());
    out.insert(out.end(), x25519_shared.begin(), x25519_shared.end());
    return true;
}

[[nodiscard]] memory::ByteVector BuildUnitedKey(
    std::span<const uint8_t> pfs_key,
    std::span<const uint8_t> nfs_key) {
    memory::ByteVector out;
    out.reserve(pfs_key.size() + nfs_key.size());
    out.insert(out.end(), pfs_key.begin(), pfs_key.end());
    out.insert(out.end(), nfs_key.begin(), nfs_key.end());
    return out;
}

}  // namespace

std::optional<size_t> VlessEncryptionRelaysLength(
    const VlessEncryptionConfig& config) noexcept {
    return RelaysLengthForKeys(config);
}

std::optional<VlessEncryptionClientNfsHello>
BuildVlessEncryptionClientNfsHello(
    const VlessEncryptionConfig& config) noexcept {
    if (config.role != VlessEncryptionRole::Client) {
        return std::nullopt;
    }

    const auto relays_length = RelaysLengthForKeys(config);
    if (!relays_length) {
        return std::nullopt;
    }

    VlessEncryptionClientNfsHello hello;
    hello.relays.resize(*relays_length);
    if (!RandomBytes(hello.iv)) {
        return std::nullopt;
    }

    std::optional<VlessEncryptionCtr> last_ctr;
    std::span<uint8_t> relays(hello.relays);
    memory::ByteVector nfs_key;
    for (size_t i = 0; i < config.keys.size(); ++i) {
        const auto& public_key = config.keys[i];
        const size_t relay_size = RelaySizeForClientKey(public_key);
        if (relays.size() < relay_size) {
            return std::nullopt;
        }

        std::span<uint8_t> current = relays.first(relay_size);
        if (public_key.size() == kVlessX25519KeySize) {
            const auto pair = GenerateVlessX25519KeyPair();
            std::copy(pair.public_key.begin(), pair.public_key.end(),
                      current.begin());
            auto shared = ComputeVlessX25519SharedKey(
                pair.private_key,
                public_key);
            if (!shared) {
                return std::nullopt;
            }
            nfs_key.assign(shared->begin(), shared->end());
        } else if (public_key.size() == kVlessMlKem768PublicKeySize) {
            auto enc = EncapsulateVlessMlKem768(public_key);
            if (!enc) {
                return std::nullopt;
            }
            std::copy(enc->ciphertext.begin(), enc->ciphertext.end(),
                      current.begin());
            nfs_key.assign(enc->shared_secret.begin(), enc->shared_secret.end());
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
        if (i + 1 == config.keys.size()) {
            break;
        }

        relays = relays.subspan(relay_size);
        if (relays.size() < kHashSize) {
            return std::nullopt;
        }

        auto hash = Hash32(config.keys[i + 1]);
        std::copy(hash.begin(), hash.end(), relays.begin());
        last_ctr = VlessEncryptionCtr::Create(nfs_key, IvSpan(hello.iv));
        if (!last_ctr ||
            !last_ctr->XorInPlace(relays.first(kHashSize))) {
            return std::nullopt;
        }
        relays = relays.subspan(kHashSize);
    }

    hello.nfs_key = std::move(nfs_key);
    hello.bytes.reserve(hello.iv.size() + hello.relays.size());
    hello.bytes.insert(hello.bytes.end(), hello.iv.begin(), hello.iv.end());
    hello.bytes.insert(hello.bytes.end(), hello.relays.begin(),
                       hello.relays.end());
    return hello;
}

std::optional<VlessEncryptionServerNfsOpenResult>
OpenVlessEncryptionClientNfsHello(
    const VlessEncryptionConfig& config,
    std::span<const uint8_t> iv_and_relays) noexcept {
    if (config.role != VlessEncryptionRole::Server ||
        iv_and_relays.size() < kVlessEncryptionIvSize) {
        return std::nullopt;
    }

    const auto relays_length = RelaysLengthForKeys(config);
    if (!relays_length ||
        iv_and_relays.size() != kVlessEncryptionIvSize + *relays_length) {
        return std::nullopt;
    }

    auto public_keys = ServerPublicKeys(config);
    if (!public_keys || public_keys->size() != config.keys.size()) {
        return std::nullopt;
    }

    VlessEncryptionServerNfsOpenResult result;
    std::copy_n(iv_and_relays.begin(), result.iv.size(), result.iv.begin());
    result.relays.assign(
        iv_and_relays.begin() + static_cast<std::ptrdiff_t>(result.iv.size()),
        iv_and_relays.end());

    std::optional<VlessEncryptionCtr> last_ctr;
    std::span<uint8_t> relays(result.relays);
    memory::ByteVector nfs_key;
    for (size_t i = 0; i < config.keys.size(); ++i) {
        const auto& secret_key = config.keys[i];
        const auto& public_key = (*public_keys)[i];
        const size_t relay_size = RelaySizeForServerKey(secret_key);
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

        if (secret_key.size() == kVlessX25519KeySize) {
            if (current[kVlessX25519KeySize - 1] > 127) {
                return std::nullopt;
            }
            auto shared = ComputeVlessX25519SharedKey(secret_key, current);
            if (!shared) {
                return std::nullopt;
            }
            nfs_key.assign(shared->begin(), shared->end());
        } else if (secret_key.size() == kVlessMlKem768SeedSize) {
            auto shared = DecapsulateVlessMlKem768FromSeed(secret_key, current);
            if (!shared) {
                return std::nullopt;
            }
            nfs_key.assign(shared->begin(), shared->end());
        } else {
            return std::nullopt;
        }

        if (i + 1 == config.keys.size()) {
            break;
        }

        relays = relays.subspan(relay_size);
        if (relays.size() < kHashSize) {
            return std::nullopt;
        }
        last_ctr = VlessEncryptionCtr::Create(nfs_key, IvSpan(result.iv));
        if (!last_ctr ||
            !last_ctr->XorInPlace(relays.first(kHashSize))) {
            return std::nullopt;
        }
        const auto expected_hash = Hash32((*public_keys)[i + 1]);
        if (!std::ranges::equal(expected_hash, relays.first(kHashSize))) {
            return std::nullopt;
        }
        relays = relays.subspan(kHashSize);
    }

    result.nfs_key = std::move(nfs_key);
    return result;
}

std::optional<VlessEncryptionClientPfsHello>
BuildVlessEncryptionClientPfsHello(
    VlessEncryptionAead& nfs_aead) noexcept {
    VlessEncryptionClientPfsHello hello;
    if (!RandomBytes(hello.mlkem_seed)) {
        return std::nullopt;
    }
    auto mlkem_public = DeriveVlessMlKem768PublicKeyFromSeed(
        hello.mlkem_seed);
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
        hello.encrypted);
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

std::optional<std::array<uint8_t, kVlessEncryptionClientPfsPublicSize>>
OpenVlessEncryptionClientPfsHello(
    VlessEncryptionAead& nfs_aead,
    std::span<const uint8_t, kVlessEncryptionClientPfsHelloSize>
        encrypted) noexcept {
    std::array<uint8_t, kVlessEncryptionLengthSize> length_plain{};
    auto opened_len = nfs_aead.Open(
        encrypted.first(kVlessEncryptionEncryptedLengthSize),
        {},
        length_plain);
    if (!opened_len || *opened_len != length_plain.size()) {
        return std::nullopt;
    }

    const auto declared_len = DecodeVlessEncryptionLength(length_plain);
    if (!declared_len ||
        *declared_len != kVlessEncryptionEncryptedClientPfsPublicSize) {
        return std::nullopt;
    }

    std::array<uint8_t, kVlessEncryptionClientPfsPublicSize> public_key{};
    auto opened_key = nfs_aead.Open(
        encrypted.subspan(kVlessEncryptionEncryptedLengthSize),
        {},
        public_key);
    if (!opened_key || *opened_key != public_key.size()) {
        return std::nullopt;
    }
    if (!ValidateVlessMlKem768PublicKey(
            std::span<const uint8_t>(
                public_key.data(),
                kVlessMlKem768PublicKeySize))) {
        return std::nullopt;
    }
    return public_key;
}

std::optional<VlessEncryptionServerPfsResponse>
BuildVlessEncryptionServerPfsResponse(
    const VlessEncryptionConfig& config,
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    std::span<const uint8_t> nfs_key,
    std::span<const uint8_t, kVlessEncryptionClientPfsPublicSize>
        client_public_key,
    VlessEncryptionAeadCipher cipher) noexcept {
    if (config.role != VlessEncryptionRole::Server) {
        return std::nullopt;
    }

    auto mlkem_enc = EncapsulateVlessMlKem768(
        client_public_key.first(kVlessMlKem768PublicKeySize));
    if (!mlkem_enc) {
        return std::nullopt;
    }

    const auto x25519 = GenerateVlessX25519KeyPair();
    auto x25519_shared = ComputeVlessX25519SharedKey(
        x25519.private_key,
        client_public_key.subspan(kVlessMlKem768PublicKeySize));
    if (!x25519_shared) {
        return std::nullopt;
    }

    VlessEncryptionServerPfsResponse response;
    std::copy(mlkem_enc->ciphertext.begin(), mlkem_enc->ciphertext.end(),
              response.public_key.begin());
    std::copy(x25519.public_key.begin(), x25519.public_key.end(),
              response.public_key.begin() +
                  static_cast<std::ptrdiff_t>(
                      kVlessMlKem768CiphertextSize));
    if (!AppendPfsKey(response.pfs_key,
                      mlkem_enc->shared_secret,
                      *x25519_shared)) {
        return std::nullopt;
    }
    response.united_key = BuildUnitedKey(response.pfs_key, nfs_key);

    auto nfs_aead = VlessEncryptionAead::Create(iv, nfs_key, cipher);
    if (!nfs_aead) {
        return std::nullopt;
    }
    auto sealed_public = nfs_aead->SealWithNonce(
        MaxNonce(),
        response.public_key,
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
        response.public_key,
        response.united_key,
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
    std::span<const uint8_t> nfs_key,
    std::span<const uint8_t, kVlessEncryptionEncryptedServerPfsPublicSize>
        encrypted_public_key,
    std::span<const uint8_t, kVlessEncryptionEncryptedTicketSize>
        encrypted_ticket,
    VlessEncryptionAeadCipher cipher) noexcept {
    auto nfs_aead = VlessEncryptionAead::Create(iv, nfs_key, cipher);
    if (!nfs_aead) {
        return std::nullopt;
    }

    VlessEncryptionClientPfsOpenResult result;
    auto opened_public = nfs_aead->OpenWithNonce(
        MaxNonce(),
        encrypted_public_key,
        {},
        result.server_public_key);
    if (!opened_public ||
        *opened_public != kVlessEncryptionServerPfsPublicSize) {
        return std::nullopt;
    }

    auto mlkem_shared = DecapsulateVlessMlKem768FromSeed(
        client_hello.mlkem_seed,
        std::span<const uint8_t>(
            result.server_public_key.data(),
            kVlessMlKem768CiphertextSize));
    if (!mlkem_shared) {
        return std::nullopt;
    }
    auto x25519_shared = ComputeVlessX25519SharedKey(
        client_hello.x25519_private_key,
        std::span<const uint8_t>(
            result.server_public_key.data() +
                static_cast<std::ptrdiff_t>(kVlessMlKem768CiphertextSize),
            kVlessX25519KeySize));
    if (!x25519_shared ||
        !AppendPfsKey(result.pfs_key, *mlkem_shared, *x25519_shared)) {
        return std::nullopt;
    }
    result.united_key = BuildUnitedKey(result.pfs_key, nfs_key);

    auto ticket_aead = VlessEncryptionAead::Create(
        result.server_public_key,
        result.united_key,
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
    const auto seconds = DecodeVlessEncryptionLength(
        std::span<const uint8_t, kVlessEncryptionLengthSize>(
            result.ticket.data(),
            kVlessEncryptionLengthSize));
    if (!seconds) {
        return std::nullopt;
    }
    result.ticket_seconds = *seconds;
    result.read_aead = std::move(*ticket_aead);
    return result;
}

std::optional<VlessEncryptionPaddingPlan>
BuildVlessEncryptionPaddingPlan(
    const VlessEncryptionConfig& config) noexcept {
    VlessEncryptionPaddingPlan plan;
    const bool use_default_padding = config.padding_lens.empty();
    const auto lens = use_default_padding
        ? std::span<const VlessEncryptionPadding>(kDefaultPaddingLens)
        : std::span<const VlessEncryptionPadding>(config.padding_lens);
    const auto gaps = use_default_padding
        ? std::span<const VlessEncryptionPadding>(kDefaultPaddingGaps)
        : std::span<const VlessEncryptionPadding>(config.padding_gaps);

    plan.fragment_lengths.reserve(lens.size());
    for (const auto& item : lens) {
        auto length = PickPaddingValue(item);
        if (!length) {
            return std::nullopt;
        }
        plan.fragment_lengths.push_back(*length);
        plan.total_length += *length;
        if (plan.total_length > kVlessEncryptionMaxPaddingLength) {
            return std::nullopt;
        }
    }

    plan.gaps_ms.reserve(gaps.size());
    for (const auto& item : gaps) {
        auto gap = PickPaddingValue(item);
        if (!gap) {
            return std::nullopt;
        }
        plan.gaps_ms.push_back(*gap);
    }

    if (plan.total_length < kVlessEncryptionMinPaddingLength) {
        return std::nullopt;
    }
    return plan;
}

std::optional<memory::ByteVector>
SealVlessEncryptionPadding(VlessEncryptionAead& aead,
                           size_t padding_length) noexcept {
    if (padding_length < kVlessEncryptionMinPaddingLength ||
        padding_length > kVlessEncryptionMaxPaddingLength) {
        return std::nullopt;
    }

    const size_t encrypted_body_length =
        padding_length - kVlessEncryptionEncryptedLengthSize;
    const size_t plaintext_body_length =
        encrypted_body_length - kVlessEncryptionTagSize;
    auto encoded_length = EncodeVlessEncryptionLength(encrypted_body_length);

    memory::ByteVector out(padding_length);
    auto length_out = std::span<uint8_t>(
        out.data(),
        kVlessEncryptionEncryptedLengthSize);
    auto sealed_length = aead.Seal(encoded_length, {}, length_out);
    if (!sealed_length ||
        *sealed_length != kVlessEncryptionEncryptedLengthSize) {
        return std::nullopt;
    }

    memory::ByteVector plain(plaintext_body_length);
    auto body_out = std::span<uint8_t>(
        out.data() + static_cast<std::ptrdiff_t>(
            kVlessEncryptionEncryptedLengthSize),
        encrypted_body_length);
    auto sealed_body = aead.Seal(plain, {}, body_out);
    if (!sealed_body || *sealed_body != encrypted_body_length) {
        return std::nullopt;
    }
    return out;
}

std::optional<VlessEncryptionEncryptedPadding>
BuildVlessEncryptionPadding(const VlessEncryptionConfig& config,
                            VlessEncryptionAead& aead) noexcept {
    auto plan = BuildVlessEncryptionPaddingPlan(config);
    if (!plan) {
        return std::nullopt;
    }
    auto bytes = SealVlessEncryptionPadding(aead, plan->total_length);
    if (!bytes) {
        return std::nullopt;
    }
    return VlessEncryptionEncryptedPadding{
        .plan = std::move(*plan),
        .bytes = std::move(*bytes),
    };
}

std::optional<VlessEncryptionClientZeroRttRequest>
BuildVlessEncryptionClientZeroRttRequest(
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    std::span<const uint8_t> nfs_key,
    std::span<const uint8_t> pfs_key,
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    VlessEncryptionAeadCipher cipher) noexcept {
    if (pfs_key.size() != kVlessEncryptionPfsKeySize) {
        return std::nullopt;
    }
    auto nfs_aead = VlessEncryptionAead::Create(iv, nfs_key, cipher);
    if (!nfs_aead) {
        return std::nullopt;
    }

    VlessEncryptionClientZeroRttRequest request;
    request.united_key = BuildUnitedKey(pfs_key, nfs_key);
    const auto encoded_ticket_len =
        EncodeVlessEncryptionLength(kVlessEncryptionEncryptedTicketSize);
    auto sealed_len = nfs_aead->Seal(
        encoded_ticket_len,
        {},
        request.encrypted_length);
    if (!sealed_len || *sealed_len != request.encrypted_length.size()) {
        return std::nullopt;
    }

    auto sealed_ticket = nfs_aead->Seal(
        ticket,
        {},
        request.encrypted_ticket);
    if (!sealed_ticket || *sealed_ticket != request.encrypted_ticket.size()) {
        return std::nullopt;
    }

    request.bytes.reserve(
        request.encrypted_length.size() + request.encrypted_ticket.size());
    request.bytes.insert(request.bytes.end(),
                         request.encrypted_length.begin(),
                         request.encrypted_length.end());
    request.bytes.insert(request.bytes.end(),
                         request.encrypted_ticket.begin(),
                         request.encrypted_ticket.end());
    return request;
}

std::optional<VlessEncryptionServerZeroRttOpenResult>
OpenVlessEncryptionClientZeroRttRequest(
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    std::span<const uint8_t> nfs_key,
    std::span<const uint8_t> pfs_key,
    std::span<const uint8_t, kVlessEncryptionEncryptedLengthSize>
        encrypted_length,
    std::span<const uint8_t, kVlessEncryptionEncryptedTicketSize>
        encrypted_ticket,
    VlessEncryptionAeadCipher cipher) noexcept {
    if (pfs_key.size() != kVlessEncryptionPfsKeySize) {
        return std::nullopt;
    }
    auto nfs_aead = VlessEncryptionAead::Create(iv, nfs_key, cipher);
    if (!nfs_aead) {
        return std::nullopt;
    }

    std::array<uint8_t, kVlessEncryptionLengthSize> length_plain{};
    auto opened_len = nfs_aead->Open(encrypted_length, {}, length_plain);
    if (!opened_len || *opened_len != length_plain.size()) {
        return std::nullopt;
    }
    const auto declared_len = DecodeVlessEncryptionLength(length_plain);
    if (!declared_len ||
        *declared_len != kVlessEncryptionEncryptedTicketSize) {
        return std::nullopt;
    }

    VlessEncryptionServerZeroRttOpenResult result;
    auto opened_ticket = nfs_aead->Open(
        encrypted_ticket,
        {},
        result.ticket);
    if (!opened_ticket || *opened_ticket != result.ticket.size()) {
        return std::nullopt;
    }

    std::copy(encrypted_ticket.begin(), encrypted_ticket.end(),
              result.encrypted_ticket.begin());
    if (!RandomBytes(result.server_random)) {
        return std::nullopt;
    }
    result.united_key = BuildUnitedKey(pfs_key, nfs_key);
    return result;
}

}  // namespace acpp::vless
