#include "vless_encryption_handshake.hpp"

#include <blake3.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <utility>

namespace acpp::vless {
namespace {

constexpr size_t kHashSize = 32;
constexpr size_t kX25519RelaySize = kVlessX25519KeySize;
constexpr size_t kMlKem768RelaySize = kVlessMlKem768CiphertextSize;

[[nodiscard]] bool RandomBytes(std::span<uint8_t> out) noexcept {
    return out.empty() ||
           RAND_bytes(out.data(), static_cast<int>(out.size())) == 1;
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
    std::vector<uint8_t> nfs_key;
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
    std::vector<uint8_t> nfs_key;
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

}  // namespace acpp::vless
