#pragma once

#include "common/byte_reader.hpp"
#include "transport/stream_settings.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <tl/expected.hpp>
#include <openssl/ssl.h>
#include <openssl/mem.h>
#include <openssl/mldsa.h>
#include <string>
#include <vector>


namespace transport {

enum class RealityKeyShareError {
    InvalidFormat,
};

[[nodiscard]] inline tl::expected<RealityKey, RealityKeyShareError>
ParseRealityClientKeyShareExtension(
    std::span<const uint8_t> extension) noexcept {
    constexpr uint16_t kTlsGroupX25519 = 29;
    constexpr uint16_t kTlsGroupX25519MlKem768 = 0x11ec;
    constexpr std::size_t kMlKem768PublicKeySize = 1184;
    constexpr std::size_t kX25519MlKem768ClientShareSize =
        kMlKem768PublicKeySize + kRealityKeySize;

    common::ByteReader outer(extension);
    const auto list = outer.ReadBytes(outer.ReadU16BE());
    if (!outer.Ok() || !outer.Empty()) {
        return tl::unexpected(RealityKeyShareError::InvalidFormat);
    }

    std::optional<RealityKey> x25519;
    std::optional<RealityKey> hybrid_x25519;
    common::ByteReader reader(list);
    while (!reader.Empty()) {
        const uint16_t group = reader.ReadU16BE();
        const uint16_t key_size = reader.ReadU16BE();
        const auto key = reader.ReadBytes(key_size);
        if (!reader.Ok() || key_size == 0) {
            return tl::unexpected(RealityKeyShareError::InvalidFormat);
        }
        if (group == kTlsGroupX25519) {
            if (x25519 || key.size() != kRealityKeySize) {
                return tl::unexpected(RealityKeyShareError::InvalidFormat);
            }
            RealityKey parsed{};
            std::copy_n(key.data(), parsed.size(), parsed.begin());
            x25519 = parsed;
        } else if (group == kTlsGroupX25519MlKem768) {
            if (hybrid_x25519 || key.size() != kX25519MlKem768ClientShareSize) {
                return tl::unexpected(RealityKeyShareError::InvalidFormat);
            }
            RealityKey parsed{};
            std::copy_n(
                key.data() + key.size() - kRealityKeySize,
                parsed.size(),
                parsed.begin());
            hybrid_x25519 = parsed;
        }
    }
    if (x25519) return *x25519;
    if (hybrid_x25519) return *hybrid_x25519;
    return tl::unexpected(RealityKeyShareError::InvalidFormat);
}

class SslContext;

struct RealityClientState {
    ~RealityClientState() {
        OPENSSL_cleanse(auth_key.data(), auth_key.size());
        OPENSSL_cleanse(short_id.data(), short_id.size());
    }
    RealityShortId short_id{};
    std::array<uint8_t, 32> auth_key{};
    std::string spider_x;
    const MLDSA65_public_key* mldsa65_verify_key = nullptr;
    std::vector<uint8_t> client_hello_raw;
    std::vector<uint8_t> server_hello_raw;
    bool auth_key_ready = false;
};

struct RealityServerConnState {
    ~RealityServerConnState() {
        OPENSSL_cleanse(auth_key.data(), auth_key.size());
    }
    std::array<uint8_t, 32> auth_key{};
    std::vector<uint8_t> client_hello_raw;
};

[[nodiscard]] bool VerifyRealityClientHandshake(
    SSL* ssl,
    const RealityClientState& state);

void ClearRealityClientState(
    SSL* ssl,
    std::unique_ptr<RealityClientState>& state) noexcept;

void ClearRealityServerConnState(SSL* ssl) noexcept;

[[nodiscard]] std::unique_ptr<RealityServerConnState>
VerifyRealityClientHello(
    std::vector<uint8_t> handshake,
    const SslContext& ctx);

// RFC 8446 sections 4.1.2 and 5.1: handshake messages may span records.
// Retain the original wire image for fallback/replay, but authenticate the
// concatenated handshake, never record headers. Append only received bytes;
// neither record nor handshake lengths cause speculative allocation.
class RealityClientHelloReader {
public:
    enum class Status { Reading, Complete, Invalid };
    // Maximum ClientHello body from its uint8/uint16 vector length fields.
    static constexpr size_t kMaxHelloSize = 4 + 2 + 32 + 1 + 32 + 2 + 65534 + 1 + 255 + 2 + 65535;

    [[nodiscard]] Status State() const noexcept { return status_; }
    [[nodiscard]] size_t ReadSize() const noexcept {
        if (status_ != Status::Reading) return 0;
        return header_size_ < header_.size()
            ? header_.size() - header_size_
            : std::min<size_t>(remaining_, 1024);
    }
    void Append(std::span<const uint8_t> bytes);
    [[nodiscard]] std::span<const uint8_t> Hello() const noexcept { return hello_; }
    [[nodiscard]] std::vector<uint8_t> TakeHello() noexcept { return std::move(hello_); }
    [[nodiscard]] std::vector<uint8_t> TakeWire() noexcept { return std::move(wire_); }
private:
    std::array<uint8_t, 5> header_{};
    size_t header_size_ = 0;
    size_t remaining_ = 0;
    size_t hello_size_ = 0;
    Status status_ = Status::Reading;
    std::vector<uint8_t> wire_;
    std::vector<uint8_t> hello_;
};
}  // namespace transport