#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/transport/link.hpp"

#include "vless_encryption_record.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace acpp {
class AsyncStream;
}  // namespace acpp

namespace acpp::vless {

class VlessEncryptionReader final : public transport::MultiBufferReader {
public:
    [[nodiscard]] static std::optional<VlessEncryptionReader> Create(
        AsyncStream& src,
        std::span<const uint8_t> read_context,
        std::span<const uint8_t> united_key,
        VlessEncryptionAeadCipher cipher) noexcept;

    VlessEncryptionReader(AsyncStream& src,
                          VlessEncryptionAead aead,
                          std::vector<uint8_t> united_key) noexcept;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;

private:
    [[nodiscard]] bool Rekey(std::span<const uint8_t> context) noexcept;

    AsyncStream& src_;
    VlessEncryptionAead aead_;
    std::vector<uint8_t> united_key_;
};

class VlessEncryptionWriter final : public transport::MultiBufferWriter {
public:
    [[nodiscard]] static std::optional<VlessEncryptionWriter> Create(
        AsyncStream& dst,
        std::span<const uint8_t> write_context,
        std::span<const uint8_t> united_key,
        VlessEncryptionAeadCipher cipher) noexcept;

    VlessEncryptionWriter(AsyncStream& dst,
                          VlessEncryptionAead aead,
                          std::vector<uint8_t> united_key) noexcept;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> AsyncShutdownWrite() override;

private:
    [[nodiscard]] bool Rekey(std::span<const uint8_t> context) noexcept;

    AsyncStream& dst_;
    VlessEncryptionAead aead_;
    std::vector<uint8_t> united_key_;
};

}  // namespace acpp::vless
