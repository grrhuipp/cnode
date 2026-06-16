#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/transport/link.hpp"

#include "vless_encryption_record.hpp"
#include "vless_encryption_xor.hpp"
#include "vless_io_util.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace acpp::vless {

class VlessEncryptionReader final : public transport::MultiBufferReader {
public:
    [[nodiscard]] static std::optional<VlessEncryptionReader> Create(
        transport::MultiBufferReader& src,
        std::span<const uint8_t> read_context,
        std::span<const uint8_t> united_key,
        VlessEncryptionAeadCipher cipher,
        std::optional<VlessEncryptionHeaderXor> header_xor =
            std::nullopt) noexcept;

    VlessEncryptionReader(transport::MultiBufferReader& src,
                          VlessEncryptionAead aead,
                          std::vector<uint8_t> united_key,
                          std::optional<VlessEncryptionHeaderXor>
                              header_xor) noexcept;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;

private:
    [[nodiscard]] bool Rekey(std::span<const uint8_t> context) noexcept;

    VlessBufferedReader src_;
    VlessEncryptionAead aead_;
    std::vector<uint8_t> united_key_;
    std::optional<VlessEncryptionHeaderXor> header_xor_;
};

class VlessEncryptionWriter final : public transport::MultiBufferWriter {
public:
    [[nodiscard]] static std::optional<VlessEncryptionWriter> Create(
        transport::MultiBufferWriter& dst,
        std::span<const uint8_t> write_context,
        std::span<const uint8_t> united_key,
        VlessEncryptionAeadCipher cipher,
        std::optional<VlessEncryptionHeaderXor> header_xor =
            std::nullopt) noexcept;

    VlessEncryptionWriter(transport::MultiBufferWriter& dst,
                          VlessEncryptionAead aead,
                          std::vector<uint8_t> united_key,
                          std::optional<VlessEncryptionHeaderXor>
                              header_xor) noexcept;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> AsyncShutdownWrite() override;

private:
    [[nodiscard]] bool Rekey(std::span<const uint8_t> context) noexcept;

    transport::MultiBufferWriter& dst_;
    VlessEncryptionAead aead_;
    std::vector<uint8_t> united_key_;
    std::optional<VlessEncryptionHeaderXor> header_xor_;
};

}  // namespace acpp::vless
