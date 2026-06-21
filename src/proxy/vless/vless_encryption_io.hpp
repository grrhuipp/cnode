#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/transport/link.hpp"

#include "vless_encryption_record.hpp"
#include "vless_encryption_xor.hpp"
#include "vless_io_util.hpp"

#include <cstdint>
#include <optional>
#include <span>

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

    [[nodiscard]] static VlessEncryptionReader CreateLazyReadContext(
        transport::MultiBufferReader& src,
        size_t read_context_size,
        std::span<const uint8_t> united_key,
        VlessEncryptionAeadCipher cipher,
        bool header_xor_from_context) noexcept;

    VlessEncryptionReader(transport::MultiBufferReader& src,
                          VlessEncryptionAead aead,
                          memory::ByteVector united_key,
                          std::optional<VlessEncryptionHeaderXor>
                              header_xor) noexcept;

    VlessEncryptionReader(transport::MultiBufferReader& src,
                          size_t read_context_size,
                          VlessEncryptionAeadCipher cipher,
                          memory::ByteVector united_key,
                          bool header_xor_from_context) noexcept;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;

private:
    [[nodiscard]] bool Rekey(std::span<const uint8_t> context) noexcept;

    VlessBufferedReader src_;
    VlessEncryptionAead aead_;
    memory::ByteVector united_key_;
    std::optional<VlessEncryptionHeaderXor> header_xor_;
    bool aead_ready_ = true;
    VlessEncryptionAeadCipher cipher_ = VlessEncryptionAeadCipher::Aes256Gcm;
    size_t pending_read_context_size_ = 0;
    bool header_xor_from_context_ = false;
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
                          memory::ByteVector united_key,
                          std::optional<VlessEncryptionHeaderXor>
                              header_xor) noexcept;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;

private:
    net::awaitable<void> WritePlaintext(std::span<const uint8_t> data);
    [[nodiscard]] bool Rekey(std::span<const uint8_t> context) noexcept;

    transport::MultiBufferWriter& dst_;
    VlessEncryptionAead aead_;
    memory::ByteVector united_key_;
    std::optional<VlessEncryptionHeaderXor> header_xor_;
};

}  // namespace acpp::vless
