#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "transport/link.hpp"

#include "vless_encryption_crypto.hpp"
#include "vless_encryption_record.hpp"
#include "vless_encryption_xor.hpp"
#include "vless_buffered_reader.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>

namespace vless {

// 记录层只报告首个认证响应前的拒绝，不借用握手凭据。
// 宿主必须地址稳定，并比延迟读端活得更久；取消本身不构成拒绝。
struct VlessEncryptionTicketRejection {
    VlessEncryptionTicketRejection() noexcept = default;
    VlessEncryptionTicketRejection(const VlessEncryptionTicketRejection&) = delete;
    VlessEncryptionTicketRejection& operator=(const VlessEncryptionTicketRejection&) = delete;
    VlessEncryptionTicketRejection(VlessEncryptionTicketRejection&&) = delete;
    VlessEncryptionTicketRejection& operator=(VlessEncryptionTicketRejection&&) = delete;

    bool rejected = false;
};

// 0-RTT client read side: it is keyed by the server random that prefixes the
// first response bytes, which also seeds the header XOR when enabled.
struct VlessEncryptionDeferredRead {
    VlessEncryptionAeadCipher cipher = VlessEncryptionAeadCipher::Aes256Gcm;
    bool header_xor = false;
    VlessEncryptionTicketRejection* ticket_rejection = nullptr;
};
using VlessEncryptionReadKeys =
    std::variant<VlessEncryptionAead, VlessEncryptionDeferredRead>;

class VlessEncryptionReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return src_.ReadEofAction(); }

    // A deferred read side must not come with a header XOR; it derives its own.
    VlessEncryptionReader(transport::MultiBufferReader& src,
                          VlessEncryptionReadKeys keys,
                          const VlessEncryptionUnitedKey& united_key,
                          std::optional<VlessEncryptionHeaderXor>
                              header_xor) noexcept;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    [[nodiscard]] bool EnableRawRead() noexcept override;
    void RejectDeferredTicket() noexcept;

private:
    [[nodiscard]] VlessEncryptionAead& KeyDeferredRead(
        const VlessEncryptionDeferredRead& deferred);

    VlessBufferedReader src_;
    VlessEncryptionReadKeys keys_;
    VlessEncryptionUnitedKey united_key_;
    std::optional<VlessEncryptionHeaderXor> header_xor_;
    // Read progress survives a cancelled sniff continuation. Header XOR is
    // applied once, before waiting for the rest of the encrypted record.
    // `bytes_read_` tracks the server random until the read side is keyed.
    std::array<uint8_t, kVlessEncryptionCtrIvSize> server_random_{};
    std::array<uint8_t, kVlessEncryptionRecordHeaderSize> read_header_{};
    buf::ContiguousWriteBuffer read_record_;
    size_t header_read_ = 0;
    size_t bytes_read_ = 0;
    size_t encrypted_size_ = 0;
    bool raw_read_ = false;
    VlessEncryptionTicketRejection* unverified_ticket_ = nullptr;
};

class VlessEncryptionWriter final : public transport::MultiBufferWriter {
public:
    VlessEncryptionWriter(transport::MultiBufferWriter& dst,
                          VlessEncryptionAead aead,
                          const VlessEncryptionUnitedKey& united_key,
                          std::optional<VlessEncryptionHeaderXor>
                              header_xor) noexcept;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;
    bool WriteShutdownClosesLink() const noexcept override {
        return dst_.WriteShutdownClosesLink();
    }

private:
    net::awaitable<void> WritePlaintext(std::span<const uint8_t> data);

    transport::MultiBufferWriter& dst_;
    VlessEncryptionAead aead_;
    VlessEncryptionUnitedKey united_key_;
    std::optional<VlessEncryptionHeaderXor> header_xor_;
};

}  // namespace vless
