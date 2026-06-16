#pragma once

#include "vless_encryption.hpp"
#include "vless_encryption_record.hpp"
#include "vless_encryption_xor.hpp"
#include "vless_io_util.hpp"

#include "acppnode/common/asio_types.hpp"

#include <optional>
#include <vector>

namespace acpp::vless {

struct VlessEncryptionRuntime {
    std::vector<uint8_t> united_key;
    VlessEncryptionAead read_aead;
    VlessEncryptionAead write_aead;
    std::optional<VlessEncryptionHeaderXor> read_xor;
    std::optional<VlessEncryptionHeaderXor> write_xor;
};

[[nodiscard]] net::awaitable<std::optional<VlessEncryptionRuntime>>
RunVlessEncryptionClient1RttHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config);

[[nodiscard]] net::awaitable<std::optional<VlessEncryptionRuntime>>
RunVlessEncryptionServer1RttHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config);

}  // namespace acpp::vless
