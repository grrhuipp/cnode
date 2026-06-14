#pragma once

#include "acppnode/proxy/vmess/account.hpp"
#include "../vmess_cipher.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <array>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

namespace acpp::vmess::encoding {

using VMessHandshakeResult = std::expected<void, ErrorCode>;

class ClientSession final {
public:
    ClientSession(const MemoryAccount& user,
                  const TargetAddress& target,
                  Security security,
                  uint8_t options = 0);

    net::awaitable<VMessHandshakeResult> EncodeRequestHeader(AsyncStream& stream);
    net::awaitable<VMessHandshakeResult> EncodeRequestBody(
        AsyncStream& stream,
        std::span<const uint8_t> payload);
    net::awaitable<void> EncodeRequestBody(
        AsyncStream& stream,
        buf::MultiBuffer mb);
    net::awaitable<void> EncodeRequestBodyEOF(AsyncStream& stream);
    net::awaitable<bool> DecodeResponseHeader(AsyncStream& stream);
    net::awaitable<buf::MultiBuffer> DecodeResponseBody(AsyncStream& stream);

private:
    MemoryAccount user_;
    TargetAddress target_;
    Security security_ = Security::AES_128_GCM;
    std::array<uint8_t, 16> request_body_key_{};
    std::array<uint8_t, 16> request_body_iv_{};
    uint8_t response_header_ = 0;
    uint8_t options_ = 0;
    std::array<uint8_t, 16> response_key_{};
    std::array<uint8_t, 16> response_iv_{};
    std::array<uint8_t, 16> request_key_{};
    std::array<uint8_t, 16> request_iv_{};
    bool sent_ = false;
    bool response_header_initialized_ = false;
    bool eof_sent_ = false;
};

}  // namespace acpp::vmess::encoding
