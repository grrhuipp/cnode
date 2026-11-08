#pragma once

#include "../account.hpp"
#include "body.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <openssl/aes.h>

#include <array>
#include <tl/expected.hpp>
#include <span>

namespace vmess::encoding {

using VMessHandshakeResult = tl::expected<void, ErrorCode>;

class ClientSession final {
public:
    // `user`, its prepared `auth_id_key` and `target` are borrowed until the
    // request header is sent.
    ClientSession(const MemoryAccount& user,
                  const AES_KEY& auth_id_key,
                  const TargetAddress& target,
                  Security security,
                  Command command,
                  ForwardedMetadataView forwarded = {});

    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;

    net::awaitable<VMessHandshakeResult> EncodeRequestHeader(AsyncStream& stream);
    net::awaitable<void> EncodeRequestBody(
        AsyncStream& stream,
        buf::MultiBuffer mb);
    net::awaitable<void> EncodeRequestBody(
        AsyncStream& stream,
        std::span<const net::const_buffer> buffers);
    net::awaitable<void> EncodeRequestBodyEOF(AsyncStream& stream);
    // Authenticates the response header on first use, then returns body
    // chunks; empty at the end of the response body.
    net::awaitable<buf::MultiBuffer> DecodeResponse(AsyncStream& stream);

private:
    struct SessionKeys {
        BodyKey request;
        BodyKey response;
        uint8_t response_header = 0;
    };

    [[nodiscard]] static SessionKeys GenerateKeys();
    net::awaitable<void> DecodeResponseHeader(AsyncStream& stream);

    const MemoryAccount* user_ = nullptr;
    const AES_KEY* auth_id_key_ = nullptr;
    const TargetAddress* target_ = nullptr;
    ForwardedMetadataView forwarded_{};
    Security security_ = Security::AES_128_GCM;
    Command command_ = Command::TCP;
    SessionKeys keys_;
    bool request_header_sent_ = false;
    bool request_eof_sent_ = false;
    BodyEncoder request_encoder_;
    BodyDecoder response_decoder_;
    // Response header progress survives a cancelled read.
    std::array<uint8_t, 18> response_length_{};
    size_t response_length_read_ = 0;
    memory::ByteVector response_header_sealed_;
    size_t response_header_read_ = 0;
    bool response_header_received_ = false;
};

}  // namespace vmess::encoding
