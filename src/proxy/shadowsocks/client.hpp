#pragma once

#include "acppnode/common/target_address.hpp"
#include "shadowsocks_protocol.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <expected>
#include <memory>
#include <span>
#include <vector>

namespace acpp::ss {

struct WriteTCPRequestResult {
    std::unique_ptr<transport::MultiBufferWriter> request_writer;
    KeyBytes request_salt;
};

// xray-core proxy/shadowsocks/client.go 对应的客户端握手与 reader/writer 入口。
[[nodiscard]] net::awaitable<std::expected<WriteTCPRequestResult, ErrorCode>>
WriteTCPRequest(const TargetAddress& target,
                const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                std::span<const KeyBytes> psk_chain,
                AsyncStream& stream);

[[nodiscard]] net::awaitable<std::expected<std::unique_ptr<transport::MultiBufferReader>, ErrorCode>>
ReadTCPResponse(const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                const KeyBytes& request_salt,
                AsyncStream& stream);

}  // namespace acpp::ss
