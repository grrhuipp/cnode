#pragma once

#include "acppnode/common/target_address.hpp"
#include "acppnode/proxy/shadowsocks/shadowsocks_protocol.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <expected>
#include <memory>

namespace acpp::ss {

// xray-core proxy/shadowsocks/client.go 对应的客户端握手与 reader/writer 入口。
[[nodiscard]] net::awaitable<std::expected<std::unique_ptr<transport::MultiBufferWriter>, ErrorCode>>
WriteTCPRequest(const TargetAddress& target,
                const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                AsyncStream& stream);

[[nodiscard]] net::awaitable<std::expected<std::unique_ptr<transport::MultiBufferReader>, ErrorCode>>
ReadTCPResponse(const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                AsyncStream& stream);

}  // namespace acpp::ss
