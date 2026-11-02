#pragma once

#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/target_address.hpp"
#include "shadowsocks_protocol.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <tl/expected.hpp>
#include <memory>
#include <string_view>
#include <utility>

namespace acpp::ss {

struct ReadTCPSessionResult {
    std::shared_ptr<const proxyman::inbound::UserStore::ShadowsocksCredential> user;
    TargetAddress target;
    InitialPayload initial_payload;
    std::unique_ptr<transport::MultiBufferReader> body_reader;
    KeyBytes request_salt;
};

// xray-core proxy/shadowsocks/server.go 对应的服务器端握手与 body reader/writer 入口。
[[nodiscard]] net::awaitable<tl::expected<ReadTCPSessionResult, ErrorCode>>
ReadTCPSession(AsyncStream& stream,
               const SsCipherInfo& cipher_info,
               std::string_view tag,
               size_t& last_matched_index);

[[nodiscard]] tl::expected<std::unique_ptr<transport::MultiBufferWriter>, ErrorCode>
WriteTCPResponse(const proxyman::inbound::UserStore::ShadowsocksCredential& user,
                 const SsCipherInfo& cipher_info,
                 const KeyBytes& request_salt,
                 AsyncStream& stream);

}  // namespace acpp::ss
