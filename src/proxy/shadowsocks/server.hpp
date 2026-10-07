#pragma once

#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/target_address.hpp"
#include "shadowsocks_protocol.hpp"
#include "validator.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <expected>
#include <memory>
#include <string_view>
#include <utility>

namespace acpp::ss {

struct ReadTCPSessionResult {
    std::shared_ptr<const proxyman::inbound::UserStore::ShadowsocksCredential> user_ref;
    const proxyman::inbound::UserStore::ShadowsocksCredential* user = nullptr;
    TargetAddress target;
    InitialPayload initial_payload;
    std::unique_ptr<transport::MultiBufferReader> body_reader;
    KeyBytes request_salt;

    void SetUser(
        std::shared_ptr<const proxyman::inbound::UserStore::ShadowsocksCredential> value) noexcept {
        user_ref = std::move(value);
        user = user_ref.get();
    }
};

// xray-core proxy/shadowsocks/server.go 对应的服务器端握手与 body reader/writer 入口。
[[nodiscard]] net::awaitable<std::expected<ReadTCPSessionResult, ErrorCode>>
ReadTCPSession(AsyncStream& stream,
               Validator& validator,
               const SsCipherInfo& cipher_info,
               std::string_view tag,
               size_t& last_matched_index);

[[nodiscard]] std::expected<std::unique_ptr<transport::MultiBufferWriter>, ErrorCode>
WriteTCPResponse(const proxyman::inbound::UserStore::ShadowsocksCredential& user,
                 const SsCipherInfo& cipher_info,
                 const KeyBytes& request_salt,
                 AsyncStream& stream);

}  // namespace acpp::ss
