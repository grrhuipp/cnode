#pragma once

#include "../validator.hpp"
#include "../vmess_request.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <memory>
#include <optional>
#include <string_view>

namespace acpp::vmess::encoding {

class ServerSession final {
public:
    ServerSession(const TimedUserValidator& validator, std::string_view tag);

    std::pair<std::optional<VMessRequest>, size_t> DecodeRequestHeader(
        const uint8_t* data,
        size_t len,
        uint64_t trace_conn_id = 0);

    void SetRequest(VMessRequest request);

    net::awaitable<bool> EncodeResponseHeader(AsyncStream& stream);

    std::unique_ptr<transport::MultiBufferReader> DecodeRequestBody(
        AsyncStream& stream);

    std::unique_ptr<transport::MultiBufferWriter> EncodeResponseBody(
        AsyncStream& stream);

    std::unique_ptr<transport::MultiBufferWriter> EncodeResponseBodyWithHeader(
        AsyncStream& stream);

private:
    const TimedUserValidator* validator_ = nullptr;
    std::string tag_;
    VMessRequest request_;
    bool request_set_ = false;
};

}  // namespace acpp::vmess::encoding
