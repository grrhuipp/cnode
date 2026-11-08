#pragma once

#include "../validator.hpp"
#include "../vmess_request.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <memory>
#include <optional>
#include <string_view>

namespace vmess::encoding {

class ServerSession final {
public:
    ServerSession(const TimedUserValidator& validator, std::string_view tag);

    // Re-submit the same growing prefix until complete. RequiredHeaderBytes()
    // is the next structured boundary; zero with no request is terminal failure.
    // This step authenticates/decrypts syntax only. The inbound handshake must
    // await validator.RegisterSessionIfNew before accepting or dispatching it.
    std::pair<std::optional<VMessRequest>, size_t> DecodeRequestHeader(
        const uint8_t* data,
        size_t len,
        uint64_t trace_conn_id = 0);
    [[nodiscard]] size_t RequiredHeaderBytes() const noexcept { return required_header_bytes_; }
    [[nodiscard]] std::string_view HeaderFailureReason() const noexcept { return header_failure_reason_; }
    [[nodiscard]] const VMessRequest* AuthenticatedRejectedHeader() const noexcept {
        return !request_set_ && request_.user ? &request_ : nullptr;
    }

    void SetRequest(VMessRequest request);

    std::unique_ptr<transport::MultiBufferReader> DecodeRequestBody(
        AsyncStream& stream,
        const TargetAddress& udp_target);
    std::unique_ptr<transport::MultiBufferReader> DecodeRequestBody(
        AsyncStream& stream) {
        return DecodeRequestBody(stream, request_.target);
    }

    std::unique_ptr<transport::MultiBufferWriter> EncodeResponseBodyWithHeader(
        AsyncStream& stream,
        const TargetAddress& udp_target);
    std::unique_ptr<transport::MultiBufferWriter> EncodeResponseBodyWithHeader(
        AsyncStream& stream) {
        return EncodeResponseBodyWithHeader(stream, request_.target);
    }
private:
    const TimedUserValidator* validator_ = nullptr;
    std::string_view tag_;
    VMessRequest request_;
    bool request_set_ = false;
    std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential> header_user_;
    size_t required_header_bytes_ = 42;
    uint16_t header_length_ = 0;
    std::string_view header_failure_reason_;
};

}  // namespace vmess::encoding
