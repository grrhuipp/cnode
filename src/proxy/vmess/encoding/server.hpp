#pragma once

#include "body.hpp"
#include "../validator.hpp"
#include "../vmess_request.hpp"
#include "common/address_codec.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <array>
#include <memory>
#include <optional>
#include <string_view>

namespace vmess::encoding {

inline constexpr size_t kResponseHeaderSize = 38;
inline constexpr size_t kMaxRequestHeaderWireSize =
    42 + 38 + kMaxEncodedAddressSize + 15 + 4 + 16;

class RequestBodyReader final : public transport::MultiBufferReader {
public:
    RequestBodyReader(const VMessRequest& request, AsyncStream& stream);

    RequestBodyReader(const RequestBodyReader&) = delete;
    RequestBodyReader& operator=(const RequestBodyReader&) = delete;
    RequestBodyReader(RequestBodyReader&&) noexcept = default;
    RequestBodyReader& operator=(RequestBodyReader&&) noexcept = default;

    transport::CancellationSource& Cancellation() noexcept override {
        return stream_->Cancellation();
    }
    transport::EofAction ReadEofAction() const noexcept override {
        return is_udp_ ? transport::EofAction::WaitForPeer : stream_->ReadEofAction();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!is_udp_) {
            return decoder_.Read(*stream_);
        }
        return ReadUdpMultiBuffer();
    }

private:
    net::awaitable<buf::MultiBuffer> ReadUdpMultiBuffer();

    BodyDecoder decoder_;
    AsyncStream* stream_ = nullptr;
    bool is_udp_ = false;
    TargetAddress udp_target_;
};

// The response header is coalesced into the first body write.
class ResponseBodyWriter final : public transport::MultiBufferWriter {
public:
    ResponseBodyWriter(const VMessRequest& request,
                       const BodyKey& response,
                       AsyncStream& stream,
                       const std::array<uint8_t, kResponseHeaderSize>& response_header);

    ResponseBodyWriter(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter& operator=(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter(ResponseBodyWriter&&) noexcept = default;
    ResponseBodyWriter& operator=(ResponseBodyWriter&&) noexcept = default;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        return encoder_.WriteMultiBuffer(
            *stream_, std::move(mb), "VMess response write cancelled before start",
            response_header_, &header_sent_, &udp_target_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return encoder_.WriteBuffers(
            *stream_, buffers, "VMess response write cancelled before start",
            response_header_, &header_sent_);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return encoder_.WriteEOF(
            *stream_, "VMess response EOF cancelled before start",
            response_header_, &header_sent_);
    }

private:
    BodyEncoder encoder_;
    AsyncStream* stream_ = nullptr;
    TargetAddress udp_target_;
    std::array<uint8_t, kResponseHeaderSize> response_header_{};
    bool header_sent_ = false;
};

class ServerSession final {
public:
    explicit ServerSession(std::string_view tag);

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

    std::optional<RequestBodyReader> DecodeRequestBody(
        AsyncStream& stream);

    std::optional<ResponseBodyWriter> EncodeResponseBodyWithHeader(
        AsyncStream& stream);
private:
    std::string_view tag_;
    VMessRequest request_;
    bool request_set_ = false;
    std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential> header_user_;
    size_t required_header_bytes_ = 42;
    uint16_t header_length_ = 0;
    std::string_view header_failure_reason_;
};

}  // namespace vmess::encoding
