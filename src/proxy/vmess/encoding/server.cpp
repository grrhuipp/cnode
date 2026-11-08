#include "server.hpp"
#include "body.hpp"
#include "common/buffer_util.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "common/byte_reader.hpp"
#include "common/address_codec.hpp"
#include "infra/log.hpp"
#include "../udp_datagram.hpp"
#include <asio/this_coro.hpp>
#include <openssl/mem.h>
#include <algorithm>
#include <cstring>
#include <new>

namespace vmess::encoding {

namespace {

// AuthID (16) + sealed length (2 + 16) + connection nonce (8).
constexpr size_t kRequestHeaderPrefixSize = 16 + 18 + 8;
constexpr size_t kResponseHeaderSize = 38;

[[nodiscard]] bool IsSupportedSecurity(Security security) noexcept {
    switch (security) {
    case Security::AES_128_GCM:
    case Security::CHACHA20_POLY1305:
    case Security::NONE:
    case Security::ZERO:
        return true;
    default:
        return false;
    }
}

bool ParseDecryptedHeader(const uint8_t* data, size_t len,
                          uint64_t trace_conn_id,
                          VMessRequest& request) {
    static constexpr size_t kFixedHeaderSize = 38;
    if (len < kFixedHeaderSize + 4) {
        LOG_CONN_TRACE(trace_conn_id, "decrypted header too short len={} min={}",
                         len,
                         kFixedHeaderSize + 4);
        return false;
    }

    ByteReader reader(data, len);

    request.version = reader.ReadU8();
    if (!reader.Ok() || request.version != VERSION) {
        LOG_CONN_DEBUG(trace_conn_id, "unsupported version {}", request.version);
        return false;
    }

    auto iv_span = reader.ReadBytes(16);
    if (!reader.Ok()) return false;
    std::memcpy(request.body_iv.data(), iv_span.data(), 16);

    auto key_span = reader.ReadBytes(16);
    if (!reader.Ok()) return false;
    std::memcpy(request.body_key.data(), key_span.data(), 16);

    request.response_header = reader.ReadU8();
    request.options = reader.ReadU8();

    uint8_t ps = reader.ReadU8();
    request.padding_len = (ps >> 4) & 0x0F;
    request.security = static_cast<Security>(ps & 0x0F);
    // Reject before routing: an unknown body security can never be framed.
    if (!IsSupportedSecurity(request.security)) {
        LOG_CONN_DEBUG(trace_conn_id, "unsupported security {}", static_cast<int>(request.security));
        return false;
    }

    reader.Skip(1);

    request.command = static_cast<Command>(reader.ReadU8());
    if (!reader.Ok()) return false;

    if (request.command == Command::Mux) {
        request.target = TargetAddress("v1.mux.cool", 0);
    } else if (request.command == Command::TCP || request.command == Command::UDP) {
        auto address = DecodeAddress(
            std::span(data + reader.Position(), reader.Remaining()),
            AddressWireFormat::PortFirst,
            {.require_non_empty_domain = true, .allow_metadata = true});
        if (address.status != AddressDecodeStatus::Complete) return false;
        reader.Skip(address.consumed);
        request.target = std::move(address.target);
        request.forwarded = std::move(address.forwarded);
        if (!request.target.IsValid()) return false;
    } else {
        LOG_CONN_DEBUG(trace_conn_id, "unsupported command {}", static_cast<int>(request.command));
        return false;
    }

    reader.Skip(request.padding_len);
    if (!reader.Ok()) return false;

    size_t pos = reader.Position();
    if (pos + 4 != len) return false;

    uint32_t expected_fnv = FNV1a32(data, pos);
    uint32_t actual_fnv = reader.ReadU32BE();

    if (!reader.Ok() || expected_fnv != actual_fnv) {
        LOG_CONN_DEBUG(trace_conn_id, "request header checksum mismatch");
        return false;
    }

    LOG_CONN_TRACE(trace_conn_id, "header decoded target={} command={} security={} options={:#04x} padding={}",
                     request.target,
                     static_cast<int>(request.command),
                     static_cast<int>(request.security),
                     static_cast<int>(request.options),
                     request.padding_len);

    return true;
}

// `packet` starts at the AuthID and holds the whole sealed header.
bool OpenRequestHeader(const uint8_t* packet,
                       std::shared_ptr<const proxyman::inbound::UserStore::VmessCredential>& user,
                       size_t header_len,
                       uint64_t trace_conn_id,
                       VMessRequest& request,
                       std::string_view& failure_reason) {
    const auto key = RequestHeaderPayloadKey(
        user->cmd_key,
        std::span<const uint8_t, 16>(packet, 16),
        std::span<const uint8_t, 8>(packet + 34, 8));
    memory::ByteVector plain(header_len);
    struct PlainCleanseGuard {
        memory::ByteVector& buf;
        ~PlainCleanseGuard() noexcept {
            if (!buf.empty()) OPENSSL_cleanse(buf.data(), buf.size());
        }
    } cleanse_plain{plain};
    size_t written = 0;
    if (!AES128GCMDecryptTo(key.key.data(), key.nonce.data(), key.nonce.size(),
            packet + kRequestHeaderPrefixSize, header_len + 16, packet, 16,
            plain.data(), plain.size(), written)) {
        failure_reason = "authentication failed: request header integrity check failed";
        LOG_CONN_DEBUG(trace_conn_id, "request header authentication failed");
        return false;
    }
    request.user = std::move(user);
    if (!ParseDecryptedHeader(plain.data(), written, trace_conn_id, request)) {
        failure_reason = "invalid authenticated request header";
        return false;
    }
    return true;
}

[[nodiscard]] BodyOptions RequestBodyOptions(const VMessRequest& request) noexcept {
    return BodyOptions{request.security, request.options, request.command};
}

[[nodiscard]] BodyKey RequestBodyKey(const VMessRequest& request) noexcept {
    return BodyKey{request.body_key, request.body_iv};
}

bool BuildResponseHeader(const VMessRequest& request,
                         const BodyKey& response,
                         std::array<uint8_t, kResponseHeaderSize>& out) {
    // xray-core does not echo request body options in the response header.
    const uint8_t payload[4] = {request.response_header, 0, 0, 0};
    const uint8_t length[2] = {0, sizeof(payload)};

    const auto length_key = ResponseHeaderLengthKey(response.key, response.iv);
    if (!AES128GCMEncrypt(length_key.key.data(), length_key.nonce.data(), nullptr, 0,
                          length, sizeof(length), out.data(), out.data() + 2)) {
        return false;
    }
    const auto payload_key = ResponseHeaderPayloadKey(response.key, response.iv);
    return AES128GCMEncrypt(payload_key.key.data(), payload_key.nonce.data(), nullptr, 0,
                            payload, sizeof(payload), out.data() + 18, out.data() + 22);
}

class RequestBodyReader final
    : public memory::ThreadAllocated
    , public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return stream_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override {
        return is_udp_ ? transport::EofAction::WaitForPeer : stream_.ReadEofAction();
    }

    RequestBodyReader(const VMessRequest& request,
                      AsyncStream& stream,
                      TargetAddress udp_target)
        : decoder_(RequestBodyOptions(request), RequestBodyKey(request), RequestBodyKey(request))
        , stream_(stream)
        , is_udp_(request.command == Command::UDP)
        , udp_target_(std::move(udp_target)) {}

    RequestBodyReader(const RequestBodyReader&) = delete;
    RequestBodyReader& operator=(const RequestBodyReader&) = delete;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        auto mb = co_await decoder_.Read(stream_);
        if (is_udp_ && mb.byte_size() != 0 &&
            !buf::SetUdpTarget(mb, udp_target_)) {
            throw std::bad_alloc();
        }
        co_return mb;
    }

private:
    BodyDecoder decoder_;
    AsyncStream& stream_;
    bool is_udp_ = false;
    TargetAddress udp_target_;
};

// The response header is coalesced into the first body write.
class ResponseBodyWriter final
    : public memory::ThreadAllocated
    , public transport::MultiBufferWriter {
public:
    ResponseBodyWriter(const VMessRequest& request,
                       const BodyKey& response,
                       AsyncStream& stream,
                       TargetAddress udp_target,
                       const std::array<uint8_t, kResponseHeaderSize>& response_header)
        : encoder_(RequestBodyOptions(request), RequestBodyKey(request), response)
        , stream_(stream)
        , udp_target_(std::move(udp_target))
        , response_header_(response_header) {}

    ResponseBodyWriter(const ResponseBodyWriter&) = delete;
    ResponseBodyWriter& operator=(const ResponseBodyWriter&) = delete;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        encoder_.CheckWritable();
        if ((co_await net::this_coro::cancellation_state).cancelled() !=
            net::cancellation_type::none) {
            throw IoSystemError(io_error::operation_aborted,
                                "VMess response write cancelled before start");
        }
        bool frame_generated = false;
        try {
            if (encoder_.PacketMode()) {
                ::vmess::ValidateFixedUdpDatagram(mb, udp_target_);
            }
            buf::MultiBuffer chunks;
            encoder_.Encode(mb, chunks);
            frame_generated = chunks.byte_size() != 0;
            mb.clear();
            co_await Flush(std::move(chunks));
        } catch (const transport::WriteClosed&) {
            encoder_.Finish();
            throw;
        } catch (...) {
            if (frame_generated || encoder_.Failed()) {
                encoder_.Abort();
                stream_.CloseAbortive();
            }
            throw;
        }
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        encoder_.CheckWritable();
        if ((co_await net::this_coro::cancellation_state).cancelled() !=
            net::cancellation_type::none) {
            throw IoSystemError(io_error::operation_aborted,
                                "VMess response write cancelled before start");
        }
        bool frame_generated = false;
        try {
            buf::MultiBuffer chunks;
            encoder_.Encode(buffers, chunks);
            frame_generated = chunks.byte_size() != 0;
            co_await Flush(std::move(chunks));
        } catch (const transport::WriteClosed&) {
            encoder_.Finish();
            throw;
        } catch (...) {
            if (frame_generated || encoder_.Failed()) {
                encoder_.Abort();
                stream_.CloseAbortive();
            }
            throw;
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (encoder_.Finished()) co_return;
        encoder_.CheckWritable();
        if ((co_await net::this_coro::cancellation_state).cancelled() !=
            net::cancellation_type::none) {
            throw IoSystemError(io_error::operation_aborted,
                                "VMess response EOF cancelled before start");
        }
        bool frame_generated = false;
        try {
            std::array<uint8_t, 128> eof_chunk{};
            const size_t eof_len = encoder_.EncodeEndTo(eof_chunk);
            if (eof_len == 0) co_return;
            frame_generated = true;
            if (!header_sent_) {
                header_sent_ = true;
                const std::array<net::const_buffer, 2> buffers{
                    net::buffer(response_header_),
                    net::buffer(eof_chunk.data(), eof_len),
                };
                co_await stream_.WriteBuffers(buffers);
            } else {
                const std::array<net::const_buffer, 1> buffers{
                    net::buffer(eof_chunk.data(), eof_len),
                };
                co_await stream_.WriteBuffers(buffers);
            }
        } catch (const transport::WriteClosed&) {
            encoder_.Finish();
            throw;
        } catch (...) {
            if (frame_generated || encoder_.Failed()) {
                encoder_.Abort();
                stream_.CloseAbortive();
            }
            throw;
        }
    }

private:
    net::awaitable<void> Flush(buf::MultiBuffer chunks) {
        if (chunks.byte_size() == 0) {
            co_return;
        }
        if (!header_sent_) {
            header_sent_ = true;
            ConstBufferSpanBuilder<1 + buf::MultiBuffer::kInlineCapacity> framed;
            framed.Append(net::buffer(response_header_));
            framed.AppendMultiBuffer(chunks);
            co_await stream_.WriteBuffers(framed.Span());
            chunks.clear();
            co_return;
        }
        co_await stream_.WriteMultiBuffer(std::move(chunks));
    }

    BodyEncoder encoder_;
    AsyncStream& stream_;
    TargetAddress udp_target_;
    std::array<uint8_t, kResponseHeaderSize> response_header_;
    bool header_sent_ = false;
};

}  // namespace

ServerSession::ServerSession(const TimedUserValidator& validator, std::string_view tag)
    : validator_(&validator)
    , tag_(tag) {}

std::pair<std::optional<VMessRequest>, size_t> ServerSession::DecodeRequestHeader(
    const uint8_t* data, size_t len, uint64_t trace_conn_id) {
    if (len < kRequestHeaderPrefixSize) {
        required_header_bytes_ = kRequestHeaderPrefixSize;
        return {std::nullopt, 0};
    }
    const std::span<const uint8_t, 16> auth_id(data, 16);
    if (!header_user_) {
        int64_t timestamp = 0;
        header_user_ = validator_->FindByAuthIDForTag(tag_, auth_id.data(), timestamp);
        if (!header_user_) {
            header_failure_reason_ = "authentication failed: no acceptable AuthID";
            required_header_bytes_ = 0;
            return {std::nullopt, 0};
        }
        const auto key = RequestHeaderLengthKey(
            header_user_->cmd_key, auth_id, std::span<const uint8_t, 8>(data + 34, 8));
        std::array<uint8_t, 2> plain{};
        size_t written = 0;
        if (!AES128GCMDecryptTo(key.key.data(), key.nonce.data(), key.nonce.size(),
                data + 16, 18, auth_id.data(), auth_id.size(),
                plain.data(), plain.size(), written) ||
            written != plain.size()) {
            header_failure_reason_ = "authentication failed: header length integrity check failed";
            header_user_.reset();
            required_header_bytes_ = 0;
            return {std::nullopt, 0};
        }
        header_length_ = (static_cast<uint16_t>(plain[0]) << 8) | plain[1];
        constexpr size_t kMinRequestHeaderLength = 38 + 4;
        constexpr size_t kMaxRequestHeaderLength = 38 + kMaxEncodedAddressSize + 15 + 4;
        if (header_length_ < kMinRequestHeaderLength ||
            header_length_ > kMaxRequestHeaderLength) {
            header_failure_reason_ = "invalid authenticated request header";
            header_user_.reset();
            required_header_bytes_ = 0;
            return {std::nullopt, 0};
        }
        required_header_bytes_ =
            kRequestHeaderPrefixSize + static_cast<size_t>(header_length_) + 16;
    }
    if (len < required_header_bytes_) return {std::nullopt, 0};

    VMessRequest request;
    const size_t consumed = required_header_bytes_;
    required_header_bytes_ = 0;
    if (!OpenRequestHeader(data, header_user_, header_length_, trace_conn_id, request,
                           header_failure_reason_)) {
        if (request.user) request_ = std::move(request);
        header_user_.reset();
        LOG_CONN_DEBUG(trace_conn_id, "request rejected > {}", header_failure_reason_);
        return {std::nullopt, 0};
    }
    return {std::move(request), consumed};
}

void ServerSession::SetRequest(VMessRequest request) {
    request_ = std::move(request);
    request_set_ = true;
}

std::unique_ptr<transport::MultiBufferReader> ServerSession::DecodeRequestBody(
    AsyncStream& stream,
    const TargetAddress& udp_target) {
    if (!request_set_) {
        return nullptr;
    }
    try {
        return std::make_unique<RequestBodyReader>(request_, stream, udp_target);
    } catch (...) {
        return nullptr;
    }
}

std::unique_ptr<transport::MultiBufferWriter> ServerSession::EncodeResponseBodyWithHeader(
    AsyncStream& stream,
    const TargetAddress& udp_target) {
    if (!request_set_) {
        return nullptr;
    }
    try {
        const BodyKey response = ResponseBodyKey(RequestBodyKey(request_));
        std::array<uint8_t, kResponseHeaderSize> response_header{};
        if (!BuildResponseHeader(request_, response, response_header)) {
            return nullptr;
        }
        return std::make_unique<ResponseBodyWriter>(
            request_, response, stream, udp_target, response_header);
    } catch (...) {
        return nullptr;
    }
}

}  // namespace vmess::encoding
