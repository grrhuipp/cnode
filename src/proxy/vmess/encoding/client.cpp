#include "client.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/address_codec.hpp"
#include "acppnode/common/byte_reader.hpp"
#include <openssl/rand.h>
#include <chrono>
#include <cstring>

namespace acpp::vmess::encoding {

namespace {

// Version, body IV/key, response header, options, security, reserved,
// command, largest address and FNV-1a checksum.
constexpr size_t kRequestHeaderMax = 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + kMaxEncodedAddressSize + 4;
// AuthID, sealed length, connection nonce, sealed header.
constexpr size_t kRequestPacketMax = 16 + 18 + 8 + kRequestHeaderMax + 16;
constexpr size_t kResponseHeaderMax = 1024;
constexpr uint8_t kClientOptions =
    Option::CHUNK_STREAM | Option::CHUNK_MASKING | Option::GLOBAL_PADDING;

tl::expected<size_t, ErrorCode> BuildRequestHeaderPacket(
    const MemoryAccount& user,
    const AES_KEY& auth_id_key,
    const TargetAddress& target,
    Security security,
    Command command,
    const BodyKey& request_body,
    uint8_t response_header,
    std::array<uint8_t, kRequestPacketMax>& packet) {
    std::array<uint8_t, kRequestHeaderMax> header{};
    ByteWriter writer(header.data(), header.size());
    writer.WriteU8(VERSION);
    writer.WriteBytes(request_body.iv.data(), request_body.iv.size());
    writer.WriteBytes(request_body.key.data(), request_body.key.size());
    writer.WriteU8(response_header);
    writer.WriteU8(kClientOptions);
    // High nibble: header padding length, always zero here.
    writer.WriteU8(static_cast<uint8_t>(security));
    writer.WriteU8(0);
    writer.WriteU8(static_cast<uint8_t>(command));
    if (!writer.Ok()) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    size_t header_len = writer.Position();
    const size_t address_size = EncodeAddressTo(
        target, header.data() + header_len, header.size() - header_len,
        AddressWireFormat::PortFirst);
    if (address_size == 0) {
        return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    header_len += address_size;
    const uint32_t checksum = FNV1a32(header.data(), header_len);
    header[header_len++] = static_cast<uint8_t>(checksum >> 24);
    header[header_len++] = static_cast<uint8_t>(checksum >> 16);
    header[header_len++] = static_cast<uint8_t>(checksum >> 8);
    header[header_len++] = static_cast<uint8_t>(checksum);

    const int64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint8_t* auth_id = packet.data();
    uint8_t* sealed_length = packet.data() + 16;
    uint8_t* connection_nonce = packet.data() + 34;
    uint8_t* sealed_header = packet.data() + 42;
    GenerateAuthID(auth_id_key, timestamp, auth_id);
    if (RAND_bytes(connection_nonce, 8) != 1) {
        return tl::unexpected(ErrorCode::INTERNAL);
    }
    const std::span<const uint8_t, 16> auth_id_view(auth_id, 16);
    const std::span<const uint8_t, 8> nonce_view(connection_nonce, 8);

    const auto length_key = RequestHeaderLengthKey(user.cmd_key, auth_id_view, nonce_view);
    const uint8_t length_plain[2] = {
        static_cast<uint8_t>(header_len >> 8),
        static_cast<uint8_t>(header_len),
    };
    if (!AES128GCMEncrypt(length_key.key.data(), length_key.nonce.data(),
                          auth_id, 16,
                          length_plain, sizeof(length_plain),
                          sealed_length, sealed_length + 2)) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    const auto payload_key = RequestHeaderPayloadKey(user.cmd_key, auth_id_view, nonce_view);
    if (!AES128GCMEncrypt(payload_key.key.data(), payload_key.nonce.data(),
                          auth_id, 16,
                          header.data(), header_len,
                          sealed_header, sealed_header + header_len)) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    return 42 + header_len + 16;
}

[[noreturn]] void ThrowResponseHeaderError() {
    throw IoSystemError(io_error::connection_reset, "VMess client read response header failed");
}

}  // namespace

ClientSession::SessionKeys ClientSession::GenerateKeys() {
    std::array<uint8_t, 33> random_bytes{};
    if (RAND_bytes(random_bytes.data(), static_cast<int>(random_bytes.size())) != 1) {
        throw IoSystemError(io_error::operation_aborted, "VMess client session random init failed");
    }
    SessionKeys keys;
    std::memcpy(keys.request.key.data(), random_bytes.data(), 16);
    std::memcpy(keys.request.iv.data(), random_bytes.data() + 16, 16);
    keys.response_header = random_bytes[32];
    keys.response = ResponseBodyKey(keys.request);
    return keys;
}

ClientSession::ClientSession(const MemoryAccount& user,
                             const AES_KEY& auth_id_key,
                             const TargetAddress& target,
                             Security security,
                             Command command)
    : user_(&user)
    , auth_id_key_(&auth_id_key)
    , target_(&target)
    , security_(security)
    , command_(command)
    , keys_(GenerateKeys())
    , request_encoder_(BodyOptions{security, kClientOptions, command},
                       keys_.request, keys_.request)
    , response_decoder_(BodyOptions{security, kClientOptions, command},
                        keys_.request, keys_.response) {}

net::awaitable<VMessHandshakeResult> ClientSession::EncodeRequestHeader(AsyncStream& stream) {
    if (request_header_sent_) {
        co_return VMessHandshakeResult{};
    }
    std::array<uint8_t, kRequestPacketMax> packet{};
    auto built = BuildRequestHeaderPacket(
        *user_, *auth_id_key_, *target_, security_, command_, keys_.request,
        keys_.response_header, packet);
    if (!built) {
        co_return tl::unexpected(built.error());
    }
    try {
        const std::array<net::const_buffer, 1> buffers{net::buffer(packet.data(), *built)};
        co_await stream.WriteBuffers(buffers);
    } catch (const IoSystemError&) {
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
    request_header_sent_ = true;
    user_ = nullptr;
    auth_id_key_ = nullptr;
    target_ = nullptr;
    co_return VMessHandshakeResult{};
}

net::awaitable<void> ClientSession::EncodeRequestBody(
    AsyncStream& stream,
    buf::MultiBuffer mb) {
    buf::MultiBuffer chunks;
    request_encoder_.Encode(mb, chunks);
    mb.clear();
    if (chunks.byte_size() != 0) {
        co_await stream.WriteMultiBuffer(std::move(chunks));
    }
}

net::awaitable<void> ClientSession::EncodeRequestBody(
    AsyncStream& stream,
    std::span<const net::const_buffer> buffers) {
    buf::MultiBuffer chunks;
    request_encoder_.Encode(buffers, chunks);
    if (chunks.byte_size() != 0) {
        co_await stream.WriteMultiBuffer(std::move(chunks));
    }
}

net::awaitable<void> ClientSession::EncodeRequestBodyEOF(AsyncStream& stream) {
    if (request_eof_sent_) {
        co_return;
    }
    buf::MultiBuffer chunks;
    request_encoder_.EncodeEnd(chunks);
    co_await stream.WriteMultiBuffer(std::move(chunks));
    request_eof_sent_ = true;
}

net::awaitable<void> ClientSession::DecodeResponseHeader(AsyncStream& stream) {
    if (response_header_sealed_.empty()) {
        if (!co_await response_decoder_.ReadExact(
                stream, response_length_, response_length_read_)) {
            ThrowResponseHeaderError();
        }
        const auto length_key = ResponseHeaderLengthKey(keys_.response.key, keys_.response.iv);
        std::array<uint8_t, 2> length{};
        size_t length_size = 0;
        if (!AES128GCMDecryptTo(length_key.key.data(), length_key.nonce.data(),
                                length_key.nonce.size(),
                                response_length_.data(), response_length_.size(),
                                nullptr, 0,
                                length.data(), length.size(), length_size) ||
            length_size != length.size()) {
            ThrowResponseHeaderError();
        }
        const size_t header_len = (static_cast<size_t>(length[0]) << 8) | length[1];
        if (header_len < 4 || header_len > kResponseHeaderMax) {
            ThrowResponseHeaderError();
        }
        response_header_sealed_.resize(header_len + 16);
    }

    if (!co_await response_decoder_.ReadExact(
            stream, response_header_sealed_, response_header_read_)) {
        ThrowResponseHeaderError();
    }
    const auto payload_key = ResponseHeaderPayloadKey(keys_.response.key, keys_.response.iv);
    const size_t header_len = response_header_sealed_.size() - 16;
    size_t opened = 0;
    if (!AES128GCMDecryptTo(payload_key.key.data(), payload_key.nonce.data(),
                            payload_key.nonce.size(),
                            response_header_sealed_.data(), response_header_sealed_.size(),
                            nullptr, 0,
                            response_header_sealed_.data(), header_len, opened) ||
        opened != header_len ||
        response_header_sealed_[0] != keys_.response_header) {
        ThrowResponseHeaderError();
    }
    response_header_received_ = true;
    memory::ByteVector{}.swap(response_header_sealed_);
}

net::awaitable<buf::MultiBuffer> ClientSession::DecodeResponse(AsyncStream& stream) {
    if (!response_header_received_) {
        co_await DecodeResponseHeader(stream);
    }
    co_return co_await response_decoder_.Read(stream);
}

}  // namespace acpp::vmess::encoding
