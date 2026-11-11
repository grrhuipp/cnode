#include "proxy/shadowsocks/ss_outbound.hpp"
#include "proxy/shadowsocks/ss_stream.hpp"

namespace proxy::shadowsocks::outbound {
class Handler final : public ::Outbound {
public:
    explicit Handler(std::shared_ptr<const PreparedSettings> prepared);

    ~Handler() noexcept override = default;

    ::net::awaitable<::OutboundProcessResult> Process(
        ::session::Context& ctx,
        ::transport::Link inbound,
        ::OutboundDialer& dialer,
        const ::TimeoutsConfig& timeouts,
        ::StatsShard& stats,
        const ::RelayConfig& relay_config,
        ::buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

private:
    std::shared_ptr<const PreparedSettings> prepared_;
};
}  // namespace proxy::shadowsocks::outbound
#include "common/scoped_cleanse.hpp"
#include "common/domain_name.hpp"
#include "common/ip_utils.hpp"
#include "core/constants.hpp"
#include "common/address_codec.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/byte_reader.hpp"
#include "proxy/uot/uot.hpp"
#include "proxy/handshake_errors.hpp"
#include "proxy/outbound_stream_endpoint.hpp"
#include "app/relay.hpp"
#include "app/proxyman/outbound/handler.hpp"
#include "infra/json.hpp"
#include "app/dns/dns.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "transport/link.hpp"
#include "transport/internet/outbound_target_builder.hpp"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <algorithm>
#include <cstring>
#include <new>
#include <optional>
#include <memory>
#include <span>
#include <type_traits>
#include <utility>
#include <variant>
#include <format>


namespace ss {

namespace {

using detail::MakeNonce;
using detail::ThrowSsWriteError;

}  // namespace


namespace {

bool WriteIdentityHeadersTo(const SsCipherInfo& cipher_info,
                            std::span<const KeyBytes> psk_chain,
                            std::span<const uint8_t> salt,
                            uint8_t* out,
                            size_t cap,
                            size_t& written) {
    written = 0;
    if (psk_chain.size() <= 1) {
        return true;
    }
    if (!Is2022AesCipher(cipher_info.type)) {
        return false;
    }

    for (size_t i = 0; i + 1 < psk_chain.size(); ++i) {
        const auto& current = psk_chain[i];
        const auto& next = psk_chain[i + 1];
        if (current.size < cipher_info.key_size || next.size < cipher_info.key_size) {
            return false;
        }

        std::array<uint8_t, 32> block_key{};
        if (!Derive2022IdentitySubkey(
                current.data(), cipher_info.key_size,
                salt.data(), salt.size(), block_key.data())) {
            return false;
        }

        std::array<uint8_t, 16> user_hash{};
        if (!Hash2022Psk(next.span(), std::span<uint8_t, 16>(user_hash))) {
            OPENSSL_cleanse(block_key.data(), block_key.size());
            return false;
        }

        std::array<uint8_t, 16> encrypted{};
        const bool ok = AesBlocksCrypt<16>(
            std::span<const uint8_t>(block_key.data(), cipher_info.key_size),
            std::span<const uint8_t, 16>(user_hash),
            std::span<uint8_t, 16>(encrypted),
            true);
        OPENSSL_cleanse(block_key.data(), block_key.size());
        if (!ok) {
            return false;
        }
        if (written + encrypted.size() > cap) {
            return false;
        }
        std::memcpy(out + written, encrypted.data(), encrypted.size());
        written += encrypted.size();
    }
    return true;
}

tl::expected<void, ErrorCode> AppendHandshakeRecord(
    SsAeadCipher& cipher, uint64_t nonce, std::span<const uint8_t> plaintext, buf::Buffer& output) {
    if (output.Available() < plaintext.size() + SsAeadCipher::kTagSize)
        return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    const auto nonce_bytes = MakeNonce(nonce);
    if (!cipher.Encrypt(nonce_bytes.data(), plaintext.data(), plaintext.size(), output.Tail().data()))
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    output.Produce(static_cast<uint32_t>(plaintext.size() + SsAeadCipher::kTagSize));
    return {};
}

struct PreparedTCPRequestHandshake {
    buf::MultiBuffer handshake_mb;
    std::optional<SsAeadCipher> write_cipher;
    KeyBytes request_salt;
};

tl::expected<PreparedTCPRequestHandshake, ErrorCode>
PrepareTCPRequest2022(const TargetAddress& target,
                      const SsCipherInfo& cipher_info,
                      const KeyBytes& master_key,
                      std::span<const KeyBytes> psk_chain,
                      ForwardedMetadataView forwarded) {
    if (cipher_info.salt_size > KeyBytes::kMaxSize ||
        cipher_info.key_size > KeyBytes::kMaxSize ||
        master_key.size < cipher_info.key_size) {
        return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    if (psk_chain.empty()) {
        psk_chain = std::span<const KeyBytes>(&master_key, 1);
    }

    std::array<uint8_t, kMaxEncodedAddressSize> addr_bytes{};
    const size_t addr_size = EncodeAddressTo(
        target, addr_bytes.data(), addr_bytes.size(), AddressWireFormat::Socks5, forwarded);
    if (addr_size == 0) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    constexpr size_t kPaddingLen = 1;
    const size_t variable_len = addr_size + 2 + kPaddingLen;
    if (variable_len > kSs2022MaxChunkPayload) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    PreparedTCPRequestHandshake prepared;
    prepared.request_salt.size = cipher_info.salt_size;
    if (RAND_bytes(prepared.request_salt.data(),
                   static_cast<int>(prepared.request_salt.size)) != 1) {
        return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    std::array<uint8_t, 32> write_subkey{};
    ScopedCleanse cleanse_write_subkey{write_subkey};
    if (!Derive2022Subkey(master_key.data(), cipher_info.key_size,
                          prepared.request_salt.data(), prepared.request_salt.size,
                          write_subkey.data())) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    std::array<uint8_t, kSs2022RequestFixedHeaderSize> fixed_plain{};
    fixed_plain[0] = 0;
    StoreU64BE(fixed_plain.data() + 1, UnixSecondsNow());
    StoreU16BE(fixed_plain.data() + 9, static_cast<uint16_t>(variable_len));

    constexpr size_t kMaxVariablePlain =
        kMaxEncodedAddressSize + 2 + kPaddingLen;
    std::array<uint8_t, kMaxVariablePlain> variable_plain{};
    std::memcpy(variable_plain.data(), addr_bytes.data(), addr_size);
    StoreU16BE(variable_plain.data() + addr_size, static_cast<uint16_t>(kPaddingLen));
    if (RAND_bytes(variable_plain.data() + addr_size + 2, static_cast<int>(kPaddingLen)) != 1) {
        OPENSSL_cleanse(write_subkey.data(), write_subkey.size());
        return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    prepared.write_cipher.emplace(cipher_info.type, write_subkey.data(), cipher_info.key_size);
    OPENSSL_cleanse(write_subkey.data(), write_subkey.size());
    const size_t handshake_size =
        prepared.request_salt.size +
        (psk_chain.size() > 0 ? (psk_chain.size() - 1) * 16 : 0) +
        fixed_plain.size() + SsAeadCipher::kTagSize +
        variable_len + SsAeadCipher::kTagSize;
    if (handshake_size > buf::Buffer::kSize) {
        return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    buf::BufferGuard handshake{buf::Buffer::New()};
    if (!handshake) {
        return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    std::memcpy(handshake->Tail().data(),
                prepared.request_salt.data(),
                prepared.request_salt.size);
    handshake->Produce(static_cast<uint32_t>(prepared.request_salt.size));

    size_t identity_len = 0;
    if (!WriteIdentityHeadersTo(
            cipher_info,
            psk_chain,
            prepared.request_salt.span(),
            handshake->Tail().data(),
            handshake->Available(),
            identity_len)) {
        return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    handshake->Produce(static_cast<uint32_t>(identity_len));

    if (auto sealed = AppendHandshakeRecord(*prepared.write_cipher, 0, fixed_plain, *handshake); !sealed)
        return tl::unexpected(sealed.error());
    if (auto sealed = AppendHandshakeRecord(*prepared.write_cipher, 1,
            std::span(variable_plain).first(variable_len), *handshake); !sealed)
        return tl::unexpected(sealed.error());

    prepared.handshake_mb.push_back(std::move(handshake));
    return prepared;
}

tl::expected<PreparedTCPRequestHandshake, ErrorCode>
PrepareTCPRequestLegacy(const TargetAddress& target,
                        const SsCipherInfo& cipher_info,
                        const KeyBytes& master_key,
                        ForwardedMetadataView forwarded) {
    if (cipher_info.salt_size > KeyBytes::kMaxSize || cipher_info.key_size > KeyBytes::kMaxSize ||
        master_key.size < cipher_info.key_size) {
        return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    std::array<uint8_t, kMaxEncodedAddressSize> addr_bytes{};
    const size_t addr_size = EncodeAddressTo(
        target, addr_bytes.data(), addr_bytes.size(), AddressWireFormat::Socks5, forwarded);
    if (addr_size == 0 || addr_size > kMaxChunkPayload) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    std::array<uint8_t, 64> client_salt{};
    if (RAND_bytes(client_salt.data(), static_cast<int>(cipher_info.salt_size)) != 1) {
        return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    std::array<uint8_t, 64> write_subkey{};
    ScopedCleanse cleanse_legacy{client_salt, write_subkey};
    if (!DeriveSubkey(master_key.data(), cipher_info.key_size,
                      client_salt.data(), cipher_info.salt_size,
                      write_subkey.data())) {
        return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    buf::BufferGuard out{buf::Buffer::New()};
    if (!out) {
        return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }

    std::memcpy(out->Tail().data(), client_salt.data(), cipher_info.salt_size);
    out->Produce(static_cast<uint32_t>(cipher_info.salt_size));

    PreparedTCPRequestHandshake prepared;
    prepared.write_cipher.emplace(cipher_info.type, write_subkey.data(), cipher_info.key_size);
    OPENSSL_cleanse(write_subkey.data(), write_subkey.size());
    const size_t payload_size = addr_size;
    const uint8_t len_plain[2] = {
        static_cast<uint8_t>(payload_size >> 8),
        static_cast<uint8_t>(payload_size & 0xFF)
    };

    if (auto sealed = AppendHandshakeRecord(*prepared.write_cipher, 0, len_plain, *out); !sealed)
        return tl::unexpected(sealed.error());
    if (auto sealed = AppendHandshakeRecord(*prepared.write_cipher, 1,
            std::span(addr_bytes).first(addr_size), *out); !sealed)
        return tl::unexpected(sealed.error());

    prepared.handshake_mb.push_back(std::move(out));
    return prepared;
}

net::awaitable<tl::expected<WriteTCPRequestResult, ErrorCode>>
WriteTCPRequest2022(const TargetAddress& target,
                    const SsCipherInfo& cipher_info,
                    const KeyBytes& master_key,
                    std::span<const KeyBytes> psk_chain,
                    AsyncStream& stream,
                    ForwardedMetadataView forwarded) {
    buf::MultiBuffer handshake_mb;
    std::optional<SsAeadCipher> write_cipher;
    KeyBytes request_salt;
    {
        auto prepared = PrepareTCPRequest2022(
            target, cipher_info, master_key, psk_chain, forwarded);
        if (!prepared) {
            co_return tl::unexpected(prepared.error());
        }
        handshake_mb = std::move(prepared->handshake_mb);
        write_cipher = std::move(prepared->write_cipher);
        request_salt = prepared->request_salt;
    }
    try {
        co_await stream.WriteMultiBuffer(std::move(handshake_mb));
    } catch (...) {
        co_return tl::unexpected(transport::ClassifyFailure(
            std::current_exception(), ErrorCode::SOCKET_WRITE_FAILED));
    }

    co_return WriteTCPRequestResult{
        .request_writer = SsStreamWriter(std::move(*write_cipher), 2, stream),
        .request_salt = request_salt,
    };
}

}  // namespace

net::awaitable<tl::expected<WriteTCPRequestResult, ErrorCode>>
WriteTCPRequest(const TargetAddress& target,
                const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                std::span<const KeyBytes> psk_chain,
                AsyncStream& stream,
                ForwardedMetadataView forwarded) {
    if (Is2022Cipher(cipher_info.type)) {
        co_return co_await WriteTCPRequest2022(
            target, cipher_info, master_key, psk_chain, stream, forwarded);
    }

    try {
        buf::MultiBuffer handshake_mb;
        std::optional<SsAeadCipher> write_cipher;
        {
            auto prepared = PrepareTCPRequestLegacy(
                target, cipher_info, master_key, forwarded);
            if (!prepared) {
                co_return tl::unexpected(prepared.error());
            }
            handshake_mb = std::move(prepared->handshake_mb);
            write_cipher = std::move(prepared->write_cipher);
        }

        try {
            co_await stream.WriteMultiBuffer(std::move(handshake_mb));
        } catch (...) {
            co_return tl::unexpected(transport::ClassifyFailure(
                std::current_exception(), ErrorCode::SOCKET_WRITE_FAILED));
        }

        co_return WriteTCPRequestResult{
            .request_writer = SsStreamWriter(std::move(*write_cipher), 2, stream),
            .request_salt = {},
        };
    } catch (...) {
        co_return tl::unexpected(transport::ClassifyFailure(
            std::current_exception(), ErrorCode::SOCKET_WRITE_FAILED));
    }
}

namespace {
net::awaitable<tl::expected<SsAeadCipher, ErrorCode>> ReadResponseCipher(
    AsyncStream& stream, const SsCipherInfo& info, const KeyBytes& master_key) {
    std::array<uint8_t, KeyBytes::kMaxSize> salt{}, key{};
    ScopedCleanse cleanse{salt, key};
    auto read = co_await proxy::ReadHandshakeExact(stream,
        std::span(salt).first(info.salt_size), proxy::HandshakeProgress::NotStarted);
    if (!read) co_return tl::unexpected(read.error());
    const auto derive = Is2022Cipher(info.type) ? Derive2022Subkey : DeriveSubkey;
    if (!derive(master_key.data(), info.key_size, salt.data(), info.salt_size, key.data()))
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    co_return SsAeadCipher(info.type, key.data(), info.key_size);
}
}  // namespace

net::awaitable<tl::expected<ReadTCPResponseResult, ErrorCode>>
ReadTCPResponse(const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                const KeyBytes& request_salt,
                AsyncStream& stream) {
    if (cipher_info.salt_size > 64 || cipher_info.key_size > 64 ||
        master_key.size < cipher_info.key_size) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    try {
        if (Is2022Cipher(cipher_info.type)) {
            if (request_salt.size != cipher_info.salt_size) {
                co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
            }

            auto cipher = co_await ReadResponseCipher(stream, cipher_info, master_key);
            if (!cipher) co_return tl::unexpected(cipher.error());
            auto read_cipher = std::move(*cipher);
            const size_t fixed_plain_size = 1 + 8 + cipher_info.salt_size + 2;
            constexpr size_t kFixedPlainMaxSize = 1 + 8 + KeyBytes::kMaxSize + 2;
            constexpr size_t kFixedCipherMaxSize =
                kFixedPlainMaxSize + SsAeadCipher::kTagSize;
            if (fixed_plain_size > kFixedPlainMaxSize) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            std::array<uint8_t, kFixedCipherMaxSize> fixed_cipher{};
            const size_t fixed_cipher_size = fixed_plain_size + SsAeadCipher::kTagSize;
            if (auto read = co_await proxy::ReadHandshakeExact(stream, {fixed_cipher.data(), fixed_cipher_size},
                    proxy::HandshakeProgress::Started); !read) {
                co_return tl::unexpected(read.error());
            }

            std::array<uint8_t, kFixedPlainMaxSize> fixed_plain{};
            ScopedCleanse cleanse_fixed_plain{fixed_plain};
            auto nonce0 = MakeNonce(0);
            if (!read_cipher.Decrypt(nonce0.data(), fixed_cipher.data(), fixed_cipher_size,
                                     fixed_plain.data())) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            if (fixed_plain[0] != 1 ||
                !TimestampFresh(LoadU64BE(fixed_plain.data() + 1), UnixSecondsNow()) ||
                std::memcmp(fixed_plain.data() + 9,
                            request_salt.data(),
                            request_salt.size) != 0) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }

            const uint16_t payload_len =
                LoadU16BE(fixed_plain.data() + 9 + cipher_info.salt_size);
            buf::MultiBuffer pending;
            uint64_t next_nonce = 1;
            if (payload_len > 0) {
                if (auto decrypt_res = co_await detail::ReadAndDecryptStreamPayload(
                        stream, read_cipher, MakeNonce(1), payload_len, pending);
                    !decrypt_res) {
                    co_return tl::unexpected(decrypt_res.error());
                }
                next_nonce = 2;
            }

            co_return ReadTCPResponseResult{
                detail::BodyReader(std::move(read_cipher), next_nonce, stream,
                                   kSs2022MaxChunkPayload),
                std::move(pending)};
        }

        auto cipher = co_await ReadResponseCipher(stream, cipher_info, master_key);
        if (!cipher) co_return tl::unexpected(cipher.error());
        auto read_cipher = std::move(*cipher);
        co_return ReadTCPResponseResult{
            detail::BodyReader(std::move(read_cipher), 0, stream), {}};
    } catch (...) {
        co_return tl::unexpected(transport::ClassifyFailure(
            std::current_exception(), ErrorCode::SOCKET_READ_FAILED));
    }
}

}  // namespace ss

namespace {

class ShadowsocksOutboundEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    struct PendingResponseState {
        ss::SsCipherInfo cipher_info;
        ss::KeyBytes master_key;
        ss::KeyBytes request_salt;

        PendingResponseState(const ss::SsCipherInfo& info,
                             const ss::KeyBytes& key,
                             const ss::KeyBytes& salt)
            : cipher_info(info), master_key(key), request_salt(salt) {}

        PendingResponseState(const PendingResponseState&) = delete;
        PendingResponseState& operator=(const PendingResponseState&) = delete;
    };

    ShadowsocksOutboundEndpoint(ss::SsStreamWriter request_writer,
                                const ss::SsCipherInfo& cipher_info,
                                const ss::KeyBytes& master_key,
                                const ss::KeyBytes& request_salt,
                                AsyncStream& stream)
        : OutboundStreamEndpointBase(stream)
        , request_writer_(std::move(request_writer))
        , response_state_(std::in_place_type<PendingResponseState>,
                          cipher_info, master_key, request_salt) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (auto* reader = std::get_if<ss::detail::BodyReader>(&response_state_)) {
            return reader->ReadMultiBuffer();
        }
        return ReadInitialMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        return request_writer_.WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return request_writer_.WriteBuffers(buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return request_writer_.AsyncShutdownWrite();
    }

    operator AsyncStream&() noexcept {
        return stream_;
    }

private:
    net::awaitable<buf::MultiBuffer> ReadInitialMultiBuffer() {
        if (auto* pending = std::get_if<PendingResponseState>(&response_state_)) {
            auto reader_result = co_await ss::ReadTCPResponse(
                pending->cipher_info, pending->master_key, pending->request_salt, stream_);
            if (!reader_result) {
                OPENSSL_cleanse(pending->master_key.bytes.data(), pending->master_key.bytes.size());
                pending->master_key.size = 0;
                OPENSSL_cleanse(pending->request_salt.bytes.data(), pending->request_salt.bytes.size());
                pending->request_salt.size = 0;
                throw transport::LinkError(reader_result.error());
            }
            response_state_.emplace<ss::detail::BodyReader>(std::move(reader_result->reader));
            if (reader_result->initial_payload.byte_size() != 0)
                co_return std::move(reader_result->initial_payload);
        }
        co_return co_await std::get<ss::detail::BodyReader>(response_state_).ReadMultiBuffer();
    }

    ss::SsStreamWriter request_writer_;
    std::variant<PendingResponseState, ss::detail::BodyReader> response_state_;
};

TargetAddress MakeServerTarget(const OutboundServer& server) {
    if (server.literal_address) {
        return TargetAddress(*server.literal_address, server.port);
    }
    return TargetAddress(std::string_view(server.address.data(), server.address.size()),
                         server.port);
}


net::awaitable<tl::expected<ss::WriteTCPRequestResult, ErrorCode>>
SendShadowsocksHandshake(
    AsyncStream& stream,
    const proxy::shadowsocks::outbound::PreparedSettings& prepared,
    bool use_uot,
    const TargetAddress& target,
    std::chrono::seconds handshake_timeout,
    const PhaseDeadlineHandle& outbound_protocol_deadline,
    const OutboundDialer& dialer,
    const session::Context& ctx) {
    const TargetAddress uot_magic_target = use_uot
        ? TargetAddress(proxy::uot::MagicAddress(*prepared.config.uot_version), 0)
        : TargetAddress{};
    const TargetAddress& protocol_target = use_uot ? uot_magic_target : target;

    stream.SetIdleTimeout(handshake_timeout);

    auto request_writer_result = co_await ss::WriteTCPRequest(
        protocol_target,
        prepared.credentials.Cipher(),
        prepared.credentials.MasterKey(),
        prepared.credentials.PskChain(),
        stream,
        dialer.ForwardedMetadata(ctx));
    if (!request_writer_result) {
        const bool timed_out = proxy::ConsumeOutboundHandshakeTimeout(
            stream, outbound_protocol_deadline);
        stream.Cancel();
        co_return tl::unexpected(timed_out
            ? ErrorCode::TIMEOUT
            : request_writer_result.error());
    }
    co_return std::move(*request_writer_result);
}

net::awaitable<tl::expected<void, ErrorCode>>
WriteUotRequest(
    ShadowsocksOutboundEndpoint& target_endpoint,
    const TargetAddress& target,
    const PhaseDeadlineHandle& outbound_protocol_deadline,
    const OutboundDialer& dialer,
    const session::Context& ctx) {
    auto request = proxy::uot::EncodeRequest(
        false, target, dialer.ForwardedMetadata(ctx));
    if (!request) {
        target_endpoint.Cancel();
        co_return tl::unexpected(request.error());
    }
    const std::array<net::const_buffer, 1> request_buffers{
        net::buffer(request->bytes.data(), request->size)};
    try {
        co_await target_endpoint.WriteBuffers(request_buffers);
    } catch (...) {
        const ErrorCode code = proxy::ClassifyOutboundHandshakeException(
            target_endpoint, outbound_protocol_deadline);
        target_endpoint.Cancel();
        co_return tl::unexpected(code);
    }
    co_return tl::expected<void, ErrorCode>{};
}
}  // namespace

net::awaitable<OutboundProcessResult> proxy::shadowsocks::outbound::Handler::Process(
    session::Context& ctx,
    transport::Link inbound,
    OutboundDialer& dialer,
    const TimeoutsConfig& timeouts,
    StatsShard& stats,
    const RelayConfig& relay_config,
    buf::MultiBufferBatch first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const auto& server = prepared_->config.server;
    const bool use_uot =
        ctx.content.network == Network::UDP && prepared_->config.uot_version.has_value();

    if (ctx.content.network == Network::UDP && !use_uot) {
        auto server_target = MakeServerTarget(server);
        if (!server_target.IsValid()) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        std::optional<UdpRequest> target_endpoint;
        if (auto opened = dialer.OpenDatagram(
                ctx,
                OutboundDialer::DatagramRemote{
                    .address = server.literal_address,
                    .family_hint = {},
                    .accepts_v4 = true,
                    .accepts_v6 = true,
                    .prefers_v6 = false,
                },
                target_endpoint,
                std::move(server_target),
                prepared_->credentials.Cipher(),
                prepared_->credentials.MasterKey(),
                prepared_->credentials.PskChain(),
                dialer.ForwardedMetadata(ctx));
            !opened) {
            co_return tl::unexpected(opened.error());
        }
        target_endpoint->SetIdleTimeout(relay_idle_timeout);
        target_endpoint->SetWriteTimeout(relay_write_timeout);
        co_return co_await DoRelayLink(
            dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
            *target_endpoint, ctx, stats, relay_config, std::move(first_payload));
    }

    auto dialed = co_await dialer.Dial(ctx, server);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);
    std::optional<ShadowsocksOutboundEndpoint> target_endpoint;
    {
        PhaseDeadlineHandle outbound_protocol_deadline =
            stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

        auto request_session = co_await SendShadowsocksHandshake(
            *stream,
            *prepared_,
            use_uot,
            ctx.outbound.target,
            timeouts.HandshakeTimeout(),
            outbound_protocol_deadline,
            dialer,
            ctx);
        if (!request_session) {
            stream->CloseAbortive();
            co_return tl::unexpected(request_session.error());
        }

        target_endpoint.emplace(
            std::move(request_session->request_writer),
            prepared_->credentials.Cipher(),
            prepared_->credentials.MasterKey(),
            request_session->request_salt,
            *stream);

        if (use_uot &&
            *prepared_->config.uot_version != proxy::uot::Version::V1) {
            if (auto ok = co_await WriteUotRequest(
                    *target_endpoint,
                    ctx.outbound.target,
                    outbound_protocol_deadline,
                    dialer,
                    ctx);
                !ok) {
                stream->CloseAbortive();
                co_return tl::unexpected(ok.error());
            }
        }
    }

    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    auto relay_endpoint = [&](auto& endpoint) {
        return DoRelayLink(
            dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
            endpoint, ctx, stats, relay_config, std::move(first_payload));
    };

    if (use_uot) {
        proxy::uot::FramedEndpoint uot_endpoint(
            *target_endpoint, false, ctx.outbound.target);
        co_return co_await relay_endpoint(uot_endpoint);
    }
    co_return co_await relay_endpoint(*target_endpoint);
}

proxy::shadowsocks::outbound::Handler::Handler(
    std::shared_ptr<const PreparedSettings> prepared)
    : prepared_(std::move(prepared)) {}


namespace proxy::shadowsocks::outbound {

std::optional<Credentials> Credentials::Prepare(
    std::string_view method, std::string_view password) {
    const auto cipher = ss::ParseCipherMethod(method);
    if (!cipher || password.empty()) {
        return std::nullopt;
    }
    if (!ss::Is2022Cipher(cipher->type)) {
        auto key = ss::DeriveKey(password, cipher->key_size);
        if (key.size != cipher->key_size) {
            return std::nullopt;
        }
        return Credentials(*cipher, key, {});
    }

    std::vector<ss::KeyBytes> chain;
    for (;;) {
        const auto separator = password.find(':');
        const auto key = ss::Decode2022Psk(password.substr(0, separator), cipher->key_size);
        if (key.size != cipher->key_size) {
            return std::nullopt;
        }
        chain.push_back(key);
        if (separator == std::string_view::npos) {
            break;
        }
        // The production TCP/UDP codecs support identity chains only for AES.
        if (!ss::Is2022AesCipher(cipher->type)) {
            return std::nullopt;
        }
        password.remove_prefix(separator + 1);
    }
    const auto master_key = chain.back();
    return Credentials(*cipher, master_key, std::move(chain));
}

namespace {

tl::expected<proxy::uot::Version, std::string> ParseVersionValue(
    const json::value& value,
    std::string_view field) {
    const auto raw = JsonUnsignedInteger(value);
    if (!raw) {
        return tl::unexpected(std::format("{} must be 1 or 2", field));
    }

    if (*raw == 1) return proxy::uot::Version::V1;
    if (*raw == 2) return proxy::uot::Version::V2;

    return tl::unexpected(std::format("{} must be 1 or 2", field));
}

tl::expected<std::optional<proxy::uot::Version>, std::string> ReadTopLevelVersion(
    const json::object& source) {
    const auto* value = source.if_contains("uotVersion");
    if (!value) {
        return std::optional<proxy::uot::Version>{};
    }
    auto parsed = ParseVersionValue(*value, "uotVersion");
    if (!parsed) {
        return tl::unexpected(std::move(parsed.error()));
    }
    return std::optional<proxy::uot::Version>{*parsed};
}

tl::expected<std::optional<proxy::uot::Version>, std::string> ParseActivation(
    const json::value& value,
    std::string_view field,
    std::optional<proxy::uot::Version> top_level_version) {
    if (value.is_bool()) {
        if (!value.as_bool()) {
            if (top_level_version) {
                return tl::unexpected(std::format(
                    "{} is disabled but a UoT version is configured", field));
            }
            return std::optional<proxy::uot::Version>{};
        }
        return std::optional<proxy::uot::Version>{
            top_level_version.value_or(proxy::uot::Version::V2)};
    }

    if (!value.is_object()) {
        return tl::unexpected(std::format(
            "{} must be a boolean or object", field));
    }
    if (top_level_version) {
        return tl::unexpected(std::format(
            "top-level UoT version cannot be combined with {} object", field));
    }

    const auto& object = value.as_object();
    bool enabled = true;
    if (const auto* enabled_value = object.if_contains("enabled")) {
        if (!enabled_value->is_bool()) {
            return tl::unexpected(std::format(
                "{}.enabled must be a boolean", field));
        }
        enabled = enabled_value->as_bool();
    }

    const auto* version_value = object.if_contains("version");
    if (!enabled) {
        if (version_value) {
            return tl::unexpected(std::format(
                "{} is disabled but version is configured", field));
        }
        return std::optional<proxy::uot::Version>{};
    }
    if (!version_value) {
        return std::optional<proxy::uot::Version>{proxy::uot::Version::V2};
    }
    auto version = ParseVersionValue(*version_value, std::format("{}.version", field));
    if (!version) return tl::unexpected(std::move(version.error()));
    return std::optional<proxy::uot::Version>{*version};
}

}  // namespace

tl::expected<std::optional<proxy::uot::Version>, std::string>
ParseUotVersion(const json::object& source) {
    auto top_level_version = ReadTopLevelVersion(source);
    if (!top_level_version) {
        return tl::unexpected(std::move(top_level_version.error()));
    }

    const auto* uot = source.if_contains("uot");
    if (!uot) {
        if (*top_level_version) {
            return tl::unexpected("UoT version requires uot");
        }
        return std::optional<proxy::uot::Version>{};
    }
    return ParseActivation(*uot, "uot", *top_level_version);
}

}  // namespace proxy::shadowsocks::outbound

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kSsOutboundRegistered = (::proxyman::outbound::RegisterProxy(
    ::constants::protocol::kShadowsocks,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::proxyman::outbound::PreparedOutboundProxy> {
        std::string password;
        std::string method(::constants::protocol::kAes256Gcm);
        std::string address;
        uint16_t port = 8388;
        std::optional<::proxy::uot::Version> uot_version;
        // A present field of the wrong type is a configuration error, never
        // an implicit default.
        auto read_ss_server = [&](const ::json::object& obj) {
            const auto fail = [&](std::string_view error) {
                LOG_ERROR("Shadowsocks outbound '{}': {}", cfg.tag, error);
                return false;
            };
            auto source_address = ::ParseJsonString(obj, "address");
            if (!source_address) return fail(source_address.error());
            const auto source_port = ::ReadJsonPort(obj, "port");
            if (source_port.Invalid()) return fail("invalid port");
            auto source_password = ::ParseJsonString(obj, "password");
            if (!source_password) return fail(source_password.error());
            auto source_key = ::ParseJsonString(obj, "key");
            if (!source_key) return fail(source_key.error());
            auto source_method = ::ParseJsonString(obj, "method");
            if (!source_method) return fail(source_method.error());
            if (*source_method && (*source_method)->empty()) return fail("method must not be empty");

            address = std::move(*source_address).value_or(std::string{});
            if (source_port.Valid()) {
                port = source_port.value;
            }
            password = std::move(*source_password).value_or(std::string{});
            if (password.empty()) {
                password = std::move(*source_key).value_or(std::string{});
            }
            if (*source_method) {
                method = LowerAscii(std::move(**source_method));
            }
            auto parsed_uot = ::proxy::shadowsocks::outbound::ParseUotVersion(obj);
            if (!parsed_uot) {
                LOG_ERROR("Shadowsocks outbound '{}': invalid UoT settings: {}",
                          cfg.tag, parsed_uot.error());
                return false;
            }
            uot_version = *parsed_uot;
            return true;
        };

        const auto server_obj = ::proxy::ParseOptionalSingleObjectArray(
            cfg.settings, "servers", "Shadowsocks", cfg.tag);
        if (!server_obj ||
            !read_ss_server(*server_obj ? **server_obj : cfg.settings)) {
            return std::nullopt;
        }
        auto next_hop = ::proxy::PrepareNextHop(
            cfg, std::move(address), port, ::OutboundStreamDefaults{});
        if (!next_hop) {
            return std::nullopt;
        }
        auto credentials = ::proxy::shadowsocks::outbound::Credentials::Prepare(
            method, password);
        if (!credentials) {
            LOG_ERROR("Shadowsocks outbound '{}': invalid cipher, password or identity chain", cfg.tag);
            return std::nullopt;
        }
        using PreparedSettings = ::proxy::shadowsocks::outbound::PreparedSettings;
        return ::proxyman::outbound::PreparedOutboundProxy{
            .create = ::proxyman::outbound::MakePreparedOutboundCreator<
                PreparedSettings,
                +[](std::string_view,
                    std::shared_ptr<const PreparedSettings> state,
                    ::net::io_context& /*io_context*/,
                    ::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::Outbound> {
                    return std::make_unique<::proxy::shadowsocks::outbound::Handler>(
                        std::move(state));
                }>(PreparedSettings{
                    ::SsOutboundConfig{
                        .server = std::move(next_hop->server),
                        .uot_version = uot_version,
                    },
                    std::move(*credentials)}),
            .sender = std::move(next_hop->sender),
        };
    }), true);
}  // namespace
