#include "proxy/shadowsocks/ss_outbound.hpp"
namespace proxy {
class SsOutboundHandler final : public ::proxy::Outbound {
public:
    explicit SsOutboundHandler(std::shared_ptr<const SsPreparedSettings> prepared);

    ~SsOutboundHandler() noexcept override = default;

    ::net::awaitable<::proxy::OutboundProcessResult> Process(
        ::common::Context& ctx,
        ::transport::Link inbound,
        ::transport::OutboundDialer& dialer,
        const ::infra::TimeoutsConfig& timeouts,
        ::app::StatsShard& stats,
        const ::app::RelayConfig& relay_config,
        ::common::MultiBufferBatch first_payload) override;

private:
    ::net::awaitable<::proxy::OutboundProcessResult> ProcessDatagram(
        ::common::Context& ctx,
        ::transport::Link inbound,
        ::transport::OutboundDialer& dialer,
        ::app::StatsShard& stats,
        const ::app::RelayConfig& relay_config,
        ::common::MultiBufferBatch first_payload);
    ::net::awaitable<::proxy::OutboundProcessResult> ProcessStream(
        ::common::Context& ctx,
        ::transport::Link inbound,
        ::transport::OutboundDialer& dialer,
        const ::infra::TimeoutsConfig& timeouts,
        ::app::StatsShard& stats,
        const ::app::RelayConfig& relay_config,
        ::common::MultiBufferBatch first_payload,
        bool use_uot);

    std::shared_ptr<const SsPreparedSettings> prepared_;
};
}  // namespace proxy
#include "common/scoped_cleanse.hpp"
#include "common/constants.hpp"
#include "common/address_codec.hpp"
#include "common/multi_buffer.hpp"
#include "proxy/uot/uot.hpp"
#include "proxy/handshake_errors.hpp"
#include "proxy/outbound_stream_endpoint.hpp"
#include "app/relay.hpp"
#include "app/outbound_handler.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "transport/link.hpp"
#include "transport/outbound_target_builder.hpp"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <cstring>
#include <new>
#include <optional>
#include <memory>
#include <span>
#include <utility>
#include <variant>


namespace proxy {

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

tl::expected<void, common::ErrorCode> AppendHandshakeRecord(
    SsAeadCipher& cipher, uint64_t nonce, std::span<const uint8_t> plaintext, common::Buffer& output) {
    if (output.Available() < plaintext.size() + SsAeadCipher::kTagSize)
        return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
    const auto nonce_bytes = MakeNonce(nonce);
    if (!cipher.Encrypt(nonce_bytes.data(), plaintext.data(), plaintext.size(), output.Tail().data()))
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    output.Produce(static_cast<uint32_t>(plaintext.size() + SsAeadCipher::kTagSize));
    return {};
}

struct PreparedTCPRequestHandshake {
    common::MultiBuffer handshake_mb;
    std::optional<SsAeadCipher> write_cipher;
    KeyBytes request_salt;
};

tl::expected<PreparedTCPRequestHandshake, common::ErrorCode>
PrepareTCPRequest2022(const common::TargetAddress& target,
                      const SsCipherInfo& cipher_info,
                      const KeyBytes& master_key,
                      std::span<const KeyBytes> psk_chain,
                      common::ForwardedMetadataView forwarded) {
    if (cipher_info.salt_size > KeyBytes::kMaxSize ||
        cipher_info.key_size > KeyBytes::kMaxSize ||
        master_key.size < cipher_info.key_size) {
        return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);
    }
    if (psk_chain.empty()) {
        psk_chain = std::span<const KeyBytes>(&master_key, 1);
    }

    constexpr size_t kPaddingLen = 1;
    constexpr size_t kMaxVariablePlain =
        common::kMaxEncodedAddressSize + 2 + kPaddingLen;
    std::array<uint8_t, kMaxVariablePlain> variable_plain{};
    const size_t addr_size = common::EncodeAddressTo(
        target, variable_plain.data(), common::kMaxEncodedAddressSize,
        common::AddressWireFormat::Socks5, forwarded);
    if (addr_size == 0) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    const size_t variable_len = addr_size + 2 + kPaddingLen;
    if (variable_len > kSs2022MaxChunkPayload) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }
    PreparedTCPRequestHandshake prepared;
    prepared.request_salt.size = cipher_info.salt_size;
    if (RAND_bytes(prepared.request_salt.data(),
                   static_cast<int>(prepared.request_salt.size)) != 1) {
        return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    }

    std::array<uint8_t, 32> write_subkey{};
    common::ScopedCleanse cleanse_write_subkey{write_subkey};
    if (!Derive2022Subkey(master_key.data(), cipher_info.key_size,
                          prepared.request_salt.data(), prepared.request_salt.size,
                          write_subkey.data())) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    std::array<uint8_t, kSs2022RequestFixedHeaderSize> fixed_plain{};
    fixed_plain[0] = 0;
    common::StoreU64BE(fixed_plain.data() + 1, UnixSecondsNow());
    common::StoreU16BE(fixed_plain.data() + 9, static_cast<uint16_t>(variable_len));

    common::StoreU16BE(variable_plain.data() + addr_size, static_cast<uint16_t>(kPaddingLen));
    if (RAND_bytes(variable_plain.data() + addr_size + 2, static_cast<int>(kPaddingLen)) != 1) {
        return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    }

    prepared.write_cipher.emplace(cipher_info.type, write_subkey.data(), cipher_info.key_size);
    const size_t handshake_size =
        prepared.request_salt.size +
        (psk_chain.size() > 0 ? (psk_chain.size() - 1) * 16 : 0) +
        fixed_plain.size() + SsAeadCipher::kTagSize +
        variable_len + SsAeadCipher::kTagSize;
    if (handshake_size > common::Buffer::kSize) {
        return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
    }

    common::BufferGuard handshake{common::Buffer::New()};
    if (!handshake) {
        return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
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
        return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);
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

tl::expected<PreparedTCPRequestHandshake, common::ErrorCode>
PrepareTCPRequestLegacy(const common::TargetAddress& target,
                        const SsCipherInfo& cipher_info,
                        const KeyBytes& master_key,
                        common::ForwardedMetadataView forwarded) {
    if (cipher_info.salt_size > KeyBytes::kMaxSize || cipher_info.key_size > KeyBytes::kMaxSize ||
        master_key.size < cipher_info.key_size) {
        return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);
    }

    std::array<uint8_t, common::kMaxEncodedAddressSize> addr_bytes{};
    const size_t addr_size = common::EncodeAddressTo(
        target, addr_bytes.data(), addr_bytes.size(), common::AddressWireFormat::Socks5, forwarded);
    if (addr_size == 0 || addr_size > kMaxChunkPayload) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    std::array<uint8_t, 64> client_salt{};
    if (RAND_bytes(client_salt.data(), static_cast<int>(cipher_info.salt_size)) != 1) {
        return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    }

    std::array<uint8_t, 64> write_subkey{};
    common::ScopedCleanse cleanse_legacy{client_salt, write_subkey};
    if (!DeriveSsSubkey(master_key.data(), cipher_info.key_size,
                      client_salt.data(), cipher_info.salt_size,
                      write_subkey.data())) {
        return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    }

    common::BufferGuard out{common::Buffer::New()};
    if (!out) {
        return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
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

}  // namespace

net::awaitable<tl::expected<WriteTCPRequestResult, common::ErrorCode>>
WriteTCPRequest(const common::TargetAddress& target,
                const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                std::span<const KeyBytes> psk_chain,
                transport::AsyncStream& stream,
                common::ForwardedMetadataView forwarded) {
    common::MultiBuffer handshake_mb;
    std::optional<SsAeadCipher> write_cipher;
    KeyBytes request_salt{};
    try {
        auto prepared = Is2022Cipher(cipher_info.type)
            ? PrepareTCPRequest2022(target, cipher_info, master_key, psk_chain, forwarded)
            : PrepareTCPRequestLegacy(target, cipher_info, master_key, forwarded);
        if (!prepared) {
            co_return tl::unexpected(prepared.error());
        }
        handshake_mb = std::move(prepared->handshake_mb);
        write_cipher = std::move(prepared->write_cipher);
        request_salt = prepared->request_salt;
    } catch (...) {
        co_return tl::unexpected(transport::ClassifyFailure(
            std::current_exception(), common::ErrorCode::SOCKET_WRITE_FAILED));
    }

    try {
        co_await stream.WriteMultiBuffer(std::move(handshake_mb));
    } catch (...) {
        OPENSSL_cleanse(request_salt.bytes.data(), request_salt.bytes.size());
        co_return tl::unexpected(transport::ClassifyFailure(
            std::current_exception(), common::ErrorCode::SOCKET_WRITE_FAILED));
    }

    co_return WriteTCPRequestResult{
        .request_writer = SsStreamWriter(std::move(*write_cipher), 2, stream),
        .request_salt = request_salt,
    };
}
namespace {
net::awaitable<tl::expected<SsAeadCipher, common::ErrorCode>> ReadResponseCipher(
    transport::AsyncStream& stream, const SsCipherInfo& info, const KeyBytes& master_key) {
    std::array<uint8_t, KeyBytes::kMaxSize> salt{}, key{};
    common::ScopedCleanse cleanse{salt, key};
    auto read = co_await proxy::ReadHandshakeExact(stream,
        std::span(salt).first(info.salt_size), proxy::HandshakeProgress::NotStarted);
    if (!read) co_return tl::unexpected(read.error());
    const auto derive = Is2022Cipher(info.type) ? Derive2022Subkey : DeriveSsSubkey;
    if (!derive(master_key.data(), info.key_size, salt.data(), info.salt_size, key.data()))
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    co_return SsAeadCipher(info.type, key.data(), info.key_size);
}
net::awaitable<tl::expected<ReadTCPResponseResult, common::ErrorCode>>
ReadTCPResponse2022(const SsCipherInfo& cipher_info,
                    const KeyBytes& master_key,
                    const KeyBytes& request_salt,
                    transport::AsyncStream& stream) {
    if (cipher_info.salt_size > 64 || cipher_info.key_size > 64 ||
        master_key.size < cipher_info.key_size ||
        request_salt.size != cipher_info.salt_size) {
        co_return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);
    }
    try {
        auto cipher = co_await ReadResponseCipher(stream, cipher_info, master_key);
        if (!cipher) co_return tl::unexpected(cipher.error());
        auto read_cipher = std::move(*cipher);
        const size_t fixed_plain_size = 1 + 8 + cipher_info.salt_size + 2;
        constexpr size_t kFixedPlainMaxSize = 1 + 8 + KeyBytes::kMaxSize + 2;
        constexpr size_t kFixedCipherMaxSize =
            kFixedPlainMaxSize + SsAeadCipher::kTagSize;
        if (fixed_plain_size > kFixedPlainMaxSize) {
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        std::array<uint8_t, kFixedCipherMaxSize> fixed_cipher{};
        const size_t fixed_cipher_size = fixed_plain_size + SsAeadCipher::kTagSize;
        if (auto read = co_await proxy::ReadHandshakeExact(stream, {fixed_cipher.data(), fixed_cipher_size},
                proxy::HandshakeProgress::Started); !read) {
            co_return tl::unexpected(read.error());
        }

        std::array<uint8_t, kFixedPlainMaxSize> fixed_plain{};
        common::ScopedCleanse cleanse_fixed_plain{fixed_plain};
        auto nonce0 = MakeNonce(0);
        if (!read_cipher.Decrypt(nonce0.data(), fixed_cipher.data(), fixed_cipher_size,
                                 fixed_plain.data())) {
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        if (fixed_plain[0] != 1 ||
            !TimestampFresh(common::LoadU64BE(fixed_plain.data() + 1), UnixSecondsNow()) ||
            std::memcmp(fixed_plain.data() + 9,
                        request_salt.data(),
                        request_salt.size) != 0) {
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }

        const uint16_t payload_len =
            common::LoadU16BE(fixed_plain.data() + 9 + cipher_info.salt_size);
        common::MultiBuffer pending;
        uint64_t next_nonce = 1;
        if (payload_len > 0) {
            if (auto decrypt_res = co_await ReadAndDecryptStreamPayload(
                    stream, read_cipher, MakeNonce(1), payload_len, pending);
                !decrypt_res) {
                co_return tl::unexpected(decrypt_res.error());
            }
            next_nonce = 2;
        }

        co_return ReadTCPResponseResult{
            BodyReader(std::move(read_cipher), next_nonce, stream,
                       kSs2022MaxChunkPayload),
            std::move(pending)};
    } catch (...) {
        co_return tl::unexpected(transport::ClassifyFailure(
            std::current_exception(), common::ErrorCode::SOCKET_READ_FAILED));
    }
}

net::awaitable<tl::expected<ReadTCPResponseResult, common::ErrorCode>>
ReadTCPResponseLegacy(const SsCipherInfo& cipher_info,
                      const KeyBytes& master_key,
                      transport::AsyncStream& stream) {
    if (cipher_info.salt_size > 64 || cipher_info.key_size > 64 ||
        master_key.size < cipher_info.key_size) {
        co_return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);
    }
    try {
        auto cipher = co_await ReadResponseCipher(stream, cipher_info, master_key);
        if (!cipher) co_return tl::unexpected(cipher.error());
        co_return ReadTCPResponseResult{
            BodyReader(std::move(*cipher), 0, stream), {}};
    } catch (...) {
        co_return tl::unexpected(transport::ClassifyFailure(
            std::current_exception(), common::ErrorCode::SOCKET_READ_FAILED));
    }
}
}  // namespace

net::awaitable<tl::expected<ReadTCPResponseResult, common::ErrorCode>>
ReadTCPResponse(const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                const KeyBytes& request_salt,
                transport::AsyncStream& stream) {
    if (Is2022Cipher(cipher_info.type)) {
        return ReadTCPResponse2022(cipher_info, master_key, request_salt, stream);
    }
    return ReadTCPResponseLegacy(cipher_info, master_key, stream);
}


namespace {

class ShadowsocksOutboundEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    struct PendingResponseState {
        proxy::SsCipherInfo cipher_info;
        const proxy::KeyBytes& master_key;
        proxy::KeyBytes request_salt;

        PendingResponseState(const proxy::SsCipherInfo& info,
                             const proxy::KeyBytes& key,
                             const proxy::KeyBytes& salt)
            : cipher_info(info), master_key(key), request_salt(salt) {}

        PendingResponseState(const PendingResponseState&) = delete;
        PendingResponseState& operator=(const PendingResponseState&) = delete;
    };

    ShadowsocksOutboundEndpoint(proxy::SsStreamWriter request_writer,
                                const proxy::SsCipherInfo& cipher_info,
                                const proxy::KeyBytes& master_key,
                                const proxy::KeyBytes& request_salt,
                                transport::AsyncStream& stream)
        : OutboundStreamEndpointBase(stream)
        , request_writer_(std::move(request_writer))
        , response_state_(std::in_place_type<PendingResponseState>,
                          cipher_info, master_key, request_salt) {}

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        if (auto* reader = std::get_if<proxy::BodyReader>(&response_state_)) {
            return reader->ReadMultiBuffer();
        }
        return ReadInitialMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        return request_writer_.WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return request_writer_.WriteBuffers(buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return request_writer_.AsyncShutdownWrite();
    }

private:
    net::awaitable<common::MultiBuffer> ReadInitialMultiBuffer() {
        if (auto* pending = std::get_if<PendingResponseState>(&response_state_)) {
            auto reader_result = co_await proxy::ReadTCPResponse(
                pending->cipher_info, pending->master_key, pending->request_salt, stream_);
            if (!reader_result) {
                OPENSSL_cleanse(pending->request_salt.bytes.data(), pending->request_salt.bytes.size());
                pending->request_salt.size = 0;
                throw transport::LinkError(reader_result.error());
            }
            response_state_.emplace<proxy::BodyReader>(std::move(reader_result->reader));
            if (reader_result->initial_payload.byte_size() != 0)
                co_return std::move(reader_result->initial_payload);
        }
        co_return co_await std::get<proxy::BodyReader>(response_state_).ReadMultiBuffer();
    }

    proxy::SsStreamWriter request_writer_;
    std::variant<PendingResponseState, proxy::BodyReader> response_state_;
};

common::TargetAddress MakeServerTarget(const transport::OutboundServer& server) {
    if (server.literal_address) {
        return common::TargetAddress(*server.literal_address, server.port);
    }
    return common::TargetAddress(std::string_view(server.address.data(), server.address.size()),
                         server.port);
}


net::awaitable<tl::expected<std::unique_ptr<transport::AsyncStream>, common::ErrorCode>>
DialAndHandshakeShadowsocks(
    common::Context& ctx,
    transport::OutboundDialer& dialer,
    const SsPreparedSettings& prepared,
    bool use_uot,
    std::chrono::seconds handshake_timeout,
    std::optional<ShadowsocksOutboundEndpoint>& target_endpoint) {
    auto dialed = co_await dialer.Dial(ctx, prepared.config.server);
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);
    transport::PhaseDeadlineToken outbound_protocol_deadline =
        stream->StartPhaseDeadline(handshake_timeout);
    stream->SetIdleTimeout(handshake_timeout);

    {
        const common::TargetAddress uot_magic_target = use_uot
            ? common::TargetAddress(proxy::MagicAddress(*prepared.config.uot_version), 0)
            : common::TargetAddress{};
        const common::TargetAddress& protocol_target = use_uot ? uot_magic_target : ctx.outbound.target;
        auto request_writer_result = co_await proxy::WriteTCPRequest(
            protocol_target,
            prepared.credentials.Cipher(),
            prepared.credentials.MasterKey(),
            prepared.credentials.PskChain(),
            *stream,
            dialer.ForwardedMetadata(ctx));
        if (!request_writer_result) {
            const bool timed_out = proxy::ConsumeOutboundHandshakeTimeout(
                *stream, outbound_protocol_deadline);
            stream->Cancel();
            stream->CloseAbortive();
            co_return tl::unexpected(timed_out
                ? common::ErrorCode::TIMEOUT
                : request_writer_result.error());
        }
        target_endpoint.emplace(
            std::move(request_writer_result->request_writer),
            prepared.credentials.Cipher(),
            prepared.credentials.MasterKey(),
            request_writer_result->request_salt,
            *stream);
    }

    if (use_uot && *prepared.config.uot_version != proxy::UotVersion::V1) {
        auto request = proxy::EncodeUotRequest(
            false, ctx.outbound.target, dialer.ForwardedMetadata(ctx));
        if (!request) {
            target_endpoint.reset();
            stream->Cancel();
            stream->CloseAbortive();
            co_return tl::unexpected(request.error());
        }
        const std::array<net::const_buffer, 1> request_buffers{
            net::buffer(request->bytes.data(), request->size)};
        try {
            co_await target_endpoint->WriteBuffers(request_buffers);
        } catch (...) {
            const common::ErrorCode code = proxy::ClassifyOutboundHandshakeException(
                target_endpoint->RelayControl(), outbound_protocol_deadline);
            target_endpoint.reset();
            stream->Cancel();
            stream->CloseAbortive();
            co_return tl::unexpected(code);
        }
    }
    co_return std::move(stream);
}
}  // namespace

net::awaitable<proxy::OutboundProcessResult> proxy::SsOutboundHandler::Process(
    common::Context& ctx,
    transport::Link inbound,
    transport::OutboundDialer& dialer,
    const infra::TimeoutsConfig& timeouts,
    app::StatsShard& stats,
    const app::RelayConfig& relay_config,
    common::MultiBufferBatch first_payload) {
    if (!inbound.Valid()) {
        return []() -> net::awaitable<proxy::OutboundProcessResult> {
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }();
    }
    const bool use_uot =
        ctx.content.network == common::Network::UDP && prepared_->config.uot_version.has_value();
    if (ctx.content.network == common::Network::UDP && !use_uot) {
        return ProcessDatagram(
            ctx, inbound, dialer, stats, relay_config, std::move(first_payload));
    }
    return ProcessStream(
        ctx, inbound, dialer, timeouts, stats, relay_config, std::move(first_payload), use_uot);
}

net::awaitable<proxy::OutboundProcessResult> proxy::SsOutboundHandler::ProcessDatagram(
    common::Context& ctx,
    transport::Link inbound,
    transport::OutboundDialer& dialer,
    app::StatsShard& stats,
    const app::RelayConfig& relay_config,
    common::MultiBufferBatch first_payload) {
    const auto& server = prepared_->config.server;
    auto server_target = MakeServerTarget(server);
    if (!server_target.IsValid()) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
    }
    std::optional<SsUdpRequest> target_endpoint;
    if (auto opened = dialer.OpenDatagram(
            ctx,
            transport::OutboundDialer::DatagramRemote{
                .address = server.literal_address,
                .family_hint = {},
                .family_policy = {},
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
    proxy::ApplyOutboundDatagramTimeouts(*target_endpoint, relay_config);
    co_return co_await app::DoRelayLink(
        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
        *target_endpoint, ctx, stats, relay_config, std::move(first_payload));
}

net::awaitable<proxy::OutboundProcessResult> proxy::SsOutboundHandler::ProcessStream(
    common::Context& ctx,
    transport::Link inbound,
    transport::OutboundDialer& dialer,
    const infra::TimeoutsConfig& timeouts,
    app::StatsShard& stats,
    const app::RelayConfig& relay_config,
    common::MultiBufferBatch first_payload,
    bool use_uot) {
    std::unique_ptr<transport::AsyncStream> stream;
    std::optional<ShadowsocksOutboundEndpoint> target_endpoint;
    {
        auto dialed = co_await DialAndHandshakeShadowsocks(
            ctx, dialer, *prepared_, use_uot, timeouts.HandshakeTimeout(), target_endpoint);
        if (!dialed) {
            co_return tl::unexpected(dialed.error());
        }
        stream = std::move(*dialed);
    }

    proxy::ApplyOutboundRelayTimeouts(*stream, relay_config);

    if (use_uot) {
        proxy::UotFramedEndpoint uot_endpoint(
            *target_endpoint, false, ctx.outbound.target);
        co_return co_await app::DoRelayLink(
            dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
            uot_endpoint, ctx, stats, relay_config, std::move(first_payload));
    }
    co_return co_await app::DoRelayLink(
        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
        *target_endpoint, ctx, stats, relay_config, std::move(first_payload));
}
proxy::SsOutboundHandler::SsOutboundHandler(
    std::shared_ptr<const SsPreparedSettings> prepared)
    : prepared_(std::move(prepared)) {}

std::optional<SsCredentials> SsCredentials::Prepare(
    const proxy::SsCipherInfo& cipher, std::string_view password) {
    if (password.empty()) return std::nullopt;
    if (!proxy::Is2022Cipher(cipher.type)) {
        auto key = proxy::DeriveKey(password, cipher.key_size);
        if (key.size != cipher.key_size) return std::nullopt;
        return SsCredentials(cipher, key, {});
    }

    std::vector<proxy::KeyBytes> chain;
    for (;;) {
        const auto separator = password.find(':');
        const auto key = proxy::Decode2022Psk(password.substr(0, separator), cipher.key_size);
        if (key.size != cipher.key_size) return std::nullopt;
        chain.push_back(key);
        if (separator == std::string_view::npos) break;
        // 生产 TCP/UDP 编码器仅支持 AES 身份链。
        if (!proxy::Is2022AesCipher(cipher.type)) return std::nullopt;
        password.remove_prefix(separator + 1);
    }
    const auto master_key = chain.back();
    return SsCredentials(cipher, master_key, std::move(chain));
}

}  // namespace proxy

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kSsOutboundRegistered = (::app::RegisterProxy(
    ::common::kShadowsocks,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::app::PreparedOutboundProxy> {
        const auto* settings = std::get_if<::infra::ShadowsocksSettings>(&cfg.settings);
        if (!settings) return std::nullopt;
        auto next_hop = ::proxy::PrepareNextHop(cfg, settings->server, ::transport::OutboundStreamDefaults{});
        auto credentials = ::proxy::SsCredentials::Prepare(
            settings->cipher, settings->password);
        if (!credentials) {
            LOG_ERROR("Shadowsocks outbound '{}': invalid cipher, password or identity chain", cfg.tag);
            return std::nullopt;
        }
        using PreparedSettings = ::proxy::SsPreparedSettings;
        return ::app::PreparedOutboundProxy{
            .create = ::app::MakePreparedOutboundCreator<
                PreparedSettings,
                +[](std::string_view,
                    std::shared_ptr<const PreparedSettings> state,
                    ::net::io_context& /*io_context*/,
                    ::common::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::proxy::Outbound> {
                    return std::make_unique<::proxy::SsOutboundHandler>(
                        std::move(state));
                }>(PreparedSettings{
                    ::proxy::SsOutboundConfig{
                        .server = std::move(next_hop.server),
                        .uot_version = settings->uot_version,
                    },
                    std::move(*credentials)}),
            .sender = std::move(next_hop.sender),
        };
    }), true);
}  // namespace
