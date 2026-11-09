#include "ss_outbound.hpp"
#include "common/domain_name.hpp"
#include "common/ip_address.hpp"
#include "common/ip_utils.hpp"
#include "core/naming.hpp"
#include "ss_outbound_uot.hpp"
#include "udp_request.hpp"
#include "../client.hpp"
#include "../../uot/uot.hpp"
#include "../../handshake_timeout.hpp"
#include "../../outbound_server.hpp"
#include "../../outbound_stream_endpoint.hpp"
#include "app/relay.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/registration.hpp"
#include "infra/json_field.hpp"
#include "app/dns/dns.hpp"
#include "infra/log.hpp"
#include "infra/config_types.hpp"
#include "transport/link.hpp"
#include "transport/internet/outbound_target_builder.hpp"

#include <openssl/crypto.h>
#include <memory>
#include <span>
#include <utility>
#include <variant>


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

        ~PendingResponseState() noexcept {
            OPENSSL_cleanse(master_key.bytes.data(), master_key.bytes.size());
            OPENSSL_cleanse(request_salt.bytes.data(), request_salt.bytes.size());
        }

        PendingResponseState(const PendingResponseState&) = delete;
        PendingResponseState& operator=(const PendingResponseState&) = delete;
    };

    ShadowsocksOutboundEndpoint(ss::RequestBodyWriter request_writer,
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
            response_state_.emplace<ss::detail::BodyReader>(std::move(*reader_result));
        }
        co_return co_await std::get<ss::detail::BodyReader>(response_state_).ReadMultiBuffer();
    }

    ss::RequestBodyWriter request_writer_;
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
    const TargetAddress protocol_target = use_uot
        ? TargetAddress(proxy::uot::MagicAddress(*prepared.config.uot_version), 0)
        : target;

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
        OPENSSL_cleanse(request_session->request_salt.bytes.data(),
                        request_session->request_salt.bytes.size());

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

    auto relay_endpoint = [&](auto& endpoint) -> net::awaitable<RelayResult> {
        co_return co_await DoRelayLink(
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
                method = ::naming::LowerAscii(std::move(**source_method));
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
