#include "ss_outbound.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/ip_address.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/core/naming.hpp"
#include "ss_outbound_uot.hpp"
#include "udp_request.hpp"
#include "../client.hpp"
#include "../../uot/uot.hpp"
#include "../../handshake_timeout.hpp"
#include "../../outbound_stream_endpoint.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "../../../app/proxyman/outbound/registration.hpp"
#include "acppnode/infra/json_field.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/transport/link.hpp"
#include "acppnode/transport/internet/outbound_target_builder.hpp"

#include <memory>
#include <span>
#include <utility>

namespace acpp {

namespace {

class ShadowsocksOutboundEndpoint final : public proxy::OutboundStreamEndpointBase {
public:
    ShadowsocksOutboundEndpoint(std::unique_ptr<transport::MultiBufferWriter> request_writer,
                                const ss::SsCipherInfo& cipher_info,
                                const ss::KeyBytes& master_key,
                                const ss::KeyBytes& request_salt,
                                AsyncStream& stream)
        : OutboundStreamEndpointBase(stream)
        , request_writer_(std::move(request_writer))
        , cipher_info_(cipher_info)
        , master_key_(master_key)
        , request_salt_(request_salt) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!response_reader_) {
            auto reader_result = co_await ss::ReadTCPResponse(
                cipher_info_, master_key_, request_salt_, stream_);
            if (!reader_result) {
                throw transport::LinkError(reader_result.error());
            }
            response_reader_ = std::move(reader_result.value());
        }
        co_return co_await response_reader_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (!request_writer_) {
            mb.clear();
            throw IoSystemError(
                io_error::not_connected,
                "Shadowsocks request writer is not initialized");
        }
        co_await request_writer_->WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (!request_writer_) {
            throw IoSystemError(
                io_error::not_connected,
                "Shadowsocks request writer is not initialized");
        }
        co_await request_writer_->WriteBuffers(buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        co_await stream_.AsyncShutdownWrite();
    }

    operator AsyncStream&() noexcept {
        return stream_;
    }

private:
    std::unique_ptr<transport::MultiBufferWriter> request_writer_;
    ss::SsCipherInfo cipher_info_;
    ss::KeyBytes master_key_;
    ss::KeyBytes request_salt_;
    std::unique_ptr<transport::MultiBufferReader> response_reader_;
};

TargetAddress MakeServerTarget(const SsOutboundConfig& config) {
    if (config.literal_address) {
        return TargetAddress(*config.literal_address, config.port);
    }
    return TargetAddress(std::string_view(config.address.data(), config.address.size()),
                         config.port);
}

net::ip::address SelectUdpBindAddress(
    const SsOutboundConfig& config,
    const tcp::endpoint* inbound_local_addr) {
    if (config.send_through.GetMode() == OutboundBind::Mode::Explicit) {
        return *config.send_through.ExplicitAddress();
    }
    if (config.send_through.GetMode() == OutboundBind::Mode::Auto && inbound_local_addr) {
        if (config.literal_address) {
            if (auto bound = config.send_through.BindAddressFor(
                    inbound_local_addr, *config.literal_address)) {
                return *bound;
            }
        } else {
            const auto inbound_local =
                iputil::NormalizeAddress(inbound_local_addr->address());
            if (auto bound = config.send_through.BindAddressFor(
                    inbound_local_addr, inbound_local)) {
                return *bound;
            }
        }
    }
    if (config.literal_address
            ? config.literal_address->is_v6()
            : config.send_through.PrefersIPv6()) {
        return net::ip::address_v6::any();
    }
    return net::ip::address_v4::any();
}


net::awaitable<tl::expected<ss::WriteTCPRequestResult, ErrorCode>>
SendShadowsocksHandshake(
    AsyncStream& stream,
    const proxy::shadowsocks::outbound::PreparedSettings& prepared,
    bool use_uot,
    const TargetAddress& target,
    std::chrono::seconds handshake_timeout,
    const PhaseDeadlineHandle& outbound_protocol_deadline) {
    const TargetAddress protocol_target = use_uot
        ? TargetAddress(
            *prepared.config.uot_version == SsUotVersion::V1
                ? proxy::uot::kV1MagicAddress
                : proxy::uot::kMagicAddress,
            0)
        : target;

    stream.SetIdleTimeout(handshake_timeout);

    auto request_writer_result = co_await ss::WriteTCPRequest(
        protocol_target,
        prepared.credentials.Cipher(),
        prepared.credentials.MasterKey(),
        prepared.credentials.PskChain(),
        stream);
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
    const PhaseDeadlineHandle& outbound_protocol_deadline) {
    auto request = proxy::uot::EncodeRequest(false, target);
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
    net::io_context& io_context,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    transport::Link inbound,
    StatsShard& stats,
    const RelayConfig& relay_config,
    buf::MultiBufferBatch first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!inbound.Valid()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const bool use_uot =
        ctx.content.network == Network::UDP && prepared_->config.uot_version.has_value();

    if (ctx.content.network == Network::UDP && !use_uot) {
        auto server = MakeServerTarget(prepared_->config);
        if (!server.IsValid()) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }

        const tcp::endpoint* effective_inbound_local = inbound_local_addr
            ? inbound_local_addr
            : (ctx.inbound.local_endpoint ? &*ctx.inbound.local_endpoint : nullptr);
        auto bind_addr = SelectUdpBindAddress(prepared_->config, effective_inbound_local);
        if (prepared_->config.send_through.GetMode() == OutboundBind::Mode::Ordered) {
            const auto remote = prepared_->config.literal_address.value_or(bind_addr);
            auto selected = prepared_->config.send_through.Select(
                remote, ctx.inbound.source_ip, ctx.inbound.source_port);
            if (!selected.address && !prepared_->config.literal_address) {
                const net::ip::address alt_remote = remote.is_v6()
                    ? net::ip::address(net::ip::address_v4::any())
                    : net::ip::address(net::ip::address_v6::any());
                selected = prepared_->config.send_through.Select(
                    alt_remote, ctx.inbound.source_ip, ctx.inbound.source_port);
            }
            if (!selected.address) {
                co_return tl::unexpected(ErrorCode::SOCKET_BIND_FAILED);
            }
            bind_addr = *selected.address;
        }
        std::optional<UdpRequest> target_endpoint;
        try {
            target_endpoint.emplace(
                io_context,
                dns_service_,
                bind_addr,
                std::move(server),
                prepared_->credentials.Cipher(),
                prepared_->credentials.MasterKey(),
                prepared_->credentials.PskChain());
            target_endpoint->SetIdleTimeout(relay_idle_timeout);
            target_endpoint->SetWriteTimeout(relay_write_timeout);
        } catch (const transport::LinkError& e) {
            co_return tl::unexpected(e.code());
        } catch (const IoSystemError& e) {
            co_return tl::unexpected(MapAsioError(e.code()));
        }
        ctx.outbound.connected_local_addr.reset();
        const auto local_ip = iputil::NormalizeAddress(bind_addr);
        if (!local_ip.is_unspecified()) {
            ctx.outbound.connected_local_addr = local_ip;
        }
        LOG_ACCESS(FormatAccessLog(ctx));
        co_return co_await DoRelayLink(
            io_context, *inbound.reader, *inbound.writer, inbound.control,
            *target_endpoint, ctx, stats, relay_config, std::move(first_payload));
    }

    auto dialed = co_await acpp::DialOutboundStream(
        io_context,
        ctx,
        OutboundTargetOptions{
            .dns_service = &dns_service_,
            .address = prepared_->config.address,
            .literal_address = prepared_->config.literal_address,
            .port = prepared_->config.port,
            .stream_settings = &prepared_->config.stream_settings,
            .security = &security_,
            .timeout = dial_timeout_,
            .send_through = &prepared_->config.send_through,
            .inbound_local_addr = inbound_local_addr,
        });
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);
    PhaseDeadlineHandle outbound_protocol_deadline =
        stream->StartPhaseDeadline(timeouts.HandshakeTimeout());

    auto request_session = co_await SendShadowsocksHandshake(
        *stream,
        *prepared_,
        use_uot,
        ctx.outbound.target,
        timeouts.HandshakeTimeout(),
        outbound_protocol_deadline);
    if (!request_session) {
        stream->CloseAbortive();
        co_return tl::unexpected(request_session.error());
    }

    ShadowsocksOutboundEndpoint target_endpoint(
        std::move(request_session->request_writer),
        prepared_->credentials.Cipher(),
        prepared_->credentials.MasterKey(),
        request_session->request_salt,
        *stream);

    if (use_uot &&
        *prepared_->config.uot_version != SsUotVersion::V1) {
        if (auto ok = co_await WriteUotRequest(
                target_endpoint,
                ctx.outbound.target,
                outbound_protocol_deadline);
            !ok) {
            stream->CloseAbortive();
            co_return tl::unexpected(ok.error());
        }
    }

    stream->SetIdleTimeout(relay_idle_timeout);
    stream->SetReadTimeout(std::chrono::seconds(0));
    stream->SetWriteTimeout(relay_write_timeout);
    stream->ClearPhaseDeadline();

    auto relay_endpoint = [&](auto& endpoint) -> net::awaitable<RelayResult> {
        co_return co_await DoRelayLink(
            io_context, *inbound.reader, *inbound.writer, inbound.control,
            endpoint, ctx, stats, relay_config, std::move(first_payload));
    };

    if (use_uot) {
        proxy::uot::FramedEndpoint uot_endpoint(
            target_endpoint, false, ctx.outbound.target);
        co_return co_await relay_endpoint(uot_endpoint);
    }
    co_return co_await relay_endpoint(target_endpoint);
}

proxy::shadowsocks::outbound::Handler::Handler(
    std::string_view tag, std::shared_ptr<const PreparedSettings> prepared,
    ::acpp::app::dns::DNS& dns_service, std::chrono::seconds dial_timeout)
    : tag_(tag), prepared_(std::move(prepared)),
      security_(prepared_->config.stream_settings, StreamEndpointRole::Outbound),
      dial_timeout_(dial_timeout), dns_service_(dns_service) {}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kSsOutboundRegistered = (acpp::proxyman::outbound::RegisterProxy(
    acpp::constants::protocol::kShadowsocks,
    [](const acpp::infra::OutboundSourceConfig& cfg)
        -> std::optional<acpp::proxyman::outbound::PreparedOutboundCreator> {
        std::string password;
        std::string method(acpp::constants::protocol::kAes256Gcm);
        // A present field of the wrong type is a configuration error, never
        // an implicit default.
        auto read_ss_server = [&](const acpp::json::object& obj,
                                  acpp::SsOutboundConfig& config) {
            const auto fail = [&](std::string_view error) {
                LOG_ERROR("Shadowsocks outbound '{}': {}", cfg.tag, error);
                return false;
            };
            auto address = acpp::ParseJsonString(obj, "address");
            if (!address) return fail(address.error());
            const auto port = acpp::ReadJsonPort(obj, "port");
            if (port.Invalid()) return fail("invalid port");
            auto source_password = acpp::ParseJsonString(obj, "password");
            if (!source_password) return fail(source_password.error());
            auto source_key = acpp::ParseJsonString(obj, "key");
            if (!source_key) return fail(source_key.error());
            auto source_method = acpp::ParseJsonString(obj, "method");
            if (!source_method) return fail(source_method.error());
            if (*source_method && (*source_method)->empty()) return fail("method must not be empty");

            config.address = std::move(*address).value_or(std::string{});
            if (port.Valid()) {
                config.port = port.value;
            }
            password = std::move(*source_password).value_or(std::string{});
            if (password.empty()) {
                password = std::move(*source_key).value_or(std::string{});
            }
            if (*source_method) {
                method = acpp::naming::LowerAscii(std::move(**source_method));
            }
            auto uot_version =
                acpp::proxy::shadowsocks::outbound::ParseUotVersion(obj);
            if (!uot_version) {
                LOG_ERROR("Shadowsocks outbound '{}': invalid UoT settings: {}",
                          cfg.tag, uot_version.error());
                return false;
            }
            config.uot_version = *uot_version;
            return true;
        };

        acpp::SsOutboundConfig ss_config;

        if (const auto* servers_p = cfg.settings.if_contains("servers")) {
            if (!servers_p->is_array() ||
                servers_p->as_array().size() != 1 ||
                !servers_p->as_array()[0].is_object()) {
                LOG_ERROR("Shadowsocks outbound '{}': servers must be a single-element object array", cfg.tag);
                return std::nullopt;
            }
            if (!read_ss_server(servers_p->as_array()[0].as_object(), ss_config)) {
                return std::nullopt;
            }
        } else if (!read_ss_server(cfg.settings, ss_config)) {
            return std::nullopt;
        }
        ss_config.send_through = cfg.send_through.value_or(acpp::OutboundBind{});
        ss_config.stream_settings = acpp::NormalizeOutboundStreamSettings(
            cfg.stream_settings,
            acpp::OutboundStreamDefaults{
                .require_tls = false,
                .fallback_server_name = ss_config.address,
                .allow_insecure = false,
                .alpn = {},
            });

        if (ss_config.address.empty() || ss_config.port == 0) {
            return std::nullopt;
        }
        auto credentials = acpp::proxy::shadowsocks::outbound::Credentials::Prepare(
            method, password);
        if (!credentials) {
            LOG_ERROR("Shadowsocks outbound '{}': invalid cipher, password or identity chain", cfg.tag);
            return std::nullopt;
        }
        ss_config.literal_address = acpp::iputil::ParseLiteral(ss_config.address);
        if (!ss_config.literal_address && !acpp::domain::IsValidDnsHostname(
                ss_config.address, acpp::domain::TrailingDotPolicy::Allow)) {
            LOG_ERROR("shadowsocks outbound '{}': address must be an IP literal or DNS hostname", cfg.tag);
            return std::nullopt;
        }
        acpp::TransportSecurity::Prepare(
            ss_config.stream_settings, acpp::StreamEndpointRole::Outbound);
        using PreparedSettings = acpp::proxy::shadowsocks::outbound::PreparedSettings;
        return acpp::proxyman::outbound::MakePreparedOutboundCreator<
            PreparedSettings,
            +[](std::string_view tag,
                std::shared_ptr<const PreparedSettings> state,
                acpp::net::io_context& /*io_context*/,
                acpp::app::dns::DNS& dns_service,
                std::chrono::seconds timeout,
                acpp::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<acpp::Outbound> {
                return std::make_unique<acpp::proxy::shadowsocks::outbound::Handler>(
                    tag, std::move(state), dns_service, timeout);
            }>(PreparedSettings{std::move(ss_config), std::move(*credentials)});
    }), true);
}  // namespace
