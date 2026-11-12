#include "proxy/inbound_admission.hpp"
#include "proxy/handshake_errors.hpp"
#include "app/relay.hpp"
#include "transport/internet/hysteria/hysteria_wire.hpp"
#include "transport/internet/hysteria/hysteria_settings.hpp"
#include "transport/internet/hysteria/hysteria_ingress.hpp"

#include "app/proxyman/inbound/handler.hpp"
#include "app/stats.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/buf/length_prefixed_packet_buffer.hpp"
#include "common/initial_payload.hpp"
#include "common/session.hpp"
#include "core/constants.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "proxy/inbound.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <tl/expected.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <span>
#include <utility>
#include <cstdint>
#include <vector>

namespace proxy::hysteria {
namespace {

namespace wire = ::transport::internet::hysteria;

constexpr size_t kMaxRequestHeaderBytes = 8192;

struct TcpRequest {
    common::TargetAddress target;
    // Request-stream bytes that followed the header in the same read.
    buf::MultiBuffer early_data;
};

[[nodiscard]] tl::expected<common::TargetAddress, wire::ProtocolError>
ParseTcpRequest(wire::Version version, std::span<const uint8_t> header,
                size_t& header_bytes) {
    if (version == wire::Version::V1) {
        auto request = wire::ParseV1Request(header);
        if (!request) return tl::unexpected(request.error());
        if (request->udp) return tl::unexpected(wire::ProtocolError::Invalid);
        header_bytes = request->header_bytes;
        return std::move(request->target);
    }
    auto request = wire::ParseV2TcpRequest(header);
    if (!request) return tl::unexpected(request.error());
    header_bytes = request->header_bytes;
    return std::move(request->target);
}

net::awaitable<tl::expected<TcpRequest, common::ErrorCode>>
ReadTcpRequest(transport::AsyncStream& stream, wire::Version version, session::Context& ctx) {
    buf::MultiBuffer received;
    for (;;) {
        buf::MultiBuffer chunk;
        try {
            chunk = co_await stream.ReadMultiBuffer();
        } catch (const transport::LinkError& error) {
            co_return tl::unexpected(
                ResolveHandshakeReadFailure(stream, error.code()));
        } catch (const IoSystemError& error) {
            co_return tl::unexpected(ClassifyHandshakeReadException(stream, error));
        }
        if (chunk.byte_size() == 0) {
            co_return tl::unexpected(ResolveHandshakeReadFailure(
                stream, received.byte_size() == 0 ? common::ErrorCode::SOCKET_EOF
                                                  : common::ErrorCode::PROTOCOL_DECODE_FAILED));
        }
        buf::AppendCoalescedStreamInput(received, std::move(chunk));

        size_t header_bytes = 0;
        tl::expected<common::TargetAddress, wire::ProtocolError> target =
            tl::unexpected(wire::ProtocolError::Incomplete);
        {
            const size_t inspect_bytes =
                std::min(received.byte_size(), kMaxRequestHeaderBytes);
            if (const auto contiguous = received.PrefixSpan(inspect_bytes);
                !contiguous.empty()) {
                target = ParseTcpRequest(version, contiguous, header_bytes);
            } else {
                std::vector<uint8_t> header(inspect_bytes);
                (void)received.CopyPrefixTo(header);
                target = ParseTcpRequest(version, header, header_bytes);
            }
        }
        if (target) {
            (void)received.DropPrefixBytes(header_bytes);
            co_return TcpRequest{std::move(*target), std::move(received)};
        }
        if (target.error() == wire::ProtocolError::Incomplete &&
            received.byte_size() < kMaxRequestHeaderBytes) {
            continue;
        }
        const std::string_view reason = target.error() == wire::ProtocolError::Incomplete
            ? "request header too large" : "invalid request header";
        LogInboundRequestRejected(ctx, reason);
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
}

// proxy/hysteria server: the transport has authenticated the connection and
// bound its identity; each logical stream is either a UDP session or a TCP
// request whose target this handler reads before dispatch.
class HysteriaInbound final : public ::proxy::Inbound {
public:
    HysteriaInbound(app::StatsShard& stats, wire::Version version) noexcept
        : stats_(stats), version_(version) {}

    net::awaitable<app::RelayResult> Process(
        std::unique_ptr<transport::AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        net::io_context& io_context,
        session::Context& ctx,
        const infra::TimeoutsConfig& timeouts,
        uint32_t /*pressure_idle_timeout*/) override {
        if (ctx.content.network == common::Network::UDP) {
            const transport::Link client{stream.get(), stream.get()};
            co_return co_await dispatcher.Dispatch(
                io_context, receiver.dispatch_policy, std::move(stream),
                client, common::InitialPayload{},
                ctx, stats_, timeouts);
        }

        common::InitialPayload initial_payload;
        {
            auto request = co_await ReadTcpRequest(*stream, version_, ctx);
            if (!request) {
                co_return RejectInbound(stats_, stream.get(), request.error());
            }
            static constexpr std::array<uint8_t, 7> kV1OkResponse{1, 0, 0, 0, 0, 0, 0};
            static constexpr std::array<uint8_t, 3> kV2OkResponse{0, 0, 0};
            const auto response = version_ == wire::Version::V1
                ? std::span<const uint8_t>(kV1OkResponse)
                : std::span<const uint8_t>(kV2OkResponse);
            try {
                co_await stream->AsyncWrite(net::buffer(response));
            } catch (const transport::LinkError& error) {
                co_return RejectInbound(
                    stats_, stream.get(),
                    (stream->ConsumePhaseDeadline() || stream->ConsumeIdleTimeout() ||
                     stream->ConsumeWriteTimeout() ? common::ErrorCode::TIMEOUT : error.code()));
            } catch (const IoSystemError& error) {
                co_return RejectInbound(
                    stats_, stream.get(),
                    ClassifyHandshakeWriteException(*stream, error));
            }
            BindInboundRequestTarget(
                ctx, InboundRequestTarget{common::Network::TCP, std::move(request->target)});
            initial_payload = common::InitialPayload(std::move(request->early_data));
        }
        stream->ClearPhaseDeadline();

        auto* tcp_stream = stream.get();
        co_return co_await dispatcher.Dispatch(
            io_context, receiver.dispatch_policy, std::move(stream),
            transport::Link{tcp_stream, tcp_stream},
            std::move(initial_payload),
            ctx, stats_, timeouts);
    }

private:
    app::StatsShard& stats_;
    wire::Version version_;
};

constexpr uint64_t kBytesPerSecondPerMbps = 125000;

[[nodiscard]] uint64_t MbpsToBytesPerSecond(uint32_t mbps) noexcept {
    return static_cast<uint64_t>(mbps) * kBytesPerSecondPerMbps;
}

std::optional<std::shared_ptr<const proxyman::inbound::ProtocolSettings>>
PrepareSettings(wire::Version version, const infra::InboundProtocolSettings& config) {
    auto settings = std::make_shared<wire::Settings>();
    settings->version = version;
    settings->upload_bytes_per_second =
        MbpsToBytesPerSecond(config.hysteria_up_mbps);
    settings->download_bytes_per_second =
        MbpsToBytesPerSecond(config.hysteria_down_mbps);
    return settings;
}

std::unique_ptr<::proxy::Inbound> CreateInbound(
    const proxyman::inbound::AdmissionEnvironment& environment,
    const proxyman::inbound::BuildRequest& request) {
    const auto* settings = wire::GetSettings(request);
    if (!settings) return nullptr;
    return std::make_unique<HysteriaInbound>(environment.stats, settings->version);
}

std::optional<proxyman::inbound::UserSet> BuildUsers(
    const proxyman::inbound::BuildRequest& request,
    std::span<const infra::InboundUserSpec> specs) {
    return ::proxy::BuildHashedInboundUsers<
        proxyman::inbound::PreparedHysteriaUser>(
        "Hysteria", request, specs,
        [](auto& user, std::string_view credential) {
            user.credential_hash = wire::HashCredential(credential);
        });
}

proxyman::inbound::ProxyRegistration Registration() {
    proxyman::inbound::ProxyRegistration registration;
    registration.user_protocol = proxyman::inbound::UserProtocol::Hysteria;
    registration.datagram_transport = proxyman::inbound::DatagramTransport::Quic;
    registration.traits = {.mailbox_email_defaults_to_tag = true, .requires_tls = true};
    registration.create_quic_listener = [](
        uint32_t worker_id, uint32_t worker_count, net::io_context& io,
        app::DatagramSessionEnvironment environment) -> std::unique_ptr<transport::internet::QuicListener> {
        return std::make_unique<wire::HysteriaIngress>(worker_id, worker_count, io, std::move(environment));
    };
    registration.create_tcp_handler = &CreateInbound;
    registration.build_users = &BuildUsers;
    return registration;
}

const bool kHysteriaRegistered = [] {
    auto v1 = Registration();
    v1.prepare_settings = [](std::string_view, const infra::InboundProtocolSettings& config)
        -> std::optional<std::shared_ptr<const proxyman::inbound::ProtocolSettings>> {
        return PrepareSettings(wire::Version::V1, config);
    };
    proxyman::inbound::RegisterProxy(constants::protocol::kHysteria, std::move(v1));

    auto v2 = Registration();
    v2.prepare_settings = [](std::string_view, const infra::InboundProtocolSettings& config)
        -> std::optional<std::shared_ptr<const proxyman::inbound::ProtocolSettings>> {
        return PrepareSettings(wire::Version::V2, config);
    };
    proxyman::inbound::RegisterProxy(constants::protocol::kHysteria2, std::move(v2));
    return true;
}();

}  // namespace
}  // namespace proxy::hysteria
