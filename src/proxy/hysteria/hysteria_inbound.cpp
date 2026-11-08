#include "../inbound_admission.hpp"
#include "../../transport/internet/hysteria/hysteria_protocol.hpp"
#include "../../transport/internet/hysteria/hysteria_settings.hpp"
#include "../../transport/internet/hysteria/quic_stream.hpp"

#include "app/proxyman/inbound/factory.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
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
#include "transport/link_error.hpp"

#include <tl/expected.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <span>
#include <utility>

namespace proxy::hysteria {
namespace {

namespace wire = ::transport::internet::hysteria;

constexpr size_t kMaxRequestHeaderBytes = 8192;

net::io_context& SessionReactor(net::io_context& fallback) noexcept {
    if (auto domain = ExecutionDomain::Current()) {
        return domain->Reactor();
    }
    return fallback;
}

struct TcpRequest {
    TargetAddress target;
    // Request-stream bytes that followed the header in the same read.
    buf::MultiBuffer early_data;
};

[[nodiscard]] tl::expected<TargetAddress, wire::ProtocolError>
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

net::awaitable<tl::expected<TcpRequest, ErrorCode>>
ReadTcpRequest(AsyncStream& stream, wire::Version version, session::Context& ctx) {
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
                stream, ErrorCode::PROTOCOL_DECODE_FAILED));
        }
        buf::AppendCoalescedStreamInput(received, std::move(chunk));

        size_t header_bytes = 0;
        tl::expected<TargetAddress, wire::ProtocolError> target =
            tl::unexpected(wire::ProtocolError::Incomplete);
        {
            const size_t inspect_bytes =
                std::min(received.byte_size(), kMaxRequestHeaderBytes);
            if (const auto contiguous = received.PrefixSpan(inspect_bytes);
                !contiguous.empty()) {
                target = ParseTcpRequest(version, contiguous, header_bytes);
            } else {
                memory::ThreadLocalVector<uint8_t> header(inspect_bytes);
                (void)received.CopyPrefixTo(header);
                target = ParseTcpRequest(version, header, header_bytes);
            }
        }
        if (target) {
            (void)received.DropPrefixBytes(header_bytes);
            if (received.empty()) {
                received.ReleaseIfIdle();
            }
            co_return TcpRequest{std::move(*target), std::move(received)};
        }
        if (target.error() == wire::ProtocolError::Incomplete &&
            received.byte_size() < kMaxRequestHeaderBytes) {
            continue;
        }
        const std::string_view reason = target.error() == wire::ProtocolError::Incomplete
            ? "request header too large" : "invalid request header";
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > {}",
                      ctx.inbound.source_ip, ctx.inbound.source_port, reason);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
}

// proxy/hysteria server: the transport has authenticated the connection and
// bound its identity; each logical stream is either a UDP session or a TCP
// request whose target this handler reads before dispatch.
class HysteriaInbound final : public ::Inbound {
public:
    HysteriaInbound(StatsShard& stats, wire::Version version) noexcept
        : stats_(stats), version_(version) {}

    net::awaitable<RelayResult> Process(
        std::unique_ptr<AsyncStream> stream,
        routing::Dispatcher& dispatcher,
        const proxyman::inbound::ReceiverSettings& receiver,
        net::io_context& io_context,
        session::Context& ctx,
        const TimeoutsConfig& timeouts,
        uint32_t /*pressure_idle_timeout*/) override {
        auto& reactor = SessionReactor(io_context);
        if (auto* session = dynamic_cast<wire::UdpSessionStream*>(stream.get())) {
            BindInboundRequestTarget(
                ctx, InboundRequestTarget{Network::UDP, session->FirstTarget()});
            co_return co_await dispatcher.Dispatch(
                reactor, receiver.dispatch_policy, std::move(stream),
                transport::Link{session, session}, InitialPayload{},
                ctx, stats_, timeouts);
        }

        InitialPayload initial_payload;
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
                    ResolveHandshakeReadFailure(*stream, error.code()));
            } catch (const IoSystemError& error) {
                co_return RejectInbound(
                    stats_, stream.get(),
                    ClassifyHandshakeReadException(*stream, error));
            }
            BindInboundRequestTarget(
                ctx, InboundRequestTarget{Network::TCP, std::move(request->target)});
            initial_payload = InitialPayload(std::move(request->early_data));
        }
        stream->ClearPhaseDeadline();

        auto* tcp_stream = stream.get();
        co_return co_await dispatcher.Dispatch(
            reactor, receiver.dispatch_policy, std::move(stream),
            transport::Link{tcp_stream, tcp_stream},
            std::move(initial_payload),
            ctx, stats_, timeouts);
    }

private:
    StatsShard& stats_;
    wire::Version version_;
};

constexpr uint64_t kBytesPerSecondPerMbps = 125000;

[[nodiscard]] uint64_t MbpsToBytesPerSecond(uint32_t mbps) noexcept {
    return static_cast<uint64_t>(mbps) * kBytesPerSecondPerMbps;
}

std::optional<std::shared_ptr<const proxyman::inbound::ProtocolSettings>>
PrepareSettings(wire::Version version, const InboundProtocolSettings& config) {
    auto settings = std::make_shared<wire::Settings>();
    settings->version = version;
    settings->upload_bytes_per_second =
        MbpsToBytesPerSecond(config.hysteria_up_mbps);
    settings->download_bytes_per_second =
        MbpsToBytesPerSecond(config.hysteria_down_mbps);
    return settings;
}

std::unique_ptr<::Inbound> CreateInbound(
    proxyman::inbound::ProtocolRuntime&,
    StatsShard& stats,
    ConnectionLimiter*,
    const proxyman::inbound::BuildRequest& request) {
    const auto* settings = wire::GetSettings(request);
    if (!settings) return nullptr;
    return std::make_unique<HysteriaInbound>(stats, settings->version);
}

std::optional<proxyman::inbound::UserSet> BuildUsers(
    const proxyman::inbound::BuildRequest& request,
    std::span<const InboundUserSpec> specs) {
    std::vector<proxyman::inbound::PreparedHysteriaUser> users;
    users.reserve(specs.size());
    for (const auto& spec : specs) {
        if (spec.credential.empty()) {
            LOG_WARN("Hysteria inbound '{}': user credential is empty", request.tag);
            return std::nullopt;
        }
        proxyman::inbound::PreparedHysteriaUser user;
        user.credential_hash = wire::HashCredential(spec.credential);
        user.profile.email = spec.email;
        user.profile.user_id = spec.user_id;
        user.profile.speed_limit = spec.speed_limit;
        user.profile.device_limit = spec.device_limit;
        users.push_back(std::move(user));
    }
    return proxyman::inbound::UserSet{std::move(users)};
}

proxyman::inbound::ProxyRegistration Registration() {
    proxyman::inbound::ProxyRegistration registration;
    registration.user_protocol = proxyman::inbound::UserProtocol::Hysteria;
    registration.datagram_transport = proxyman::inbound::DatagramTransport::Quic;
    registration.create_runtime = []() -> std::unique_ptr<
        proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<UserOnlineProtocolRuntime>();
    };
    registration.create_tcp_handler = &CreateInbound;
    registration.build_users = &BuildUsers;
    return registration;
}

const bool kHysteriaRegistered = [] {
    auto v1 = Registration();
    v1.prepare_settings = [](std::string_view, const InboundProtocolSettings& config)
        -> std::optional<std::shared_ptr<const proxyman::inbound::ProtocolSettings>> {
        return PrepareSettings(wire::Version::V1, config);
    };
    proxyman::inbound::RegisterProxy(constants::protocol::kHysteria, std::move(v1));

    auto v2 = Registration();
    v2.prepare_settings = [](std::string_view, const InboundProtocolSettings& config)
        -> std::optional<std::shared_ptr<const proxyman::inbound::ProtocolSettings>> {
        return PrepareSettings(wire::Version::V2, config);
    };
    proxyman::inbound::RegisterProxy(constants::protocol::kHysteria2, std::move(v2));
    return true;
}();

}  // namespace
}  // namespace proxy::hysteria
