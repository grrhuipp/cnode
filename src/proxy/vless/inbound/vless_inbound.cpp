#include "common/mux/mux_codec.hpp"
#include "proxy/handshake_errors.hpp"
#include "proxy/mux/mux_server.hpp"
#include "app/relay.hpp"
#include "common/scoped_cleanse.hpp"
#include "proxy/inbound_admission.hpp"
#include "proxy/inbound.hpp"
#include "common/sharded_user_stats.hpp"
#include "proxy/vless/vless_codec.hpp"
#include "proxy/vless/vless_encryption.hpp"
#include "app/worker_mailbox.hpp"
#include "app/proxyman/inbound/handler.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "common/const_buffer_span.hpp"
#include "app/rate_limiter.hpp"
#include "app/stats.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"
#include "common/initial_payload.hpp"
#include "common/session.hpp"
#include "core/constants.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <array>
#include <tl/expected.hpp>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>


namespace {

using proxy::BufferedStreamReader;

// Coalesces the fixed response header into the first downstream write.
class VlessResponseHeaderWriter final : public transport::MultiBufferWriter {
public:
    explicit VlessResponseHeaderWriter(transport::MultiBufferWriter& dst) noexcept
        : dst_(dst) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (header_sent_) {
            return dst_.WriteMultiBuffer(std::move(mb));
        }
        return WriteFirstMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (header_sent_) {
            return dst_.WriteBuffers(buffers);
        }
        return WriteFirstBuffers(buffers);
    }
    net::awaitable<void> AsyncShutdownWrite() override {
        if (!header_sent_) {
            header_sent_ = true;
            const std::array<net::const_buffer, 1> out{HeaderBuffer()};
            co_await dst_.WriteBuffers(out);
        }
        co_await dst_.AsyncShutdownWrite();
    }

    bool WriteShutdownClosesLink() const noexcept override {
        return dst_.WriteShutdownClosesLink();
    }

private:
    net::awaitable<void> WriteFirstMultiBuffer(buf::MultiBuffer mb) {
        if (mb.byte_size() == 0) {
            mb.clear();
            co_return;
        }
        header_sent_ = true;
        common::ConstBufferSpanBuilder<1 + buf::MultiBuffer::kInlineCapacity> out;
        out.Append(HeaderBuffer());
        out.AppendMultiBuffer(mb);
        co_await dst_.WriteBuffers(out.Span());
        mb.clear();
    }

    net::awaitable<void> WriteFirstBuffers(std::span<const net::const_buffer> buffers) {
        if (std::ranges::all_of(buffers, [](const net::const_buffer& b) { return b.size() == 0; })) {
            co_return;
        }
        header_sent_ = true;
        common::ConstBufferSpanBuilder<1 + buf::MultiBuffer::kInlineCapacity> out;
        out.Append(HeaderBuffer());
        out.AppendBuffers(buffers);
        co_await dst_.WriteBuffers(out.Span());
    }

    [[nodiscard]] static net::const_buffer HeaderBuffer() noexcept {
        return net::const_buffer(::proxy::vless::kResponseHeader.data(),
                                 ::proxy::vless::kResponseHeader.size());
    }

    transport::MultiBufferWriter& dst_;
    bool header_sent_ = false;
};


net::awaitable<tl::expected<::proxy::vless::RequestHeader, common::ErrorCode>>
ReadVlessRequestHeader(proxy::BufferedStreamReader& active_reader,
                       transport::AsyncStream& stream,
                       session::Context& ctx) {
    const auto& client_ip = ctx.inbound.source_ip;
    using ::proxy::vless::RequestHeaderDecodeStatus;
    std::array<uint8_t, ::proxy::vless::kMaxRequestHeaderSize> handshake{};
    size_t total_read = 0;
    common::ScopedCleanse cleanse_handshake{handshake};
    size_t required = 1;
    for (;;) {
        bool read_ok = false;
        size_t step_read = 0;
        try {
            read_ok = active_reader.ReadBuffered(
                          handshake.data() + total_read,
                          required - total_read,
                          step_read) ||
                      co_await active_reader.ReadExact(
                          handshake.data() + total_read,
                          required - total_read, &step_read);
        } catch (const IoSystemError& error) {
            const common::ErrorCode classified =
                proxy::ClassifyHandshakeReadException(stream, error);
            if (classified == common::ErrorCode::TIMEOUT) {
                LOG_CONN_WARN(ctx, "handshake phase deadline from {}:{}",
                              client_ip, ctx.inbound.source_port);
            }
            co_return tl::unexpected(classified);
        }
        if (!read_ok) {
            co_return tl::unexpected(
                proxy::ResolveHandshakeReadFailure(
                    stream,
                    total_read == 0 && step_read == 0
                        ? common::ErrorCode::SOCKET_EOF
                        : common::ErrorCode::PROTOCOL_DECODE_FAILED));
        }
        total_read = required;

        auto decoded = ::proxy::vless::DecodeRequestHeader(
            std::span<const uint8_t>(handshake.data(), total_read));
        switch (decoded.status) {
        case RequestHeaderDecodeStatus::Complete:
            co_return std::move(decoded.header);
        case RequestHeaderDecodeStatus::Incomplete:
            required = decoded.required;
            continue;
        case RequestHeaderDecodeStatus::InvalidVersion:
            proxy::LogInboundRequestRejected(ctx, "invalid protocol version");
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_INVALID_VERSION);
        case RequestHeaderDecodeStatus::InvalidAddress:
            proxy::LogInboundRequestRejected(ctx, "invalid target address");
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
        case RequestHeaderDecodeStatus::InvalidCommand:
        case RequestHeaderDecodeStatus::InvalidAddons:
            break;
        }
        proxy::LogInboundRequestRejected(ctx, "invalid request header");
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
}

struct VlessHandshakeOutcome {
    common::UserOnlineSessionGuard user_session;
    common::Network net = common::Network::TCP;
    bool packet_addr_udp = false;
    bool use_vision = false;
    std::array<uint8_t, 16> request_uuid{};
    ::proxy::vless::VlessActiveIo active;
};

net::awaitable<tl::expected<VlessHandshakeOutcome, common::ErrorCode>>
CompleteVlessInboundHandshake(
    transport::AsyncStream& stream,
    const std::shared_ptr<const ::proxy::vless::VlessEncryptionConfig>& decryption,
    proxy::BufferedStreamReader& protocol_reader,
    transport::MultiBufferWriter& protocol_writer,
    std::optional<::proxy::vless::VlessEncryptedIo>& encrypted_io,
    const proxyman::inbound::AdmissionEnvironment& environment,
    proxy::InboundAuthentication authentication,
    const proxyman::inbound::ReceiverSettings& receiver,
    session::Context& ctx) {
    const auto tag = ctx.inbound.tag;
    const auto& client_ip = ctx.inbound.source_ip;
    auto* active_reader = &protocol_reader;
    auto* active_writer = &protocol_writer;
    std::optional<::proxy::vless::VlessEncryptionIssuedTicket> issued_ticket;
    std::optional<std::array<uint8_t, 16>> resumed_identity;
    if (decryption) {
        try {
            auto runtime =
                co_await ::proxy::vless::RunVlessEncryptionServerHandshake(
                    environment.coordinator,
                    protocol_reader,
                    protocol_writer,
                    decryption,
                    tag);
            if (!runtime) {
                if (proxy::ConsumeStreamReadTimeout(stream)) {
                    LOG_CONN_WARN(ctx, "encryption handshake timed out from {}:{}",
                                  client_ip, ctx.inbound.source_port);
                    co_return tl::unexpected(common::ErrorCode::TIMEOUT);
                }
                if (runtime.error() == ::proxy::vless::VlessEncryptionHandshakeFailure::Closed) {
                    co_return tl::unexpected(common::ErrorCode::SOCKET_EOF);
                }
                const bool truncated =
                    runtime.error() == ::proxy::vless::VlessEncryptionHandshakeFailure::Truncated;
                const auto reason = truncated
                    ? "encryption handshake truncated" : "encryption handshake rejected";
                if (truncated) {
                    LOG_CONN_WARN(ctx, "{} from {}:{}", reason, client_ip, ctx.inbound.source_port);
                } else {
                    proxy::LogInboundRequestRejected(ctx, reason);
                }
                co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            issued_ticket = std::move(runtime->issued_ticket);
            resumed_identity = runtime->resumed_identity;
            encrypted_io.emplace(
                protocol_reader, protocol_writer, std::move(*runtime));
            active_reader = &encrypted_io->plain_reader;
            active_writer = &encrypted_io->writer;
        } catch (const IoSystemError& error) {
            const common::ErrorCode classified =
                proxy::ClassifyHandshakeReadException(stream, error);
            if (classified == common::ErrorCode::CANCELLED) {
                LOG_CONN_DEBUG(ctx, "encryption handshake cancelled from {}:{}",
                               client_ip, ctx.inbound.source_port);
            } else {
                LOG_CONN_WARN(ctx, "encryption handshake failed from {}:{} > {}",
                              client_ip, ctx.inbound.source_port,
                              classified == common::ErrorCode::TIMEOUT ? "timeout" : "transport error");
            }
            co_return tl::unexpected(classified);
        } catch (const app::WorkerMailboxFull&) {
            co_return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
        } catch (...) {
            proxy::LogInboundRequestRejected(ctx, "encryption handshake exception");
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
    }

    auto parsed_request = co_await ReadVlessRequestHeader(
        *active_reader, stream, ctx);
    if (!parsed_request) {
        co_return tl::unexpected(parsed_request.error());
    }
    auto& request = *parsed_request;
    const auto credential = co_await authentication.VerifyCredential({proxy::KeyedInboundProtocol::Vless, request.uuid});
    if (credential != common::ErrorCode::OK) co_return tl::unexpected(credential);
    auto user_info = proxyman::inbound::UserStore::FindVlessUser(tag, request.uuid);
    if (!user_info) {
        co_return tl::unexpected(co_await authentication.RejectCredential("no matching user"));
    }
    common::Network net = common::Network::TCP;
    if (request.command == ::proxy::vless::Command::UDP) {
        net = common::Network::UDP;
    } else if (request.command == ::proxy::vless::Command::MUX) {
        net = common::Network::MUX;
    }
    const bool packet_addr_udp =
        request.command == ::proxy::vless::Command::UDP &&
        ::proxy::vless::IsPacketAddrMagic(request.target);
    // Published before flow/transport validation so those rejections log the
    // authenticated user and the requested target.
    auto bound = std::move(authentication).Bind(user_info->profile,
        proxy::InboundRequestTarget{
            net,
            std::move(request.target),
            std::move(request.forwarded)});
    if (resumed_identity &&
        CRYPTO_memcmp(resumed_identity->data(), request.uuid.data(), request.uuid.size()) != 0) {
        co_return tl::unexpected(std::move(bound).Reject("resumed identity mismatch", common::ErrorCode::PROTOCOL_AUTH_FAILED));
    }
    const bool use_vision = ::proxy::vless::IsVisionFlow(request.flow);
    if (!request.flow.empty()) {
        if (std::string_view(request.flow) != user_info->flow) {
            co_return tl::unexpected(std::move(bound).Reject("request flow not allowed", common::ErrorCode::PROTOCOL_UNSUPPORTED));
        }
        if (!use_vision) {
            co_return tl::unexpected(std::move(bound).Reject("unknown request flow", common::ErrorCode::PROTOCOL_UNSUPPORTED));
        }
    }
    if (!user_info->flow.empty() && !::proxy::vless::IsVisionFlow(user_info->flow)) {
        co_return tl::unexpected(std::move(bound).Reject("unsupported configured flow", common::ErrorCode::PROTOCOL_UNSUPPORTED));
    }
    if (request.flow.empty() && ::proxy::vless::IsVisionFlow(user_info->flow)) {
        co_return tl::unexpected(std::move(bound).Reject("missing required flow", common::ErrorCode::PROTOCOL_UNSUPPORTED));
    }
    if (use_vision && request.command != ::proxy::vless::Command::TCP) {
        co_return tl::unexpected(std::move(bound).Reject("flow only supports TCP", common::ErrorCode::PROTOCOL_UNSUPPORTED));
    }
    if (use_vision &&
        (!(receiver.stream_settings.IsTlsLike() || decryption != nullptr) ||
         receiver.stream_settings.network_mode != transport::internet::NetworkMode::Tcp)) {
        co_return tl::unexpected(std::move(bound).Reject("flow requires raw TCP TLS-like transport", common::ErrorCode::PROTOCOL_UNSUPPORTED));
    }

    auto user_session = co_await std::move(bound).Admit();
    if (!user_session) co_return tl::unexpected(user_session.error());

    // Flow validation and metadata copy are complete; no credential is needed
    // by the request body or Vision's per-session UUID state.
    user_info.reset();

    if (issued_ticket) {
        try {
            (void)co_await ::proxy::vless::AuthenticateVlessTicket(
                environment.coordinator, decryption, tag, std::move(*issued_ticket), request.uuid);
        } catch (const app::WorkerMailboxFull&) {
            co_return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
        } catch (const IoSystemError&) {
            co_return tl::unexpected(common::ErrorCode::CANCELLED);
        }
    }

    co_return VlessHandshakeOutcome{
        .user_session = std::move(*user_session),
        .net = net,
        .packet_addr_udp = packet_addr_udp,
        .use_vision = use_vision,
        .request_uuid = request.uuid,
        .active = {active_reader, active_writer},
    };
}
}  // namespace

namespace proxy::vless::inbound {

class Handler final : public ::proxy::Inbound {
public:
    Handler(const ::proxyman::inbound::AdmissionEnvironment& environment,
            std::shared_ptr<
                const ::proxy::vless::VlessEncryptionConfig> decryption = {});
    ~Handler() override;

    ::net::awaitable<::app::RelayResult> Process(
        std::unique_ptr<::transport::AsyncStream> stream,
        ::routing::Dispatcher& dispatcher,
        const ::proxyman::inbound::ReceiverSettings& receiver,
        ::net::io_context& io_context,
        ::session::Context& ctx,
        const ::infra::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

private:
    const ::proxyman::inbound::AdmissionEnvironment& environment_;
    std::shared_ptr<const ::proxy::vless::VlessEncryptionConfig> decryption_;
};

}  // namespace proxy::vless::inbound

proxy::vless::inbound::Handler::Handler(
    const ::proxyman::inbound::AdmissionEnvironment& environment,
    std::shared_ptr<const ::proxy::vless::VlessEncryptionConfig> decryption)
    : environment_(environment)
    , decryption_(std::move(decryption)) {}

proxy::vless::inbound::Handler::~Handler() = default;

net::awaitable<app::RelayResult>
proxy::vless::inbound::Handler::Process(
    std::unique_ptr<transport::AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
    const infra::TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout) {


    auto fail_abortive = [&](common::ErrorCode error) {
        return proxy::RejectInbound(environment_.stats, stream.get(), error);
    };

    auto authentication = co_await proxy::BeginInboundAuthentication(environment_, ctx);
    if (!authentication) co_return fail_abortive(authentication.error());

    proxy::BufferedStreamReader protocol_reader(*stream);
    transport::MultiBufferWriter& protocol_writer = *stream;
    proxy::BufferedStreamReader* active_reader = &protocol_reader;
    transport::MultiBufferWriter* active_writer = &protocol_writer;
    std::optional<::proxy::vless::VlessEncryptedIo> encrypted_io;

    common::UserOnlineSessionGuard user_session;
    common::Network net = common::Network::TCP;
    bool packet_addr_udp = false;
    bool use_vision = false;
    std::array<uint8_t, 16> request_uuid{};
    {
        auto handshake = co_await CompleteVlessInboundHandshake(
            *stream,
            decryption_,
            protocol_reader,
            protocol_writer,
            encrypted_io,
            environment_,
            std::move(*authentication),
            receiver,
            ctx);
        if (!handshake) {
            co_return fail_abortive(handshake.error());
        }
        active_reader = handshake->active.reader;
        active_writer = handshake->active.writer;
        user_session = std::move(handshake->user_session);
        net = handshake->net;
        packet_addr_udp = handshake->packet_addr_udp;
        use_vision = handshake->use_vision;
        if (use_vision) {
            request_uuid = handshake->request_uuid;
        }
        OPENSSL_cleanse(handshake->request_uuid.data(), handshake->request_uuid.size());
    }
    VlessResponseHeaderWriter response_writer(*active_writer);
    active_writer = &response_writer;

    if (net == common::Network::MUX) {
        co_return co_await proxy::ServeMuxInbound(
            io_context,
            transport::Link{active_reader, active_writer},
            *stream,
            dispatcher,
            receiver.dispatch_policy,
            environment_,
            ctx,
            environment_.stats,
            timeouts,
            pressure_idle_timeout);
    }

    if (net == common::Network::UDP) {
        ::proxy::vless::UdpStreamEndpoint udp_endpoint(
            *active_reader, *active_writer, ctx.outbound.target, packet_addr_udp);
        common::InitialPayload first_datagram;
        if (packet_addr_udp) {
            auto packet = co_await udp_endpoint.ReadMultiBuffer();
            if (packet.empty()) co_return app::RelayResult{};
            const auto datagram = buf::InspectUdpDatagram(packet);
            if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid())
                co_return fail_abortive(common::ErrorCode::PROTOCOL_DECODE_FAILED);
            // The magic address selects framing, not a routable destination.
            proxy::BindInboundRequestTarget(
                ctx, proxy::InboundRequestTarget{common::Network::UDP, *datagram.target});
            first_datagram = common::InitialPayload(std::move(packet));
        }
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver.dispatch_policy,
            std::move(stream),
            transport::Link{&udp_endpoint, &udp_endpoint},
            std::move(first_datagram),
            ctx,
            environment_.stats,
            timeouts);
    }

    if (use_vision) {
        ::proxy::vless::VisionTrafficState traffic;
        ::proxy::vless::VisionReader vision_reader(
            *active_reader,
            request_uuid,
            traffic);
        ::proxy::vless::VisionWriter vision_writer(*active_writer, request_uuid, traffic);
        OPENSSL_cleanse(request_uuid.data(), request_uuid.size());
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver.dispatch_policy,
            std::move(stream),
            transport::Link{&vision_reader, &vision_writer},
            common::InitialPayload{},
            ctx,
            environment_.stats,
            timeouts);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{active_reader, active_writer},
        common::InitialPayload{},
        ctx,
        environment_.stats,
        timeouts);
}


namespace {
class VlessSettings final
    : public ::proxyman::inbound::ProtocolSettings {
public:
    std::shared_ptr<const ::proxy::vless::VlessEncryptionConfig> decryption;
};

[[nodiscard]] const VlessSettings* GetVlessSettings(
    const ::proxyman::inbound::BuildRequest& req) noexcept {
    return dynamic_cast<const VlessSettings*>(req.settings.get());
}

[[nodiscard]] std::optional<::proxyman::inbound::PreparedVlessUser>
BuildPreparedVlessUser(const ::infra::InboundUserSpec& spec) {
    auto uuid_bytes = ::proxy::vless::ParseUuidBytes(spec.credential);
    if (!uuid_bytes) {
        return std::nullopt;
    }
    ::proxyman::inbound::PreparedVlessUser info;
    info.uuid_bytes = *uuid_bytes;
    info.flow = ::proxy::vless::NormalizeFlow(spec.flow);
    info.profile = ::proxy::MakeUserProfile(spec);
    return info;
}

const bool kVlessInboundRegistered = [] {
    ::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = ::proxyman::inbound::UserProtocol::Vless;


    reg.create_tcp_handler =
        [](const ::proxyman::inbound::AdmissionEnvironment& environment,
           const ::proxyman::inbound::BuildRequest& req)
            -> std::unique_ptr<::proxy::Inbound> {
            const auto* settings = GetVlessSettings(req);
            if (!settings) {
                return nullptr;
            }
            return std::make_unique<::proxy::vless::inbound::Handler>(
                environment,
                settings->decryption);
        };

    reg.prepare_settings =
        [](std::string_view tag, const ::infra::InboundProtocolSettings& config)
            -> std::optional<std::shared_ptr<
                const ::proxyman::inbound::ProtocolSettings>> {
            auto settings = std::make_shared<VlessSettings>();
                auto parsed = ::proxy::vless::ParseVlessServerDecryption(
                    config.vless_decryption);
                if (!parsed) {
                    LOG_WARN("VLESS inbound '{}': invalid decryption: {}",
                             tag,
                             ::proxy::vless::VlessEncryptionParseErrorMessage(
                                 parsed.error()));
                    return std::nullopt;
                }
                if (*parsed) settings->decryption =
                    std::make_shared<::proxy::vless::VlessEncryptionConfig>(
                        std::move(**parsed));
            return settings;
        };

    // Decryption settings are validated once by prepare_settings; inbound
    // preparation runs it before building users.
    reg.build_users =
        [](const ::proxyman::inbound::BuildRequest& req,
           std::span<const ::infra::InboundUserSpec> specs)
            -> std::optional<::proxyman::inbound::UserSet> {
            std::vector<::proxyman::inbound::PreparedVlessUser> users;
            users.reserve(specs.size());
            for (const auto& spec : specs) {
                auto user = BuildPreparedVlessUser(spec);
                if (!user) {
                    LOG_WARN("VLESS inbound '{}': invalid user UUID", req.tag);
                    return std::nullopt;
                }
                users.push_back(std::move(*user));
            }
            return ::proxyman::inbound::UserSet{std::move(users)};
        };

    ::proxyman::inbound::RegisterProxy(
        ::constants::protocol::kVless, std::move(reg));
    return true;
}();
}  // namespace
