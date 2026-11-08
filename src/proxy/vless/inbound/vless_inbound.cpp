#include "vless_inbound.hpp"
#include "../credentials.hpp"
#include "../../mux/inbound/mux_inbound.hpp"
#include "../../inbound_admission.hpp"

#include "../vless_codec.hpp"
#include "../vless_encryption.hpp"
#include "../vless_encryption_io.hpp"
#include "../vless_encryption_runtime.hpp"
#include "../vless_ticket_service.hpp"
#include "app/worker_mailbox.hpp"
#include "../vless_buffered_reader.hpp"
#include "../udp_framing.hpp"
#include "../vless_vision.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "common/buffer_util.hpp"
#include "app/rate_limiter.hpp"
#include "app/stats.hpp"
#include "app/udp_types.hpp"
#include "common/allocator.hpp"
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

using ::vless::VlessBufferedReader;

class VlessUdpReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }

    VlessUdpReader(transport::MultiBufferReader& src,
                   TargetAddress target,
                   bool packet_addr)
        : src_(src)
        , target_(std::move(target))
        , framer_(packet_addr) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        return framer_.ReadDatagram(src_, target_);
    }

private:
    transport::MultiBufferReader& src_;
    TargetAddress target_;
    ::vless::UdpFramer framer_;
};

class VlessUdpWriter final : public transport::MultiBufferWriter {
public:
    VlessUdpWriter(transport::MultiBufferWriter& dst, bool packet_addr)
        : dst_(dst)
        , packet_addr_(packet_addr) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        return ::vless::WriteUdpDatagram(
            dst_, std::move(mb), packet_addr_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (packet_addr_) {
            throw IoSystemError(
                io_error::invalid_argument,
                "packet-address VLESS UDP write requires a target");
        }
        // Without packet addresses the frame carries no target bytes.
        co_await ::vless::WriteUdpDatagram(
            dst_, TargetAddress{}, false, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return dst_.AsyncShutdownWrite();
    }

    bool WriteShutdownClosesLink() const noexcept override {
        return dst_.WriteShutdownClosesLink();
    }

private:
    transport::MultiBufferWriter& dst_;
    bool packet_addr_ = false;
};

// Coalesces the fixed response header into the first downstream write.
class VlessResponseHeaderWriter final : public transport::MultiBufferWriter {
public:
    explicit VlessResponseHeaderWriter(transport::MultiBufferWriter& dst) noexcept
        : dst_(dst) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (mb.byte_size() == 0) {
            mb.clear();
            co_return;
        }
        if (header_sent_) {
            co_await dst_.WriteMultiBuffer(std::move(mb));
            co_return;
        }
        header_sent_ = true;
        ConstBufferSpanBuilder<1 + buf::MultiBuffer::kInlineCapacity> out;
        out.Append(HeaderBuffer());
        out.AppendMultiBuffer(mb);
        co_await dst_.WriteBuffers(out.Span());
        mb.clear();
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (std::ranges::all_of(buffers, [](const net::const_buffer& b) { return b.size() == 0; })) {
            co_return;
        }
        if (header_sent_) {
            co_await dst_.WriteBuffers(buffers);
            co_return;
        }
        header_sent_ = true;
        ConstBufferSpanBuilder<1 + buf::MultiBuffer::kInlineCapacity> out;
        out.Append(HeaderBuffer());
        out.AppendBuffers(buffers);
        co_await dst_.WriteBuffers(out.Span());
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
    [[nodiscard]] static net::const_buffer HeaderBuffer() noexcept {
        return net::const_buffer(::vless::kResponseHeader.data(),
                                 ::vless::kResponseHeader.size());
    }

    transport::MultiBufferWriter& dst_;
    bool header_sent_ = false;
};


net::awaitable<tl::expected<::vless::RequestHeader, ErrorCode>>
ReadVlessRequestHeader(VlessBufferedReader& active_reader,
                       AsyncStream& stream,
                       session::Context& ctx,
                       std::string_view client_ip) {
    using ::vless::RequestHeaderDecodeStatus;
    std::array<uint8_t, ::vless::kMaxRequestHeaderSize> handshake{};
    size_t total_read = 0;
    struct HandshakeCleanseGuard {
        std::array<uint8_t, ::vless::kMaxRequestHeaderSize>& buf;
        size_t& read_bytes;
        ~HandshakeCleanseGuard() noexcept {
            if (read_bytes > 0) OPENSSL_cleanse(buf.data(), read_bytes);
        }
    } cleanse_handshake{handshake, total_read};
    size_t required = 1;
    for (;;) {
        bool read_ok = false;
        size_t step_read = 0;
        try {
            read_ok = co_await active_reader.ReadExact(
                handshake.data() + total_read,
                required - total_read,
                false,
                &step_read);
        } catch (const IoSystemError& error) {
            const ErrorCode classified =
                proxy::ClassifyHandshakeReadException(stream, error);
            if (classified == ErrorCode::TIMEOUT) {
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
                        ? ErrorCode::SOCKET_EOF
                        : ErrorCode::PROTOCOL_DECODE_FAILED));
        }
        total_read = required;

        auto decoded = ::vless::DecodeRequestHeader(
            std::span<const uint8_t>(handshake.data(), total_read));
        switch (decoded.status) {
        case RequestHeaderDecodeStatus::Complete:
            co_return std::move(decoded.header);
        case RequestHeaderDecodeStatus::Incomplete:
            required = decoded.required;
            continue;
        case RequestHeaderDecodeStatus::InvalidVersion:
            LOG_CONN_WARN(ctx, "request rejected from {}:{} > invalid protocol version",
                          client_ip, ctx.inbound.source_port);
            LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "invalid protocol version"));
            co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_VERSION);
        case RequestHeaderDecodeStatus::InvalidAddress:
            LOG_CONN_WARN(ctx, "request rejected from {}:{} > invalid target address",
                          client_ip, ctx.inbound.source_port);
            LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "invalid target address"));
            co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        case RequestHeaderDecodeStatus::InvalidCommand:
        case RequestHeaderDecodeStatus::InvalidAddons:
            break;
        }
        LOG_CONN_WARN(ctx, "invalid request header from {}:{}", client_ip, ctx.inbound.source_port);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "invalid request header"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }
}

struct VlessHandshakeOutcome {
    UserOnlineSessionGuard user_session;
    Network net = Network::TCP;
    bool packet_addr_udp = false;
    bool use_vision = false;
    std::array<uint8_t, 16> request_uuid{};
};

net::awaitable<tl::expected<VlessHandshakeOutcome, ErrorCode>>
CompleteVlessInboundHandshake(
    AsyncStream& stream,
    const std::shared_ptr<const ::vless::VlessEncryptionConfig>& decryption,
    VlessBufferedReader& protocol_reader,
    transport::MultiBufferWriter& protocol_writer,
    std::unique_ptr<::vless::VlessEncryptedIo>& encrypted_io,
    VlessBufferedReader*& active_reader,
    transport::MultiBufferWriter*& active_writer,
    ::UserOnlineTracker& validator,
    ConnectionLimiter* limiter,
    const proxyman::inbound::ReceiverSettings& receiver,
    session::Context& ctx,
    std::string_view tag,
    std::string_view client_ip) {
    std::optional<::vless::VlessEncryptionIssuedTicket> issued_ticket;
    std::optional<std::array<uint8_t, 16>> resumed_identity;
    if (decryption) {
        try {
            auto runtime =
                co_await ::vless::RunVlessEncryptionServerHandshake(
                    protocol_reader,
                    protocol_writer,
                    decryption,
                    tag);
            if (!runtime) {
                if (proxy::ConsumeStreamReadTimeout(stream)) {
                    LOG_CONN_WARN(ctx, "encryption handshake timed out from {}:{}",
                                  client_ip, ctx.inbound.source_port);
                    co_return tl::unexpected(ErrorCode::TIMEOUT);
                }
                if (runtime.error() == ::vless::VlessEncryptionHandshakeFailure::Closed) {
                    co_return tl::unexpected(ErrorCode::SOCKET_EOF);
                }
                const bool truncated =
                    runtime.error() == ::vless::VlessEncryptionHandshakeFailure::Truncated;
                const auto reason = truncated
                    ? "encryption handshake truncated" : "encryption handshake rejected";
                LOG_CONN_WARN(ctx, "{} from {}:{}", reason, client_ip, ctx.inbound.source_port);
                if (!truncated) {
                    LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
                }
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            issued_ticket = std::move(runtime->issued_ticket);
            resumed_identity = runtime->resumed_identity;
            encrypted_io = std::make_unique<::vless::VlessEncryptedIo>(
                protocol_reader, protocol_writer, std::move(*runtime));
            active_reader = &encrypted_io->plain_reader;
            active_writer = &encrypted_io->writer;
        } catch (const IoSystemError& error) {
            const ErrorCode classified =
                proxy::ClassifyHandshakeReadException(stream, error);
            if (classified == ErrorCode::CANCELLED) {
                LOG_CONN_DEBUG(ctx, "encryption handshake cancelled from {}:{}",
                               client_ip, ctx.inbound.source_port);
            } else {
                LOG_CONN_WARN(ctx, "encryption handshake failed from {}:{} > {}",
                              client_ip, ctx.inbound.source_port,
                              classified == ErrorCode::TIMEOUT ? "timeout" : "transport error");
            }
            co_return tl::unexpected(classified);
        } catch (const WorkerMailboxFull&) {
            co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        } catch (...) {
            LOG_CONN_WARN(ctx, "encryption handshake failed from {}:{} > handshake exception",
                          client_ip, ctx.inbound.source_port);
            LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "encryption handshake exception"));
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
    }

    auto parsed_request = co_await ReadVlessRequestHeader(
        *active_reader, stream, ctx, client_ip);
    if (!parsed_request) {
        co_return tl::unexpected(parsed_request.error());
    }
    auto& request = *parsed_request;
    const auto credential_revision = proxyman::inbound::UserStore::CredentialRevision(
        proxyman::inbound::UserProtocol::Vless, ctx.inbound.tag);
    const auto credential = limiter
        ? std::optional(limiter->FingerprintCredential(
              ctx.inbound.tag, request.uuid, credential_revision))
        : std::nullopt;
    if (credential) {
        const auto error = co_await proxy::CheckInboundCredential(
            *limiter, ctx, *credential, proxyman::inbound::UserProtocol::Vless,
            credential_revision);
        if (error != ErrorCode::OK) co_return tl::unexpected(error);
    }
    if (resumed_identity &&
        CRYPTO_memcmp(resumed_identity->data(), request.uuid.data(), request.uuid.size()) != 0) {
        co_await proxy::RecordInboundAuthFailure(
            limiter, ctx, "resumed identity mismatch", credential);
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    auto user_info = proxyman::inbound::UserStore::FindVlessUser(tag, request.uuid);
    if (!user_info) {
        co_await proxy::RecordInboundAuthFailure(
            limiter, ctx, "no matching user", credential);
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    Network net = Network::TCP;
    if (request.command == ::vless::Command::UDP) {
        net = Network::UDP;
    } else if (request.command == ::vless::Command::MUX) {
        net = Network::MUX;
    }
    const bool packet_addr_udp =
        request.command == ::vless::Command::UDP &&
        ::vless::IsPacketAddrMagic(request.target);
    // Published before flow/transport validation so those rejections log the
    // authenticated user and the requested target.
    proxy::BindAuthenticatedInbound(
        ctx, user_info->profile,
        proxy::InboundRequestTarget{
            net,
            std::move(request.target),
            std::move(request.forwarded)});
    if (request.addons_len != 0 && request.flow.empty()) {
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > unsupported addons", client_ip, ctx.inbound.source_port);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "unsupported request addons"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    const bool use_vision = ::vless::IsVisionFlow(request.flow);
    if (!request.flow.empty()) {
        if (std::string_view(request.flow) != user_info->flow) {
            LOG_CONN_WARN(ctx, "request rejected from {}:{} > flow '{}' not allowed",
                          client_ip, ctx.inbound.source_port, request.flow);
            LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "request flow not allowed"));
            co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
        if (!use_vision) {
            LOG_CONN_WARN(ctx, "request rejected from {}:{} > unknown flow '{}'",
                          client_ip, ctx.inbound.source_port, request.flow);
            LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "unknown request flow"));
            co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
    }
    if (!user_info->flow.empty() && !::vless::IsVisionFlow(user_info->flow)) {
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > unsupported configured flow '{}'",
                      client_ip, ctx.inbound.source_port, user_info->flow);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "unsupported configured flow"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (request.flow.empty() && ::vless::IsVisionFlow(user_info->flow)) {
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > missing required flow '{}'",
                      client_ip, ctx.inbound.source_port, user_info->flow);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "missing required flow"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (use_vision && request.command != ::vless::Command::TCP) {
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > flow '{}' only supports TCP",
                      client_ip, ctx.inbound.source_port, request.flow);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "flow only supports TCP"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (use_vision &&
        (!(receiver.stream_settings.IsTlsLike() || decryption != nullptr) ||
         receiver.stream_settings.network_mode != NetworkMode::Tcp)) {
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > flow '{}' requires raw TCP TLS-like transport",
                      client_ip, ctx.inbound.source_port, request.flow);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "flow requires raw TCP TLS-like transport"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    auto user_session = co_await proxy::AdmitAuthenticatedInbound(
        validator, ctx, user_info->profile);
    if (!user_session) {
        co_return tl::unexpected(ErrorCode::PERMISSION_DENIED);
    }

    // Flow validation and metadata copy are complete; no credential is needed
    // by the request body or Vision's per-session UUID state.
    user_info.reset();

    if (issued_ticket) {
        try {
            (void)co_await ::vless::AuthenticateVlessTicket(
                decryption, tag, std::move(*issued_ticket), request.uuid);
        } catch (const WorkerMailboxFull&) {
            co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
        } catch (const IoSystemError&) {
            co_return tl::unexpected(ErrorCode::CANCELLED);
        }
    }

    co_return VlessHandshakeOutcome{
        .user_session = std::move(*user_session),
        .net = net,
        .packet_addr_udp = packet_addr_udp,
        .use_vision = use_vision,
        .request_uuid = request.uuid,
    };
}
}  // namespace

proxy::vless::inbound::Handler::Handler(
    ::UserOnlineTracker& validator,
    StatsShard& stats,
    ConnectionLimiter* limiter,
    std::shared_ptr<const ::vless::VlessEncryptionConfig> decryption)
    : validator_(validator)
    , stats_(&stats)
    , limiter_(limiter)
    , decryption_(std::move(decryption)) {}

proxy::vless::inbound::Handler::~Handler() = default;

net::awaitable<RelayResult>
proxy::vless::inbound::Handler::Process(
    std::unique_ptr<AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout) {
    const std::string_view tag = ctx.inbound.tag;
    const std::string_view client_ip = ctx.inbound.source_ip;
    auto fail_abortive = [&](ErrorCode error) {
        return proxy::RejectInbound(*stats_, stream.get(), error);
    };

    if (co_await proxy::CheckInboundIpBanned(limiter_, ctx)) {
        co_return fail_abortive(ErrorCode::BLOCKED);
    }

    VlessBufferedReader protocol_reader(*stream);
    transport::MultiBufferWriter& protocol_writer = *stream;
    VlessBufferedReader* active_reader = &protocol_reader;
    transport::MultiBufferWriter* active_writer = &protocol_writer;
    std::unique_ptr<::vless::VlessEncryptedIo> encrypted_io;

    UserOnlineSessionGuard user_session;
    Network net = Network::TCP;
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
            active_reader,
            active_writer,
            validator_,
            limiter_,
            receiver,
            ctx,
            tag,
            client_ip);
        if (!handshake) {
            co_return fail_abortive(handshake.error());
        }
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

    if (net == Network::MUX) {
        co_return co_await mux::ProcessInbound(
            io_context,
            transport::Link{active_reader, active_writer},
            *stream,
            dispatcher,
            receiver.dispatch_policy,
            limiter_,
            ctx,
            *stats_,
            timeouts,
            pressure_idle_timeout);
    }

    if (net == Network::UDP) {
        VlessUdpReader udp_reader(
            *active_reader, ctx.outbound.target, packet_addr_udp);
        VlessUdpWriter udp_writer(*active_writer, packet_addr_udp);
        InitialPayload first_datagram;
        if (packet_addr_udp) {
            auto packet = co_await udp_reader.ReadMultiBuffer();
            if (packet.empty()) co_return RelayResult{};
            const auto datagram = buf::InspectUdpDatagram(packet);
            if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid())
                co_return fail_abortive(ErrorCode::PROTOCOL_DECODE_FAILED);
            // The magic address selects framing, not a routable destination.
            proxy::BindInboundRequestTarget(
                ctx, proxy::InboundRequestTarget{Network::UDP, *datagram.target});
            first_datagram = InitialPayload(std::move(packet));
        }
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver.dispatch_policy,
            std::move(stream),
            transport::Link{&udp_reader, &udp_writer},
            std::move(first_datagram),
            ctx,
            *stats_,
            timeouts);
    }

    if (use_vision) {
        ::vless::VisionTrafficState traffic;
        ::vless::VisionReader vision_reader(
            *active_reader,
            request_uuid,
            traffic);
        ::vless::VisionWriter vision_writer(*active_writer, request_uuid, traffic);
        OPENSSL_cleanse(request_uuid.data(), request_uuid.size());
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver.dispatch_policy,
            std::move(stream),
            transport::Link{&vision_reader, &vision_writer},
            InitialPayload{},
            ctx,
            *stats_,
            timeouts);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{active_reader, active_writer},
        InitialPayload{},
        ctx,
        *stats_,
        timeouts);
}


namespace {
class VlessSettings final
    : public ::proxyman::inbound::ProtocolSettings {
public:
    std::shared_ptr<const ::vless::VlessEncryptionConfig> decryption;
};

[[nodiscard]] const VlessSettings* GetVlessSettings(
    const ::proxyman::inbound::BuildRequest& req) noexcept {
    return dynamic_cast<const VlessSettings*>(req.settings.get());
}

[[nodiscard]] std::optional<::proxyman::inbound::PreparedVlessUser>
BuildPreparedVlessUser(const ::InboundUserSpec& spec) {
    auto uuid_bytes = ::vless::ParseUuidBytes(spec.credential);
    if (!uuid_bytes) {
        return std::nullopt;
    }
    ::proxyman::inbound::PreparedVlessUser info;
    info.uuid_bytes = *uuid_bytes;
    info.flow = ::vless::NormalizeFlow(spec.flow);
    info.profile.email = spec.email;
    info.profile.user_id = spec.user_id;
    info.profile.speed_limit = spec.speed_limit;
    info.profile.device_limit = spec.device_limit;
    return info;
}

const bool kVlessInboundRegistered = [] {
    ::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = ::proxyman::inbound::UserProtocol::Vless;

    reg.create_runtime = []() -> std::unique_ptr<
        ::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<::proxy::UserOnlineProtocolRuntime>();
    };

    reg.create_tcp_handler =
        [](::proxyman::inbound::ProtocolRuntime& runtime,
           ::StatsShard& stats,
           ::ConnectionLimiter* limiter,
           const ::proxyman::inbound::BuildRequest& req)
            -> std::unique_ptr<::Inbound> {
            auto* vless_runtime = dynamic_cast<::proxy::UserOnlineProtocolRuntime*>(&runtime);
            const auto* settings = GetVlessSettings(req);
            if (!vless_runtime || !settings) {
                return nullptr;
            }
            return std::make_unique<::proxy::vless::inbound::Handler>(
                vless_runtime->validator,
                stats,
                limiter,
                settings->decryption);
        };

    reg.prepare_settings =
        [](std::string_view tag, const ::InboundProtocolSettings& config)
            -> std::optional<std::shared_ptr<
                const ::proxyman::inbound::ProtocolSettings>> {
            auto settings = std::make_shared<VlessSettings>();
            if (!::vless::IsNoVlessEncryption(config.vless_decryption)) {
                auto parsed = ::vless::ParseVlessServerDecryption(
                    config.vless_decryption);
                if (!parsed) {
                    LOG_WARN("VLESS inbound '{}': invalid decryption: {}",
                             tag,
                             ::vless::VlessEncryptionParseErrorMessage(
                                 parsed.error));
                    return std::nullopt;
                }
                settings->decryption =
                    std::make_shared<::vless::VlessEncryptionConfig>(
                        std::move(*parsed.config));
            }
            return settings;
        };

    // Decryption settings are validated once by prepare_settings; inbound
    // preparation runs it before building users.
    reg.build_users =
        [](const ::proxyman::inbound::BuildRequest& req,
           std::span<const ::InboundUserSpec> specs)
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
