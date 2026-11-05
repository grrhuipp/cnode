#include "vless_inbound.hpp"
#include "../credentials.hpp"
#include "../../mux/inbound/mux_inbound.hpp"

#include "../vless_codec.hpp"
#include "../vless_encryption.hpp"
#include "../vless_encryption_io.hpp"
#include "../vless_encryption_runtime.hpp"
#include "../vless_ticket_service.hpp"
#include "acppnode/app/worker_mailbox.hpp"
#include "../vless_buffered_reader.hpp"
#include "../udp_framing.hpp"
#include "../vless_vision.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <array>
#include <tl/expected.hpp>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace acpp {

namespace {

using ::acpp::vless::VlessBufferedReader;

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
    ::acpp::vless::UdpFramer framer_;
};

class VlessUdpWriter final : public transport::MultiBufferWriter {
public:
    VlessUdpWriter(transport::MultiBufferWriter& dst, bool packet_addr)
        : dst_(dst)
        , packet_addr_(packet_addr) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        return ::acpp::vless::WriteUdpDatagram(
            dst_, std::move(mb), packet_addr_);
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        if (packet_addr_) {
            throw IoSystemError(
                io_error::invalid_argument,
                "packet-address VLESS UDP write requires a target");
        }
        // Without packet addresses the frame carries no target bytes.
        co_await ::acpp::vless::WriteUdpDatagram(
            dst_, TargetAddress{}, false, buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return dst_.AsyncShutdownWrite();
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

private:
    [[nodiscard]] static net::const_buffer HeaderBuffer() noexcept {
        return net::const_buffer(::acpp::vless::kResponseHeader.data(),
                                 ::acpp::vless::kResponseHeader.size());
    }

    transport::MultiBufferWriter& dst_;
    bool header_sent_ = false;
};


net::awaitable<tl::expected<::acpp::vless::RequestHeader, ErrorCode>>
ReadVlessRequestHeader(VlessBufferedReader& active_reader,
                       AsyncStream& stream,
                       session::Context& ctx,
                       std::string_view client_ip) {
    using ::acpp::vless::RequestHeaderDecodeStatus;
    std::array<uint8_t, ::acpp::vless::kMaxRequestHeaderSize> handshake{};
    size_t total_read = 0;
    size_t required = 1;
    for (;;) {
        bool read_ok = false;
        try {
            read_ok = co_await active_reader.ReadExact(
                handshake.data() + total_read, required - total_read);
        } catch (const IoSystemError&) {
            if (stream.ConsumePhaseDeadline()) {
                LOG_CONN_WARN(ctx, "handshake phase deadline from {}:{}",
                              client_ip, ctx.inbound.source_port);
                co_return tl::unexpected(ErrorCode::TIMEOUT);
            }
            co_return tl::unexpected(ErrorCode::SOCKET_READ_FAILED);
        }
        if (!read_ok) {
            if (stream.ConsumePhaseDeadline() || stream.ConsumeIdleTimeout()) {
                co_return tl::unexpected(ErrorCode::TIMEOUT);
            }
            co_return tl::unexpected(ErrorCode::SOCKET_EOF);
        }
        total_read = required;

        auto decoded = ::acpp::vless::DecodeRequestHeader(
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
    const std::shared_ptr<const ::acpp::vless::VlessEncryptionConfig>& decryption,
    VlessBufferedReader& protocol_reader,
    transport::MultiBufferWriter& protocol_writer,
    std::unique_ptr<::acpp::vless::VlessEncryptedIo>& encrypted_io,
    VlessBufferedReader*& active_reader,
    transport::MultiBufferWriter*& active_writer,
    ::acpp::UserOnlineTracker& validator,
    ConnectionLimiter* limiter,
    const proxyman::inbound::ReceiverSettings& receiver,
    session::Context& ctx,
    std::string_view tag,
    std::string_view client_ip) {
    std::optional<::acpp::vless::VlessEncryptionIssuedTicket> issued_ticket;
    std::optional<std::array<uint8_t, 16>> resumed_identity;
    if (decryption) {
        try {
            auto runtime =
                co_await ::acpp::vless::RunVlessEncryptionServerHandshake(
                    protocol_reader,
                    protocol_writer,
                    decryption,
                    std::string(tag));
            if (!runtime) {
                LOG_CONN_WARN(ctx, "encryption handshake failed from {}:{} > handshake rejected",
                              client_ip, ctx.inbound.source_port);
                LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "encryption handshake rejected"));
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            issued_ticket = std::move(runtime->issued_ticket);
            resumed_identity = runtime->resumed_identity;
            encrypted_io = std::make_unique<::acpp::vless::VlessEncryptedIo>(
                protocol_reader, protocol_writer, std::move(*runtime));
            active_reader = &encrypted_io->plain_reader;
            active_writer = &encrypted_io->writer;
        } catch (const IoSystemError&) {
            co_return tl::unexpected(stream.ConsumePhaseDeadline()
                ? ErrorCode::TIMEOUT
                : ErrorCode::SOCKET_READ_FAILED);
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
    if (resumed_identity &&
        CRYPTO_memcmp(resumed_identity->data(), request.uuid.data(), request.uuid.size()) != 0) {
        LOG_CONN_WARN(ctx, "authentication failed from {}:{} > resumed identity mismatch",
                      client_ip, ctx.inbound.source_port);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "authentication failed: resumed identity mismatch"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    auto user_info = proxyman::inbound::UserStore::FindVlessUser(tag, request.uuid);
    if (!user_info) {
        LOG_CONN_WARN(ctx, "authentication failed from {}:{} > no matching user",
                      client_ip, ctx.inbound.source_port);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "authentication failed: no matching user"));
        if (limiter && ctx.inbound.HasProxyProtocolClientIP()) {
            co_await limiter->OnAuthFailTracked(tag, client_ip);
        }
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    ctx.inbound.user_id = user_info->profile.user_id;
    ctx.inbound.user_email = user_info->profile.email;
    if (request.addons_len != 0 && request.flow.empty()) {
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > unsupported addons", client_ip, ctx.inbound.source_port);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "unsupported request addons"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    const bool use_vision = ::acpp::vless::IsVisionFlow(request.flow);
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
    if (!user_info->flow.empty() && !::acpp::vless::IsVisionFlow(user_info->flow)) {
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > unsupported configured flow '{}'",
                      client_ip, ctx.inbound.source_port, user_info->flow);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "unsupported configured flow"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (request.flow.empty() && ::acpp::vless::IsVisionFlow(user_info->flow)) {
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > missing required flow '{}'",
                      client_ip, ctx.inbound.source_port, user_info->flow);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "missing required flow"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (use_vision && request.command != ::acpp::vless::Command::TCP) {
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > flow '{}' only supports TCP",
                      client_ip, ctx.inbound.source_port, request.flow);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "flow only supports TCP"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }
    if (use_vision &&
        (!receiver.stream_settings.IsTlsLike() ||
         receiver.stream_settings.network_mode != NetworkMode::Tcp)) {
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > flow '{}' requires raw TCP TLS-like transport",
                      client_ip, ctx.inbound.source_port, request.flow);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "flow requires raw TCP TLS-like transport"));
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    const auto& profile = user_info->profile;
    ctx.content.speed_limit = profile.speed_limit;
    auto user_session = co_await validator.TryConnectSession(
        tag, profile.user_id, ctx.inbound.source_ip, profile.device_limit);
    if (!user_session) {
        LOG_CONN_DEBUG(ctx, "connection rejected from {}:{} > device limit={} domain_online_devices={}",
            ctx.inbound.source_ip, ctx.inbound.source_port, profile.device_limit,
            validator.OnlineDeviceCount(tag, static_cast<uint64_t>(profile.user_id)));
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "device limit"));
        co_return tl::unexpected(ErrorCode::PERMISSION_DENIED);
    }

    // Flow validation and metadata copy are complete; no credential is needed
    // by the request body or Vision's per-session UUID state.
    user_info.reset();

    Network net = Network::TCP;
    if (request.command == ::acpp::vless::Command::UDP) {
        net = Network::UDP;
    } else if (request.command == ::acpp::vless::Command::MUX) {
        net = Network::MUX;
    }
    const bool packet_addr_udp =
        request.command == ::acpp::vless::Command::UDP &&
        ::acpp::vless::IsPacketAddrMagic(request.target);
    ctx.outbound.original_target = request.target;
    ctx.outbound.target = std::move(request.target);
    ctx.content.network = net;
    if (issued_ticket) {
        try {
            if (!co_await ::acpp::vless::AuthenticateVlessTicket(
                    decryption, std::string(tag), std::move(*issued_ticket), request.uuid)) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
            }
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
    ::acpp::UserOnlineTracker& validator,
    StatsShard& stats,
    ConnectionLimiter* limiter,
    std::shared_ptr<const ::acpp::vless::VlessEncryptionConfig> decryption)
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
    ctx.inbound.user_id = 0;
    ctx.inbound.user_email.clear();

    auto fail = [&](ErrorCode error) {
        stats_->OnError();
        RelayResult result;
        result.error = error;
        return result;
    };
    auto fail_abortive = [&](ErrorCode error) {
        if (stream) {
            stream->CloseAbortive();
        }
        return fail(error);
    };

    if (limiter_ && ctx.inbound.HasProxyProtocolClientIP() &&
        co_await limiter_->IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_CONN_DEBUG(ctx, "connection rejected from {}:{} > IP banned",
                       ctx.inbound.source_ip, ctx.inbound.source_port);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "IP banned"));
        co_return fail_abortive(ErrorCode::BLOCKED);
    }

    VlessBufferedReader protocol_reader(*stream);
    transport::MultiBufferWriter& protocol_writer = *stream;
    VlessBufferedReader* active_reader = &protocol_reader;
    transport::MultiBufferWriter* active_writer = &protocol_writer;
    std::unique_ptr<::acpp::vless::VlessEncryptedIo> encrypted_io;

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
        request_uuid = handshake->request_uuid;
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
            ctx,
            *stats_,
            timeouts,
            pressure_idle_timeout);
    }

    if (net == Network::UDP) {
        VlessUdpReader udp_reader(
            *active_reader, ctx.outbound.target, packet_addr_udp);
        VlessUdpWriter udp_writer(*active_writer, packet_addr_udp);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver.dispatch_policy,
            std::move(stream),
            transport::Link{&udp_reader, &udp_writer},
            InitialPayload{},
            ctx,
            *stats_,
            timeouts);
    }

    if (use_vision) {
        ::acpp::vless::VisionTrafficState traffic;
        ::acpp::vless::VisionReader vision_reader(
            *active_reader,
            request_uuid,
            traffic);
        ::acpp::vless::VisionWriter vision_writer(*active_writer, request_uuid, traffic);
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

}  // namespace acpp

namespace {
class VlessRuntime final : public acpp::proxyman::inbound::ProtocolRuntime {
public:
    [[nodiscard]] std::vector<acpp::OnlineDevice>
    GetOnlineDevices(std::string_view tag) const override {
        return validator.GetOnlineDevices(tag);
    }

    acpp::UserOnlineTracker validator;
};

class VlessSettings final
    : public acpp::proxyman::inbound::ProtocolSettings {
public:
    std::shared_ptr<const acpp::vless::VlessEncryptionConfig> decryption;
};

[[nodiscard]] const VlessSettings* GetVlessSettings(
    const acpp::proxyman::inbound::BuildRequest& req) noexcept {
    return dynamic_cast<const VlessSettings*>(req.settings.get());
}

const bool kVlessInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = acpp::proxyman::inbound::UserProtocol::Vless;

    reg.create_runtime = []() -> std::unique_ptr<
        acpp::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<VlessRuntime>();
    };

    reg.create_tcp_handler =
        [](acpp::proxyman::inbound::ProtocolRuntime& runtime,
           acpp::StatsShard& stats,
           acpp::ConnectionLimiter* limiter,
           const acpp::proxyman::inbound::BuildRequest& req)
            -> std::unique_ptr<acpp::Inbound> {
            auto* vless_runtime = dynamic_cast<VlessRuntime*>(&runtime);
            const auto* settings = GetVlessSettings(req);
            if (!vless_runtime || !settings) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::vless::inbound::Handler>(
                vless_runtime->validator,
                stats,
                limiter,
                settings->decryption);
        };

    reg.prepare_settings =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<std::shared_ptr<
                const acpp::proxyman::inbound::ProtocolSettings>> {
            auto settings = std::make_shared<VlessSettings>();
            if (!acpp::vless::IsNoVlessEncryption(config.vless_decryption)) {
                auto parsed = acpp::vless::ParseVlessServerDecryption(
                    config.vless_decryption);
                if (!parsed) {
                    LOG_WARN("VLESS inbound '{}': invalid decryption: {}",
                             tag,
                             acpp::vless::VlessEncryptionParseErrorMessage(
                                 parsed.error));
                    return std::nullopt;
                }
                settings->decryption =
                    std::make_shared<acpp::vless::VlessEncryptionConfig>(
                        std::move(*parsed.config));
            }
            return settings;
        };

    // Decryption settings are validated once by prepare_settings; static
    // inbound preparation runs it before building users.
    reg.build_static_users =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedVlessUser> users;
            users.reserve(config.clients.size());
            for (const auto& client : config.clients) {
                std::string uuid = client.id.empty() ? client.password : client.id;
                auto uuid_bytes = acpp::vless::ParseUuidBytes(uuid);
                if (!uuid_bytes) {
                    LOG_WARN("VLESS inbound '{}': invalid static user UUID", tag);
                    return std::nullopt;
                }
                acpp::proxyman::inbound::PreparedVlessUser info;
                info.uuid_bytes = *uuid_bytes;
                info.flow = acpp::vless::NormalizeFlow(client.flow);
                info.profile.email = client.email;
                users.push_back(std::move(info));
            }
            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    reg.build_users =
        [](const acpp::proxyman::inbound::BuildRequest& /*req*/,
           std::span<const acpp::proxyman::inbound::RuntimeUser> runtime_users)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedVlessUser> users;
            users.reserve(runtime_users.size());
            for (const auto& runtime_user : runtime_users) {
                const std::string& uuid = runtime_user.credential;
                auto uuid_bytes = acpp::vless::ParseUuidBytes(uuid);
                if (!uuid_bytes) {
                    return std::nullopt;
                }
                acpp::proxyman::inbound::PreparedVlessUser info;
                info.uuid_bytes = *uuid_bytes;
                info.flow = acpp::vless::NormalizeFlow(runtime_user.flow);
                info.profile.email = runtime_user.email;
                info.profile.user_id = runtime_user.user_id;
                info.profile.speed_limit = runtime_user.speed_limit;
                info.profile.device_limit = runtime_user.device_limit;
                users.push_back(std::move(info));
            }
            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kVless, std::move(reg));
    return true;
}();
}  // namespace
