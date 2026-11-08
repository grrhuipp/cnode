#include "vmess_inbound.hpp"
#include "../../mux/inbound/mux_inbound.hpp"
#include "../../inbound_admission.hpp"
#include "transport/async_stream.hpp"
#include "app/rate_limiter.hpp"
#include "app/stats.hpp"
#include "features/routing/dispatcher.hpp"
#include "../encoding/server.hpp"
#include "../account.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "common/allocator.hpp"
#include "common/initial_payload.hpp"
#include "common/session.hpp"

#include <cstring>
#include <tl/expected.hpp>
#include <span>
#include <utility>


namespace {

Network RequestNetwork(::vmess::Command command) noexcept {
    return command == ::vmess::Command::UDP
        ? Network::UDP : command == ::vmess::Command::Mux
        ? Network::MUX : Network::TCP;
}

net::awaitable<tl::expected<UserOnlineSessionGuard, ErrorCode>>
ParseHandshake(AsyncStream& stream,
               ::vmess::encoding::ServerSession& vmess_session,
               ::vmess::TimedUserValidator& validator,
               ConnectionLimiter* limiter,
               session::Context& ctx,
               std::string_view client_ip) {
    memory::ByteVector header_buf;
    size_t total_read = 0;
    std::optional<::vmess::VMessRequest> request;
    size_t consumed = 0;
    while (!request) {
        const size_t required = vmess_session.RequiredHeaderBytes();
        if (required > header_buf.size()) {
            header_buf.resize(required);
        }
        while (total_read < required) {
            size_t n = 0;
            try {
                n = co_await stream.AsyncRead(net::buffer(
                    header_buf.data() + total_read, required - total_read));
            } catch (const IoSystemError& error) {
                co_return tl::unexpected(
                    proxy::ClassifyHandshakeReadException(stream, error));
            }
            if (n == 0) {
                co_return tl::unexpected(
                    proxy::ResolveHandshakeReadFailure(
                        stream,
                        total_read == 0 ? ErrorCode::SOCKET_EOF
                                        : ErrorCode::PROTOCOL_DECODE_FAILED));
            }
            total_read += n;
        }
        auto decoded = vmess_session.DecodeRequestHeader(
            header_buf.data(), total_read, ctx.conn_id);
        request = std::move(decoded.first);
        consumed = decoded.second;
        if (!request && vmess_session.RequiredHeaderBytes() == 0) {
            const auto reason = vmess_session.HeaderFailureReason();
            const auto* authenticated = vmess_session.AuthenticatedRejectedHeader();
            if (!authenticated) {
                co_await proxy::RecordInboundAuthFailure(limiter, ctx, reason);
                co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
            }
            proxy::BindAuthenticatedInbound(
                ctx, authenticated->user->profile,
                proxy::InboundRequestTarget{
                    RequestNetwork(authenticated->command), authenticated->target});
            LOG_CONN_WARN(ctx, "request rejected from {}:{} > {}",
                          client_ip, ctx.inbound.source_port, reason);
            LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
    }

    memory::ByteVector{}.swap(header_buf);

    if (!request->user) {
        co_await proxy::RecordInboundAuthFailure(
            limiter, ctx, "authentication failed: no authenticated user");
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    proxy::BindAuthenticatedInbound(
        ctx, request->user->profile,
        proxy::InboundRequestTarget{
            RequestNetwork(request->command),
            request->target,
            std::move(request->forwarded)});
    if (!co_await validator.RegisterSessionIfNew(
            *request->user, request->body_key, request->body_iv)) {
        // Replay is not a credential failure: it never feeds the ban table.
        constexpr std::string_view reason = "session replay admission rejected";
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > {}",
                      client_ip, ctx.inbound.source_port, reason);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
        co_return tl::unexpected(ErrorCode::PERMISSION_DENIED);
    }

    LOG_CONN_TRACE(ctx,
                   "parsed command={} security={} options={:#04x} target={} consumed={}",
                   static_cast<int>(request->command),
                   static_cast<int>(request->security),
                   static_cast<int>(request->options),
                   request->target,
                   consumed);

    auto user_session = co_await proxy::AdmitAuthenticatedInbound(
        validator, ctx, request->user->profile);
    if (!user_session) {
        co_return tl::unexpected(ErrorCode::PERMISSION_DENIED);
    }

    // Header authentication and replay checks are finished. Body/response keys
    // are already owned by request; do not move a user-table owner into Session.
    request->user.reset();

    vmess_session.SetRequest(std::move(*request));

    co_return std::move(*user_session);
}

}  // namespace

// ============================================================================
// proxy/vmess/inbound.Handler 实现（代理层，无传输层知识）
// ============================================================================

proxy::vmess::inbound::Handler::Handler(
    ::vmess::TimedUserValidator& validator,
    StatsShard& stats,
    ConnectionLimiter* limiter)
    : validator_(validator)
    , stats_(&stats)
    , limiter_(limiter)
{}

net::awaitable<RelayResult>
proxy::vmess::inbound::Handler::Process(
    std::unique_ptr<AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout)
{
    const std::string_view tag   = ctx.inbound.tag;
    const std::string_view client_ip = ctx.inbound.source_ip;

    LOG_CONN_DEBUG(ctx, "processing connection from {}:{}", client_ip, ctx.inbound.source_port);

    try {
        if (co_await proxy::CheckInboundIpBanned(limiter_, ctx)) {
            co_return proxy::RejectInbound(*stats_, stream.get(), ErrorCode::BLOCKED);
        }
    } catch (const WorkerMailboxFull&) {
        co_return proxy::RejectInbound(*stats_, stream.get(), ErrorCode::RESOURCE_EXHAUSTED);
    } catch (const IoSystemError& e) {
        co_return proxy::RejectInbound(
            *stats_, stream.get(),
            e.code() == net::error::operation_aborted ? ErrorCode::CANCELLED : MapAsioError(e.code()));
    }
    std::optional<UserOnlineSessionGuard> user_session;
    std::unique_ptr<transport::MultiBufferReader> request_reader;
    std::unique_ptr<transport::MultiBufferWriter> response_writer;
    try {
        ::vmess::encoding::ServerSession vmess_session(validator_, tag);
        auto parsed_session = co_await ParseHandshake(
            *stream, vmess_session, validator_, limiter_, ctx, client_ip);
        if (!parsed_session) {
            co_return proxy::RejectInbound(*stats_, stream.get(), parsed_session.error());
        }
        user_session.emplace(std::move(*parsed_session));
        request_reader = vmess_session.DecodeRequestBody(*stream, ctx.outbound.target);
        response_writer = vmess_session.EncodeResponseBodyWithHeader(*stream, ctx.outbound.target);
    } catch (const WorkerMailboxFull&) {
        co_return proxy::RejectInbound(*stats_, stream.get(), ErrorCode::RESOURCE_EXHAUSTED);
    } catch (const IoSystemError& e) {
        co_return proxy::RejectInbound(
            *stats_, stream.get(),
            e.code() == net::error::operation_aborted ? ErrorCode::CANCELLED : MapAsioError(e.code()));
    }
    if (!request_reader || !response_writer) {
        co_return proxy::RejectInbound(*stats_, stream.get(), ErrorCode::RESOURCE_EXHAUSTED);
    }
    const Network net = ctx.content.network;

    if (net == Network::MUX) {
        co_return co_await mux::ProcessInbound(
            io_context,
            transport::Link{request_reader.get(), response_writer.get()},
            *stream,
            dispatcher,
            receiver.dispatch_policy,
            limiter_,
            ctx,
            *stats_,
            timeouts,
            pressure_idle_timeout);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{request_reader.get(), response_writer.get()},
        InitialPayload{},
        ctx,
        *stats_,
        timeouts);
}


// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
[[nodiscard]] std::optional<::proxyman::inbound::PreparedVmessUser>
BuildPreparedVmessUser(const ::InboundUserSpec& spec) {
    auto user = ::vmess::MemoryAccount::FromUUID(
        spec.credential, spec.user_id, spec.email, spec.speed_limit, spec.device_limit);
    if (!user) {
        return std::nullopt;
    }
    return ::proxyman::inbound::PreparedVmessUser{
        .uuid = std::move(user->uuid),
        .uuid_bytes = user->uuid_bytes,
        .cmd_key = user->cmd_key,
        .auth_key = user->auth_key,
        .profile = std::move(user->profile),
    };
}

const bool kVmessInboundRegistered = [] {
    ::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = ::proxyman::inbound::UserProtocol::Vmess;

    reg.create_runtime = []() -> std::unique_ptr<
        ::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<
            ::proxy::InboundTrackerRuntime<::vmess::TimedUserValidator>>();
    };

    reg.create_tcp_handler =
        [](::proxyman::inbound::ProtocolRuntime& runtime,
           ::StatsShard& stats,
           ::ConnectionLimiter* limiter,
           const ::proxyman::inbound::BuildRequest&) -> std::unique_ptr<::Inbound> {
            auto* vmess_runtime = dynamic_cast<
                ::proxy::InboundTrackerRuntime<::vmess::TimedUserValidator>*>(&runtime);
            if (!vmess_runtime) {
                return nullptr;
            }
            return std::make_unique<::proxy::vmess::inbound::Handler>(
                vmess_runtime->validator,
                stats,
                limiter);
        };

    reg.build_users =
        [](const ::proxyman::inbound::BuildRequest& req,
           std::span<const ::InboundUserSpec> specs)
            -> std::optional<::proxyman::inbound::UserSet> {
            std::vector<::proxyman::inbound::PreparedVmessUser> users;
            users.reserve(specs.size());

            for (const auto& spec : specs) {
                auto user = BuildPreparedVmessUser(spec);
                if (!user) {
                    LOG_WARN("VMess inbound '{}': invalid user UUID", req.tag);
                    return std::nullopt;
                }
                users.push_back(std::move(*user));
            }
            return ::proxyman::inbound::UserSet{std::move(users)};
        };

    ::proxyman::inbound::RegisterProxy(
        ::constants::protocol::kVmess, std::move(reg));
    return true;
}();
}  // namespace
