#include "vmess_inbound.hpp"
#include "../../mux/inbound/mux_inbound.hpp"
#include "../../inbound_admission.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "../encoding/server.hpp"
#include "../account.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/session.hpp"

#include <cstring>
#include <tl/expected.hpp>
#include <span>
#include <utility>

namespace acpp {

namespace {

net::awaitable<tl::expected<std::optional<UserOnlineSessionGuard>, ErrorCode>>
ParseHandshake(AsyncStream& stream,
               ::acpp::vmess::encoding::ServerSession& vmess_session,
               ::acpp::vmess::TimedUserValidator& validator,
               ConnectionLimiter* limiter,
               session::Context& ctx,
               std::string_view tag,
               std::string_view client_ip) {
    memory::ByteVector header_buf;
    size_t total_read = 0;
    std::optional<::acpp::vmess::VMessRequest> request;
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
                // EOF in a structured header is truncation, never an auth miss.
                co_return tl::unexpected(
                    proxy::ResolveHandshakeReadFailure(
                        stream, ErrorCode::PROTOCOL_DECODE_FAILED));
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
            if (authenticated) {
                ctx.inbound.user_id = authenticated->user->profile.user_id;
                ctx.inbound.user_email = authenticated->user->profile.email;
                ctx.outbound.original_target = authenticated->target;
                ctx.outbound.target = authenticated->target;
                ctx.content.network = authenticated->command == ::acpp::vmess::Command::UDP
                    ? Network::UDP : authenticated->command == ::acpp::vmess::Command::Mux
                    ? Network::MUX : Network::TCP;
            }
            LOG_CONN_WARN(ctx, "request rejected from {}:{} > {}",
                          client_ip, ctx.inbound.source_port, reason);
            LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
            if (!authenticated && limiter && ctx.inbound.HasProxyProtocolClientIP()) {
                co_await limiter->OnAuthFailTracked(tag, client_ip);
            }
            co_return tl::unexpected(authenticated
                ? ErrorCode::PROTOCOL_DECODE_FAILED : ErrorCode::PROTOCOL_AUTH_FAILED);
        }
    }

    memory::ByteVector{}.swap(header_buf);

    if (request->user) {
        ctx.inbound.user_id = request->user->profile.user_id;
        ctx.inbound.user_email = request->user->profile.email;
        ctx.outbound.original_target = request->target;
        ctx.outbound.target = request->target;
        ctx.content.network = request->command == ::acpp::vmess::Command::UDP
            ? Network::UDP : request->command == ::acpp::vmess::Command::Mux
            ? Network::MUX : Network::TCP;
    }
    if (!request->user || !co_await validator.RegisterSessionIfNew(
            *request->user, request->body_key, request->body_iv)) {
        const auto reason = request->user
            ? "session replay admission rejected"
            : "authentication failed: no authenticated user";
        LOG_CONN_WARN(ctx, "request rejected from {}:{} > {}",
                      client_ip, ctx.inbound.source_port, reason);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, reason));
        if (!request->user && limiter && ctx.inbound.HasProxyProtocolClientIP())
            co_await limiter->OnAuthFailTracked(tag, client_ip);
        co_return tl::unexpected(request->user
            ? ErrorCode::PERMISSION_DENIED : ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    LOG_CONN_TRACE(ctx,
                   "parsed command={} security={} options={:#04x} target={} consumed={}",
                   static_cast<int>(request->command),
                   static_cast<int>(request->security),
                   static_cast<int>(request->options),
                   request->target,
                   consumed);

    std::optional<UserOnlineSessionGuard> user_session;
    if (request->user) {
        const auto& profile = request->user->profile;
        ctx.content.speed_limit = profile.speed_limit;

        user_session = co_await proxy::TryAcquireInboundUserSession(
            validator, tag, profile.user_id, profile.device_limit, ctx);
        if (!user_session) {
            co_return tl::unexpected(ErrorCode::PERMISSION_DENIED);
        }
    }

    LOG_CONN_DEBUG(ctx, "authentication succeeded from {}:{} -> {}",
                   client_ip, ctx.inbound.source_port, request->target);

    // Header authentication and replay checks are finished. Body/response keys
    // are already owned by request; do not move a user-table owner into Session.
    request->user.reset();

    vmess_session.SetRequest(std::move(*request));

    co_return std::move(user_session);
}

}  // namespace

// ============================================================================
// proxy/vmess/inbound.Handler 实现（代理层，无传输层知识）
// ============================================================================

proxy::vmess::inbound::Handler::Handler(
    ::acpp::vmess::TimedUserValidator& validator,
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
    auto fail = [&](ErrorCode error) {
        if (stream) {
            stream->CloseAbortive();
        }
        if (error != ErrorCode::CANCELLED && error != ErrorCode::SOCKET_EOF) {
            stats_->OnError();
        }
        RelayResult result;
        result.error = error;
        return result;
    };

    LOG_CONN_DEBUG(ctx, "processing connection from {}:{}", client_ip, ctx.inbound.source_port);

    if (co_await proxy::CheckInboundIpBanned(limiter_, ctx)) {
        co_return fail(ErrorCode::BLOCKED);
    }
    ::acpp::vmess::encoding::ServerSession vmess_session(validator_, tag);
    std::optional<UserOnlineSessionGuard> user_session;
    {
        auto parsed_session = co_await ParseHandshake(
            *stream, vmess_session, validator_, limiter_, ctx, tag, client_ip);
        if (!parsed_session) {
            co_return fail(parsed_session.error());
        }
        user_session = std::move(*parsed_session);
    }
    const Network net = ctx.content.network;

    auto request_reader = vmess_session.DecodeRequestBody(*stream);
    auto response_writer = vmess_session.EncodeResponseBodyWithHeader(*stream);
    if (!request_reader || !response_writer) {
        co_return fail(ErrorCode::RESOURCE_EXHAUSTED);
    }

    if (net == Network::MUX) {
        co_return co_await mux::ProcessInbound(
            io_context,
            transport::Link{request_reader.get(), response_writer.get()},
            *stream,
            dispatcher,
            receiver.dispatch_policy,
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

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
[[nodiscard]] std::optional<acpp::proxyman::inbound::PreparedVmessUser>
BuildPreparedVmessUser(
    const std::string& uuid,
    int64_t user_id,
    const std::string& email,
    uint64_t speed_limit = 0,
    uint32_t device_limit = 0) {
    auto user = acpp::vmess::MemoryAccount::FromUUID(
        uuid, user_id, email, speed_limit, device_limit);
    if (!user) {
        return std::nullopt;
    }
    return acpp::proxyman::inbound::PreparedVmessUser{
        .uuid = std::move(user->uuid),
        .uuid_bytes = user->uuid_bytes,
        .cmd_key = user->cmd_key,
        .auth_key = user->auth_key,
        .profile = std::move(user->profile),
    };
}

const bool kVmessInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = acpp::proxyman::inbound::UserProtocol::Vmess;

    reg.create_runtime = []() -> std::unique_ptr<
        acpp::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<
            acpp::proxy::InboundTrackerRuntime<acpp::vmess::TimedUserValidator>>();
    };

    reg.create_tcp_handler =
        [](acpp::proxyman::inbound::ProtocolRuntime& runtime,
           acpp::StatsShard& stats,
           acpp::ConnectionLimiter* limiter,
           const acpp::proxyman::inbound::BuildRequest&) -> std::unique_ptr<acpp::Inbound> {
            auto* vmess_runtime = dynamic_cast<
                acpp::proxy::InboundTrackerRuntime<acpp::vmess::TimedUserValidator>*>(&runtime);
            if (!vmess_runtime) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::vmess::inbound::Handler>(
                vmess_runtime->validator,
                stats,
                limiter);
        };

    reg.build_static_users =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedVmessUser> users;
            users.reserve(config.clients.size());

            for (const auto& client : config.clients) {
                if (client.id.empty()) {
                    LOG_WARN("VMess inbound '{}': static user UUID is empty", tag);
                    return std::nullopt;
                }
                auto user = BuildPreparedVmessUser(client.id, 0, client.email);
                if (!user) {
                    LOG_WARN("VMess inbound '{}': invalid static user UUID", tag);
                    return std::nullopt;
                }
                users.push_back(std::move(*user));
            }

            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    reg.build_users =
        [](const acpp::proxyman::inbound::BuildRequest& /*req*/,
           std::span<const acpp::proxyman::inbound::RuntimeUser> runtime_users)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedVmessUser> users;
            users.reserve(runtime_users.size());

            for (const auto& runtime_user : runtime_users) {
                auto user = BuildPreparedVmessUser(
                    runtime_user.credential,
                    runtime_user.user_id,
                    runtime_user.email,
                    runtime_user.speed_limit,
                    runtime_user.device_limit);
                if (!user) {
                    return std::nullopt;
                }
                users.push_back(std::move(*user));
            }
            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kVmess, std::move(reg));
    return true;
}();
}  // namespace
