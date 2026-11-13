#include "common/mux_codec.hpp"
#include "proxy/handshake_errors.hpp"
#include "proxy/mux/mux_server.hpp"
#include "app/relay.hpp"
#include "proxy/inbound_admission.hpp"
#include "proxy/inbound.hpp"
#include "common/user_online_tracker.hpp"
#include "transport/async_stream.hpp"
#include "app/rate_limiter.hpp"
#include "app/stats.hpp"
#include "routing/dispatcher.hpp"
#include "proxy/vmess/body.hpp"
#include "proxy/vmess/vmess_crypto.hpp"
#include "app/proxyman/inbound_handler.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "common/initial_payload.hpp"
#include "common/session.hpp"

#include <cstring>
#include <memory>
#include <tl/expected.hpp>
#include <span>
#include <utility>


namespace {

common::Network RequestNetwork(::proxy::VmessCommand command) noexcept {
    return command == ::proxy::VmessCommand::UDP
        ? common::Network::UDP : command == ::proxy::VmessCommand::Mux
        ? common::Network::MUX : common::Network::TCP;
}

net::awaitable<tl::expected<common::UserOnlineSessionGuard, common::ErrorCode>>
ParseHandshake(transport::AsyncStream& stream,
               ::proxy::ServerSession& vmess_session,
               const app::AdmissionEnvironment& environment,
               proxy::InboundAuthentication authentication,
               common::Context& ctx) {
    std::array<uint8_t, ::proxy::kMaxRequestHeaderWireSize> header_buf{};
    size_t total_read = 0;
    std::optional<::proxy::VMessRequest> request;
    size_t consumed = 0;
    while (!request) {
        const size_t required = vmess_session.RequiredHeaderBytes();
        if (required > header_buf.size()) {
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        auto read = co_await proxy::ReadHandshakeExact(
            stream, {header_buf.data() + total_read, required - total_read},
            total_read == 0 ? proxy::HandshakeProgress::NotStarted
                            : proxy::HandshakeProgress::Started);
        if (!read) co_return tl::unexpected(read.error());
        total_read = required;
        auto decoded = vmess_session.DecodeRequestHeader(
            header_buf.data(), total_read, ctx.conn_id);
        request = std::move(decoded.first);
        consumed = decoded.second;
        if (!request && vmess_session.RequiredHeaderBytes() == 0) {
            const auto reason = vmess_session.HeaderFailureReason();
            const auto* authenticated = vmess_session.AuthenticatedRejectedHeader();
            if (!authenticated) {
                co_return tl::unexpected(co_await authentication.RejectCredential(reason));
            }
            auto bound = std::move(authentication).Bind(authenticated->user->profile,
                proxy::InboundRequestTarget{RequestNetwork(authenticated->command), authenticated->target});
            co_return tl::unexpected(std::move(bound).Reject(reason, common::ErrorCode::PROTOCOL_DECODE_FAILED));
        }
    }

    if (!request->user) {
        co_return tl::unexpected(co_await authentication.RejectCredential("no authenticated user"));
    }
    auto bound = std::move(authentication).Bind(request->user->profile,
        proxy::InboundRequestTarget{
            RequestNetwork(request->command),
            request->target,
            std::move(request->forwarded)});
    if (!co_await ::proxy::RegisterSessionIfNew(
            environment.coordinator, *request->user, request->body_key, request->body_iv)) {
        // Replay is not a credential failure: it never feeds the ban table.
        constexpr std::string_view reason = "session replay admission rejected";
        co_return tl::unexpected(std::move(bound).Reject(reason, common::ErrorCode::PERMISSION_DENIED));
    }

    LOG_CONN_TRACE(ctx,
                   "parsed command={} security={} options={:#04x} target={} consumed={}",
                   static_cast<int>(request->command),
                   static_cast<int>(request->security),
                   static_cast<int>(request->options),
                   request->target,
                   consumed);

    auto user_session = co_await std::move(bound).Admit();
    if (!user_session) co_return tl::unexpected(user_session.error());

    // Header authentication and replay checks are finished. Body/response keys
    // are already owned by request; do not move a user-table owner into Session.
    request->user.reset();

    vmess_session.SetRequest(std::move(*request));

    co_return std::move(*user_session);
}

}  // namespace

namespace proxy {

class VmessInboundHandler final : public ::proxy::Inbound {
public:
    explicit VmessInboundHandler(const ::app::AdmissionEnvironment& environment);

    ::net::awaitable<::app::RelayResult> Process(
        std::unique_ptr<::transport::AsyncStream> stream,
        ::routing::Dispatcher& dispatcher,
        const ::app::ReceiverSettings& receiver,
        ::net::io_context& io_context,
        ::common::Context& ctx,
        const ::infra::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

private:
    const ::app::AdmissionEnvironment& environment_;
};

}  // namespace proxy

// ============================================================================
// proxy/vmess/inbound.Handler 实现（代理层，无传输层知识）
// ============================================================================

proxy::VmessInboundHandler::VmessInboundHandler(
    const ::app::AdmissionEnvironment& environment)
    : environment_(environment)
{}

net::awaitable<app::RelayResult>
proxy::VmessInboundHandler::Process(
    std::unique_ptr<transport::AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const app::ReceiverSettings& receiver,
    net::io_context& io_context,
    common::Context& ctx,
    const infra::TimeoutsConfig& timeouts,
    uint32_t pressure_idle_timeout)
{
    const std::string_view tag   = ctx.inbound.tag;
    const std::string_view client_ip = ctx.inbound.source_ip;

    LOG_CONN_DEBUG(ctx, "processing connection from {}:{}", client_ip, ctx.inbound.source_port);

    std::optional<common::UserOnlineSessionGuard> user_session;
    std::optional<::proxy::RequestBodyReader> request_reader;
    std::optional<::proxy::ResponseBodyWriter> response_writer;
    try {
        auto authentication = co_await proxy::BeginInboundAuthentication(environment_, ctx);
        if (!authentication) co_return proxy::RejectInbound(environment_.stats, stream.get(), authentication.error());
        {
            ::proxy::ServerSession vmess_session(tag);
            auto parsed_session = co_await ParseHandshake(
                *stream, vmess_session, environment_, std::move(*authentication), ctx);
            if (!parsed_session) {
                co_return proxy::RejectInbound(environment_.stats, stream.get(), parsed_session.error());
            }
            user_session.emplace(std::move(*parsed_session));
            auto reader = vmess_session.DecodeRequestBody(*stream);
            if (!reader) co_return proxy::RejectInbound(environment_.stats, stream.get(), reader.error());
            auto writer = vmess_session.EncodeResponseBodyWithHeader(*stream);
            if (!writer) co_return proxy::RejectInbound(environment_.stats, stream.get(), writer.error());
            request_reader.emplace(std::move(*reader));
            response_writer.emplace(std::move(*writer));
        }
    } catch (...) {
        co_return proxy::RejectInbound(
            environment_.stats, stream.get(),
            proxy::ClassifyInboundHandshakeException(std::current_exception()));
    }
    if (!request_reader || !response_writer) {
        co_return proxy::RejectInbound(environment_.stats, stream.get(), common::ErrorCode::RESOURCE_EXHAUSTED);
    }
    const common::Network net = ctx.content.network;

    if (net == common::Network::MUX) {
        co_return co_await proxy::ServeMuxInbound(
            io_context,
            transport::Link{&*request_reader, &*response_writer},
            *stream,
            dispatcher,
            receiver.dispatch_policy,
            environment_,
            ctx,
            environment_.stats,
            timeouts,
            pressure_idle_timeout);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{&*request_reader, &*response_writer},
        common::InitialPayload{},
        ctx,
        environment_.stats,
        timeouts);
}


// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
[[nodiscard]] std::optional<::app::PreparedVmessUser>
BuildPreparedVmessUser(const ::infra::InboundUserSpec& spec) {
    auto user = ::proxy::VmessUserAccount::FromUUID(spec.credential);
    if (!user) {
        return std::nullopt;
    }
    return ::app::PreparedVmessUser{
        .uuid_bytes = user->uuid_bytes,
        .cmd_key = user->cmd_key,
        .auth_key = user->auth_key,
        .profile = ::proxy::MakeUserProfile(spec),
    };
}

const bool kVmessInboundRegistered = [] {
    ::app::ProxyRegistration reg;
    reg.user_protocol = ::app::UserProtocol::Vmess;


    reg.create_tcp_handler =
        [](const ::app::AdmissionEnvironment& environment,
           const ::app::BuildRequest&) -> std::unique_ptr<::proxy::Inbound> {
            return std::make_unique<::proxy::VmessInboundHandler>(environment);
        };

    reg.build_users =
        [](const ::app::BuildRequest& req,
           std::span<const ::infra::InboundUserSpec> specs)
            -> std::optional<::app::UserSet> {
            std::vector<::app::PreparedVmessUser> users;
            users.reserve(specs.size());

            for (const auto& spec : specs) {
                auto user = BuildPreparedVmessUser(spec);
                if (!user) {
                    LOG_WARN("VMess inbound '{}': invalid user UUID", req.tag);
                    return std::nullopt;
                }
                users.push_back(std::move(*user));
            }
            return ::app::UserSet{std::move(users)};
        };

    ::app::RegisterProxy(
        ::common::kVmess, std::move(reg));
    return true;
}();
}  // namespace
