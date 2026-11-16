#include "proxy/handshake_errors.hpp"
#include "proxy/mux/mux_server.hpp"
#include "app/relay.hpp"
#include "proxy/inbound_admission.hpp"
#include "proxy/inbound.hpp"
#include "transport/async_stream.hpp"
#include "app/stats.hpp"
#include "routing/dispatcher.hpp"
#include "proxy/vmess/body.hpp"
#include "proxy/vmess/vmess_crypto.hpp"
#include "app/inbound_handler.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "common/session.hpp"
#include "common/scoped_cleanse.hpp"

#include <memory>
#include <tl/expected.hpp>
#include <span>
#include <utility>
#include <variant>


namespace {

common::Network RequestNetwork(::proxy::VmessCommand command) noexcept {
    return command == ::proxy::VmessCommand::UDP
        ? common::Network::UDP : command == ::proxy::VmessCommand::Mux
        ? common::Network::MUX : common::Network::TCP;
}

struct DecodedVMessHeader {
    std::optional<::proxy::VMessRequest> request;
    size_t consumed = 0;
};

net::awaitable<tl::expected<DecodedVMessHeader, common::ErrorCode>>
ReadVMessHandshakeHeader(transport::AsyncStream& stream,
                         ::proxy::ServerSession& vmess_session,
                         uint64_t conn_id) {
    std::array<uint8_t, ::proxy::kMaxRequestHeaderWireSize> header_buf{};
    common::ScopedCleanse cleanse_header{header_buf};
    size_t total_read = 0;
    DecodedVMessHeader out;
    while (!out.request) {
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
            header_buf.data(), total_read, conn_id);
        out.request = std::move(decoded.first);
        out.consumed = decoded.second;
        if (!out.request && vmess_session.RequiredHeaderBytes() == 0) {
            break;
        }
    }
    co_return out;
}

struct PreparedVmessInboundSession {
    ::proxy::RequestBodyReader request_reader;
    ::proxy::ResponseBodyWriter response_writer;
};

}  // namespace
namespace proxy {
struct VmessSession : MultiplexedInboundSession {
    VmessSession() = default;
    VmessSession(const VmessSession&) = delete;
    VmessSession(VmessSession&&) = delete;

    std::variant<std::monostate, ::proxy::ServerSession, PreparedVmessInboundSession> state;

    net::awaitable<tl::expected<proxy::AuthenticatedInbound, common::ErrorCode>>
    Authenticate(transport::AsyncStream& stream,
                 proxy::InboundAuthentication authentication,
                 proxy::InboundContext& context) {
        auto& ctx = context.session;
        auto& vmess_session = state.emplace<::proxy::ServerSession>(ctx.inbound.tag);
        auto header = co_await ReadVMessHandshakeHeader(stream, vmess_session, ctx.conn_id);
        if (!header) {
            co_return tl::unexpected(header.error());
        }
        if (!header->request) {
            const auto reason = vmess_session.HeaderFailureReason();
            const auto* authenticated = vmess_session.AuthenticatedRejectedHeader();
            if (!authenticated) {
                co_return tl::unexpected(co_await authentication.RejectCredential(reason));
            }
            auto bound = std::move(authentication).Bind(authenticated->user->profile,
                proxy::InboundRequestTarget{RequestNetwork(authenticated->command), authenticated->target});
            co_return tl::unexpected(std::move(bound).Reject(reason, common::ErrorCode::PROTOCOL_DECODE_FAILED));
        }
        auto& request = header->request;
        if (!request->user) {
            co_return tl::unexpected(co_await authentication.RejectCredential("no authenticated user"));
        }
        auto bound = std::move(authentication).Bind(request->user->profile,
            proxy::InboundRequestTarget{
                RequestNetwork(request->command),
                request->target,
                std::move(request->forwarded)});
        if (!co_await ::proxy::RegisterSessionIfNew(
                context.admission.coordinator, *request->user, request->body_key, request->body_iv)) {
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
                       header->consumed);

        // Keep only body parameters across admission, never the user-table owner.
        request->user.reset();
        vmess_session.SetRequest(std::move(*request));
        co_return std::move(bound);
    }

    MultiplexedInboundPrepared Prepare(std::unique_ptr<transport::AsyncStream>& stream,
                                       InboundContext& context) {
        auto& vmess_session = std::get<::proxy::ServerSession>(state);
        auto reader = vmess_session.DecodeRequestBody(*stream);
        if (!reader) return tl::unexpected(reader.error());
        auto writer = vmess_session.EncodeResponseBodyWithHeader(*stream);
        if (!writer) return tl::unexpected(writer.error());
        auto& prepared = state.emplace<PreparedVmessInboundSession>(
            PreparedVmessInboundSession{std::move(*reader), std::move(*writer)});

        if (context.session.content.network == common::Network::MUX) {
            return MuxPlan(
                transport::Link{&prepared.request_reader, &prepared.response_writer},
                *stream, MuxAllowedNetwork::Any);
        }
        return routing::DispatchRequest{
            std::move(stream),
            transport::Link{&prepared.request_reader, &prepared.response_writer}};
    }
};

}  // namespace proxy

namespace proxy {

class VmessInboundHandler final : public ::proxy::Inbound {
public:
    explicit VmessInboundHandler(const ::app::AdmissionEnvironment& environment);

    using Session = VmessSession;
    const app::AdmissionEnvironment& Environment() const noexcept { return environment_; }
    auto SessionArguments() const noexcept { return std::tuple{}; }

private:
    const ::app::AdmissionEnvironment& environment_;
};

}  // namespace proxy

// ============================================================================
// proxy/vmess/inbound.Handler 实现（代理层，无传输层知识）
// ============================================================================

proxy::VmessInboundHandler::VmessInboundHandler(
    const ::app::AdmissionEnvironment& environment)
    : Inbound(std::in_place_type<VmessInboundHandler>), environment_(environment)
{}



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
