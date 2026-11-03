#include "vmess_inbound.hpp"
#include "../../mux/inbound/mux_inbound.hpp"
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


// ============================================================================
// proxy/vmess/inbound.Handler 实现（代理层，无传输层知识）
// ============================================================================

proxy::vmess::inbound::Handler::Handler(
    ::acpp::vmess::TimedUserValidator& validator,
    StatsShard& stats,
    ConnectionLimiterPtr limiter)
    : validator_(validator)
    , stats_(&stats)
    , limiter_(std::move(limiter))
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
        stats_->OnError();
        RelayResult result;
        result.error = error;
        return result;
    };

    LOG_CONN_DEBUG(ctx, "[VMess][{}] Process start from {}", tag, client_ip);

    if (limiter_ && ctx.inbound.HasProxyProtocolClientIP() &&
        limiter_->IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_NET_DEBUG("{} from {}:{} rejected ip_banned [{}]",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag);
        co_return fail(ErrorCode::BLOCKED);
    }
    std::optional<UserOnlineSessionGuard> user_session;

    memory::ByteVector header_buf;
    size_t total_read = 0;
    ::acpp::vmess::encoding::ServerSession vmess_session(validator_, tag);
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
                n = co_await stream->AsyncRead(net::buffer(
                    header_buf.data() + total_read, required - total_read));
            } catch (const IoSystemError&) {
                co_return fail(stream->ConsumePhaseDeadline()
                    ? ErrorCode::TIMEOUT : ErrorCode::SOCKET_READ_FAILED);
            }
            if (n == 0) {
                if (stream->ConsumePhaseDeadline() || stream->ConsumeIdleTimeout()) {
                    co_return fail(ErrorCode::TIMEOUT);
                }
                // EOF in a structured header is truncation, never an auth miss.
                co_return fail(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            total_read += n;
        }
        auto decoded = vmess_session.DecodeRequestHeader(
            header_buf.data(), total_read, ctx.conn_id);
        request = std::move(decoded.first);
        consumed = decoded.second;
        if (!request && vmess_session.RequiredHeaderBytes() == 0) {
            LOG_NET_WARN("[{}] VMess auth failed from {}", tag, client_ip);
            if (limiter_ && ctx.inbound.HasProxyProtocolClientIP()) {
                limiter_->OnAuthFailTracked(tag, client_ip);
            }
            co_return fail(ErrorCode::PROTOCOL_AUTH_FAILED);
        }
    }

    memory::ByteVector{}.swap(header_buf);

    LOG_CONN_TRACE(ctx,
                   "[VMess][{}] parsed command={} security={} options={:#04x} target={} consumed={} pending={}",
                   tag,
                   static_cast<int>(request->command),
                   static_cast<int>(request->security),
                   static_cast<int>(request->options),
                   request->target,
                   consumed,
                   request->PendingDataSize());

    // 填充用户信息
    if (request->user) {
        const auto& profile = request->user->profile;
        ctx.inbound.user_id = profile.user_id;
        ctx.inbound.user_email = profile.email;
        ctx.content.speed_limit = profile.speed_limit;

        // 在线追踪：认证成功后由当前协议 Process 的本地 guard 解注册。
        uint64_t uid = static_cast<uint64_t>(profile.user_id);
        if (!validator_.CanAcceptDevice(
                tag, uid, ctx.inbound.source_ip, profile.device_limit)) {
            LOG_NET_DEBUG("{} from {}:{} rejected device_limit [{}] user={} limit={} online_devices={}",
                FormatTimestamp(ctx.accept_time_us),
                ctx.inbound.source_ip, ctx.inbound.source_port, tag, ctx.inbound.user_email,
                profile.device_limit,
                validator_.OnlineDeviceCount(tag, uid));
            co_return fail(ErrorCode::PERMISSION_DENIED);
        }

        validator_.OnUserConnected(tag, uid, ctx.inbound.source_ip);
        user_session.emplace(validator_, tag, uid, ctx.inbound.source_ip);
    }

    LOG_CONN_DEBUG(ctx, "[VMess][{}] auth ok: {} -> {} user={}",
                   tag, client_ip, request->target,
                   ctx.inbound.user_email);

    // Header authentication and replay checks are finished. Body/response keys
    // are already owned by request; do not move a user-table owner into Session.
    request->user.reset();

    // 在 move 之前提取所有需要的字段
    TargetAddress target = request->target;
    Network net          = Network::TCP;
    if (request->command == ::acpp::vmess::Command::UDP) {
        net = Network::UDP;
    } else if (request->command == ::acpp::vmess::Command::Mux) {
        net = Network::MUX;  // Mux.Cool 多路复用，由私有 Mux inbound 处理
    }

    vmess_session.SetRequest(std::move(*request));
    request.reset();

    ctx.outbound.original_target = target;
    ctx.outbound.target = std::move(target);
    ctx.content.network = net;

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
class VmessRuntime final : public acpp::proxyman::inbound::ProtocolRuntime {
public:
    [[nodiscard]] std::vector<acpp::OnlineDevice>
    GetOnlineDevices(std::string_view tag) const override {
        return validator.GetOnlineDevices(tag);
    }

    acpp::vmess::TimedUserValidator validator;
};

const bool kVmessInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = acpp::proxyman::inbound::UserProtocol::Vmess;

    reg.create_runtime = []() -> std::unique_ptr<
        acpp::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<VmessRuntime>();
    };

    reg.create_tcp_handler =
        [](acpp::proxyman::inbound::ProtocolRuntime& runtime,
           acpp::StatsShard& stats,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest&) -> std::unique_ptr<acpp::Inbound> {
            auto* vmess_runtime = dynamic_cast<VmessRuntime*>(&runtime);
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

            for (const auto& client : config.clients) {
                if (client.id.empty()) {
                    LOG_WARN("VMess inbound '{}': static user UUID is empty", tag);
                    return std::nullopt;
                }
                auto user = acpp::vmess::MemoryAccount::FromUUID(
                    client.id, 0, client.email, 0);
                if (!user) {
                    LOG_WARN("VMess inbound '{}': invalid static user UUID", tag);
                    return std::nullopt;
                }
                users.push_back(acpp::proxyman::inbound::PreparedVmessUser{
                    .uuid = user->uuid,
                    .uuid_bytes = user->uuid_bytes,
                    .cmd_key = user->cmd_key,
                    .auth_key = user->auth_key,
                    .cached_auth_aes_key = user->cached_auth_aes_key,
                    .profile = user->profile,
                });
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
                if (auto user = acpp::vmess::MemoryAccount::FromUUID(
                        runtime_user.credential,
                        runtime_user.user_id,
                        runtime_user.email,
                        runtime_user.speed_limit,
                        runtime_user.device_limit)) {
                    users.push_back(acpp::proxyman::inbound::PreparedVmessUser{
                        .uuid = user->uuid,
                        .uuid_bytes = user->uuid_bytes,
                        .cmd_key = user->cmd_key,
                        .auth_key = user->auth_key,
                        .cached_auth_aes_key = user->cached_auth_aes_key,
                        .profile = user->profile,
                    });
                } else {
                    return std::nullopt;
                }
            }

            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kVmess, std::move(reg));
    return true;
}();
}  // namespace
