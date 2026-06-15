#include "acppnode/proxy/vmess/inbound/vmess_inbound.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "../encoding/server.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/session.hpp"

#include <algorithm>
#include <array>
#include <expected>
#include <span>
#include <utility>

namespace acpp {

namespace {

class VMessOnlineSession {
public:
    VMessOnlineSession(::acpp::vmess::TimedUserValidator& manager,
                       std::string_view tag,
                       uint64_t user_id,
                       std::string_view client_ip)
        : manager_(&manager)
        , tag_(tag)
        , user_id_(user_id)
        , client_ip_(client_ip) {}

    ~VMessOnlineSession() noexcept {
        if (!manager_ || user_id_ == 0) {
            return;
        }
        try {
            manager_->OnUserDisconnected(tag_, user_id_, client_ip_);
        } catch (...) {
        }
    }

    VMessOnlineSession(const VMessOnlineSession&) = delete;
    VMessOnlineSession& operator=(const VMessOnlineSession&) = delete;
    VMessOnlineSession(VMessOnlineSession&&) = delete;
    VMessOnlineSession& operator=(VMessOnlineSession&&) = delete;

private:
    ::acpp::vmess::TimedUserValidator* manager_;
    memory::ThreadLocalString tag_;
    uint64_t user_id_;
    memory::ThreadLocalString client_ip_;
};

[[nodiscard]] std::string FormatHexPrefix(const uint8_t* data, size_t len, size_t max_bytes = 24) {
    if (!data || len == 0) {
        return "-";
    }

    const size_t limit = std::min(len, max_bytes);
    std::string out;
    out.reserve(limit * 3 + 8);
    static constexpr char kHex[] = "0123456789abcdef";

    for (size_t i = 0; i < limit; ++i) {
        if (i > 0) out.push_back(' ');
        out.push_back(kHex[(data[i] >> 4) & 0x0F]);
        out.push_back(kHex[data[i] & 0x0F]);
    }

    if (len > limit) {
        out.append(" ...");
    }
    return out;
}

}  // namespace

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

    if (limiter_ && limiter_->GetLimiter().IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_ACCESS_FMT("{} from {}:{} rejected ip_banned [{}]",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag);
        co_return fail(ErrorCode::BLOCKED);
    }
    std::optional<VMessOnlineSession> user_session;

    buf::BufferGuard handshake_guard{buf::Buffer::New()};
    if (!handshake_guard) {
        co_return fail(ErrorCode::RESOURCE_EXHAUSTED);
    }
    uint8_t* handshake_buf = handshake_guard->Tail().data();
    const size_t handshake_capacity = handshake_guard->Available();
    auto read_handshake = [&]() -> net::awaitable<std::expected<size_t, ErrorCode>> {
        size_t n = 0;
        try {
            n = co_await stream->AsyncRead(net::buffer(handshake_buf, handshake_capacity));
        } catch (const IoSystemError&) {
            if (stream->ConsumePhaseDeadline()) {
                LOG_CONN_FAIL_CTX(ctx, "[VMess][{}] handshake phase deadline from {}",
                                  ctx.inbound.tag, ctx.inbound.source_ip);
                co_return std::unexpected(ErrorCode::TIMEOUT);
            }
            LOG_CONN_FAIL_CTX(ctx, "[VMess][{}] handshake read failed from {}",
                              ctx.inbound.tag, ctx.inbound.source_ip);
            co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
        }
        if (n == 0 && stream->ConsumePhaseDeadline()) {
            LOG_CONN_FAIL_CTX(ctx, "[VMess][{}] handshake phase deadline from {}",
                              ctx.inbound.tag, ctx.inbound.source_ip);
            co_return std::unexpected(ErrorCode::TIMEOUT);
        }
        if (n == 0 && stream->ConsumeIdleTimeout()) {
            LOG_CONN_FAIL_CTX(ctx, "[VMess][{}] handshake idle timeout from {}",
                              ctx.inbound.tag, ctx.inbound.source_ip);
            co_return std::unexpected(ErrorCode::TIMEOUT);
        }
        if (n == 0) co_return std::unexpected(ErrorCode::SOCKET_EOF);
        co_return n;
    };
    auto read_result = co_await read_handshake();
    if (!read_result) co_return fail(read_result.error());
    const size_t total_read = *read_result;

    LOG_CONN_TRACE(ctx,
                   "[VMess][{}] handshake bytes={} prefix={}",
                   tag,
                   total_read,
                   FormatHexPrefix(handshake_buf, total_read));

    // VMess AEAD 解析（tag 限定范围，减少搜索量）
    ::acpp::vmess::encoding::ServerSession vmess_session(validator_, tag);
    auto [request, consumed] = vmess_session.DecodeRequestHeader(
        handshake_buf, total_read, ctx.conn_id);

    if (!request) {
        LOG_CONN_TRACE(ctx,
                       "[VMess][{}] auth failed after {} handshake bytes prefix={}",
                       tag,
                       total_read,
                       FormatHexPrefix(handshake_buf, total_read));
        LOG_CONN_FAIL("[{}] VMess auth failed from {}", tag, client_ip);
        if (limiter_ && ban_tracking_enabled_) {
            limiter_->OnAuthFailTracked(tag, client_ip);
        }
        co_return fail(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    // 握手后的剩余数据存入 pending_data，VMess inbound Link 构造时消费
    if (consumed < total_read) {
        handshake_guard->Produce(static_cast<uint32_t>(total_read));
        request->SetPendingBuffer(
            std::move(handshake_guard),
            consumed,
            total_read - consumed);
    }

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
        const auto& profile = *request->user->profile;
        ctx.inbound.user_id = profile.user_id;
        ctx.inbound.user_email = profile.email;
        ctx.content.speed_limit = profile.speed_limit;

        // 在线追踪：认证成功后由当前协议 Process 的本地 guard 解注册。
        uint64_t uid = static_cast<uint64_t>(profile.user_id);
        if (!validator_.CanAcceptDevice(
                tag, uid, ctx.inbound.source_ip, profile.device_limit)) {
            LOG_ACCESS_FMT("{} from {}:{} rejected device_limit [{}] user={} limit={} online_devices={}",
                FormatTimestamp(ctx.accept_time_us),
                ctx.inbound.source_ip, ctx.inbound.source_port, tag, ctx.inbound.user_email,
                profile.device_limit,
                validator_.OnlineDeviceCount(tag, uid));
            co_return fail(ErrorCode::RESOURCE_EXHAUSTED);
        }

        validator_.OnUserConnected(tag, uid, ctx.inbound.source_ip);
        user_session.emplace(validator_, tag, uid, ctx.inbound.source_ip);
    }

    LOG_CONN_DEBUG(ctx, "[VMess][{}] auth ok: {} -> {} user={}",
                   tag, client_ip, request->target,
                   request->user && request->user->profile ? request->user->profile->email : "");

    // 在 move 之前提取所有需要的字段
    TargetAddress target = request->target;
    Network net          = Network::TCP;
    if (request->command == ::acpp::vmess::Command::UDP) {
        net = Network::UDP;
    } else if (request->command == ::acpp::vmess::Command::Mux) {
        net = Network::MUX;  // Mux.Cool 多路复用，由 DoMuxRelay 处理
    }

    vmess_session.SetRequest(std::move(*request));

    ctx.outbound.original_target = target;
    ctx.outbound.target = std::move(target);
    ctx.content.network = net;

    if (!co_await vmess_session.EncodeResponseHeader(*stream)) {
        co_return fail(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    auto request_reader = vmess_session.DecodeRequestBody(*stream);
    auto response_writer = vmess_session.EncodeResponseBody(*stream);
    if (!request_reader || !response_writer) {
        co_return fail(ErrorCode::RESOURCE_EXHAUSTED);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver,
        std::move(stream),
        transport::Link{request_reader.get(), response_writer.get()},
        InitialPayload{},
        ctx,
        *stats_,
        timeouts,
        pressure_idle_timeout);
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kVmessInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;

    reg.create_tcp_handler =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<acpp::Inbound> {
            auto* validator = deps.ValidatorAs<acpp::vmess::TimedUserValidator>();
            if (!validator || !deps.stats) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::vmess::inbound::Handler>(
                *validator,
                *deps.stats,
                limiter);
        };

    reg.build_static_users =
        [](std::string_view /*tag*/, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedVmessUser> users;

            for (const auto& client : config.clients) {
                if (client.id.empty()) {
                    continue;
                }
                if (auto user = acpp::vmess::MemoryAccount::FromUUID(
                        client.id, 0, client.email, 0)) {
                    users.push_back(acpp::proxyman::inbound::PreparedVmessUser{
                        .uuid = user->uuid,
                        .uuid_bytes = user->uuid_bytes,
                        .cmd_key = user->cmd_key,
                        .auth_key = user->auth_key,
                        .cached_auth_aes_key = std::to_array(user->cached_auth_aes_key.key),
                        .profile = user->profile,
                    });
                }
            }

            acpp::proxyman::inbound::UserSet result;
            result.vmess_accounts = std::move(users);
            return result;
        };

    reg.build_users =
        [](const acpp::proxyman::inbound::BuildRequest& /*req*/,
           std::span<const acpp::proxyman::inbound::RuntimeUser> runtime_users)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            std::vector<acpp::proxyman::inbound::PreparedVmessUser> users;
            users.reserve(runtime_users.size());

            for (const auto& runtime_user : runtime_users) {
                if (auto user = acpp::vmess::MemoryAccount::FromUUID(
                        runtime_user.uuid,
                        runtime_user.user_id,
                        runtime_user.email,
                        runtime_user.speed_limit,
                        runtime_user.device_limit)) {
                    users.push_back(acpp::proxyman::inbound::PreparedVmessUser{
                        .uuid = user->uuid,
                        .uuid_bytes = user->uuid_bytes,
                        .cmd_key = user->cmd_key,
                        .auth_key = user->auth_key,
                        .cached_auth_aes_key = std::to_array(user->cached_auth_aes_key.key),
                        .profile = user->profile,
                    });
                }
            }

            acpp::proxyman::inbound::UserSet result;
            result.vmess_accounts = std::move(users);
            return result;
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kVmess, std::move(reg));
    return true;
}();
}  // namespace
