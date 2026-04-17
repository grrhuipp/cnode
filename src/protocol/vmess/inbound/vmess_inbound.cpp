#include "acppnode/protocol/vmess/inbound/vmess_inbound.hpp"
#include "acppnode/protocol/vmess/vmess_stream.hpp"
#include "acppnode/protocol/inbound_registry.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/panel/v2board_panel.hpp"

#include <algorithm>
#include <array>

namespace acpp {

namespace {

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
// VMessInboundHandler 实现（代理层，无传输层知识）
// ============================================================================

VMessInboundHandler::VMessInboundHandler(
    vmess::VMessUserManager& user_manager,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    std::function<void(const std::string&)> auth_callback)
    : InboundHandlerBase(stats, std::move(limiter))
    , user_manager_(user_manager)
    , auth_callback_(std::move(auth_callback))
{}

cobalt::task<std::expected<ParsedAction, ErrorCode>> VMessInboundHandler::ParseStream(
    AsyncStream& stream, SessionContext& ctx)
{
    const std::string& tag       = ctx.inbound_tag;
    const std::string& client_ip = ctx.client_ip;

    LOG_CONN_DEBUG(ctx, "[VMess][{}] ParseStream start from {}", tag, client_ip);

    if (RejectBanned(ctx)) co_return std::unexpected(ErrorCode::BLOCKED);

    std::array<uint8_t, 1024> handshake_buf{};
    auto read_result = co_await ReadHandshakeInto(
        stream,
        std::span<uint8_t>(handshake_buf.data(), handshake_buf.size()),
        ctx,
        "VMess");
    if (!read_result) co_return std::unexpected(read_result.error());
    const size_t total_read = *read_result;

    LOG_CONN_TRACE(ctx,
                   "[VMess][{}] handshake bytes={} prefix={}",
                   tag,
                   total_read,
                   FormatHexPrefix(handshake_buf.data(), total_read));

    // VMess AEAD 解析（tag 限定范围，减少搜索量）
    vmess::VMessParser parser(user_manager_, tag);
    auto [request, consumed] = parser.ParseRequest(handshake_buf.data(), total_read, ctx.conn_id);

    if (!request) {
        LOG_CONN_TRACE(ctx,
                       "[VMess][{}] auth failed after {} handshake bytes prefix={}",
                       tag,
                       total_read,
                       FormatHexPrefix(handshake_buf.data(), total_read));
        LOG_CONN_FAIL("[{}] VMess auth failed from {}", tag, client_ip);
        OnAuthFail(tag, client_ip);
        co_return std::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    // 握手后的剩余数据存入 pending_data，VMessServerAsyncStream 构造时消费
    if (consumed < total_read) {
        request->pending_data.assign(
            handshake_buf.data() + consumed,
            handshake_buf.data() + total_read);
    }

    LOG_CONN_TRACE(ctx,
                   "[VMess][{}] parsed command={} security={} options={:#04x} target={} consumed={} pending={}",
                   tag,
                   static_cast<int>(request->command),
                   static_cast<int>(request->security),
                   static_cast<int>(request->options),
                   request->target.ToString(),
                   consumed,
                   request->pending_data.size());

    // 填充用户信息
    if (request->user) {
        FillUserInfo(ctx, request->user->user_id, request->user->email,
                     request->user->speed_limit);

        // 在线追踪：认证成功时注册，ctx 析构时自动解注册
        uint64_t uid = static_cast<uint64_t>(request->user->user_id);
        user_manager_.OnUserConnected(tag, uid);
        ctx.on_disconnect = [mgr = &user_manager_, t = tag, uid] {
            mgr->OnUserDisconnected(t, uid);
        };
    }

    if (auth_callback_) auth_callback_(client_ip);

    LOG_CONN_DEBUG(ctx, "[VMess][{}] auth ok: {} -> {} user={}",
                   tag, client_ip, request->target.ToString(),
                   request->user ? request->user->email : "");

    // 在 move 之前提取所有需要的字段
    TargetAddress target = request->target;
    Network net          = Network::TCP;
    if (request->command == vmess::Command::UDP) {
        net = Network::UDP;
    } else if (request->command == vmess::Command::Mux) {
        net = Network::MUX;  // Mux.Cool 多路复用，由 DoMuxRelay 处理
    }

    auto pdata = std::make_unique<VMessProtocolData>();
    pdata->request = std::move(*request);
    ctx.protocol_data = std::move(pdata);

    ParsedAction action;
    action.target  = target;
    action.network = net;
    if (net == Network::UDP) {
        TargetAddress udp_target = target;
        action.make_udp_framer = [udp_target]() mutable -> UdpFramer {
            return UdpFramer{PayloadOnlyUdpFramer{std::move(udp_target)}};
        };
    }
    co_return action;
}

cobalt::task<InboundWrapResult> VMessInboundHandler::WrapStream(
    std::unique_ptr<AsyncStream> stream, SessionContext& ctx)
{
    auto* pdata = dynamic_cast<VMessProtocolData*>(ctx.protocol_data.get());
    if (!pdata) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    co_return InboundWrapResult(std::make_unique<vmess::VMessServerAsyncStream>(
        std::move(stream),
        std::move(pdata->request)));
}

std::unique_ptr<IInboundHandler> CreateVMessInboundHandler(
    vmess::VMessUserManager& user_manager,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    std::function<void(const std::string&)> auth_callback)
{
    return std::make_unique<VMessInboundHandler>(
        user_manager, stats, std::move(limiter), std::move(auth_callback));
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kVmessInboundRegistered = [] {
    acpp::InboundProtocolRegistration reg;

    reg.create_tcp_handler =
        [](const acpp::InboundProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::InboundBuildRequest& req) -> std::unique_ptr<acpp::IInboundHandler> {
            if (!deps.vmess_user_manager || !deps.stats) {
                return nullptr;
            }
            return acpp::CreateVMessInboundHandler(
                *deps.vmess_user_manager,
                *deps.stats,
                std::move(limiter),
                req.auth_callback);
        };

    reg.load_static_users =
        [](std::string_view tag, const boost::json::object& settings) -> bool {
            std::vector<acpp::vmess::VMessUser> users;

            if (const auto* clients = settings.if_contains("clients");
                    clients && clients->is_array()) {
                for (const auto& c : clients->as_array()) {
                    if (!c.is_object()) continue;
                    const auto& co = c.as_object();

                    std::string uuid;
                    if (const auto* id = co.if_contains("id"); id && id->is_string()) {
                        uuid = std::string(id->as_string());
                    }
                    if (uuid.empty()) continue;

                    std::string email;
                    if (const auto* e = co.if_contains("email"); e && e->is_string()) {
                        email = std::string(e->as_string());
                    }

                    if (auto user = acpp::vmess::VMessUser::FromUUID(uuid, 0, email, 0)) {
                        users.push_back(*user);
                    }
                }
            }

            acpp::vmess::VMessUserManager::UpdateSharedUsersForTag(
                std::string(tag), std::move(users));
            return true;
        };

    reg.sync_worker_users =
        [](const acpp::InboundProtocolDeps& deps, std::string_view tag) {
            if (!deps.vmess_user_manager) return;
            deps.vmess_user_manager->UpdateUsersForTag(std::string(tag), {});
        };

    reg.update_panel_users =
        [](std::string_view tag,
           const acpp::NodeConfig& /*node_config*/,
           const std::vector<acpp::PanelUser>& panel_users) {
            std::vector<acpp::vmess::VMessUser> users;
            users.reserve(panel_users.size());

            for (const auto& pu : panel_users) {
                uint64_t speed_limit = 0;
                if (pu.speed_limit > 0) {
                    speed_limit = static_cast<uint64_t>(pu.speed_limit) * 1024 * 1024 / 8;
                }
                if (auto user = acpp::vmess::VMessUser::FromUUID(
                        pu.uuid, pu.user_id, pu.email, speed_limit)) {
                    users.push_back(*user);
                }
            }

            acpp::vmess::VMessUserManager::UpdateSharedUsersForTag(
                std::string(tag), std::move(users));
        };

    reg.clear_users = [](std::string_view tag) {
        acpp::vmess::VMessUserManager::UpdateSharedUsersForTag(std::string(tag), {});
    };

    acpp::InboundFactory::Instance().Register(
        acpp::constants::protocol::kVmess, std::move(reg));
    return true;
}();
}  // namespace
