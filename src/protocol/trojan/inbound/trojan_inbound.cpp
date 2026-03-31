#include "acppnode/protocol/trojan/inbound/trojan_inbound.hpp"
#include "acppnode/protocol/inbound_registry.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/panel/v2board_panel.hpp"

#include <array>

namespace acpp {

// ============================================================================
// TrojanInboundHandler 实现（代理层，无传输层知识）
// ============================================================================

TrojanInboundHandler::TrojanInboundHandler(
    trojan::TrojanUserManager& user_manager,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    std::function<void(const std::string&)> auth_callback)
    : InboundHandlerBase(stats, std::move(limiter))
    , user_manager_(user_manager)
    , auth_callback_(std::move(auth_callback))
{}

cobalt::task<std::expected<ParsedAction, ErrorCode>> TrojanInboundHandler::ParseStream(
    AsyncStream& stream, SessionContext& ctx)
{
    const std::string& tag       = ctx.inbound_tag;
    const std::string& client_ip = ctx.client_ip;

    LOG_CONN_DEBUG(ctx, "[Trojan][{}] ParseStream start from {}", tag, client_ip);

    if (RejectBanned(ctx)) co_return std::unexpected(ErrorCode::BLOCKED);

    std::array<uint8_t, 4096> handshake_buf{};
    auto read_result = co_await ReadHandshakeInto(
        stream,
        std::span<uint8_t>(handshake_buf.data(), handshake_buf.size()),
        ctx,
        "Trojan");
    if (!read_result) co_return std::unexpected(read_result.error());
    const size_t total_read = *read_result;

    size_t consumed = 0;
    auto request = trojan::TrojanCodec::ParseRequest(
        handshake_buf.data(), total_read, consumed);

    if (!request) {
        LOG_CONN_FAIL("[{}] Trojan parse failed from {}", tag, client_ip);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (!user_manager_.Validate(tag, request->password_hash)) {
        LOG_CONN_FAIL("[{}] Trojan auth failed from {} hash={}...{} store_size={} tag_size={}",
                      tag, client_ip,
                      request->password_hash.substr(0, 8),
                      request->password_hash.substr(request->password_hash.size() > 8 ? request->password_hash.size() - 4 : 0),
                      user_manager_.Size(),
                      trojan::TrojanUserManager::SharedStore().SizeForTag(tag));
        OnAuthFail(tag, client_ip);
        co_return std::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    auto user_info = user_manager_.FindUser(tag, request->password_hash);
    if (user_info) {
        FillUserInfo(ctx, user_info->user_id, user_info->email, user_info->speed_limit);
    }

    // 在线追踪：认证成功时注册，ctx 析构时自动解注册
    uint64_t tracked_uid = user_manager_.OnUserConnected(tag, request->password_hash);
    ctx.on_disconnect = [mgr = &user_manager_, t = tag, tracked_uid] {
        mgr->OnUserDisconnected(t, tracked_uid);
    };

    if (auth_callback_) auth_callback_(client_ip);

    LOG_CONN_DEBUG(ctx, "[Trojan][{}] auth ok: {} -> {} user={}",
                   tag, client_ip, request->target.ToString(), ctx.user_email);

    Network net = (request->command == trojan::TrojanCommand::UDP_ASSOCIATE)
                  ? Network::UDP : Network::TCP;

    ParsedAction action;
    action.target  = request->target;
    action.network = net;
    if (net == Network::UDP) {
        action.make_udp_framer = []() -> UdpFramer {
            return UdpFramer{trojan::TrojanUdpFramer{}};
        };
    }

    if (consumed < total_read) {
        action.initial_payload.assign(
            handshake_buf.data() + consumed,
            handshake_buf.data() + total_read);
    }

    co_return action;
}

cobalt::task<InboundWrapResult> TrojanInboundHandler::WrapStream(
    std::unique_ptr<AsyncStream> stream, SessionContext& /*ctx*/)
{
    co_return InboundWrapResult(std::move(stream));
}

std::unique_ptr<IInboundHandler> CreateTrojanInboundHandler(
    trojan::TrojanUserManager& user_manager,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    std::function<void(const std::string&)> auth_callback)
{
    return std::make_unique<TrojanInboundHandler>(
        user_manager, stats, std::move(limiter), std::move(auth_callback));
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kTrojanInboundRegistered = [] {
    acpp::InboundProtocolRegistration reg;

    reg.create_tcp_handler =
        [](const acpp::InboundProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::InboundBuildRequest& req) -> std::unique_ptr<acpp::IInboundHandler> {
            if (!deps.trojan_user_manager || !deps.stats) {
                return nullptr;
            }
            return acpp::CreateTrojanInboundHandler(
                *deps.trojan_user_manager,
                *deps.stats,
                std::move(limiter),
                req.auth_callback);
        };

    reg.load_static_users =
        [](std::string_view tag, const boost::json::object& settings) -> bool {
            std::vector<acpp::trojan::TrojanUserInfo> users;

            if (const auto* clients = settings.if_contains("clients");
                    clients && clients->is_array()) {
                for (const auto& c : clients->as_array()) {
                    if (!c.is_object()) continue;
                    const auto& co = c.as_object();

                    std::string password;
                    if (const auto* p = co.if_contains("password"); p && p->is_string()) {
                        password = std::string(p->as_string());
                    }
                    if (password.empty()) continue;

                    acpp::trojan::TrojanUserInfo info;
                    info.password_hash = acpp::trojan::TrojanUserManager::HashPassword(password);
                    if (const auto* e = co.if_contains("email"); e && e->is_string()) {
                        info.email = std::string(e->as_string());
                    }
                    users.push_back(std::move(info));
                }
            }

            acpp::trojan::TrojanUserManager::UpdateSharedUsersForTag(
                std::string(tag), std::move(users));
            return true;
        };

    reg.sync_worker_users =
        [](const acpp::InboundProtocolDeps& deps, std::string_view tag) {
            if (!deps.trojan_user_manager) return;
            deps.trojan_user_manager->UpdateUsersForTag(std::string(tag), {});
        };

    reg.update_panel_users =
        [](std::string_view tag,
           const acpp::NodeConfig& /*node_config*/,
           const std::vector<acpp::PanelUser>& panel_users) {
            std::vector<acpp::trojan::TrojanUserInfo> users;
            users.reserve(panel_users.size());

            for (const auto& pu : panel_users) {
                acpp::trojan::TrojanUserInfo info;
                info.password_hash = acpp::trojan::TrojanUserManager::HashPassword(pu.uuid);
                info.email         = pu.email;
                info.user_id       = pu.user_id;
                if (pu.speed_limit > 0) {
                    info.speed_limit = static_cast<uint64_t>(pu.speed_limit) * 1024 * 1024 / 8;
                }
                users.push_back(std::move(info));
            }

            acpp::trojan::TrojanUserManager::UpdateSharedUsersForTag(
                std::string(tag), std::move(users));
        };

    reg.clear_users = [](std::string_view tag) {
        acpp::trojan::TrojanUserManager::UpdateSharedUsersForTag(std::string(tag), {});
    };

    acpp::InboundFactory::Instance().Register(
        acpp::constants::protocol::kTrojan, std::move(reg));
    return true;
}();
}  // namespace
