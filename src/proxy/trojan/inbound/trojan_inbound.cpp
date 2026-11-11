#include "proxy/inbound_admission.hpp"
#include "proxy/handshake_errors.hpp"
#include "app/relay.hpp"
#include "common/scoped_cleanse.hpp"
#include "proxy/inbound.hpp"
#include "common/sharded_user_stats.hpp"
#include "transport/async_stream.hpp"
#include "proxy/trojan/trojan_codec.hpp"
#include "app/rate_limiter.hpp"
#include "app/stats.hpp"
#include "features/routing/dispatcher.hpp"
#include "app/proxyman/inbound/handler.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "common/initial_payload.hpp"
#include "common/session.hpp"
#include "common/buf/multi_buffer.hpp"
#include "transport/link.hpp"
#include <array>
#include <openssl/crypto.h>
#include <memory>
#include <span>
#include <tl/expected.hpp>
#include <optional>
#include <utility>


namespace {

constexpr size_t kMaxTrojanHandshakeBytes =
    ::trojan::kRequestPrefixSize + kMaxEncodedAddressSize + 2;

struct TrojanHandshakeResult {
    std::shared_ptr<const proxyman::inbound::UserStore::TrojanCredential> user;
    ::trojan::TrojanCommand command = ::trojan::TrojanCommand::CONNECT;
    TargetAddress target;
    std::optional<ForwardedMetadata> forwarded;
};

net::awaitable<tl::expected<TrojanHandshakeResult, ErrorCode>>
ParseTrojanRequest(AsyncStream& stream,
                   session::Context& ctx,
                   ConnectionLimiter* limiter) {
    std::array<uint8_t, kMaxTrojanHandshakeBytes> handshake_buf{};
    size_t total_read = 0;
    size_t required = ::trojan::kRequestPrefixSize;
    ::trojan::RequestDecodeResult decoded;
    ScopedCleanse cleanse_handshake{handshake_buf, decoded.request.password_hash};
    while (true) {
        if (required > kMaxTrojanHandshakeBytes) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        if (total_read < required) {
            const auto progress = total_read == 0 ? proxy::HandshakeProgress::NotStarted
                                                  : proxy::HandshakeProgress::Started;
            auto read = co_await proxy::ReadHandshakeExact(
                stream,
                std::span<uint8_t>(handshake_buf.data() + total_read, required - total_read),
                progress);
            if (!read) co_return tl::unexpected(read.error());
            total_read = required;
        }
        decoded = ::trojan::DecodeRequest(
            std::span<const uint8_t>(handshake_buf.data(), total_read));
        if (decoded.status == ::trojan::RequestDecodeStatus::Complete) {
            break;
        }
        if (decoded.status == ::trojan::RequestDecodeStatus::InvalidAddress) {
            proxy::LogInboundRequestRejected(ctx, "invalid target address");
            co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        if (decoded.status == ::trojan::RequestDecodeStatus::InvalidHeader) {
            proxy::LogInboundRequestRejected(ctx, "invalid request header");
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        required = decoded.required;
    }

    auto& request = decoded.request;
    OPENSSL_cleanse(handshake_buf.data(), handshake_buf.size());
    const auto credential = co_await proxy::VerifyInboundCredential(
        limiter, ctx, proxyman::inbound::UserProtocol::Trojan,
        {reinterpret_cast<const uint8_t*>(request.password_hash.data()),
         request.password_hash.size()});
    if (credential.error != ErrorCode::OK) co_return tl::unexpected(credential.error);
    auto user_info = proxyman::inbound::UserStore::FindTrojanUser(
        ctx.inbound.tag, request.PasswordHashView());
    if (!user_info) {
        co_await proxy::RecordInboundAuthFailure(
            limiter, ctx, "no matching credential", credential.key);
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    co_return TrojanHandshakeResult{
        .user = std::move(user_info),
        .command = request.command,
        .target = std::move(request.target),
        .forwarded = std::move(request.forwarded),
    };
}

}  // namespace

namespace proxy::trojan::inbound {

class Handler final : public ::Inbound {
public:
    Handler(::UserOnlineTracker& tracker,
            ::StatsShard& stats,
            ::ConnectionLimiter* limiter);

    ::net::awaitable<::RelayResult> Process(
        std::unique_ptr<::AsyncStream> stream,
        ::routing::Dispatcher& dispatcher,
        const ::proxyman::inbound::ReceiverSettings& receiver,
        ::net::io_context& io_context,
        ::session::Context& ctx,
        const ::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

private:
    ::UserOnlineTracker& tracker_;
    ::StatsShard& stats_;
    ::ConnectionLimiter* limiter_;
};

}  // namespace proxy::trojan::inbound

// ============================================================================
// proxy/trojan/inbound.Handler 实现（代理层，无传输层知识）
// ============================================================================

proxy::trojan::inbound::Handler::Handler(
    ::UserOnlineTracker& tracker,
    StatsShard& stats,
    ConnectionLimiter* limiter)
    : tracker_(tracker)
    , stats_(stats)
    , limiter_(limiter)
{}

net::awaitable<RelayResult>
proxy::trojan::inbound::Handler::Process(
    std::unique_ptr<AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    uint32_t /*pressure_idle_timeout*/)
{
    LOG_CONN_DEBUG(ctx, "processing connection from {}:{}",
                   ctx.inbound.source_ip, ctx.inbound.source_port);

    if (proxy::BeginInboundAuthentication(limiter_, ctx) &&
        co_await proxy::CheckInboundIpBanned(*limiter_, ctx)) {
        co_return proxy::RejectInbound(stats_, stream.get(), ErrorCode::BLOCKED);
    }
    std::optional<UserOnlineSessionGuard> user_session;
    Network net = Network::TCP;
    {
        auto handshake = co_await ParseTrojanRequest(*stream, ctx, limiter_);
        if (!handshake) {
            co_return proxy::RejectInbound(stats_, stream.get(), handshake.error());
        }
        net = (handshake->command == ::trojan::TrojanCommand::UDP_ASSOCIATE)
              ? Network::UDP : Network::TCP;
        proxy::BindAuthenticatedInbound(
            ctx, handshake->user->profile,
            proxy::InboundRequestTarget{
                net,
                std::move(handshake->target),
                std::move(handshake->forwarded)});
        user_session = co_await proxy::AdmitAuthenticatedInbound(
            tracker_, ctx, handshake->user->profile);
        if (!user_session) {
            co_return proxy::RejectInbound(
                stats_, stream.get(), ErrorCode::PERMISSION_DENIED);
        }
        // Session metadata is owned; release the authentication snapshot before I/O.
        handshake->user.reset();
    }

    if (net == Network::UDP) {
        ::trojan::UdpStreamEndpoint udp_endpoint(*stream);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver.dispatch_policy,
            std::move(stream),
            transport::Link{&udp_endpoint, &udp_endpoint},
            InitialPayload{},
            ctx,
            stats_,
            timeouts);
    }

    auto* tcp_stream = stream.get();
    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{tcp_stream, tcp_stream},
        InitialPayload{},
        ctx,
        stats_,
        timeouts);
}


// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kTrojanInboundRegistered = [] {
    ::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = ::proxyman::inbound::UserProtocol::Trojan;

    reg.create_runtime = &::proxy::CreateUserOnlineProtocolRuntime;

    reg.create_tcp_handler =
        [](::proxyman::inbound::ProtocolRuntime& runtime,
           ::StatsShard& stats,
           ::ConnectionLimiter* limiter,
           const ::proxyman::inbound::BuildRequest&) -> std::unique_ptr<::Inbound> {
            auto* tracker = runtime.OnlineTracker();
            if (!tracker) {
                return nullptr;
            }
            return std::make_unique<::proxy::trojan::inbound::Handler>(
                *tracker,
                stats,
                limiter);
        };

    reg.build_users =
        [](const ::proxyman::inbound::BuildRequest& req,
           std::span<const ::InboundUserSpec> specs) {
            return ::proxy::BuildHashedInboundUsers<
                ::proxyman::inbound::PreparedTrojanUser>(
                "Trojan", req, specs,
                [](auto& info, std::string_view credential) {
                    const auto hash = ::trojan::HashPassword(credential);
                    info.password_hash.assign(hash.data(), hash.size());
                });
        };

    ::proxyman::inbound::RegisterProxy(
        ::constants::protocol::kTrojan, std::move(reg));
    return true;
}();
}  // namespace
