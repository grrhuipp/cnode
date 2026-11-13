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
#include "routing/dispatcher.hpp"
#include "app/proxyman/inbound_handler.hpp"
#include "app/proxyman/user_store.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "common/initial_payload.hpp"
#include "common/session.hpp"
#include "common/multi_buffer.hpp"
#include "transport/link.hpp"
#include <array>
#include <openssl/crypto.h>
#include <memory>
#include <span>
#include <tl/expected.hpp>
#include <optional>
#include <utility>


namespace proxy {
namespace {

constexpr size_t kMaxTrojanHandshakeBytes =
    kRequestPrefixSize + common::kMaxEncodedAddressSize + 2;

struct TrojanHandshakeResult {
    std::shared_ptr<const app::UserStore::TrojanCredential> user;
    TrojanCommand command = TrojanCommand::CONNECT;
    common::TargetAddress target;
    std::optional<common::ForwardedMetadata> forwarded;
};

net::awaitable<tl::expected<TrojanHandshakeResult, common::ErrorCode>>
ParseTrojanRequest(transport::AsyncStream& stream,
                   common::Context& ctx,
                   InboundAuthentication& authentication) {
    std::array<uint8_t, kMaxTrojanHandshakeBytes> handshake_buf{};
    size_t total_read = 0;
    size_t required = kRequestPrefixSize;
    TrojanRequestDecodeResult decoded;
    while (true) {
        if (required > kMaxTrojanHandshakeBytes) {
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
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
        decoded = DecodeTrojanRequest(
            std::span<const uint8_t>(handshake_buf.data(), total_read));
        if (decoded.status == TrojanRequestDecodeStatus::Complete) {
            break;
        }
        if (decoded.status == TrojanRequestDecodeStatus::InvalidAddress) {
            LOG_ACCESS(common::FormatAccessLog(ctx, common::AccessStatus::Rejected, "invalid target address"));
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        if (decoded.status == TrojanRequestDecodeStatus::InvalidHeader) {
            LOG_ACCESS(common::FormatAccessLog(ctx, common::AccessStatus::Rejected, "invalid request header"));
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        required = decoded.required;
    }

    auto& request = decoded.request;
    OPENSSL_cleanse(handshake_buf.data(), handshake_buf.size());
    const auto credential = co_await authentication.VerifyCredential({
        proxy::KeyedInboundProtocol::Trojan,
        {reinterpret_cast<const uint8_t*>(request.password_hash.data()), request.password_hash.size()}});
    if (credential != common::ErrorCode::OK) co_return tl::unexpected(credential);
    auto user_info = app::UserStore::FindTrojanUser(
        ctx.inbound.tag, request.PasswordHashView());
    if (!user_info) {
        co_return tl::unexpected(co_await authentication.RejectCredential("no matching credential"));
    }

    co_return TrojanHandshakeResult{
        .user = std::move(user_info),
        .command = request.command,
        .target = std::move(request.target),
        .forwarded = std::move(request.forwarded),
    };
}

}  // namespace

class TrojanInboundHandler final : public ::proxy::Inbound {
public:
    explicit TrojanInboundHandler(const ::app::AdmissionEnvironment& environment);

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

// ============================================================================
// proxy/trojan/inbound.Handler 实现（代理层，无传输层知识）
// ============================================================================

TrojanInboundHandler::TrojanInboundHandler(
    const ::app::AdmissionEnvironment& environment)
    : environment_(environment)
{}

net::awaitable<app::RelayResult>
TrojanInboundHandler::Process(
    std::unique_ptr<transport::AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const app::ReceiverSettings& receiver,
    net::io_context& io_context,
    common::Context& ctx,
    const infra::TimeoutsConfig& timeouts,
    uint32_t /*pressure_idle_timeout*/)
{
    LOG_CONN_DEBUG(ctx, "processing connection from {}:{}",
                   ctx.inbound.source_ip, ctx.inbound.source_port);

    auto authentication = co_await proxy::BeginInboundAuthentication(environment_, ctx);
    if (!authentication) co_return proxy::RejectInbound(environment_.stats, stream.get(), authentication.error());
    std::optional<common::UserOnlineSessionGuard> user_session;
    common::Network net = common::Network::TCP;
    {
        auto handshake = co_await ParseTrojanRequest(*stream, ctx, *authentication);
        if (!handshake) {
            co_return proxy::RejectInbound(environment_.stats, stream.get(), handshake.error());
        }
        net = (handshake->command == TrojanCommand::UDP_ASSOCIATE)
              ? common::Network::UDP : common::Network::TCP;
        auto bound = std::move(*authentication).Bind(
            handshake->user->profile,
            proxy::InboundRequestTarget{net, std::move(handshake->target), std::move(handshake->forwarded)});
        // Session metadata is owned; release the authentication snapshot before I/O.
        handshake->user.reset();
        auto admitted = co_await std::move(bound).Admit();
        if (!admitted) co_return proxy::RejectInbound(environment_.stats, stream.get(), admitted.error());
        user_session.emplace(std::move(*admitted));
    }

    if (net == common::Network::UDP) {
        TrojanUdpStreamEndpoint udp_endpoint(*stream);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver.dispatch_policy,
            std::move(stream),
            transport::Link{&udp_endpoint, &udp_endpoint},
            common::InitialPayload{},
            ctx,
            environment_.stats,
            timeouts);
    }

    auto* tcp_stream = stream.get();
    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{tcp_stream, tcp_stream},
        common::InitialPayload{},
        ctx,
        environment_.stats,
        timeouts);
}


// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kTrojanInboundRegistered = [] {
    ::app::ProxyRegistration reg;
    reg.user_protocol = ::app::UserProtocol::Trojan;
    reg.traits.requires_tls = true;


    reg.create_tcp_handler =
        [](const ::app::AdmissionEnvironment& environment,
           const ::app::BuildRequest&) -> std::unique_ptr<::proxy::Inbound> {
            return std::make_unique<::proxy::TrojanInboundHandler>(environment);
        };

    reg.build_users =
        [](const ::app::BuildRequest& req,
           std::span<const ::infra::InboundUserSpec> specs) {
            return ::proxy::BuildHashedInboundUsers<
                ::app::PreparedTrojanUser>(
                "Trojan", req, specs,
                [](auto& info, std::string_view credential) {
                    const auto hash = ::proxy::HashTrojanPassword(credential);
                    info.password_hash.assign(hash.data(), hash.size());
                });
        };

    ::app::RegisterProxy(
        ::common::kTrojan, std::move(reg));
    return true;
}();
}  // namespace
}  // namespace proxy
