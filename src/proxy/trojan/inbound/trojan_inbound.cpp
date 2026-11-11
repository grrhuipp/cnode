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
    ::proxy::trojan::kRequestPrefixSize + common::kMaxEncodedAddressSize + 2;

struct TrojanHandshakeResult {
    std::shared_ptr<const proxyman::inbound::UserStore::TrojanCredential> user;
    ::proxy::trojan::TrojanCommand command = ::proxy::trojan::TrojanCommand::CONNECT;
    common::TargetAddress target;
    std::optional<common::ForwardedMetadata> forwarded;
};

net::awaitable<tl::expected<TrojanHandshakeResult, common::ErrorCode>>
ParseTrojanRequest(transport::AsyncStream& stream,
                   session::Context& ctx,
                   proxy::InboundAuthentication& authentication) {
    std::array<uint8_t, kMaxTrojanHandshakeBytes> handshake_buf{};
    size_t total_read = 0;
    size_t required = ::proxy::trojan::kRequestPrefixSize;
    ::proxy::trojan::RequestDecodeResult decoded;
    common::ScopedCleanse cleanse_handshake{handshake_buf, decoded.request.password_hash};
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
        decoded = ::proxy::trojan::DecodeRequest(
            std::span<const uint8_t>(handshake_buf.data(), total_read));
        if (decoded.status == ::proxy::trojan::RequestDecodeStatus::Complete) {
            break;
        }
        if (decoded.status == ::proxy::trojan::RequestDecodeStatus::InvalidAddress) {
            LOG_ACCESS(common::FormatAccessLog(ctx, common::AccessStatus::Rejected, "invalid target address"));
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        if (decoded.status == ::proxy::trojan::RequestDecodeStatus::InvalidHeader) {
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
    auto user_info = proxyman::inbound::UserStore::FindTrojanUser(
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

namespace proxy::trojan::inbound {

class Handler final : public ::proxy::Inbound {
public:
    explicit Handler(const ::proxyman::inbound::AdmissionEnvironment& environment);

    ::net::awaitable<::app::RelayResult> Process(
        std::unique_ptr<::transport::AsyncStream> stream,
        ::routing::Dispatcher& dispatcher,
        const ::proxyman::inbound::ReceiverSettings& receiver,
        ::net::io_context& io_context,
        ::session::Context& ctx,
        const ::infra::TimeoutsConfig& timeouts,
        uint32_t pressure_idle_timeout) override;

private:
    const ::proxyman::inbound::AdmissionEnvironment& environment_;
};

}  // namespace proxy::trojan::inbound

// ============================================================================
// proxy/trojan/inbound.Handler 实现（代理层，无传输层知识）
// ============================================================================

proxy::trojan::inbound::Handler::Handler(
    const ::proxyman::inbound::AdmissionEnvironment& environment)
    : environment_(environment)
{}

net::awaitable<app::RelayResult>
proxy::trojan::inbound::Handler::Process(
    std::unique_ptr<transport::AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
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
        net = (handshake->command == ::proxy::trojan::TrojanCommand::UDP_ASSOCIATE)
              ? common::Network::UDP : common::Network::TCP;
        auto admitted = co_await proxy::AuthenticateAndAdmit(
            std::move(*authentication), &handshake->user->profile, "no matching credential",
            proxy::InboundRequestTarget{net, std::move(handshake->target), std::move(handshake->forwarded)});
        if (!admitted) co_return proxy::RejectInbound(environment_.stats, stream.get(), admitted.error());
        user_session.emplace(std::move(*admitted));
        // Session metadata is owned; release the authentication snapshot before I/O.
        handshake->user.reset();
    }

    if (net == common::Network::UDP) {
        ::proxy::trojan::UdpStreamEndpoint udp_endpoint(*stream);
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
    ::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = ::proxyman::inbound::UserProtocol::Trojan;
    reg.traits.requires_tls = true;


    reg.create_tcp_handler =
        [](const ::proxyman::inbound::AdmissionEnvironment& environment,
           const ::proxyman::inbound::BuildRequest&) -> std::unique_ptr<::proxy::Inbound> {
            return std::make_unique<::proxy::trojan::inbound::Handler>(environment);
        };

    reg.build_users =
        [](const ::proxyman::inbound::BuildRequest& req,
           std::span<const ::infra::InboundUserSpec> specs) {
            return ::proxy::BuildHashedInboundUsers<
                ::proxyman::inbound::PreparedTrojanUser>(
                "Trojan", req, specs,
                [](auto& info, std::string_view credential) {
                    const auto hash = ::proxy::trojan::HashPassword(credential);
                    info.password_hash.assign(hash.data(), hash.size());
                });
        };

    ::proxyman::inbound::RegisterProxy(
        ::constants::protocol::kTrojan, std::move(reg));
    return true;
}();
}  // namespace
