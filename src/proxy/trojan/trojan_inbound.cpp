#include "proxy/inbound_admission.hpp"
#include "proxy/handshake_errors.hpp"
#include "app/relay.hpp"
#include "common/scoped_cleanse.hpp"
#include "proxy/inbound.hpp"
#include "common/user_online_tracker.hpp"
#include "transport/async_stream.hpp"
#include "proxy/trojan/trojan_codec.hpp"
#include "app/stats.hpp"
#include "routing/dispatcher.hpp"
#include "app/inbound_handler.hpp"
#include "app/user_store.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "common/session.hpp"
#include "transport/link.hpp"
#include <array>
#include <memory>
#include <span>
#include <tl/expected.hpp>
#include <optional>
#include <utility>


namespace proxy {
namespace {

constexpr size_t kMaxTrojanHandshakeBytes =
    kRequestPrefixSize + common::kMaxEncodedAddressSize + 2;

struct AdmittedTrojanRequest {
    common::UserOnlineSessionGuard user_session;
    common::Network net = common::Network::TCP;
};

net::awaitable<tl::expected<TrojanRequest, common::ErrorCode>>
ReadRawTrojanRequest(transport::AsyncStream& stream, common::Context& ctx) {
    std::array<uint8_t, kMaxTrojanHandshakeBytes> handshake_buf{};
    common::ScopedCleanse cleanse_handshake{handshake_buf};
    size_t total_read = 0;
    size_t required = kRequestPrefixSize;
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
        auto decoded = DecodeTrojanRequest(
            std::span<const uint8_t>(handshake_buf.data(), total_read));
        if (decoded.status == TrojanRequestDecodeStatus::Complete) {
            co_return std::move(decoded.request);
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
}

net::awaitable<tl::expected<AdmittedTrojanRequest, common::ErrorCode>>
AuthenticateTrojanRequest(transport::AsyncStream& stream,
                          const app::AdmissionEnvironment& environment,
                          common::Context& ctx) {
    auto auth_phase = co_await proxy::BeginInboundAuthentication(environment, ctx);
    if (!auth_phase) {
        co_return tl::unexpected(auth_phase.error());
    }
    auto authentication = std::move(*auth_phase);
    auto parsed_request = co_await ReadRawTrojanRequest(stream, ctx);
    if (!parsed_request) {
        co_return tl::unexpected(parsed_request.error());
    }
    auto& request = *parsed_request;
    common::ScopedCleanse cleanse_hash{request.password_hash};
    const auto credential = co_await authentication.VerifyCredential({
        proxy::KeyedInboundProtocol::Trojan,
        {reinterpret_cast<const uint8_t*>(request.password_hash.data()), request.password_hash.size()}});
    if (credential != common::ErrorCode::OK) co_return tl::unexpected(credential);
    auto user_info = app::UserStore::FindTrojanUser(
        ctx.inbound.tag, request.PasswordHashView());
    if (!user_info) {
        co_return tl::unexpected(co_await authentication.RejectCredential("no matching credential"));
    }
    const common::Network net = (request.command == TrojanCommand::UDP_ASSOCIATE)
        ? common::Network::UDP : common::Network::TCP;
    auto bound = std::move(authentication).Bind(
        user_info->profile,
        proxy::InboundRequestTarget{net, std::move(request.target), std::move(request.forwarded)});
    // Session metadata is owned; release the authentication snapshot before I/O.
    user_info.reset();
    auto admitted = co_await std::move(bound).Admit();
    if (!admitted) co_return tl::unexpected(admitted.error());
    co_return AdmittedTrojanRequest{
        .user_session = std::move(*admitted),
        .net = net,
    };
}

net::awaitable<app::RelayResult> DispatchTrojanUdp(
    std::unique_ptr<transport::AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const app::ReceiverSettings& receiver,
    net::io_context& io_context,
    common::Context& ctx,
    const app::AdmissionEnvironment& environment,
    const infra::TimeoutsConfig& timeouts) {
    TrojanUdpStreamEndpoint udp_endpoint(*stream);
    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{&udp_endpoint, &udp_endpoint},
        common::InitialPayload{},
        ctx,
        environment.stats,
        timeouts);
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

    common::UserOnlineSessionGuard user_session;
    common::Network net = common::Network::TCP;
    {
        auto admitted = co_await AuthenticateTrojanRequest(*stream, environment_, ctx);
        if (!admitted) {
            co_return proxy::RejectInbound(environment_.stats, stream.get(), admitted.error());
        }
        user_session = std::move(admitted->user_session);
        net = admitted->net;
    }

    if (net == common::Network::UDP) {
        co_return co_await DispatchTrojanUdp(
            std::move(stream), dispatcher, receiver, io_context, ctx, environment_, timeouts);
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
