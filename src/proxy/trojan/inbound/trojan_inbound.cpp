#include "trojan_inbound.hpp"
#include "../../inbound_admission.hpp"
#include "transport/async_stream.hpp"
#include "../trojan_codec.hpp"
#include "../credentials.hpp"
#include "../udp_framing.hpp"
#include "app/rate_limiter.hpp"
#include "app/stats.hpp"
#include "features/routing/dispatcher.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "common/allocator.hpp"
#include "common/initial_payload.hpp"
#include "common/session.hpp"
#include "common/buf/multi_buffer.hpp"
#include "transport/link.hpp"
#include "app/udp_types.hpp"
#include <array>
#include <openssl/crypto.h>
#include <span>
#include <tl/expected.hpp>
#include <optional>
#include <utility>


namespace {



// ============================================================================
// Trojan UDP reader/writer helper
//
// 把 TCP 隧道上的 Trojan UDP 帧解析/封装为携带逐包目标的 MultiBuffer，
// 供 dispatcher.Dispatch -> outbound.Process -> DoRelayLink 以协议无关方式中继。
// 对齐 xray-core 把 UDP 封帧放在入站 reader/writer，而非 relay 内部。
// ============================================================================
class TrojanUdpReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }

    explicit TrojanUdpReader(AsyncStream& src) : src_(src) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        return trojan::ReadUdpDatagram(src_, framer_);
    }

private:
    AsyncStream& src_;
    trojan::UdpFramer framer_;
};

class TrojanUdpWriter final : public transport::MultiBufferWriter {
public:
    explicit TrojanUdpWriter(AsyncStream& dst) : dst_(dst) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        return trojan::WriteUdpDatagram(dst_, std::move(mb));
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return dst_.AsyncShutdownWrite();
    }

    bool WriteShutdownClosesLink() const noexcept override {
        return dst_.WriteShutdownClosesLink();
    }

private:
    AsyncStream& dst_;
};

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
                   ConnectionLimiter* limiter,
                   std::string_view tag,
                   std::string_view client_ip) {
    std::array<uint8_t, kMaxTrojanHandshakeBytes> handshake_buf{};
    size_t total_read = 0;
    size_t required = ::trojan::kRequestPrefixSize;
    ::trojan::RequestDecodeResult decoded;
    struct CleanseHandshake {
        std::array<uint8_t, kMaxTrojanHandshakeBytes>& buf;
        ::trojan::PasswordHash& hash;
        ~CleanseHandshake() noexcept {
            OPENSSL_cleanse(buf.data(), buf.size());
            OPENSSL_cleanse(hash.data(), hash.size());
        }
    } cleanse_handshake{handshake_buf, decoded.request.password_hash};
    while (true) {
        if (required > kMaxTrojanHandshakeBytes) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        while (total_read < required) {
            size_t n = 0;
            try {
                n = co_await stream.AsyncRead(net::buffer(
                    handshake_buf.data() + total_read, required - total_read));
            } catch (const IoSystemError& error) {
                co_return tl::unexpected(
                    proxy::ClassifyHandshakeReadException(stream, error));
            }
            if (n == 0) {
                co_return tl::unexpected(
                    proxy::ResolveHandshakeReadFailure(
                        stream, ErrorCode::PROTOCOL_DECODE_FAILED));
            }
            total_read += n;
        }
        decoded = ::trojan::DecodeRequest(
            std::span<const uint8_t>(handshake_buf.data(), total_read));
        if (decoded.status == ::trojan::RequestDecodeStatus::Complete) {
            break;
        }
        if (decoded.status == ::trojan::RequestDecodeStatus::InvalidAddress) {
            LOG_CONN_WARN(ctx, "request rejected from {}:{} > invalid target address",
                          client_ip, ctx.inbound.source_port);
            LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "invalid target address"));
            co_return tl::unexpected(ErrorCode::PROTOCOL_INVALID_ADDRESS);
        }
        if (decoded.status == ::trojan::RequestDecodeStatus::InvalidHeader) {
            LOG_CONN_WARN(ctx, "invalid request header from {}:{}", client_ip, ctx.inbound.source_port);
            LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "invalid request header"));
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        required = decoded.required;
    }

    auto& request = decoded.request;
    auto user_info = proxyman::inbound::UserStore::FindTrojanUser(
        tag, request.PasswordHashView());
    OPENSSL_cleanse(handshake_buf.data(), handshake_buf.size());
    OPENSSL_cleanse(request.password_hash.data(), request.password_hash.size());
    if (!user_info) {
        co_await proxy::RecordInboundAuthFailure(limiter, ctx, "no matching credential");
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

// ============================================================================
// proxy/trojan/inbound.Handler 实现（代理层，无传输层知识）
// ============================================================================

proxy::trojan::inbound::Handler::Handler(
    ::UserOnlineTracker& validator,
    StatsShard& stats,
    ConnectionLimiter* limiter)
    : validator_(validator)
    , stats_(&stats)
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
    const std::string_view tag   = ctx.inbound.tag;
    const std::string_view client_ip = ctx.inbound.source_ip;

    LOG_CONN_DEBUG(ctx, "processing connection from {}:{}", client_ip, ctx.inbound.source_port);

    if (co_await proxy::CheckInboundIpBanned(limiter_, ctx)) {
        co_return proxy::RejectInbound(*stats_, stream.get(), ErrorCode::BLOCKED);
    }
    std::optional<UserOnlineSessionGuard> user_session;
    Network net = Network::TCP;
    {
        auto handshake = co_await ParseTrojanRequest(
            *stream, ctx, limiter_, tag, client_ip);
        if (!handshake) {
            co_return proxy::RejectInbound(*stats_, stream.get(), handshake.error());
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
            validator_, ctx, handshake->user->profile);
        if (!user_session) {
            co_return proxy::RejectInbound(
                *stats_, stream.get(), ErrorCode::PERMISSION_DENIED);
        }
        // Session metadata is owned; release the authentication snapshot before I/O.
        handshake->user.reset();
    }

    if (net == Network::UDP) {
        TrojanUdpReader udp_reader(*stream);
        TrojanUdpWriter udp_writer(*stream);
        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver.dispatch_policy,
            std::move(stream),
            transport::Link{&udp_reader, &udp_writer},
            InitialPayload{},
            ctx,
            *stats_,
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
        *stats_,
        timeouts);
}


// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kTrojanInboundRegistered = [] {
    ::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = ::proxyman::inbound::UserProtocol::Trojan;

    reg.create_runtime = []() -> std::unique_ptr<
        ::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<::proxy::UserOnlineProtocolRuntime>();
    };

    reg.create_tcp_handler =
        [](::proxyman::inbound::ProtocolRuntime& runtime,
           ::StatsShard& stats,
           ::ConnectionLimiter* limiter,
           const ::proxyman::inbound::BuildRequest&) -> std::unique_ptr<::Inbound> {
            auto* trojan_runtime = dynamic_cast<::proxy::UserOnlineProtocolRuntime*>(&runtime);
            if (!trojan_runtime) {
                return nullptr;
            }
            return std::make_unique<::proxy::trojan::inbound::Handler>(
                trojan_runtime->validator,
                stats,
                limiter);
        };

    reg.build_users =
        [](const ::proxyman::inbound::BuildRequest& req,
           std::span<const ::InboundUserSpec> specs)
            -> std::optional<::proxyman::inbound::UserSet> {
            std::vector<::proxyman::inbound::PreparedTrojanUser> users;
            users.reserve(specs.size());

            for (const auto& spec : specs) {
                if (spec.credential.empty()) {
                    LOG_WARN("Trojan inbound '{}': user password is empty", req.tag);
                    return std::nullopt;
                }
                ::proxyman::inbound::PreparedTrojanUser info;
                const auto hash = ::trojan::HashPassword(spec.credential);
                info.password_hash.assign(hash.data(), hash.size());
                info.profile.email = spec.email;
                info.profile.user_id = spec.user_id;
                info.profile.speed_limit = spec.speed_limit;
                info.profile.device_limit = spec.device_limit;
                users.push_back(std::move(info));
            }

            return ::proxyman::inbound::UserSet{std::move(users)};
        };

    ::proxyman::inbound::RegisterProxy(
        ::constants::protocol::kTrojan, std::move(reg));
    return true;
}();
}  // namespace
