#include "ss_inbound.hpp"
#include "../../inbound_admission.hpp"
#include "transport/async_stream.hpp"
#include "transport/link_error.hpp"
#include "../server.hpp"
#include "../ss_udp.hpp"
#include "../../uot/uot.hpp"
#include "app/rate_limiter.hpp"
#include "app/relay.hpp"
#include "app/stats.hpp"
#include "features/routing/dispatcher.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "common/allocator.hpp"
#include "common/initial_payload.hpp"
#include "common/session.hpp"

#include "common/buffer_util.hpp"
#include "common/byte_reader.hpp"
#include "common/buf/multi_buffer.hpp"
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <algorithm>
#include <cstring>
#include <span>
#include <utility>


namespace {



class ShadowsocksUdpResponseContext final : public InboundDatagramResponse {
public:
    ShadowsocksUdpResponseContext(ss::KeyBytes reply_key, ss::SsCipherInfo cipher_info)
        : reply_key_(std::move(reply_key))
        , cipher_info_(cipher_info) {}

    explicit ShadowsocksUdpResponseContext(ss::Ss2022UdpSessionState session)
        : ss2022_session_(std::move(session)) {}


    [[nodiscard]] buf::MultiBuffer Encode(UDPPacketView packet) override;

private:
    [[nodiscard]] size_t EncodePacketTo(
        const TargetAddress& target,
        std::span<const uint8_t> payload,
        uint8_t* out,
        size_t out_capacity);

    ss::KeyBytes reply_key_;
    ss::SsCipherInfo cipher_info_;
    std::optional<ss::Ss2022UdpSessionState> ss2022_session_;
};

struct PreparedSsTcpSession {
    ss::detail::BodyReader request_reader;
    ss::ResponseBodyWriter response_writer;
    InitialPayload initial_payload;
    UserOnlineSessionGuard user_session;
    std::optional<proxy::uot::Version> uot_version;
};

net::awaitable<tl::expected<PreparedSsTcpSession, ErrorCode>>
PrepareSsTcpSession(
    AsyncStream& stream,
    const ss::SsCipherInfo& cipher_info,
    size_t& last_matched_index,
    UserOnlineTracker& validator,
    ConnectionLimiter* limiter,
    session::Context& ctx,
    std::string_view tag,
    std::string_view client_ip) {
    auto session_result = co_await ss::ReadTCPSession(
        stream,
        cipher_info,
        tag,
        last_matched_index);
    if (!session_result) {
        const ErrorCode error = session_result.error();
        if (error == ErrorCode::PROTOCOL_AUTH_FAILED) {
            co_await proxy::RecordInboundAuthFailure(limiter, ctx, "no matching credential");
        } else if (error == ErrorCode::SOCKET_READ_FAILED) {
            // ReadTCPSession returns this code when ReadFull reaches EOF;
            // transport errors throw instead.
            LOG_CONN_DEBUG(ctx, "TCP session header ended before completion from {}:{} > {}",
                           client_ip, ctx.inbound.source_port, ErrorCodeToString(error));
        } else if (error != ErrorCode::SOCKET_EOF && error != ErrorCode::CONNECTION_CLOSED &&
                   error != ErrorCode::CANCELLED) {
            LOG_CONN_WARN(ctx, "TCP session handshake failed from {}:{} > {}",
                          client_ip, ctx.inbound.source_port, ErrorCodeToString(error));
        }
        co_return tl::unexpected(error);
    }

    auto request_reader = std::move(session_result->body_reader);
    const auto* matched = session_result->user.get();
    if (!matched) {
        co_await proxy::RecordInboundAuthFailure(limiter, ctx, "no authenticated user");
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    // UoT resolves its UDP destination only after admission; the magic address
    // is admitted as the TCP request target, as before.
    const auto uot_version = proxy::uot::VersionFromMagicAddress(session_result->target);
    proxy::BindAuthenticatedInbound(
        ctx, matched->profile,
        proxy::InboundRequestTarget{
            Network::TCP,
            std::move(session_result->target),
            std::move(session_result->forwarded)});
    auto user_session = co_await proxy::AdmitAuthenticatedInbound(
        validator, ctx, matched->profile);
    if (!user_session) {
        co_return tl::unexpected(ErrorCode::PERMISSION_DENIED);
    }

    auto response_writer_result = ss::WriteTCPResponse(
        *matched, cipher_info, session_result->request_salt, stream);
    if (!request_reader) {
        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
    }
    if (!response_writer_result) {
        co_return tl::unexpected(response_writer_result.error());
    }
    // Both directions now own their cipher/key state, including the lazy
    // response header. Authentication ownership must end before UoT/relay waits.
    session_result->user.reset();

    co_return PreparedSsTcpSession{
        .request_reader = std::move(*request_reader),
        .response_writer = std::move(*response_writer_result),
        .initial_payload = std::move(session_result->initial_payload),
        .user_session = std::move(*user_session),
        .uot_version = uot_version,
    };
}

net::awaitable<RelayResult> DispatchSsUotSession(
    proxy::uot::Version uot_version,
    std::unique_ptr<AsyncStream> stream,
    transport::MultiBufferReader& request_reader,
    transport::MultiBufferWriter& response_writer,
    buf::MultiBuffer pending,
    routing::Dispatcher& dispatcher,
    const routing::DispatchPolicy& dispatch_policy,
    net::io_context& io_context,
    session::Context& ctx,
    StatsShard& stats,
    const TimeoutsConfig& timeouts) {
    tl::expected<proxy::uot::PreparedRequest, ErrorCode> prepared =
        tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    try {
        prepared = co_await proxy::uot::ReadUotRequestHeader(
            uot_version, request_reader, std::move(pending));
    } catch (const transport::LinkError& e) {
        prepared = tl::unexpected(e.code());
    } catch (const IoSystemError& e) {
        prepared = tl::unexpected(
            stream ? proxy::ClassifyHandshakeReadException(*stream, e)
                   : MapAsioError(e.code()));
    }
    if (!prepared) {
        co_return proxy::RejectInbound(stats, stream.get(), prepared.error());
    }
    co_return co_await proxy::uot::DispatchPreparedUotRequest(
        std::move(*prepared),
        std::move(stream),
        request_reader,
        response_writer,
        dispatcher,
        dispatch_policy,
        io_context,
        ctx,
        stats,
        timeouts);
}

}  // namespace

// ============================================================================
// proxy/shadowsocks/inbound.Handler
// ============================================================================

proxy::shadowsocks::inbound::Handler::Handler(
    UserOnlineTracker& validator,
    StatsShard& stats,
    ConnectionLimiter* limiter,
    ss::SsCipherInfo cipher_info)
    : validator_(validator)
    , stats_(stats)
    , limiter_(limiter)
    , cipher_info_(cipher_info) {}

// ----------------------------------------------------------------------------
// Process
// 流程：
//   1. 读取 salt（salt_size 字节）
//   2. 遍历所有用户，尝试派生子密钥并解密首 chunk 长度字段
//   3. 找到匹配用户后解密首 chunk payload
//   4. 解析 SOCKS5 目标地址
//   5. 将剩余数据作为 initial_payload
//   6. 调用 dispatcher 进入出站处理
//
// 握手超时由底层 TcpStream 空闲超时保护（proxyman inbound 已在 Process
// 前设置 handshake 超时），无需额外守卫。
// ----------------------------------------------------------------------------
net::awaitable<RelayResult>
proxy::shadowsocks::inbound::Handler::Process(
    std::unique_ptr<AsyncStream> stream,
    routing::Dispatcher& dispatcher,
    const proxyman::inbound::ReceiverSettings& receiver,
    net::io_context& io_context,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    uint32_t /*pressure_idle_timeout*/) {

    const std::string_view tag   = ctx.inbound.tag;
    const std::string_view client_ip = ctx.inbound.source_ip;

    LOG_CONN_DEBUG(ctx, "processing connection from {}:{}", client_ip, ctx.inbound.source_port);

    if (co_await proxy::CheckInboundIpBanned(limiter_, ctx)) {
        co_return proxy::RejectInbound(stats_, stream.get(), ErrorCode::BLOCKED);
    }
    auto prepared = co_await PrepareSsTcpSession(
        *stream,
        cipher_info_,
        last_matched_index_,
        validator_,
        limiter_,
        ctx,
        tag,
        client_ip);
    if (!prepared) {
        co_return proxy::RejectInbound(stats_, stream.get(), prepared.error());
    }

    if (prepared->uot_version) {
        co_return co_await DispatchSsUotSession(
            *prepared->uot_version,
            std::move(stream),
            prepared->request_reader,
            prepared->response_writer,
            std::move(prepared->initial_payload).MoveToMultiBuffer(),
            dispatcher,
            receiver.dispatch_policy,
            io_context,
            ctx,
            stats_,
            timeouts);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{&prepared->request_reader, &prepared->response_writer},
        std::move(prepared->initial_payload),
        ctx,
        stats_,
        timeouts);
}

tl::expected<::InboundDatagramResult, ::ErrorCode>
proxy::shadowsocks::inbound::Handler::Process(
    const InboundDatagramRequest& request) {
    const auto tag = request.tag;

    auto users = proxyman::inbound::UserStore::ShadowsocksUsers(tag);
    if (users.empty()) {
        return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    auto decoded = ss::DecodeUdpPacket(
        request.payload.data(), request.payload.size(), users,
        cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size,
        udp_replay_cache_, request.associations != nullptr);
    if (!decoded) {
        // UDP datagrams use the socket peer address, never a PROXY protocol source.
        return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    const auto& user = users[decoded->user_index];

    InboundDatagramResult result;
    if (!result.session_owner.Assign(user.derived_key.span())) {
        return tl::unexpected(ErrorCode::INTERNAL);
    }
    result.target = std::move(decoded->target);
    result.payload = std::move(decoded->payload);
    result.forwarded = std::move(decoded->forwarded);
    result.session_id = decoded->session_id;
    result.packet_id = decoded->packet_id;
    if (request.associations && decoded->session_id && decoded->packet_id) {
        result.association_policy = &ss::Ss2022UdpAssociation::Policy();
        const auto found = request.associations->find(InboundDatagramAssociationKey{
            result.session_owner, *decoded->session_id, request.configuration});
        if (found != request.associations->end() && found->second) {
            auto* association = found->second;
            // The configuration/credential/session lookup and immutable policy
            // identity together establish the concrete protocol state type.
            if (&association->Policy() != result.association_policy)
                return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
            if (!association->claimed) {
                auto& state = static_cast<ss::Ss2022UdpAssociation&>(*association);
                if (!state.ss::Ss2022UdpAssociation::Check(*decoded->packet_id, request.worker_id,
                        request.client_endpoint, InboundDatagramCheck::Commit))
                    return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
                result.committed_association = association;
            }
        }
    }
    result.user_owner = std::shared_ptr<const UserProfile>(std::move(users.users), &user.profile);
    result.user = result.user_owner.get();
    result.limiter = limiter_;
    return result;
}

tl::expected<std::shared_ptr<InboundDatagramResponse>, ErrorCode>
proxy::shadowsocks::inbound::Handler::CreateDatagramResponse(
    const InboundDatagramResult& decoded) {
    ss::KeyBytes key;
    if (!key.assign(std::span(decoded.session_owner.bytes).first(decoded.session_owner.size))) {
        return tl::unexpected(ErrorCode::INTERNAL);
    }
    if (!ss::Is2022Cipher(cipher_info_.type)) {
        return memory::AllocateShared<ShadowsocksUdpResponseContext>(key, cipher_info_);
    }
    if (!decoded.session_id) return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    ss::Ss2022UdpSessionState state;
    state.cipher_info = cipher_info_;
    state.key = key;
    StoreU64BE(state.client_session_id.data(), *decoded.session_id);
    if (RAND_bytes(state.server_session_id.data(), state.server_session_id.size()) != 1) {
        return tl::unexpected(ErrorCode::INTERNAL);
    }
    return memory::AllocateShared<ShadowsocksUdpResponseContext>(std::move(state));
}

size_t ShadowsocksUdpResponseContext::EncodePacketTo(
    const TargetAddress& target,
    std::span<const uint8_t> payload,
    uint8_t* out,
    size_t out_capacity) {
    if (ss2022_session_) {
        return ss::Encode2022UdpResponsePacketTo(
            target,
            payload.data(),
            payload.size(),
            *ss2022_session_,
            out,
            out_capacity);
    }
    return ss::EncodeUdpPacketTo(
        target,
        payload.data(),
        payload.size(),
        reply_key_.span(),
        cipher_info_.type,
        cipher_info_.key_size,
        cipher_info_.salt_size,
        out,
        out_capacity);
}

buf::MultiBuffer ShadowsocksUdpResponseContext::Encode(UDPPacketView packet) {
    const size_t encoded_len = EncodePacketTo(
        packet.target, packet.data, nullptr, 0);
    if (encoded_len == 0) {
        return {};
    }

    buf::ContiguousWriteBuffer encoded;
    uint8_t* dst = encoded.TryPrepare(encoded_len);
    if (!dst) {
        return {};
    }
    const size_t written = EncodePacketTo(
        packet.target,
        packet.data,
        dst,
        encoded_len);
    if (written != encoded_len) {
        return {};
    }

    buf::MultiBuffer payload;
    if (!encoded.TryAppendTo(written, payload)) {
        return {};
    }
    return payload;
}


// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
class ShadowsocksSettings final
    : public ::proxyman::inbound::ProtocolSettings {
public:
    ::ss::SsCipherInfo cipher;
    // SS2022-AES identity header key; empty when EIH is disabled.
    ::proxyman::inbound::PreparedKeyBytes identity_key;
    ::Ss2022UserKey user_key = ::Ss2022UserKey::Base64Psk;
};

[[nodiscard]] const ShadowsocksSettings* GetSettings(
    const ::proxyman::inbound::BuildRequest& req) noexcept {
    return dynamic_cast<const ShadowsocksSettings*>(req.settings.get());
}

const bool kSsInboundRegistered = [] {
    ::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = ::proxyman::inbound::UserProtocol::Shadowsocks;
    reg.datagram_transport =
        ::proxyman::inbound::DatagramTransport::Packet;

    reg.create_runtime = &::proxy::CreateUserOnlineProtocolRuntime;

    const auto create_handler =
        [](::proxyman::inbound::ProtocolRuntime& runtime,
           ::StatsShard& stats,
           ::ConnectionLimiter* limiter,
           const ::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<::Inbound> {
            auto* tracker = runtime.OnlineTracker();
            const auto* settings = GetSettings(req);
            if (!tracker || !settings) {
                return nullptr;
            }
            return std::make_unique<::proxy::shadowsocks::inbound::Handler>(
                *tracker,
                stats,
                limiter,
                settings->cipher);
        };
    reg.create_tcp_handler = create_handler;
    reg.create_datagram_handler = create_handler;

    reg.prepare_settings =
        [](std::string_view tag, const ::InboundProtocolSettings& config)
            -> std::optional<std::shared_ptr<
                const ::proxyman::inbound::ProtocolSettings>> {
            const std::string method = config.method.empty()
                ? std::string(::constants::protocol::kAes256Gcm)
                : config.method;
            auto cipher = ::ss::ParseCipherMethod(method);
            if (!cipher) {
                LOG_WARN("Inbound '{}': unknown SS cipher '{}'", tag, method);
                return std::nullopt;
            }
            auto settings = std::make_shared<ShadowsocksSettings>();
            settings->cipher = *cipher;
            settings->user_key = config.ss2022_user_key;
            if (::ss::Is2022AesCipher(cipher->type)) {
                if (!config.identity_password.empty()) {
                    settings->identity_key =
                        ::ss::BuildMasterKey(config.identity_password, *cipher);
                    if (settings->identity_key.empty()) {
                        LOG_WARN("Inbound '{}': invalid SS2022 identity password", tag);
                        return std::nullopt;
                    }
                } else if (config.ss2022_user_key == ::Ss2022UserKey::UuidDerived) {
                    LOG_WARN("Inbound '{}': SS2022 UUID users require server identity key", tag);
                    return std::nullopt;
                }
            }
            return settings;
        };

    reg.build_users =
        [](const ::proxyman::inbound::BuildRequest& req,
           std::span<const ::InboundUserSpec> specs)
            -> std::optional<::proxyman::inbound::UserSet> {
            const auto* settings = GetSettings(req);
            if (!settings) {
                LOG_WARN("Inbound '{}': missing prepared SS settings", req.tag);
                return std::nullopt;
            }
            const auto& cipher_info = settings->cipher;
            const bool uuid_derived =
                ::ss::Is2022Cipher(cipher_info.type) &&
                settings->user_key == ::Ss2022UserKey::UuidDerived;

            std::vector<::proxyman::inbound::PreparedShadowsocksUser> users;
            users.reserve(specs.size());
            for (const auto& spec : specs) {
                if (spec.credential.empty()) {
                    LOG_WARN("Inbound '{}': SS password is empty", req.tag);
                    return std::nullopt;
                }
                ::proxyman::inbound::PreparedShadowsocksUser info;
                info.profile = ::proxy::MakeUserProfile(spec);
                info.derived_key = uuid_derived
                    ? ::ss::Build2022UserKeyFromUuid(spec.credential, cipher_info)
                    : ::ss::BuildMasterKey(spec.credential, cipher_info);
                info.identity_key = settings->identity_key;
                if (info.derived_key.empty()) {
                    LOG_WARN("Inbound '{}': invalid SS password for user '{}'",
                             req.tag, spec.email);
                    return std::nullopt;
                }
                if (!info.identity_key.empty() &&
                    !::ss::Hash2022Psk(info.derived_key.span(), info.psk_hash)) {
                    return std::nullopt;
                }
                users.push_back(std::move(info));
            }

            return ::proxyman::inbound::UserSet{std::move(users)};
        };

    ::proxyman::inbound::RegisterProxy(
        ::constants::protocol::kShadowsocks, std::move(reg));
    return true;
}();
}  // namespace
