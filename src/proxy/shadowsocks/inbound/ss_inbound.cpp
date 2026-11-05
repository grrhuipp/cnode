#include "ss_inbound.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "../server.hpp"
#include "../ss_udp.hpp"
#include "../../uot/uot.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/initial_payload.hpp"
#include "acppnode/common/session.hpp"

#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include <openssl/rand.h>
#include <algorithm>
#include <cstring>
#include <span>
#include <utility>

namespace acpp {

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
    ss::KeyBytes reply_key_;
    ss::SsCipherInfo cipher_info_;
    std::optional<ss::Ss2022UdpSessionState> ss2022_session_;
};

struct PreparedSsTcpSession {
    std::unique_ptr<transport::MultiBufferReader> request_reader;
    std::unique_ptr<transport::MultiBufferWriter> response_writer;
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
    StatsShard& stats,
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
            LOG_CONN_WARN(ctx, "authentication failed from {}:{} > no matching credential",
                          client_ip, ctx.inbound.source_port);
            LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "authentication failed: no matching credential"));
            if (limiter && ctx.inbound.HasProxyProtocolClientIP()) {
                co_await limiter->OnAuthFailTracked(tag, client_ip);
            }
            stats.OnError();
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
        LOG_CONN_WARN(ctx, "authentication failed from {}:{} > no authenticated user",
                      client_ip, ctx.inbound.source_port);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "authentication failed: no authenticated user"));
        if (limiter && ctx.inbound.HasProxyProtocolClientIP()) {
            co_await limiter->OnAuthFailTracked(tag, client_ip);
        }
        stats.OnError();
        co_return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    const auto& profile = matched->profile;
    ctx.inbound.user_id = profile.user_id;
    ctx.inbound.user_email = profile.email;
    ctx.content.speed_limit = profile.speed_limit;

    auto user_session = co_await validator.TryConnectSession(
        tag, profile.user_id, ctx.inbound.source_ip, profile.device_limit);
    if (!user_session) {
        LOG_CONN_DEBUG(ctx, "connection rejected from {}:{} > device limit={} domain_online_devices={}",
            ctx.inbound.source_ip, ctx.inbound.source_port, profile.device_limit,
            validator.OnlineDeviceCount(tag, static_cast<uint64_t>(profile.user_id)));
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "device limit"));
        co_return tl::unexpected(ErrorCode::PERMISSION_DENIED);
    }

    LOG_CONN_DEBUG(ctx, "authentication succeeded from {}:{} -> {}",
                   client_ip, ctx.inbound.source_port, session_result->target);
    const auto uot_version = proxy::uot::VersionFromMagicAddress(session_result->target);
    ctx.outbound.original_target = session_result->target;
    ctx.outbound.target = std::move(session_result->target);
    ctx.content.network = Network::TCP;

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
        .request_reader = std::move(request_reader),
        .response_writer = std::move(response_writer_result.value()),
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
    auto prepared = co_await proxy::uot::ReadUotRequestHeader(
        uot_version, request_reader, std::move(pending));
    if (!prepared) {
        stats.OnError();
        RelayResult result;
        result.error = prepared.error();
        co_return result;
    }
    const bool is_connect = prepared->is_connect;
    const TargetAddress udp_target = prepared->destination;
    proxy::uot::PacketReader uot_reader(request_reader, std::move(*prepared));
    proxy::uot::PacketWriter uot_writer(response_writer, is_connect, udp_target);
    ctx.outbound.original_target = udp_target;
    ctx.outbound.target = udp_target;
    ctx.outbound.route_target = udp_target;
    ctx.content.network = Network::UDP;

    co_return co_await dispatcher.Dispatch(
        io_context,
        dispatch_policy,
        std::move(stream),
        transport::Link{&uot_reader, &uot_writer},
        InitialPayload{},
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
    , stats_(&stats)
    , limiter_(limiter)
    , cipher_info_(cipher_info) {}

void proxy::shadowsocks::inbound::Handler::AdoptWorkerStateFrom(
    Inbound& previous) noexcept {
    auto* previous_handler = dynamic_cast<Handler*>(&previous);
    if (!previous_handler) {
        return;
    }
    udp_replay_cache_ = std::move(previous_handler->udp_replay_cache_);
}

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
    ctx.inbound.user_id = 0;
    ctx.inbound.user_email.clear();
    auto fail = [&](ErrorCode error) {
        stats_->OnError();
        RelayResult result;
        result.error = error;
        return result;
    };

    LOG_CONN_DEBUG(ctx, "processing connection from {}:{}", client_ip, ctx.inbound.source_port);

    if (limiter_ && ctx.inbound.HasProxyProtocolClientIP() &&
        co_await limiter_->IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_CONN_DEBUG(ctx, "connection rejected from {}:{} > IP banned",
                       ctx.inbound.source_ip, ctx.inbound.source_port);
        LOG_ACCESS(FormatAccessLog(ctx, AccessStatus::Rejected, "IP banned"));
        co_return fail(ErrorCode::BLOCKED);
    }
    std::unique_ptr<transport::MultiBufferReader> request_reader;
    std::unique_ptr<transport::MultiBufferWriter> response_writer;
    InitialPayload initial_payload;
    UserOnlineSessionGuard user_session;
    std::optional<proxy::uot::Version> uot_version;
    {
        auto prepared = co_await PrepareSsTcpSession(
            *stream,
            cipher_info_,
            last_matched_index_,
            validator_,
            limiter_,
            *stats_,
            ctx,
            tag,
            client_ip);
        if (!prepared) {
            co_return fail(prepared.error());
        }
        request_reader = std::move(prepared->request_reader);
        response_writer = std::move(prepared->response_writer);
        initial_payload = std::move(prepared->initial_payload);
        user_session = std::move(prepared->user_session);
        uot_version = prepared->uot_version;
    }

    if (uot_version) {
        co_return co_await DispatchSsUotSession(
            *uot_version,
            std::move(stream),
            *request_reader,
            *response_writer,
            initial_payload.MoveToMultiBuffer(),
            dispatcher,
            receiver.dispatch_policy,
            io_context,
            ctx,
            *stats_,
            timeouts);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver.dispatch_policy,
        std::move(stream),
        transport::Link{request_reader.get(), response_writer.get()},
        std::move(initial_payload),
        ctx,
        *stats_,
        timeouts);
}

tl::expected<acpp::InboundDatagramResult, acpp::ErrorCode>
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
        udp_replay_cache_);
    if (!decoded) {
        // UDP datagrams use the socket peer address, never a PROXY protocol source.
        return tl::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    const auto& user = users[decoded->user_index];
    const auto& profile = user.profile;

    InboundDatagramResult result;
    if (!result.session_owner.Assign(user.derived_key.span())) {
        return tl::unexpected(ErrorCode::INTERNAL);
    }
    result.target = std::move(decoded->target);
    result.payload = std::move(decoded->payload);
    result.session_id = decoded->session_id;
    result.user_id = profile.user_id;
    result.user_email = profile.email;
    result.speed_limit = profile.speed_limit;
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
    for (size_t i = 0; i < state.client_session_id.size(); ++i) {
        state.client_session_id[i] = static_cast<uint8_t>(
            *decoded.session_id >> ((state.client_session_id.size() - 1 - i) * 8));
    }
    if (RAND_bytes(state.server_session_id.data(), state.server_session_id.size()) != 1) {
        return tl::unexpected(ErrorCode::INTERNAL);
    }
    return memory::AllocateShared<ShadowsocksUdpResponseContext>(std::move(state));
}

buf::MultiBuffer ShadowsocksUdpResponseContext::Encode(UDPPacketView packet) {
    if (ss2022_session_) {
        auto& session = *ss2022_session_;
        const size_t encoded_len = ss::Encode2022UdpResponsePacketTo(
            packet.target,
            packet.data.data(),
            packet.data.size(),
            session,
            nullptr,
            0);
        if (encoded_len == 0) {
            return {};
        }

        if (encoded_len <= buf::Buffer::kSize) {
            buf::BufferGuard payload{buf::Buffer::New()};
            if (!payload) {
                return {};
            }
            const size_t written = ss::Encode2022UdpResponsePacketTo(
                packet.target,
                packet.data.data(),
                packet.data.size(),
                session,
                payload->Tail().data(),
                payload->Available());
            if (written != encoded_len) {
                return {};
            }
            payload->Produce(static_cast<uint32_t>(written));
            return buf::MultiBuffer{std::move(payload)};
        }

        memory::ByteVector scratch(encoded_len);
        const size_t written = ss::Encode2022UdpResponsePacketTo(
            packet.target,
            packet.data.data(),
            packet.data.size(),
            session,
            scratch.data(),
            scratch.size());
        if (written != encoded_len) {
            return {};
        }

        buf::MultiBuffer payload;
        payload.reserve((encoded_len + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
        if (!buf::AppendSpanToMultiBuffer(
                std::span<const uint8_t>(scratch.data(), scratch.size()),
                payload)) {
            return {};
        }
        return payload;
    }

    const size_t encoded_len = ss::EncodeUdpPacketTo(
        packet.target,
        packet.data.data(),
        packet.data.size(),
        reply_key_.span(),
        cipher_info_.type,
        cipher_info_.key_size,
        cipher_info_.salt_size,
        nullptr,
        0);
    if (encoded_len == 0) {
        return {};
    }

    if (encoded_len <= buf::Buffer::kSize) {
        buf::BufferGuard payload{buf::Buffer::New()};
        if (!payload) {
            return {};
        }
        const size_t written = ss::EncodeUdpPacketTo(
            packet.target,
            packet.data.data(),
            packet.data.size(),
            reply_key_.span(),
            cipher_info_.type,
            cipher_info_.key_size,
            cipher_info_.salt_size,
            payload->Tail().data(),
            payload->Available());
        if (written != encoded_len) {
            return {};
        }
        payload->Produce(static_cast<uint32_t>(written));
        return buf::MultiBuffer{std::move(payload)};
    }

    memory::ByteVector scratch(encoded_len);
    const size_t written = ss::EncodeUdpPacketTo(
        packet.target,
        packet.data.data(),
        packet.data.size(),
        reply_key_.span(),
        cipher_info_.type,
        cipher_info_.key_size,
        cipher_info_.salt_size,
        scratch.data(),
        scratch.size());
    if (written != encoded_len) {
        return {};
    }

    buf::MultiBuffer payload;
    payload.reserve((encoded_len + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
    if (!buf::AppendSpanToMultiBuffer(
            std::span<const uint8_t>(scratch.data(), scratch.size()),
            payload)) {
        return {};
    }
    return payload;
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
acpp::proxyman::inbound::PreparedKeyBytes ToPreparedKey(acpp::ss::KeyBytes key) {
    acpp::proxyman::inbound::PreparedKeyBytes prepared;
    prepared.assign(key.span());
    return prepared;
}

class ShadowsocksRuntime final
    : public acpp::proxyman::inbound::ProtocolRuntime {
public:
    [[nodiscard]] std::vector<acpp::OnlineDevice>
    GetOnlineDevices(std::string_view tag) const override {
        return validator.GetOnlineDevices(tag);
    }

    acpp::UserOnlineTracker validator;
};

class ShadowsocksSettings final
    : public acpp::proxyman::inbound::ProtocolSettings {
public:
    acpp::ss::SsCipherInfo cipher;
    std::string identity_password;
};

[[nodiscard]] const ShadowsocksSettings* GetSettings(
    const acpp::proxyman::inbound::BuildRequest& req) noexcept {
    return dynamic_cast<const ShadowsocksSettings*>(req.settings.get());
}

const bool kSsInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;
    reg.user_protocol = acpp::proxyman::inbound::UserProtocol::Shadowsocks;

    reg.create_runtime = []() -> std::unique_ptr<
        acpp::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<ShadowsocksRuntime>();
    };

    reg.create_tcp_handler =
        [](acpp::proxyman::inbound::ProtocolRuntime& runtime,
           acpp::StatsShard& stats,
           acpp::ConnectionLimiter* limiter,
           const acpp::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<acpp::Inbound> {
            auto* ss_runtime = dynamic_cast<ShadowsocksRuntime*>(&runtime);
            const auto* settings = GetSettings(req);
            if (!ss_runtime || !settings) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::shadowsocks::inbound::Handler>(
                ss_runtime->validator,
                stats,
                limiter,
                settings->cipher);
        };

    reg.create_datagram_handler =
        [](acpp::proxyman::inbound::ProtocolRuntime& runtime,
           acpp::StatsShard& stats,
           acpp::ConnectionLimiter* limiter,
           const acpp::proxyman::inbound::BuildRequest& req)
            -> std::unique_ptr<acpp::Inbound> {
            auto* ss_runtime = dynamic_cast<ShadowsocksRuntime*>(&runtime);
            const auto* settings = GetSettings(req);
            if (!ss_runtime || !settings) {
                return nullptr;
            }
            return std::make_unique<acpp::proxy::shadowsocks::inbound::Handler>(
                ss_runtime->validator, stats, limiter, settings->cipher);
        };

    reg.prepare_settings =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<std::shared_ptr<
                const acpp::proxyman::inbound::ProtocolSettings>> {
            const std::string method = config.method.empty()
                ? std::string(acpp::constants::protocol::kAes256Gcm)
                : config.method;
            auto cipher = acpp::ss::ParseCipherMethod(method);
            if (!cipher) {
                LOG_WARN("Inbound '{}': unknown SS cipher '{}'", tag, method);
                return std::nullopt;
            }
            auto settings = std::make_shared<ShadowsocksSettings>();
            settings->cipher = *cipher;
            settings->identity_password = config.identity_password;
            return settings;
        };

    reg.build_static_users =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            auto cipher_info = acpp::ss::ParseCipherMethod(config.method);
            if (!cipher_info) {
                LOG_WARN("Static inbound '{}': unknown SS cipher '{}'", tag, config.method);
                return std::nullopt;
            }

            std::vector<acpp::proxyman::inbound::PreparedShadowsocksUser> users;
            int64_t synthetic_uid = -1;
            acpp::proxyman::inbound::PreparedKeyBytes identity_key;
            const bool use_identity =
                acpp::ss::Is2022Cipher(cipher_info->type) &&
                !config.identity_password.empty() &&
                (config.clients.size() > 1 ||
                 (config.clients.size() == 1 &&
                  config.clients.front().password != config.identity_password));
            if (use_identity) {
                identity_key = ToPreparedKey(
                    acpp::ss::BuildMasterKey(config.identity_password, *cipher_info));
                if (identity_key.empty()) {
                    LOG_WARN("Static inbound '{}': invalid SS2022 identity password", tag);
                    return std::nullopt;
                }
            }

            for (const auto& client : config.clients) {
                if (client.password.empty()) {
                    LOG_WARN("Static inbound '{}': SS password is empty", tag);
                    return std::nullopt;
                }
                acpp::proxyman::inbound::PreparedShadowsocksUser info;
                info.password    = client.password;
                info.profile.user_id = synthetic_uid--;
                info.key_size    = cipher_info->key_size;
                info.salt_size   = cipher_info->salt_size;
                info.derived_key = ToPreparedKey(
                    acpp::ss::BuildMasterKey(client.password, *cipher_info));
                info.identity_key = identity_key;
                if (info.derived_key.empty()) {
                    LOG_WARN("Static inbound '{}': invalid SS password for user '{}'",
                             tag, client.email);
                    return std::nullopt;
                }
                if (!info.identity_key.empty() &&
                    !acpp::ss::Hash2022Psk(info.derived_key.span(), info.psk_hash)) {
                    return std::nullopt;
                }
                info.profile.email = client.email;
                users.push_back(std::move(info));
            }

            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    reg.build_users =
        [](const acpp::proxyman::inbound::BuildRequest& req,
           std::span<const acpp::proxyman::inbound::RuntimeUser> runtime_users)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            const auto* settings = GetSettings(req);
            if (!settings) {
                LOG_WARN("Inbound '{}': missing prepared SS settings", req.tag);
                return std::nullopt;
            }
            const auto& cipher_info = settings->cipher;

            std::vector<acpp::proxyman::inbound::PreparedShadowsocksUser> users;
            users.reserve(runtime_users.size());
            acpp::proxyman::inbound::PreparedKeyBytes identity_key;
            if (acpp::ss::Is2022AesCipher(cipher_info.type) &&
                settings->identity_password.empty()) {
                LOG_WARN("Inbound '{}': SS2022 UUID users require server identity key",
                         req.tag);
                return std::nullopt;
            }
            if (acpp::ss::Is2022Cipher(cipher_info.type) &&
                !settings->identity_password.empty()) {
                identity_key = ToPreparedKey(
                    acpp::ss::BuildMasterKey(
                        settings->identity_password, cipher_info));
                if (identity_key.empty()) {
                    LOG_WARN("Inbound '{}': invalid SS2022 identity password", req.tag);
                    return std::nullopt;
                }
            }

            for (const auto& runtime_user : runtime_users) {
                if (runtime_user.credential.empty()) {
                    return std::nullopt;
                }
                acpp::proxyman::inbound::PreparedShadowsocksUser info;
                info.password = runtime_user.credential;
                info.profile.email = runtime_user.email;
                info.profile.user_id = runtime_user.user_id;
                info.profile.speed_limit = runtime_user.speed_limit;
                info.profile.device_limit = runtime_user.device_limit;
                info.key_size = cipher_info.key_size;
                info.salt_size = cipher_info.salt_size;
                info.derived_key = ToPreparedKey(acpp::ss::Is2022Cipher(cipher_info.type)
                    ? acpp::ss::Build2022UserKeyFromUuid(runtime_user.credential, cipher_info)
                    : acpp::ss::BuildMasterKey(runtime_user.credential, cipher_info));
                info.identity_key = identity_key;
                if (info.derived_key.empty()) {
                    LOG_WARN("Inbound '{}': invalid SS password for user '{}'",
                             req.tag, runtime_user.email);
                    return std::nullopt;
                }
                if (!info.identity_key.empty() &&
                    !acpp::ss::Hash2022Psk(info.derived_key.span(), info.psk_hash)) {
                    return std::nullopt;
                }
                users.push_back(std::move(info));
            }

            return acpp::proxyman::inbound::UserSet{std::move(users)};
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kShadowsocks, std::move(reg));
    return true;
}();
}  // namespace
