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

ss::KeyBytes ToSsKey(const proxyman::inbound::PreparedKeyBytes& key) {
    ss::KeyBytes out;
    out.assign(key.span());
    return out;
}

class ShadowsocksOnlineSession {
public:
    ShadowsocksOnlineSession(ss::Validator& validator,
                             std::string_view tag,
                             int64_t user_id,
                             std::string_view client_ip)
        : validator_(&validator)
        , tag_(tag)
        , user_id_(user_id)
        , client_ip_(client_ip) {}

    ~ShadowsocksOnlineSession() noexcept {
        if (!validator_ || user_id_ == 0) {
            return;
        }
        try {
            validator_->OnUserDisconnected(tag_, user_id_, client_ip_);
        } catch (...) {
        }
    }

    ShadowsocksOnlineSession(const ShadowsocksOnlineSession&) = delete;
    ShadowsocksOnlineSession& operator=(const ShadowsocksOnlineSession&) = delete;
    ShadowsocksOnlineSession(ShadowsocksOnlineSession&&) = delete;
    ShadowsocksOnlineSession& operator=(ShadowsocksOnlineSession&&) = delete;

private:
    ss::Validator* validator_;
    memory::ThreadLocalString tag_;
    int64_t user_id_;
    memory::ThreadLocalString client_ip_;
};

class ShadowsocksUdpResponseContext final : public InboundDatagramResponse {
public:
    ShadowsocksUdpResponseContext(ss::KeyBytes reply_key, ss::SsCipherInfo cipher_info)
        : reply_key_(std::move(reply_key))
        , cipher_info_(cipher_info) {}

    ShadowsocksUdpResponseContext(std::shared_ptr<ss::Ss2022UdpSessionState> session)
        : ss2022_session_(std::move(session)) {}

    [[nodiscard]] buf::MultiBuffer Encode(UDPPacketView packet) override;

private:
    ss::KeyBytes reply_key_;
    ss::SsCipherInfo cipher_info_;
    std::shared_ptr<ss::Ss2022UdpSessionState> ss2022_session_;
};

}  // namespace

// ============================================================================
// proxy/shadowsocks/inbound.Handler
// ============================================================================

proxy::shadowsocks::inbound::Handler::Handler(
    ss::Validator& validator,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    ss::SsCipherInfo cipher_info)
    : validator_(validator)
    , stats_(&stats)
    , limiter_(std::move(limiter))
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
    auto fail = [&](ErrorCode error) {
        stats_->OnError();
        RelayResult result;
        result.error = error;
        return result;
    };

    LOG_CONN_DEBUG(ctx, "[SS][{}] Process start from {}", tag, client_ip);

    if (limiter_ && limiter_->GetLimiter().IsBanned(ctx.inbound.tag, ctx.inbound.source_ip)) {
        LOG_NET_DEBUG("{} from {}:{} rejected ip_banned [{}]",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, ctx.inbound.tag);
        co_return fail(ErrorCode::BLOCKED);
    }
    std::optional<ShadowsocksOnlineSession> user_session;

    auto session_result = co_await ss::ReadTCPSession(
        *stream,
        validator_,
        cipher_info_,
        tag,
        last_matched_index_);
    if (!session_result) {
        const ErrorCode error = session_result.error();
        if (error == ErrorCode::PROTOCOL_AUTH_FAILED) {
            LOG_NET_WARN("[{}] SS auth failed from {}", tag, client_ip);
            if (limiter_) {
                limiter_->OnAuthFailTracked(tag, client_ip);
            }
            stats_->OnError();
        } else {
            LOG_CONN_WARN(ctx, "[SS][{}] ReadTCPSession failed from {}: {}",
                              tag, client_ip, ErrorCodeToString(error));
        }
        co_return fail(error);
    }

    const auto* matched = session_result->user;
    if (!matched) {
        LOG_NET_WARN("[{}] SS auth failed from {}", tag, client_ip);
        if (limiter_) {
            limiter_->OnAuthFailTracked(tag, client_ip);
        }
        stats_->OnError();
        co_return fail(ErrorCode::PROTOCOL_AUTH_FAILED);
    }
    const auto& profile = *matched->profile;

    // ── 6. 填充上下文 ─────────────────────────────────────────────────────────
    ctx.inbound.user_id = profile.user_id;
    ctx.inbound.user_email = profile.email;
    ctx.content.speed_limit = profile.speed_limit;

    // 在线追踪：认证成功后由当前协议 Process 的本地 guard 解注册。
    int64_t uid = profile.user_id;
    if (!validator_.CanAcceptDevice(tag, uid, ctx.inbound.source_ip, profile.device_limit)) {
        LOG_NET_DEBUG("{} from {}:{} rejected device_limit [{}] user={} limit={} online_devices={}",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, tag, ctx.inbound.user_email,
            profile.device_limit,
            validator_.OnlineDeviceCount(tag, uid));
        co_return fail(ErrorCode::PERMISSION_DENIED);
    }

    validator_.OnUserConnected(tag, uid, ctx.inbound.source_ip);
    user_session.emplace(validator_, tag, uid, ctx.inbound.source_ip);

    LOG_CONN_DEBUG(ctx, "[SS][{}] auth ok: {} -> {} user={}",
                   tag, client_ip, session_result->target, ctx.inbound.user_email);

    // ── 7. 填充 session 并进入 dispatcher ───────────────────────────────────
    ctx.outbound.original_target = session_result->target;
    ctx.outbound.target = std::move(session_result->target);
    ctx.content.network = Network::TCP;

    auto request_reader = std::move(session_result->body_reader);
    auto response_writer_result = ss::WriteTCPResponse(
        *matched, cipher_info_, session_result->request_salt, *stream);
    if (!request_reader) {
        co_return fail(ErrorCode::RESOURCE_EXHAUSTED);
    }
    if (!response_writer_result) {
        co_return fail(response_writer_result.error());
    }
    auto response_writer = std::move(response_writer_result.value());

    if (const auto uot_version = proxy::uot::VersionFromMagicAddress(
            ctx.outbound.target)) {
        buf::MultiBuffer pending =
            session_result->initial_payload.MoveToMultiBuffer();
        bool is_connect = false;
        TargetAddress udp_target;

        if (*uot_version == proxy::uot::Version::V2) {
            auto request = co_await proxy::uot::ReadRequest(
                *request_reader, pending);
            if (!request || !request->destination.IsValid()) {
                co_return fail(request
                    ? ErrorCode::PROTOCOL_INVALID_ADDRESS
                    : request.error());
            }
            is_connect = request->is_connect;
            udp_target = std::move(request->destination);
        }

        proxy::uot::PacketReader uot_reader(
            *request_reader, is_connect, udp_target, std::move(pending));

        if (*uot_version == proxy::uot::Version::V1) {
            try {
                auto first_packet = co_await uot_reader.ReadMultiBuffer();
                if (!buf::HasData(first_packet)) {
                    co_return fail(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                for (const buf::Buffer* buffer : first_packet) {
                    if (buffer && buffer->HasUDP()) {
                        udp_target = buffer->UDP();
                        break;
                    }
                }
                if (!udp_target.IsValid()) {
                    co_return fail(ErrorCode::PROTOCOL_INVALID_ADDRESS);
                }
                uot_reader.SetInitialDecoded(std::move(first_packet));
            } catch (const IoSystemError& e) {
                co_return fail(MapAsioError(e.code()));
            }
        }

        proxy::uot::PacketWriter uot_writer(
            *response_writer, is_connect, udp_target);
        ctx.outbound.original_target = udp_target;
        ctx.outbound.target = udp_target;
        ctx.outbound.route_target = udp_target;
        ctx.content.network = Network::UDP;

        co_return co_await dispatcher.Dispatch(
            io_context,
            receiver,
            std::move(stream),
            transport::Link{&uot_reader, &uot_writer},
            InitialPayload{},
            ctx,
            *stats_,
            timeouts);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver,
        std::move(stream),
        transport::Link{request_reader.get(), response_writer.get()},
        std::move(session_result->initial_payload),
        ctx,
        *stats_,
        timeouts);
}

std::expected<acpp::InboundDatagramResult, acpp::ErrorCode>
proxy::shadowsocks::inbound::Handler::Process(
    const InboundDatagramRequest& request) {
    const auto tag = request.tag;
    const auto client_ip = request.client_ip;

    if (limiter_ && limiter_->GetLimiter().IsBanned(tag, client_ip)) {
        LOG_NET_DEBUG("source={} rejected=ip_banned inbound={} network=udp",
                      client_ip, tag);
        return std::unexpected(ErrorCode::BLOCKED);
    }

    auto users = validator_.FindUsersForTag(tag);
    if (users.empty()) {
        return std::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    auto decoded = ss::DecodeUdpPacket(
        request.payload.data(), request.payload.size(), users,
        cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size,
        udp_replay_cache_);
    if (!decoded) {
        if (limiter_) {
            limiter_->OnAuthFailTracked(tag, client_ip);
        }
        return std::unexpected(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    const auto& user = users[decoded->user_index];
    const auto& profile = *user.profile;

    InboundDatagramResult result;
    if (!result.session_owner.Assign(user.derived_key.span())) {
        return std::unexpected(ErrorCode::INTERNAL);
    }
    result.target = std::move(decoded->target);
    result.payload = std::move(decoded->payload);
    result.session_key = std::string(decoded->session_key.begin(), decoded->session_key.end());
    result.user_id = profile.user_id;
    result.user_email = profile.email;
    result.speed_limit = profile.speed_limit;
    if (decoded->ss2022_session) {
        result.response = std::make_shared<ShadowsocksUdpResponseContext>(
            std::move(decoded->ss2022_session));
    } else {
        result.response = std::make_shared<ShadowsocksUdpResponseContext>(
            ToSsKey(user.derived_key),
            cipher_info_);
    }
    return result;
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
            return buf::MultiBuffer{payload.release()};
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
        return buf::MultiBuffer{payload.release()};
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
acpp::proxyman::inbound::PreparedAeadCipher ToPreparedCipher(acpp::ss::SsCipherType type) {
    using Prepared = acpp::proxyman::inbound::PreparedAeadCipher;
    switch (type) {
        case acpp::ss::SsCipherType::AES_128_GCM:
            return Prepared::AES_128_GCM;
        case acpp::ss::SsCipherType::AES_256_GCM:
            return Prepared::AES_256_GCM;
        case acpp::ss::SsCipherType::CHACHA20_POLY1305:
            return Prepared::CHACHA20_POLY1305;
        case acpp::ss::SsCipherType::AES_128_GCM_2022:
            return Prepared::AES_128_GCM_2022;
        case acpp::ss::SsCipherType::AES_256_GCM_2022:
            return Prepared::AES_256_GCM_2022;
        case acpp::ss::SsCipherType::CHACHA20_POLY1305_2022:
            return Prepared::CHACHA20_POLY1305_2022;
    }
    return Prepared::AES_256_GCM;
}

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

    acpp::ss::Validator validator;
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
           acpp::ConnectionLimiterPtr limiter,
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
           acpp::ConnectionLimiterPtr limiter,
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
                acpp::ss::Is2022Cipher(*cipher_info) &&
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
                info.cipher_type = ToPreparedCipher(cipher_info->type);
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
            const bool has_uuid_backed_2022_users =
                acpp::ss::Is2022AesCipher(cipher_info.type) &&
                std::ranges::any_of(
                    runtime_users,
                    [](const auto& user) {
                        return !user.uuid.empty() && user.password == user.uuid;
                    });
            if (has_uuid_backed_2022_users &&
                settings->identity_password.empty()) {
                LOG_WARN("Inbound '{}': SS2022 UUID users require server identity key",
                         req.tag);
                return std::nullopt;
            }
            if (acpp::ss::Is2022Cipher(cipher_info) &&
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
                if (runtime_user.password.empty()) {
                    continue;
                }
                acpp::proxyman::inbound::PreparedShadowsocksUser info;
                info.password = runtime_user.password;
                info.profile.email = runtime_user.email;
                info.profile.user_id = runtime_user.user_id;
                info.profile.speed_limit = runtime_user.speed_limit;
                info.profile.device_limit = runtime_user.device_limit;
                info.cipher_type = ToPreparedCipher(cipher_info.type);
                info.key_size = cipher_info.key_size;
                info.salt_size = cipher_info.salt_size;
                const bool uuid_backed_2022_key =
                    acpp::ss::Is2022Cipher(cipher_info) &&
                    !runtime_user.uuid.empty() &&
                    runtime_user.password == runtime_user.uuid;
                info.derived_key = ToPreparedKey(uuid_backed_2022_key
                    ? acpp::ss::Build2022UserKeyFromUuid(
                        runtime_user.uuid, cipher_info)
                    : acpp::ss::BuildMasterKey(
                        runtime_user.password, cipher_info));
                info.identity_key = identity_key;
                if (info.derived_key.empty()) {
                    LOG_WARN("Inbound '{}': invalid SS password for user '{}'",
                             req.tag, runtime_user.email);
                    continue;
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
