#include "acppnode/proxy/shadowsocks/inbound/ss_inbound.hpp"
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

class ShadowsocksUdpResponseContext final : public proxyman::inbound::UdpResponseContext {
public:
    ShadowsocksUdpResponseContext(ss::KeyBytes reply_key, ss::SsCipherInfo cipher_info)
        : reply_key_(std::move(reply_key))
        , cipher_info_(cipher_info) {}

    ShadowsocksUdpResponseContext(std::shared_ptr<ss::Ss2022UdpSessionState> session)
        : ss2022_session_(std::move(session)) {}

    [[nodiscard]] const ss::KeyBytes& ReplyKey() const noexcept {
        return reply_key_;
    }

    [[nodiscard]] const ss::SsCipherInfo& CipherInfo() const noexcept {
        return cipher_info_;
    }

    [[nodiscard]] ss::Ss2022UdpSessionState* Ss2022Session() const noexcept {
        return ss2022_session_.get();
    }

private:
    ss::KeyBytes reply_key_;
    ss::SsCipherInfo cipher_info_;
    std::shared_ptr<ss::Ss2022UdpSessionState> ss2022_session_;
};

[[nodiscard]] const ShadowsocksUdpResponseContext* AsShadowsocksUdpContext(
    const proxyman::inbound::UdpResponseContext& context) noexcept {
    return dynamic_cast<const ShadowsocksUdpResponseContext*>(&context);
}

}  // namespace

// ============================================================================
// proxy/shadowsocks/inbound.Handler
// ============================================================================

proxy::shadowsocks::inbound::Handler::Handler(
    ss::Validator& validator,
    StatsShard& stats,
    ConnectionLimiterPtr limiter,
    std::string cipher_method)
    : validator_(validator)
    , stats_(&stats)
    , limiter_(std::move(limiter))
    , cipher_method_(std::move(cipher_method)) {
    auto info = ss::ParseCipherMethod(cipher_method_);
    if (info) {
        cipher_info_ = *info;
    } else {
        // 默认 aes-256-gcm
        LOG_WARN("[SS] Unknown cipher method '{}', falling back to aes-256-gcm", cipher_method_);
        cipher_info_ = ss::SsCipherInfo{ss::SsCipherType::AES_256_GCM, 32, 32};
    }
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
    uint32_t pressure_idle_timeout) {

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
        LOG_ACCESS_FMT("{} from {}:{} rejected ip_banned [{}]",
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
            LOG_CONN_FAIL("[{}] SS auth failed from {}", tag, client_ip);
            if (limiter_) {
                limiter_->OnAuthFailTracked(tag, client_ip);
            }
            stats_->OnError();
        } else {
            LOG_CONN_FAIL_CTX(ctx, "[SS][{}] ReadTCPSession failed from {}: {}",
                              tag, client_ip, ErrorCodeToString(error));
        }
        co_return fail(error);
    }

    const auto* matched = session_result->user;
    if (!matched) {
        LOG_CONN_FAIL("[{}] SS auth failed from {}", tag, client_ip);
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
        LOG_ACCESS_FMT("{} from {}:{} rejected device_limit [{}] user={} limit={} online_devices={}",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, tag, ctx.inbound.user_email,
            profile.device_limit,
            validator_.OnlineDeviceCount(tag, uid));
        co_return fail(ErrorCode::RESOURCE_EXHAUSTED);
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
            timeouts,
            pressure_idle_timeout);
    }

    co_return co_await dispatcher.Dispatch(
        io_context,
        receiver,
        std::move(stream),
        transport::Link{request_reader.get(), response_writer.get()},
        std::move(session_result->initial_payload),
        ctx,
        *stats_,
        timeouts,
        pressure_idle_timeout);
}

std::optional<acpp::proxyman::inbound::UdpDecodeResult>
proxy::shadowsocks::inbound::Handler::DecodeUdp(
    std::string_view tag,
    std::string_view client_ip,
    const uint8_t* data,
    size_t len) const {

    if (limiter_ && limiter_->GetLimiter().IsBanned(tag, client_ip)) {
        LOG_ACCESS_FMT("{} from {} rejected ip_banned [{}] (udp)",
                       LogLocalNow(), client_ip, tag);
        return std::nullopt;
    }

    auto users = validator_.FindUsersForTag(tag);
    if (users.empty()) {
        return std::nullopt;
    }

    auto decoded = ss::DecodeUdpPacket(
        data, len, users,
        cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size);
    if (!decoded) {
        if (limiter_) {
            limiter_->OnAuthFailTracked(tag, client_ip);
        }
        return std::nullopt;
    }

    const auto& user = users[decoded->user_index];
    const auto& profile = *user.profile;

    proxyman::inbound::UdpDecodeResult result;
    result.target = std::move(decoded->target);
    result.payload = std::move(decoded->payload);
    result.session_key = std::string(decoded->session_key.begin(), decoded->session_key.end());
    result.user_id = profile.user_id;
    result.user_email = profile.email;
    result.speed_limit = profile.speed_limit;
    if (decoded->ss2022_session) {
        result.response_context = std::make_shared<ShadowsocksUdpResponseContext>(
            std::move(decoded->ss2022_session));
    } else {
        result.response_context = std::make_shared<ShadowsocksUdpResponseContext>(
            ToSsKey(user.derived_key),
            cipher_info_);
    }
    return result;
}

buf::MultiBuffer proxy::shadowsocks::inbound::Handler::EncodeUdpResponse(
    UDPPacketView packet,
    const proxyman::inbound::UdpResponseContext& response_context) const {
    const auto* ss_context = AsShadowsocksUdpContext(response_context);
    if (!ss_context) {
        return {};
    }
    if (auto* session = ss_context->Ss2022Session()) {
        const size_t encoded_len = ss::Encode2022UdpResponsePacketTo(
            packet.target,
            packet.data.data(),
            packet.data.size(),
            *session,
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
                *session,
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
            *session,
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

    const auto& reply_key = ss_context->ReplyKey();
    const auto& cipher = ss_context->CipherInfo();
    const size_t encoded_len = ss::EncodeUdpPacketTo(
        packet.target,
        packet.data.data(),
        packet.data.size(),
        reply_key.span(),
        cipher.type,
        cipher.key_size,
        cipher.salt_size,
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
            reply_key.span(),
            cipher.type,
            cipher.key_size,
            cipher.salt_size,
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
        reply_key.span(),
        cipher.type,
        cipher.key_size,
        cipher.salt_size,
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

const bool kSsInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;

    reg.create_tcp_handler =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<acpp::Inbound> {
            auto* validator = deps.ValidatorAs<acpp::ss::Validator>();
            if (!validator || !deps.stats) {
                return nullptr;
            }
            const std::string method = req.cipher_method.empty()
                ? std::string(acpp::constants::protocol::kAes256Gcm)
                : req.cipher_method;
            return std::make_unique<acpp::proxy::shadowsocks::inbound::Handler>(
                *validator,
                *deps.stats,
                limiter,
                method);
        };

    reg.create_udp_handler =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req)
            -> std::unique_ptr<acpp::proxyman::inbound::UdpHandler> {
            auto* validator = deps.ValidatorAs<acpp::ss::Validator>();
            if (!validator || !deps.stats) {
                return nullptr;
            }
            const std::string method = req.cipher_method.empty()
                ? std::string(acpp::constants::protocol::kAes256Gcm)
                : req.cipher_method;
            return std::make_unique<acpp::proxy::shadowsocks::inbound::Handler>(
                *validator, *deps.stats, limiter, method);
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

            acpp::proxyman::inbound::UserSet result;
            result.ss_users = std::move(users);
            return result;
        };

    reg.build_users =
        [](const acpp::proxyman::inbound::BuildRequest& req,
           std::span<const acpp::proxyman::inbound::RuntimeUser> runtime_users)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            const std::string method = req.cipher_method.empty()
                ? std::string(acpp::constants::protocol::kAes256Gcm)
                : req.cipher_method;
            auto cipher_info = acpp::ss::ParseCipherMethod(method);
            if (!cipher_info) {
                LOG_WARN("Inbound '{}': unknown SS cipher '{}'", req.tag, method);
                return std::nullopt;
            }

            std::vector<acpp::proxyman::inbound::PreparedShadowsocksUser> users;
            users.reserve(runtime_users.size());
            acpp::proxyman::inbound::PreparedKeyBytes identity_key;
            const bool has_uuid_backed_2022_users =
                acpp::ss::Is2022AesCipher(cipher_info->type) &&
                std::ranges::any_of(
                    runtime_users,
                    [](const auto& user) {
                        return !user.uuid.empty() && user.password == user.uuid;
                    });
            if (has_uuid_backed_2022_users && req.ss_identity_password.empty()) {
                LOG_WARN("Inbound '{}': SS2022 UUID users require server identity key",
                         req.tag);
                return std::nullopt;
            }
            if (acpp::ss::Is2022Cipher(*cipher_info) &&
                !req.ss_identity_password.empty()) {
                identity_key = ToPreparedKey(
                    acpp::ss::BuildMasterKey(req.ss_identity_password, *cipher_info));
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
                info.cipher_type = ToPreparedCipher(cipher_info->type);
                info.key_size = cipher_info->key_size;
                info.salt_size = cipher_info->salt_size;
                const bool uuid_backed_2022_key =
                    acpp::ss::Is2022Cipher(*cipher_info) &&
                    !runtime_user.uuid.empty() &&
                    runtime_user.password == runtime_user.uuid;
                info.derived_key = ToPreparedKey(uuid_backed_2022_key
                    ? acpp::ss::Build2022UserKeyFromUuid(
                        runtime_user.uuid, *cipher_info)
                    : acpp::ss::BuildMasterKey(
                        runtime_user.password, *cipher_info));
                info.identity_key = identity_key;
                if (info.derived_key.empty()) {
                    LOG_WARN("Inbound '{}': invalid SS password for user '{}'",
                             req.tag, runtime_user.email);
                    continue;
                }
                users.push_back(std::move(info));
            }

            acpp::proxyman::inbound::UserSet result;
            result.ss_users = std::move(users);
            return result;
        };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kShadowsocks, std::move(reg));
    return true;
}();
}  // namespace
