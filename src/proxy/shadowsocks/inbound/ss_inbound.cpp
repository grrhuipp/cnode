#include "acppnode/proxy/shadowsocks/inbound/ss_inbound.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "../server.hpp"
#include "../ss_udp.hpp"
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
#include <utility>

namespace acpp {

namespace {

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

    [[nodiscard]] const ss::KeyBytes& ReplyKey() const noexcept {
        return reply_key_;
    }

    [[nodiscard]] const ss::SsCipherInfo& CipherInfo() const noexcept {
        return cipher_info_;
    }

private:
    ss::KeyBytes reply_key_;
    ss::SsCipherInfo cipher_info_;
};

[[nodiscard]] const ShadowsocksUdpResponseContext* AsShadowsocksUdpContext(
    const proxyman::inbound::UdpResponseContext& context) noexcept {
    return dynamic_cast<const ShadowsocksUdpResponseContext*>(&context);
}

[[nodiscard]] bool AppendSpanToMultiBuffer(std::span<const uint8_t> data,
                                           buf::MultiBuffer& out) {
    size_t offset = 0;
    while (offset < data.size()) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            return false;
        }
        const size_t n = std::min(data.size() - offset,
                                  static_cast<size_t>(buffer->Available()));
        std::memcpy(buffer->Tail().data(), data.data() + offset, n);
        buffer->Produce(static_cast<uint32_t>(n));
        out.push_back(buffer.release());
        offset += n;
    }
    return true;
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
            if (limiter_ && ban_tracking_enabled_) {
                limiter_->OnAuthFailTracked(tag, client_ip);
            }
            stats_->OnError();
        } else {
            LOG_CONN_FAIL_CTX(ctx, "[SS][{}] ReadTCPSession failed from {}: {}",
                              tag, client_ip, ErrorCodeToString(error));
        }
        co_return fail(error);
    }

    const ss::SsUserInfo* matched = session_result->user;
    if (!matched) {
        LOG_CONN_FAIL("[{}] SS auth failed from {}", tag, client_ip);
        if (limiter_ && ban_tracking_enabled_) {
            limiter_->OnAuthFailTracked(tag, client_ip);
        }
        stats_->OnError();
        co_return fail(ErrorCode::PROTOCOL_AUTH_FAILED);
    }

    // ── 6. 填充上下文 ─────────────────────────────────────────────────────────
    ctx.inbound.user_id = matched->user_id;
    ctx.inbound.user_email = matched->email;
    ctx.content.speed_limit = matched->speed_limit;

    // 在线追踪：认证成功后由当前协议 Process 的本地 guard 解注册。
    int64_t uid = matched->user_id;
    if (!validator_.CanAcceptDevice(tag, uid, ctx.inbound.source_ip, matched->device_limit)) {
        LOG_ACCESS_FMT("{} from {}:{} rejected device_limit [{}] user={} limit={} online_devices={}",
            FormatTimestamp(ctx.accept_time_us),
            ctx.inbound.source_ip, ctx.inbound.source_port, tag, ctx.inbound.user_email,
            matched->device_limit,
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
    auto response_writer_result = ss::WriteTCPResponse(*matched, *stream);
    if (!request_reader) {
        co_return fail(ErrorCode::RESOURCE_EXHAUSTED);
    }
    if (!response_writer_result) {
        co_return fail(response_writer_result.error());
    }
    auto response_writer = std::move(response_writer_result.value());

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
        if (limiter_ && ban_tracking_enabled_) {
            limiter_->OnAuthFailTracked(tag, client_ip);
        }
        return std::nullopt;
    }

    const ss::SsUserInfo& user = users[decoded->user_index];

    proxyman::inbound::UdpDecodeResult result;
    result.target = std::move(decoded->target);
    result.payload = std::move(decoded->payload);
    result.user_id = user.user_id;
    result.user_email = user.email;
    result.speed_limit = user.speed_limit;
    result.response_context = std::make_shared<ShadowsocksUdpResponseContext>(
        user.derived_key,
        cipher_info_);
    return result;
}

buf::MultiBuffer proxy::shadowsocks::inbound::Handler::EncodeUdpResponse(
    UDPPacketView packet,
    const proxyman::inbound::UdpResponseContext& response_context) const {
    const auto* ss_context = AsShadowsocksUdpContext(response_context);
    if (!ss_context) {
        return {};
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
    if (!AppendSpanToMultiBuffer(scratch, payload)) {
        return {};
    }
    return payload;
}

}  // namespace acpp

// ============================================================================
// 自注册（静态初始化）
// ============================================================================
namespace {
const bool kSsInboundRegistered = [] {
    acpp::proxyman::inbound::ProxyRegistration reg;

    reg.create_tcp_handler =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req) -> std::unique_ptr<acpp::Inbound> {
            if (!deps.ss_validator || !deps.stats) {
                return nullptr;
            }
            const std::string method = req.cipher_method.empty()
                ? std::string(acpp::constants::protocol::kAes256Gcm)
                : req.cipher_method;
            return std::make_unique<acpp::proxy::shadowsocks::inbound::Handler>(
                *deps.ss_validator,
                *deps.stats,
                limiter,
                method);
        };

    reg.create_udp_handler =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           acpp::ConnectionLimiterPtr limiter,
           const acpp::proxyman::inbound::BuildRequest& req)
            -> std::unique_ptr<acpp::proxyman::inbound::UdpHandler> {
            if (!deps.ss_validator || !deps.stats) {
                return nullptr;
            }
            const std::string method = req.cipher_method.empty()
                ? std::string(acpp::constants::protocol::kAes256Gcm)
                : req.cipher_method;
            return std::make_unique<acpp::proxy::shadowsocks::inbound::Handler>(
                *deps.ss_validator, *deps.stats, limiter, method);
        };

    reg.build_static_users =
        [](std::string_view tag, const acpp::StaticUserConfig& config)
            -> std::optional<acpp::proxyman::inbound::UserSet> {
            auto cipher_info = acpp::ss::ParseCipherMethod(config.method);
            if (!cipher_info) {
                LOG_WARN("Static inbound '{}': unknown SS cipher '{}'", tag, config.method);
                return std::nullopt;
            }

            std::vector<acpp::ss::SsUserInfo> users;
            int64_t synthetic_uid = -1;

            for (const auto& client : config.clients) {
                if (client.password.empty()) {
                    continue;
                }
                acpp::ss::SsUserInfo info;
                info.password    = client.password;
                info.user_id     = synthetic_uid--;
                info.cipher_type = cipher_info->type;
                info.key_size    = cipher_info->key_size;
                info.salt_size   = cipher_info->salt_size;
                info.derived_key = acpp::ss::DeriveKey(client.password, cipher_info->key_size);
                info.email       = client.email;
                users.push_back(std::move(info));
            }

            acpp::proxyman::inbound::UserSet result;
            result.ss_users = std::move(users);
            return result;
        };

    reg.apply_worker_users =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           std::string_view tag,
           const acpp::proxyman::inbound::UserSet& users) {
            if (!deps.ss_validator) return;
            deps.ss_validator->UpdateUsersForTag(std::string(tag), users.ss_users);
        };

    reg.add_worker_users =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           std::string_view tag,
           const acpp::proxyman::inbound::UserSet& users) {
            if (!deps.ss_validator) return;
            deps.ss_validator->AddUsersForTag(std::string(tag), users.ss_users);
        };

    reg.remove_worker_users =
        [](const acpp::proxyman::inbound::ProtocolDeps& deps,
           std::string_view tag,
           const acpp::proxyman::inbound::UserSet& users) {
            if (!deps.ss_validator) return;
            deps.ss_validator->RemoveUsersForTag(std::string(tag), users.ss_users);
        };

    reg.clear_worker_users = [](const acpp::proxyman::inbound::ProtocolDeps& deps, std::string_view tag) {
        if (deps.ss_validator) {
            deps.ss_validator->UpdateUsersForTag(std::string(tag), {});
        }
    };

    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kShadowsocks, std::move(reg));
    return true;
}();
}  // namespace
