#include "acppnode/protocol/shadowsocks/ss_udp_inbound.hpp"
#include "acppnode/protocol/shadowsocks/ss_udp.hpp"
#include "acppnode/infra/log.hpp"

namespace acpp::ss {

SsUdpInboundHandler::SsUdpInboundHandler(SsUserManager&       user_manager,
                                         SsCipherInfo         cipher_info,
                                         ConnectionLimiterPtr limiter)
    : user_manager_(user_manager)
    , cipher_info_(cipher_info)
    , limiter_(std::move(limiter)) {}

std::optional<UdpInboundDecodeResult> SsUdpInboundHandler::Decode(
    std::string_view tag,
    std::string_view client_ip,
    const uint8_t*   data,
    size_t           len)
{
    const std::string tag_str(tag);
    const std::string ip_str(client_ip);

    // ── 1. ban 检查（只读，不增加连接计数，避免 UDP 无对应 Release 的问题）──
    if (limiter_ && limiter_->GetLimiter().IsBanned(tag_str, ip_str)) {
        LOG_ACCESS_FMT("{} from {} rejected ip_banned [{}] (udp)", LogLocalNow(), ip_str, tag_str);
        return std::nullopt;
    }

    // ── 2. 多用户 HKDF+AEAD 解密 ────────────────────────────────────────────
    auto snapshot = user_manager_.GetSnapshot();
    auto users = snapshot->GetTagUserList(tag_str);
    if (!users || users->empty()) return std::nullopt;

    auto decoded = DecodeUdpPacket(
        data, len, *users,
        cipher_info_.type, cipher_info_.key_size, cipher_info_.salt_size);

    // ── 3. 认证失败记录 ──────────────────────────────────────────────────────
    if (!decoded) {
        if (limiter_) limiter_->OnAuthFail(tag_str, ip_str);
        return std::nullopt;
    }

    const SsUserInfo& user = *(*users)[decoded->user_index];

    // ── 4. 构建回包编码函数（值捕获密钥 + 密码套件，生命周期安全）────────────
    std::vector<uint8_t> reply_key = user.derived_key;
    const SsCipherInfo   reply_ci  = cipher_info_;

    UdpInboundDecodeResult result;
    result.target       = std::move(decoded->target);
    result.payload      = std::move(decoded->payload);
    result.user_id      = user.user_id;
    result.user_email   = user.email;
    result.speed_limit  = user.speed_limit;
    result.encode_reply = [reply_key, reply_ci](
                              const TargetAddress& tgt,
                              const uint8_t* payload,
                              size_t payload_len,
                              uint8_t* output,
                              size_t output_size
                          ) -> size_t {
        return EncodeUdpPacketTo(
            tgt, payload, payload_len,
            reply_key, reply_ci.type, reply_ci.key_size, reply_ci.salt_size,
            output, output_size);
    };

    return result;
}

std::unique_ptr<SsUdpInboundHandler> CreateSsUdpInboundHandler(
    SsUserManager&       user_manager,
    SsCipherInfo         cipher_info,
    ConnectionLimiterPtr limiter)
{
    return std::make_unique<SsUdpInboundHandler>(
        user_manager, std::move(cipher_info), std::move(limiter));
}

}  // namespace acpp::ss
