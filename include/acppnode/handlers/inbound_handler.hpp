#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/app/udp_framer.hpp"

#include <expected>
#include <string_view>
#include <vector>
#include <memory>

namespace acpp {

using InboundWrapResult = std::expected<std::unique_ptr<AsyncStream>, ErrorCode>;

// ============================================================================
// ParsedAction - 协议解析结果（IInboundHandler::ParseStream 的返回值）
//
// 协议层解析完头部后，填充此结构并返回给 SessionHandler。
// SessionHandler 根据 target 做路由、拨号，再调用 IOutboundHandler。
// ============================================================================
struct ParsedAction {
    TargetAddress target;                  // 解析出的目标地址
    Network       network = Network::TCP;  // TCP 或 UDP

    // 协议头之后紧跟的应用层数据（可能为空）
    // 例如：Trojan 头后面的首个 TCP 数据包
    std::vector<uint8_t> initial_payload;

    // 是否已解密（Shadowsocks 等在解析时同步解密）
    bool payload_decrypted = false;

    // UDP 帧编解码工厂（由协议层提供，SessionHandler 无需协议分支）
    // 为空时，SessionHandler 回退到 PayloadOnlyUdpFramer(target)。
    unique_function<UdpFramer()> make_udp_framer;
};

// ============================================================================
// IInboundHandler - 入站协议处理器接口（代理层）
//
// 职责：纯协议解析 + 认证，不涉及传输层（TLS/WS 由 SessionHandler 负责）。
//
// 调用顺序（由 SessionHandler 保证）：
//   1. ParseStream(stream, ctx)    → ParsedAction（含目标地址）
//   2. WrapStream(stream, ctx)     → 加密/帧装饰后的流（VMess 需要，Trojan 透传）
//
// 协议实现示例：
//   - VMessInboundHandler: ParseStream 解析 AEAD 头，WrapStream 返回 VMessServerStream
//   - TrojanInboundHandler: ParseStream 解析 SHA224+目标，WrapStream 透传原流
// ============================================================================
class IInboundHandler {
public:
    virtual ~IInboundHandler() noexcept = default;

    // -----------------------------------------------------------------------
    // 从已建立的传输流中解析协议头
    //
    // @param stream  已完成 TLS/WS 等传输层握手的字节流
    // @param ctx     会话上下文（用于填充用户信息、错误记录）
    // @return        成功返回 ParsedAction；失败返回 std::unexpected(ErrorCode)
    // -----------------------------------------------------------------------
    virtual cobalt::task<std::expected<ParsedAction, ErrorCode>> ParseStream(
        AsyncStream& stream,
        SessionContext& ctx) = 0;

    // -----------------------------------------------------------------------
    // 包装流以应用协议加密/帧格式
    //
    // 对于无加密协议（Trojan），直接返回原流。
    // 对于 VMess，返回 VMessServerAsyncStream（处理 chunk 加密）。
    //
    // 与 IOutboundHandler::WrapStream 保持对称，统一返回 cobalt::task，
    // 使协议层未来可按需引入异步初始化逻辑（如延迟密钥协商）。
    //
    // @param stream  ParseStream 使用过的同一流（ownership 转移）
    // @param ctx     会话上下文
    // @return        success: wrapped stream；failure: ErrorCode
    // -----------------------------------------------------------------------
    virtual cobalt::task<InboundWrapResult> WrapStream(
        std::unique_ptr<AsyncStream> stream,
        SessionContext& ctx) = 0;
};

// ============================================================================
// InboundHandlerBase - 入站处理器通用基类
//
// 所有协议入站处理器继承此类，而非直接实现 IInboundHandler。
// 提供三类公共能力：
//   1. OnAuthFail()    — 认证失败的统一处理（通知限速器 + 计数）
//   2. ReadHandshakeBuffer() — 单次 AsyncRead 握手首包读取（VMess/Trojan 模式）
//   3. FillUserInfo()  — 认证成功后填充用户信息到会话上下文
//
// 握手超时由底层 TcpStream 的空闲超时统一处理（SessionHandler 在 BuildInbound
// 前设置 handshake 超时，ParseStream 期间继续生效），无需协议层额外守卫。
// ============================================================================
class InboundHandlerBase : public IInboundHandler {
public:
    virtual ~InboundHandlerBase() noexcept = default;

protected:
    // 公共依赖（所有协议入站处理器都需要）
    StatsShard&          stats_;
    ConnectionLimiterPtr limiter_;

    InboundHandlerBase(StatsShard& stats, ConnectionLimiterPtr limiter) noexcept
        : stats_(stats), limiter_(std::move(limiter)) {}

    // -----------------------------------------------------------------------
    // RejectBanned — IP 封禁检查（TCP 入站协议握手前调用）
    //
    // 若 IP 在封禁期内，写入 access.log 并返回 true，调用方 co_return BLOCKED。
    // -----------------------------------------------------------------------
    [[nodiscard]] bool RejectBanned(const SessionContext& ctx) const noexcept {
        if (!limiter_ || !limiter_->GetLimiter().IsBanned(ctx.inbound_tag, ctx.client_ip))
            return false;
        LOG_ACCESS_FMT("{} from {}:{} rejected ip_banned [{}]",
            FormatTimestamp(ctx.accept_time_us),
            ctx.client_ip, ctx.src_addr.port(), ctx.inbound_tag);
        return true;
    }

    // -----------------------------------------------------------------------
    // OnAuthFail — 认证失败的统一处理
    //
    // 通知限速器（触发封锁计数）并更新错误统计。
    // 调用方负责在调用前写日志，之后 co_return 错误码。
    // -----------------------------------------------------------------------
    void OnAuthFail(const std::string& tag, const std::string& client_ip) noexcept {
        if (limiter_) limiter_->OnAuthFail(tag, client_ip);
        stats_.OnError();
    }

    // -----------------------------------------------------------------------
    // FillUserInfo — 认证成功后填充用户信息到会话上下文
    // -----------------------------------------------------------------------
    static void FillUserInfo(SessionContext& ctx, int64_t user_id,
                             std::string_view email, uint64_t speed_limit) noexcept {
        ctx.user_id     = user_id;
        ctx.user_email  = std::string(email);
        ctx.speed_limit = speed_limit;
    }

    // -----------------------------------------------------------------------
    // ReadHandshakeInto — 读取握手首包到调用方提供的缓冲区（零堆分配）
    //
    // 适用于高并发场景的热路径：调用方可提供栈上 std::array 作为临时缓冲，
    // 避免每连接为首包解析分配 std::vector。
    // -----------------------------------------------------------------------
    cobalt::task<std::expected<size_t, ErrorCode>>
    ReadHandshakeInto(AsyncStream& stream, std::span<uint8_t> buffer,
                      const SessionContext& ctx, std::string_view proto_name) {
        if (buffer.empty()) {
            co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }

        size_t n = 0;
        try {
            n = co_await stream.AsyncRead(net::buffer(buffer.data(), buffer.size()));
        } catch (const boost::system::system_error&) {
            if (stream.ConsumePhaseDeadline()) {
                LOG_CONN_FAIL_CTX(ctx, "[{}][{}] handshake phase deadline from {}",
                                  proto_name, ctx.inbound_tag, ctx.client_ip);
                co_return std::unexpected(ErrorCode::TIMEOUT);
            }
            LOG_CONN_FAIL_CTX(ctx, "[{}][{}] handshake read failed from {}",
                              proto_name, ctx.inbound_tag, ctx.client_ip);
            co_return std::unexpected(ErrorCode::SOCKET_READ_FAILED);
        }
        if (n == 0 && stream.ConsumePhaseDeadline()) {
            LOG_CONN_FAIL_CTX(ctx, "[{}][{}] handshake phase deadline from {}",
                              proto_name, ctx.inbound_tag, ctx.client_ip);
            co_return std::unexpected(ErrorCode::TIMEOUT);
        }
        if (n == 0 && stream.ConsumeIdleTimeout()) {
            LOG_CONN_FAIL_CTX(ctx, "[{}][{}] handshake idle timeout from {}",
                              proto_name, ctx.inbound_tag, ctx.client_ip);
            co_return std::unexpected(ErrorCode::TIMEOUT);
        }
        if (n == 0) co_return std::unexpected(ErrorCode::SOCKET_EOF);
        co_return n;
    }

    // -----------------------------------------------------------------------
    // ReadHandshakeBuffer — 读取握手首包（单次 AsyncRead 模式）
    //
    // 适用于 VMess / Trojan 这类"一次 AsyncRead 拿到完整握手帧"的协议。
    // SS 使用多次定长读取（ReadFull），不使用此接口。
    //
    // 超时由底层 TcpStream 空闲超时保护：超时后读操作会提前结束，
    // 可通过 stream.ConsumeIdleTimeout() 区分"超时"和"对端 EOF"。
    //
    // 成功：返回 {data, n_bytes}。
    // 失败：返回 SOCKET_READ_FAILED / SOCKET_EOF。
    // -----------------------------------------------------------------------
    cobalt::task<std::expected<std::pair<std::vector<uint8_t>, size_t>, ErrorCode>>
    ReadHandshakeBuffer(AsyncStream& stream, size_t buf_size,
                        const SessionContext& ctx, std::string_view proto_name) {
        std::vector<uint8_t> buffer(buf_size);
        auto read = co_await ReadHandshakeInto(
            stream,
            std::span<uint8_t>(buffer.data(), buffer.size()),
            ctx,
            proto_name);
        if (!read) {
            co_return std::unexpected(read.error());
        }
        co_return std::make_pair(std::move(buffer), *read);
    }
};

}  // namespace acpp
