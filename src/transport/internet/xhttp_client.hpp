#pragma once

// XHTTP 客户端分离模式（packet-up / stream-up）：下行 GET 与上行请求各自拨号，
// 组合为一条逻辑出站流。服务端对应实现位于 xhttp_session.cpp。

#include "common/asio_types.hpp"
#include "transport/internet/outbound_target_builder.hpp"

#include <array>
#include <cstddef>

// 16 字节随机数的小写 hex 字符数。
namespace transport::internet {

inline constexpr size_t kXHttpSessionIdLength = 32;
using XHttpSessionId = std::array<char, kXHttpSessionIdLength>;

// session_id 是服务端会话表的键，能被旁观者猜中就能向他人会话注入上行请求，
// 因此每次取 16 字节 CSPRNG 随机数（对齐 Xray 客户端的随机 UUID）。
[[nodiscard]] XHttpSessionId GenerateXHttpSessionId() noexcept;

// 对单个已解析候选建立裸 TCP 连接（transport_dialer.cpp 实现）；XHTTP 的下行与
// 各次上行请求与普通拨号共用这一步，绑定地址与超时语义保持一致。
[[nodiscard]] net::awaitable<DialResult> ConnectOutboundCandidate(
    net::io_context& io_context,
    const OutboundTransportTarget& target,
    const OutboundDialCandidate& candidate);

// 按候选顺序建立下行后返回组合流，上行请求在写入时才拨号；
// |target| 的 XHTTP 模式必须解析为 PacketUp 或 StreamUp，否则返回失败。
[[nodiscard]] net::awaitable<DialResult> DialXHttpSplitOutboundTransport(
    net::io_context& io_context,
    session::Context& ctx,
    const OutboundTransportTarget& target);

}  // namespace transport::internet
