#pragma once

// XHTTP 客户端分离模式（packet-up / stream-up）：下行 GET 与上行请求各自拨号，
// 组合为一条逻辑出站流。服务端对应实现位于 xhttp_session.cpp。

#include "common/asio_types.hpp"
#include "transport/outbound_target_builder.hpp"
#include <array>
#include <cstddef>

// 16 字节随机数的小写 hex 字符数。
namespace transport {

inline constexpr size_t kXHttpSessionIdLength = 32;
using XHttpSessionId = std::array<char, kXHttpSessionIdLength>;

// session_id 是服务端会话表的键，能被旁观者猜中就能向他人会话注入上行请求，
// 因此每次取 16 字节 CSPRNG 随机数（对齐 Xray 客户端的随机 UUID）。
[[nodiscard]] XHttpSessionId GenerateXHttpSessionId() noexcept;

// 对单个已解析候选建立裸 TCP 连接（transport_dialer.cpp 实现）；XHTTP 的
// 各次上行请求与普通拨号共用这一步，绑定地址与超时语义保持一致。
[[nodiscard]] net::awaitable<DialResult> ConnectOutboundCandidate(
    net::io_context& io_context,
    const OutboundDialCandidate& candidate,
    std::chrono::seconds timeout);

// 多候选竞速的裸 TCP 连接；candidate 借用自传入的候选序列，仅成功时非空。
struct OutboundCandidateConnection {
    DialResult tcp;
    const OutboundDialCandidate* candidate = nullptr;
};

// 对至少两个已解析候选按 RFC 8305 Happy Eyeballs 竞速建立裸 TCP 连接
// （transport_dialer.cpp 实现）：从首个候选的地址族起交替两族，每 250 ms 或
// 前一尝试失败时发起下一尝试，整场竞速受同一个 timeout 约束；首个建连成功者
// 胜出，其余尝试取消并收束后才返回。普通拨号与 XHTTP 下行共用这一步。
[[nodiscard]] net::awaitable<OutboundCandidateConnection> RaceOutboundCandidates(
    net::io_context& io_context,
    common::Context& ctx,
    std::span<const OutboundDialCandidate> candidates,
    std::chrono::seconds timeout);

// 下行按候选竞速建连后返回组合流，上行请求在写入时才拨号，且与下行共用
// 同一目标时沿用下行胜出的候选；|target| 的 XHTTP 模式必须解析为 PacketUp
// 或 StreamUp，否则返回失败。
[[nodiscard]] net::awaitable<DialResult> DialXHttpSplitOutboundTransport(
    net::io_context& io_context,
    common::Context& ctx,
    const OutboundTransportTarget& target);

}  // namespace transport
