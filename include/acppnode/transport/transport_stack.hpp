#pragma once

#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/stream_settings.hpp"
#include <expected>
#include <memory>

namespace acpp {

using TransportBuildResult = std::expected<std::unique_ptr<AsyncStream>, ErrorCode>;

// ============================================================================
// TransportStack - 传输层堆叠构建器
//
// 职责：根据 StreamSettings 将原始 TCP 流包装成最终传输流。
// 协议层（VMess/Trojan）调用 ParseStream() 前，传入的流已经是处理完
// TLS 握手、WS 升级之后的字节流，协议层对此一无所知。
//
// 入站堆叠顺序（服务端）：
//   raw TCP → [TlsStream server] → [WsStream server] → 协议层
//
// 出站堆叠顺序（客户端）：
//   raw TCP → [TlsStream client] → [WsStream client] → 协议层
// ============================================================================
class TransportStack {
public:
    // -----------------------------------------------------------------------
    // 构建入站传输栈（服务端模式）
    //
    // @param raw          原始 TCP 流（已 accept 但未握手）
    // @param s            StreamSettings（协议+安全配置）
    // @param out_real_ip  若非 nullptr，WS 握手成功且 WsConfig::real_ip_header
    //                     已配置时，写入提取到的真实客户端 IP（否则保持不变）
    // @param trace_conn_id 若非 0，传输层 trace 日志使用该连接号，便于与上层会话日志关联
    // @return             成功返回完成 TLS 握手、WS 升级后的流；失败返回 ErrorCode
    // -----------------------------------------------------------------------
    static cobalt::task<TransportBuildResult> BuildInbound(
        std::unique_ptr<AsyncStream> raw,
        const StreamSettings& s,
        std::string* out_real_ip = nullptr,
        uint64_t trace_conn_id = 0);

    // -----------------------------------------------------------------------
    // 构建出站传输栈（客户端模式）
    //
    // @param raw         原始 TCP 流（已 connect）
    // @param s           StreamSettings
    // @param server_name TLS SNI 服务器名（留空则使用 s.tls.server_name）
    // @return            成功返回完成 TLS 握手、WS 握手后的流；失败返回 ErrorCode
    // -----------------------------------------------------------------------
    static cobalt::task<TransportBuildResult> BuildOutbound(
        std::unique_ptr<AsyncStream> raw,
        const StreamSettings& s,
        const std::string& server_name = "");
};

}  // namespace acpp
