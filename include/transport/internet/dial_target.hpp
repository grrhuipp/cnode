#pragma once

#include "common/asio_types.hpp"
#include "common/defaults.hpp"
#include "common/allocator.hpp"
#include "transport/internet/stream_settings.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>


class SslContext;

// 单个候选拨号地址
struct OutboundDialCandidate {
    tcp::endpoint endpoint;
    std::optional<net::ip::address> bind_local;  // 可按候选 IP 单独决定绑定地址
};

// 出站传输目标（仅携带已解析拨号候选）：transport/internet 的拨号输入，
// 不属于 proxy 出站协议壳。
struct OutboundTransportTarget {
    std::optional<OutboundDialCandidate> single_candidate; // 单个已解析候选，避免每连接 vector 分配
    memory::ThreadLocalVector<OutboundDialCandidate> candidates; // 已解析候选地址（按优先级排序）
    std::string_view tls_server_name;               // TLS SNI（冷路径配置视图，可空）
    memory::ThreadLocalString ws_host;              // HTTP Host/authority（WS、HTTPUpgrade、gRPC、XHTTP，已按端口格式化）
    const StreamSettings* stream_settings = nullptr; // 必填：冷路径准备好的传输层组合配置
    SslContext* security_context = nullptr;          // TLS/REALITY 时必填：出站 handler 的 Worker 私有上下文
    std::chrono::seconds timeout{defaults::kDialTimeout};

    // XHTTP packet-up / stream-up 可用独立下行入口；仅保存已解析候选和不可变配置视图。
    std::shared_ptr<const OutboundTransportTarget> xhttp_download_target;
};

