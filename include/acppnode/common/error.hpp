#pragma once

#include <cstdint>
#include <string_view>
#include <boost/system/error_code.hpp>

namespace acpp {

// ============================================================================
// 错误码定义
// ============================================================================
enum class ErrorCode : int {
    // 成功
    OK = 0,
    SUCCESS = 0,  // 别名

    // 通用错误 (1-99)
    TIMEOUT = 1,
    CANCELLED = 2,
    INTERNAL = 3,
    INVALID_ARGUMENT = 4,
    NOT_FOUND = 5,
    ALREADY_EXISTS = 6,
    PERMISSION_DENIED = 7,
    RESOURCE_EXHAUSTED = 8,
    NOT_SUPPORTED = 9,
    CONNECTION_CLOSED = 10,

    // Socket/Network 错误 (100-199)
    SOCKET_CREATE_FAILED = 100,
    SOCKET_BIND_FAILED = 101,
    SOCKET_LISTEN_FAILED = 102,
    SOCKET_CONNECT_FAILED = 103,
    SOCKET_READ_FAILED = 104,
    SOCKET_WRITE_FAILED = 105,
    SOCKET_CLOSED = 106,
    SOCKET_EOF = 107,
    NETWORK_BIND_FAILED = 110,
    NETWORK_IO_ERROR = 111,

    // 协议错误 (200-299)
    PROTOCOL_INVALID_VERSION = 200,
    PROTOCOL_INVALID_COMMAND = 201,
    PROTOCOL_INVALID_ADDRESS = 202,
    PROTOCOL_AUTH_FAILED = 203,
    PROTOCOL_DECODE_FAILED = 204,
    PROTOCOL_ENCODE_FAILED = 205,
    PROTOCOL_UNSUPPORTED = 206,

    // 路由错误 (300-399)
    ROUTER_NO_MATCH = 300,
    ROUTER_OUTBOUND_NOT_FOUND = 301,
    ROUTER_INVALID_RULE = 302,
    BLOCKED = 303,  // 被黑洞/规则阻止

    // 拨号错误 (400-499)
    DIAL_DNS_FAILED = 400,
    DIAL_CONNECT_FAILED = 401,
    DIAL_TIMEOUT = 402,
    DIAL_REFUSED = 403,
    DIAL_NETWORK_UNREACHABLE = 404,
    DIAL_HOST_UNREACHABLE = 405,
    OUTBOUND_CONNECTION_FAILED = 406,

    // Relay 错误 (500-549)
    RELAY_READ_FAILED = 500,
    RELAY_WRITE_FAILED = 501,
    RELAY_TIMEOUT = 502,
    RELAY_CLIENT_CLOSED = 503,
    RELAY_TARGET_CLOSED = 504,

    // Sniff 错误 (550-599)
    SNIFF_FAILED = 550,
    SNIFF_TIMEOUT = 551,
    SNIFF_UNSUPPORTED = 552,
    SNIFF_INCOMPLETE = 553,

    // TLS 错误 (600-699)
    TLS_HANDSHAKE_FAILED = 600,
    TLS_CERT_INVALID = 601,
    TLS_VERSION_MISMATCH = 602,
    TLS_VERIFY_FAILED = 603,
    TLS_ALERT_RECEIVED = 604,

    // VMess 错误 (700-799)
    VMESS_INVALID_USER = 700,
    VMESS_INVALID_REQUEST = 701,
    VMESS_TIMESTAMP_EXPIRED = 702,
    VMESS_REPLAY_ATTACK = 703,
    VMESS_CHECKSUM_MISMATCH = 704,
    VMESS_INVALID_RESPONSE = 705,

    // DNS 错误 (800-899)
    DNS_RESOLVE_FAILED = 800,
    DNS_TIMEOUT = 801,
    DNS_NO_RECORD = 802,
    DNS_SERVER_FAILED = 803,
    DNS_FORMAT_ERROR = 804,
    DNS_REFUSED = 805,

    // 面板错误 (900-999)
    PANEL_API_FAILED = 900,
    PANEL_AUTH_FAILED = 901,
    PANEL_NODE_NOT_FOUND = 902,
    PANEL_USER_NOT_FOUND = 903,
    PANEL_USER_DISABLED = 904,
    PANEL_TRAFFIC_EXCEEDED = 905,
    PANEL_RATE_LIMITED = 906,
    PANEL_INVALID_RESPONSE = 907,
    PANEL_NETWORK_ERROR = 908,
};

// 错误码转字符串
constexpr std::string_view ErrorCodeToString(ErrorCode code) {
    switch (code) {
        case ErrorCode::OK: return "OK";
        case ErrorCode::TIMEOUT: return "TIMEOUT";
        case ErrorCode::CANCELLED: return "CANCELLED";
        case ErrorCode::INTERNAL: return "INTERNAL";
        case ErrorCode::INVALID_ARGUMENT: return "INVALID_ARGUMENT";
        case ErrorCode::NOT_FOUND: return "NOT_FOUND";
        case ErrorCode::ALREADY_EXISTS: return "ALREADY_EXISTS";
        case ErrorCode::PERMISSION_DENIED: return "PERMISSION_DENIED";
        case ErrorCode::RESOURCE_EXHAUSTED: return "RESOURCE_EXHAUSTED";
        case ErrorCode::NOT_SUPPORTED: return "NOT_SUPPORTED";
        case ErrorCode::CONNECTION_CLOSED: return "CONNECTION_CLOSED";
        
        case ErrorCode::SOCKET_CREATE_FAILED: return "SOCKET_CREATE_FAILED";
        case ErrorCode::SOCKET_BIND_FAILED: return "SOCKET_BIND_FAILED";
        case ErrorCode::SOCKET_LISTEN_FAILED: return "SOCKET_LISTEN_FAILED";
        case ErrorCode::SOCKET_CONNECT_FAILED: return "SOCKET_CONNECT_FAILED";
        case ErrorCode::SOCKET_READ_FAILED: return "SOCKET_READ_FAILED";
        case ErrorCode::SOCKET_WRITE_FAILED: return "SOCKET_WRITE_FAILED";
        case ErrorCode::SOCKET_CLOSED: return "SOCKET_CLOSED";
        case ErrorCode::SOCKET_EOF: return "SOCKET_EOF";
        case ErrorCode::NETWORK_BIND_FAILED: return "NETWORK_BIND_FAILED";
        case ErrorCode::NETWORK_IO_ERROR: return "NETWORK_IO_ERROR";
        
        case ErrorCode::PROTOCOL_INVALID_VERSION: return "PROTOCOL_INVALID_VERSION";
        case ErrorCode::PROTOCOL_INVALID_COMMAND: return "PROTOCOL_INVALID_COMMAND";
        case ErrorCode::PROTOCOL_INVALID_ADDRESS: return "PROTOCOL_INVALID_ADDRESS";
        case ErrorCode::PROTOCOL_AUTH_FAILED: return "PROTOCOL_AUTH_FAILED";
        case ErrorCode::PROTOCOL_DECODE_FAILED: return "PROTOCOL_DECODE_FAILED";
        case ErrorCode::PROTOCOL_ENCODE_FAILED: return "PROTOCOL_ENCODE_FAILED";
        case ErrorCode::PROTOCOL_UNSUPPORTED: return "PROTOCOL_UNSUPPORTED";
        
        case ErrorCode::ROUTER_NO_MATCH: return "ROUTER_NO_MATCH";
        case ErrorCode::ROUTER_OUTBOUND_NOT_FOUND: return "ROUTER_OUTBOUND_NOT_FOUND";
        case ErrorCode::ROUTER_INVALID_RULE: return "ROUTER_INVALID_RULE";
        case ErrorCode::BLOCKED: return "BLOCKED";
        
        case ErrorCode::DIAL_DNS_FAILED: return "DIAL_DNS_FAILED";
        case ErrorCode::DIAL_CONNECT_FAILED: return "DIAL_CONNECT_FAILED";
        case ErrorCode::DIAL_TIMEOUT: return "DIAL_TIMEOUT";
        case ErrorCode::DIAL_REFUSED: return "DIAL_REFUSED";
        case ErrorCode::DIAL_NETWORK_UNREACHABLE: return "DIAL_NETWORK_UNREACHABLE";
        case ErrorCode::DIAL_HOST_UNREACHABLE: return "DIAL_HOST_UNREACHABLE";
        case ErrorCode::OUTBOUND_CONNECTION_FAILED: return "OUTBOUND_CONNECTION_FAILED";
        
        case ErrorCode::RELAY_READ_FAILED: return "RELAY_READ_FAILED";
        case ErrorCode::RELAY_WRITE_FAILED: return "RELAY_WRITE_FAILED";
        case ErrorCode::RELAY_TIMEOUT: return "RELAY_TIMEOUT";
        case ErrorCode::RELAY_CLIENT_CLOSED: return "RELAY_CLIENT_CLOSED";
        case ErrorCode::RELAY_TARGET_CLOSED: return "RELAY_TARGET_CLOSED";
        
        case ErrorCode::SNIFF_FAILED: return "SNIFF_FAILED";
        case ErrorCode::SNIFF_TIMEOUT: return "SNIFF_TIMEOUT";
        case ErrorCode::SNIFF_UNSUPPORTED: return "SNIFF_UNSUPPORTED";
        case ErrorCode::SNIFF_INCOMPLETE: return "SNIFF_INCOMPLETE";
        
        case ErrorCode::TLS_HANDSHAKE_FAILED: return "TLS_HANDSHAKE_FAILED";
        case ErrorCode::TLS_CERT_INVALID: return "TLS_CERT_INVALID";
        case ErrorCode::TLS_VERSION_MISMATCH: return "TLS_VERSION_MISMATCH";
        case ErrorCode::TLS_VERIFY_FAILED: return "TLS_VERIFY_FAILED";
        case ErrorCode::TLS_ALERT_RECEIVED: return "TLS_ALERT_RECEIVED";
        
        case ErrorCode::VMESS_INVALID_USER: return "VMESS_INVALID_USER";
        case ErrorCode::VMESS_INVALID_REQUEST: return "VMESS_INVALID_REQUEST";
        case ErrorCode::VMESS_TIMESTAMP_EXPIRED: return "VMESS_TIMESTAMP_EXPIRED";
        case ErrorCode::VMESS_REPLAY_ATTACK: return "VMESS_REPLAY_ATTACK";
        case ErrorCode::VMESS_CHECKSUM_MISMATCH: return "VMESS_CHECKSUM_MISMATCH";
        case ErrorCode::VMESS_INVALID_RESPONSE: return "VMESS_INVALID_RESPONSE";
        
        case ErrorCode::DNS_RESOLVE_FAILED: return "DNS_RESOLVE_FAILED";
        case ErrorCode::DNS_TIMEOUT: return "DNS_TIMEOUT";
        case ErrorCode::DNS_NO_RECORD: return "DNS_NO_RECORD";
        case ErrorCode::DNS_SERVER_FAILED: return "DNS_SERVER_FAILED";
        case ErrorCode::DNS_FORMAT_ERROR: return "DNS_FORMAT_ERROR";
        case ErrorCode::DNS_REFUSED: return "DNS_REFUSED";
        
        case ErrorCode::PANEL_API_FAILED: return "PANEL_API_FAILED";
        case ErrorCode::PANEL_AUTH_FAILED: return "PANEL_AUTH_FAILED";
        case ErrorCode::PANEL_NODE_NOT_FOUND: return "PANEL_NODE_NOT_FOUND";
        case ErrorCode::PANEL_USER_NOT_FOUND: return "PANEL_USER_NOT_FOUND";
        case ErrorCode::PANEL_USER_DISABLED: return "PANEL_USER_DISABLED";
        case ErrorCode::PANEL_TRAFFIC_EXCEEDED: return "PANEL_TRAFFIC_EXCEEDED";
        case ErrorCode::PANEL_RATE_LIMITED: return "PANEL_RATE_LIMITED";
        case ErrorCode::PANEL_INVALID_RESPONSE: return "PANEL_INVALID_RESPONSE";
        case ErrorCode::PANEL_NETWORK_ERROR: return "PANEL_NETWORK_ERROR";
        
        default: return "UNKNOWN";
    }
}

// 判断是否为成功
[[nodiscard]]
constexpr bool IsOk(ErrorCode code) {
    return code == ErrorCode::OK;
}

// 判断是否为超时相关错误
[[nodiscard]]
constexpr bool IsTimeout(ErrorCode code) {
    return code == ErrorCode::TIMEOUT ||
           code == ErrorCode::DIAL_TIMEOUT ||
           code == ErrorCode::RELAY_TIMEOUT ||
           code == ErrorCode::SNIFF_TIMEOUT ||
           code == ErrorCode::DNS_TIMEOUT;
}

// 判断是否为连接关闭相关错误
[[nodiscard]]
constexpr bool IsConnectionClosed(ErrorCode code) {
    return code == ErrorCode::SOCKET_CLOSED ||
           code == ErrorCode::SOCKET_EOF ||
           code == ErrorCode::RELAY_CLIENT_CLOSED ||
           code == ErrorCode::RELAY_TARGET_CLOSED;
}

// 从 Boost.Asio error_code 映射到 ErrorCode
ErrorCode MapAsioError(const boost::system::error_code& ec);

}  // namespace acpp
