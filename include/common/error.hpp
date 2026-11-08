#pragma once

#include <exception>
#include <string>
#include <string_view>

#include "common/asio_types.hpp"


// Match only actual asynchronous-operation cancellation. A real failure that
// races shutdown must retain its identity and must not be reported as success.
[[nodiscard]] inline bool IsOperationCancelled(const std::exception_ptr& failure) noexcept {
    if (!failure) return false;
    try {
        std::rethrow_exception(failure);
    } catch (const IoSystemError& error) {
        return error.code() == io_error::operation_aborted;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// 错误码定义
// ============================================================================
enum class ErrorCode : int {
    // 成功
    OK = 0,

    // 通用错误 (1-99)
    TIMEOUT = 1,
    CANCELLED = 2,
    INTERNAL = 3,
    INVALID_ARGUMENT = 4,
    NOT_FOUND = 5,
    PERMISSION_DENIED = 7,
    RESOURCE_EXHAUSTED = 8,
    NOT_SUPPORTED = 9,
    CONNECTION_CLOSED = 10,

    // Socket/Network 错误 (100-199)
    SOCKET_CREATE_FAILED = 100,
    SOCKET_BIND_FAILED = 101,
    SOCKET_READ_FAILED = 104,
    SOCKET_WRITE_FAILED = 105,
    SOCKET_CLOSED = 106,
    SOCKET_EOF = 107,

    // 协议错误 (200-299)
    PROTOCOL_INVALID_VERSION = 200,
    PROTOCOL_INVALID_COMMAND = 201,
    PROTOCOL_INVALID_ADDRESS = 202,
    PROTOCOL_AUTH_FAILED = 203,
    PROTOCOL_DECODE_FAILED = 204,
    PROTOCOL_ENCODE_FAILED = 205,
    PROTOCOL_UNSUPPORTED = 206,

    // 路由错误 (300-399)
    ROUTER_OUTBOUND_NOT_FOUND = 301,
    BLOCKED = 303,  // 被黑洞/规则阻止

    // 拨号错误 (400-499)
    DIAL_CONNECT_FAILED = 401,
    DIAL_TIMEOUT = 402,
    DIAL_REFUSED = 403,
    DIAL_NETWORK_UNREACHABLE = 404,
    DIAL_HOST_UNREACHABLE = 405,

    // Relay 错误 (500-549)
    RELAY_READ_FAILED = 500,
    RELAY_WRITE_FAILED = 501,
    RELAY_TIMEOUT = 502,

    // TLS 错误 (600-699)
    TLS_HANDSHAKE_FAILED = 600,
    TLS_CERT_INVALID = 601,

    // DNS 错误 (800-899)
    DNS_RESOLVE_FAILED = 800,
    DNS_TIMEOUT = 801,
    DNS_NO_RECORD = 802,
    DNS_SERVER_FAILED = 803,
    DNS_FORMAT_ERROR = 804,
    DNS_REFUSED = 805,

    // 面板错误 (900-999)
    PANEL_API_FAILED = 900,
    PANEL_INVALID_RESPONSE = 907,
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
        case ErrorCode::PERMISSION_DENIED: return "PERMISSION_DENIED";
        case ErrorCode::RESOURCE_EXHAUSTED: return "RESOURCE_EXHAUSTED";
        case ErrorCode::NOT_SUPPORTED: return "NOT_SUPPORTED";
        case ErrorCode::CONNECTION_CLOSED: return "CONNECTION_CLOSED";

        case ErrorCode::SOCKET_CREATE_FAILED: return "SOCKET_CREATE_FAILED";
        case ErrorCode::SOCKET_BIND_FAILED: return "SOCKET_BIND_FAILED";
        case ErrorCode::SOCKET_READ_FAILED: return "SOCKET_READ_FAILED";
        case ErrorCode::SOCKET_WRITE_FAILED: return "SOCKET_WRITE_FAILED";
        case ErrorCode::SOCKET_CLOSED: return "SOCKET_CLOSED";
        case ErrorCode::SOCKET_EOF: return "SOCKET_EOF";

        case ErrorCode::PROTOCOL_INVALID_VERSION: return "PROTOCOL_INVALID_VERSION";
        case ErrorCode::PROTOCOL_INVALID_COMMAND: return "PROTOCOL_INVALID_COMMAND";
        case ErrorCode::PROTOCOL_INVALID_ADDRESS: return "PROTOCOL_INVALID_ADDRESS";
        case ErrorCode::PROTOCOL_AUTH_FAILED: return "PROTOCOL_AUTH_FAILED";
        case ErrorCode::PROTOCOL_DECODE_FAILED: return "PROTOCOL_DECODE_FAILED";
        case ErrorCode::PROTOCOL_ENCODE_FAILED: return "PROTOCOL_ENCODE_FAILED";
        case ErrorCode::PROTOCOL_UNSUPPORTED: return "PROTOCOL_UNSUPPORTED";

        case ErrorCode::ROUTER_OUTBOUND_NOT_FOUND: return "ROUTER_OUTBOUND_NOT_FOUND";
        case ErrorCode::BLOCKED: return "BLOCKED";

        case ErrorCode::DIAL_CONNECT_FAILED: return "DIAL_CONNECT_FAILED";
        case ErrorCode::DIAL_TIMEOUT: return "DIAL_TIMEOUT";
        case ErrorCode::DIAL_REFUSED: return "DIAL_REFUSED";
        case ErrorCode::DIAL_NETWORK_UNREACHABLE: return "DIAL_NETWORK_UNREACHABLE";
        case ErrorCode::DIAL_HOST_UNREACHABLE: return "DIAL_HOST_UNREACHABLE";

        case ErrorCode::RELAY_READ_FAILED: return "RELAY_READ_FAILED";
        case ErrorCode::RELAY_WRITE_FAILED: return "RELAY_WRITE_FAILED";
        case ErrorCode::RELAY_TIMEOUT: return "RELAY_TIMEOUT";

        case ErrorCode::TLS_HANDSHAKE_FAILED: return "TLS_HANDSHAKE_FAILED";
        case ErrorCode::TLS_CERT_INVALID: return "TLS_CERT_INVALID";

        case ErrorCode::DNS_RESOLVE_FAILED: return "DNS_RESOLVE_FAILED";
        case ErrorCode::DNS_TIMEOUT: return "DNS_TIMEOUT";
        case ErrorCode::DNS_NO_RECORD: return "DNS_NO_RECORD";
        case ErrorCode::DNS_SERVER_FAILED: return "DNS_SERVER_FAILED";
        case ErrorCode::DNS_FORMAT_ERROR: return "DNS_FORMAT_ERROR";
        case ErrorCode::DNS_REFUSED: return "DNS_REFUSED";

        case ErrorCode::PANEL_API_FAILED: return "PANEL_API_FAILED";
        case ErrorCode::PANEL_INVALID_RESPONSE: return "PANEL_INVALID_RESPONSE";

        default: return "UNKNOWN";
    }
}

// Local error logs use xray-style lowercase reasons, not the stable code name.
[[nodiscard]]
inline std::string ErrorCodeToLogReason(ErrorCode code) {
    const auto raw = ErrorCodeToString(code);
    std::string reason;
    reason.reserve(raw.size());
    for (const char ch : raw) {
        if (ch == '_') {
            reason.push_back(' ');
        } else if (ch >= 'A' && ch <= 'Z') {
            reason.push_back(static_cast<char>(ch - 'A' + 'a'));
        } else {
            reason.push_back(ch);
        }
    }
    return reason;
}

// 错误消息统一格式化
[[nodiscard]]
inline std::string ErrorMessage(ErrorCode code, std::string_view message = {}) {
    return message.empty() ? std::string(ErrorCodeToString(code)) : std::string(message);
}

// ========================================================================
// 统一结果状态
//
// 让不同模块的 Result 类型共享同一套 error / error_msg / Ok() 语义，
// 避免每个接口重复实现“错误码 + 错误消息 + 成功判断”。
// ========================================================================
struct ResultStatus {
    ErrorCode error = ErrorCode::OK;
    std::string error_msg;

    [[nodiscard]] bool Ok() const noexcept {
        return error == ErrorCode::OK;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return Ok();
    }

    void SetError(ErrorCode code, std::string_view msg = {}) {
        error = code;
        error_msg = ErrorMessage(code, msg);
    }

};

// 从 Asio error_code 映射到 ErrorCode
ErrorCode MapAsioError(const IoErrorCode& ec);

