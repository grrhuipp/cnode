#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛
#include "acppnode/core/constants.hpp"
#include <algorithm>
#include <charconv>
#include <cstring>

namespace acpp {

namespace {

bool ParsePort(std::string_view text, uint16_t& port) {
    if (text.empty()) {
        return false;
    }

    uint32_t value = 0;
    const char* first = text.data();
    const char* last = text.data() + text.size();
    auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc{} || ptr != last || value == 0 || value > 65535) {
        return false;
    }
    port = static_cast<uint16_t>(value);
    return true;
}

}  // namespace

// ============================================================================
// HTTP Sniffer 实现
// ============================================================================

SniffResult HttpSniffer::Sniff(std::span<const uint8_t> data) {
    SniffResult result;

    auto host_port = ParseHttpHost(data);
    if (host_port) {
        result.success = true;
        result.protocol = constants::protocol::kHttp;
        result.domain.assign(host_port->host);
        result.port = host_port->port;
    }

    return result;
}

std::optional<HttpSniffer::HostPortView> HttpSniffer::ParseHttpHost(
    std::span<const uint8_t> data) {

    // 检查是否是 HTTP 请求（以常见方法开头）
    static const char* methods[] = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
        "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "
    };

    bool is_http = false;
    for (const char* method : methods) {
        size_t len = std::strlen(method);
        if (data.size() >= len &&
            std::memcmp(data.data(), method, len) == 0) {
            is_http = true;
            break;
        }
    }

    if (!is_http) {
        return std::nullopt;
    }

    // 转换为字符串视图
    // ISSUE-02-02: 使用 unsafe::ptr_cast 替代 reinterpret_cast
    std::string_view request(unsafe::ptr_cast<const char>(data.data()), data.size());

    // 查找 Host 头
    // HTTP 头部格式: Header-Name: Header-Value\r\n

    // 不区分大小写查找 "Host:"
    auto find_host_header = [](std::string_view sv) -> size_t {
        for (size_t i = 0; i + 5 <= sv.size(); ++i) {
            if ((sv[i] == 'H' || sv[i] == 'h') &&
                (sv[i+1] == 'O' || sv[i+1] == 'o') &&
                (sv[i+2] == 'S' || sv[i+2] == 's') &&
                (sv[i+3] == 'T' || sv[i+3] == 't') &&
                sv[i+4] == ':') {
                return i;
            }
        }
        return std::string_view::npos;
    };

    size_t host_pos = find_host_header(request);
    if (host_pos == std::string_view::npos) {
        return std::nullopt;
    }

    // 跳过 "Host:"
    host_pos += 5;

    // 跳过空格
    while (host_pos < request.size() && request[host_pos] == ' ') {
        host_pos++;
    }

    // 找到行尾
    size_t line_end = request.find("\r\n", host_pos);
    if (line_end == std::string_view::npos) {
        line_end = request.find('\n', host_pos);
        if (line_end == std::string_view::npos) {
            line_end = request.size();
        }
    }

    std::string_view host_value = request.substr(host_pos, line_end - host_pos);

    // 移除尾部空格
    while (!host_value.empty() &&
           (host_value.back() == ' ' || host_value.back() == '\r')) {
        host_value.remove_suffix(1);
    }

    if (host_value.empty()) {
        return std::nullopt;
    }

    // 解析主机和端口。host_view 指向 sniff_data，调用方只在最终结果中复制一次。
    std::string_view host_view;
    uint16_t port = 0;

    if (host_value[0] == '[') {
        const size_t close = host_value.find(']');
        if (close == std::string_view::npos || close == 1) {
            return std::nullopt;
        }

        host_view = host_value.substr(1, close - 1);
        if (close + 1 < host_value.size()) {
            if (host_value[close + 1] != ':' ||
                !ParsePort(host_value.substr(close + 2), port)) {
                return std::nullopt;
            }
        }
    } else {
        const size_t colon = host_value.rfind(':');
        const bool has_single_colon = colon != std::string_view::npos &&
            host_value.find(':') == colon;
        if (!has_single_colon) {
            host_view = host_value;
        } else {
            // 检查是否是端口（全数字）
            std::string_view maybe_port = host_value.substr(colon + 1);
            bool is_port = !maybe_port.empty();
            for (char c : maybe_port) {
                if (c < '0' || c > '9') {
                    is_port = false;
                    break;
                }
            }

            if (is_port) {
                host_view = host_value.substr(0, colon);
                ParsePort(maybe_port, port);
            } else {
                host_view = host_value;
            }
        }
    }

    if (host_view.empty()) {
        return std::nullopt;
    }

    return HostPortView{host_view, port};
}

}  // namespace acpp
