#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛
#include <algorithm>
#include <cctype>

namespace acpp {

// ============================================================================
// HTTP Sniffer 实现
// ============================================================================

SniffResult HttpSniffer::Sniff(std::span<const uint8_t> data) {
    SniffResult result;
    
    auto host_port = ParseHttpHost(data);
    if (host_port) {
        result.success = true;
        result.protocol = "http";
        result.domain = host_port->first;
        result.port = host_port->second;
    }
    
    return result;
}

std::optional<std::pair<std::string, uint16_t>> HttpSniffer::ParseHttpHost(
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
    
    // 解析主机和端口
    std::string host;
    uint16_t port = 0;
    
    // 检查是否有端口
    size_t colon = host_value.rfind(':');
    
    if (host_value[0] == '[') {
        return std::nullopt;
    } else if (colon != std::string_view::npos) {
        // 检查是否是端口（全数字）
        std::string_view maybe_port = host_value.substr(colon + 1);
        bool is_port = !maybe_port.empty();
        for (char c : maybe_port) {
            if (!std::isdigit(c)) {
                is_port = false;
                break;
            }
        }
        
        if (is_port) {
            host = std::string(host_value.substr(0, colon));
            try {
                port = static_cast<uint16_t>(std::stoi(std::string(maybe_port)));
            } catch (...) {
                port = 0;
            }
        } else {
            host = std::string(host_value);
        }
    } else {
        host = std::string(host_value);
    }
    
    if (host.empty()) {
        return std::nullopt;
    }
    
    return std::make_pair(host, port);
}

}  // namespace acpp
