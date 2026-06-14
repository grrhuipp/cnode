#pragma once

#include <string>
#include <vector>

namespace acpp {

// ============================================================================
// TLS 配置
// ============================================================================
struct TlsConfig {
    // 服务端配置
    std::string cert_file;              // 证书文件路径
    std::string key_file;               // 私钥文件路径
    std::string ca_file;                // CA 证书（可选，用于客户端验证）

    // 客户端配置
    std::string server_name;            // 客户端 SNI / 自签证书默认域名
    bool allow_insecure = false;        // 是否允许不验证证书
    std::vector<std::string> alpn;      // ALPN 协议列表

    // 通用配置
    std::string min_version = "1.2";    // 最低 TLS 版本
    std::string max_version = "1.3";    // 最高 TLS 版本
    std::vector<std::string> cipher_suites;  // 密码套件

    bool IsServer() const { return !cert_file.empty() && !key_file.empty(); }
};

}  // namespace acpp
