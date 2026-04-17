#pragma once

// ============================================================================
// vmess_parser.hpp — VMess AEAD 请求解析器
//
// 职责：从字节流中解析 VMess AEAD 握手请求头，完成用户认证并填充 VMessRequest。
// ============================================================================

#include "acppnode/protocol/vmess/vmess_user_manager.hpp"
#include "acppnode/protocol/vmess/vmess_request.hpp"

#include <optional>
#include <utility>

namespace acpp {
namespace vmess {

// ============================================================================
// VMessParser — VMess AEAD 请求解析器
//
// 使用流程：
//   VMessParser parser(user_manager, tag);
//   auto [request, consumed] = parser.ParseRequest(data, len);
//
// tag 参数：
//   - 非空：只在指定 tag 的用户中搜索（O(N_tag)，推荐）
//   - 空：搜索所有用户（O(N_total)，向后兼容）
// ============================================================================
class VMessParser {
public:
    // 向后兼容：搜索所有 tag
    explicit VMessParser(const VMessUserManager& user_manager);

    // 推荐：限定在特定 tag 中搜索
    VMessParser(const VMessUserManager& user_manager, const std::string& tag);

    // 解析 VMess AEAD 请求头
    // 返回：(解析结果, 消耗的字节数)；解析失败时返回 (nullopt, 0)
    std::pair<std::optional<VMessRequest>, size_t>
    ParseRequest(const uint8_t* data, size_t len, uint64_t trace_conn_id = 0);

private:
    bool ParseRequestHeader(const uint8_t* data, size_t len,
                            const VMessUser* user,
                            const uint8_t* auth_id,
                            const uint8_t* connection_nonce,
                            uint64_t trace_conn_id,
                            VMessRequest& request,
                            size_t& consumed);

    bool ParseDecryptedHeader(const uint8_t* data, size_t len,
                              uint64_t trace_conn_id,
                              VMessRequest& request);

    const VMessUserManager& user_manager_;
    std::string             tag_;
};

}  // namespace vmess
}  // namespace acpp
