#pragma once

#include <boost/json/object.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace acpp::json {

// ============================================================================
// JSON 配置解析工具函数
//
// 单键版本：直接查找指定 key
// 双键版本：先查 key1（PascalCase），失败再查 key2（camelCase）
// ============================================================================

// ── 单键版本 ─────────────────────────────────────────────────────────────────

inline std::string GetString(const boost::json::object& obj, std::string_view key,
                             std::string_view def = "") {
    const auto* p = obj.if_contains(key);
    if (!p || !p->is_string()) return std::string(def);
    return std::string(p->as_string());
}

inline int64_t GetInt(const boost::json::object& obj, std::string_view key,
                      int64_t def = 0) {
    const auto* p = obj.if_contains(key);
    if (!p) return def;
    if (p->is_int64())  return p->as_int64();
    if (p->is_uint64()) return static_cast<int64_t>(p->as_uint64());
    return def;
}

inline bool GetBool(const boost::json::object& obj, std::string_view key,
                    bool def = false) {
    const auto* p = obj.if_contains(key);
    if (!p || !p->is_bool()) return def;
    return p->as_bool();
}

// ── 双键版本（PascalCase 回退 camelCase）─────────────────────────────────────

inline std::string GetString(const boost::json::object& obj,
                             std::string_view key1, std::string_view key2,
                             std::string_view def) {
    const auto* p = obj.if_contains(key1);
    if (p && p->is_string()) return std::string(p->as_string());
    const auto* q = obj.if_contains(key2);
    if (q && q->is_string()) return std::string(q->as_string());
    return std::string(def);
}

inline int64_t GetInt(const boost::json::object& obj,
                      std::string_view key1, std::string_view key2,
                      int64_t def = 0) {
    const auto* p = obj.if_contains(key1);
    if (p) {
        if (p->is_int64())  return p->as_int64();
        if (p->is_uint64()) return static_cast<int64_t>(p->as_uint64());
    }
    const auto* q = obj.if_contains(key2);
    if (q) {
        if (q->is_int64())  return q->as_int64();
        if (q->is_uint64()) return static_cast<int64_t>(q->as_uint64());
    }
    return def;
}

inline bool GetBool(const boost::json::object& obj,
                    std::string_view key1, std::string_view key2,
                    bool def = false) {
    const auto* p = obj.if_contains(key1);
    if (p && p->is_bool()) return p->as_bool();
    const auto* q = obj.if_contains(key2);
    if (q && q->is_bool()) return q->as_bool();
    return def;
}

}  // namespace acpp::json
