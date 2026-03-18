#pragma once

#include "acppnode/common.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/common/target_address.hpp"

#include <regex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

namespace acpp {

struct TransparentStringHash {
    using is_transparent = void;

    [[nodiscard]] size_t operator()(std::string_view value) const noexcept {
        return std::hash<std::string_view>{}(value);
    }

    [[nodiscard]] size_t operator()(const std::string& value) const noexcept {
        return (*this)(std::string_view(value));
    }
};

struct TransparentStringEq {
    using is_transparent = void;

    [[nodiscard]] bool operator()(std::string_view lhs,
                                  std::string_view rhs) const noexcept {
        return lhs == rhs;
    }

    [[nodiscard]] bool operator()(const std::string& lhs,
                                  std::string_view rhs) const noexcept {
        return std::string_view(lhs) == rhs;
    }

    [[nodiscard]] bool operator()(std::string_view lhs,
                                  const std::string& rhs) const noexcept {
        return lhs == std::string_view(rhs);
    }

    [[nodiscard]] bool operator()(const std::string& lhs,
                                  const std::string& rhs) const noexcept {
        return lhs == rhs;
    }
};

// ============================================================================
// 域名匹配器 - 使用 Trie 树优化后缀匹配
// ============================================================================

class DomainTrie {
public:
    DomainTrie();
    ~DomainTrie() noexcept;

    DomainTrie(DomainTrie&&) noexcept = default;
    DomainTrie& operator=(DomainTrie&&) noexcept = default;
    DomainTrie(const DomainTrie&) = delete;
    DomainTrie& operator=(const DomainTrie&) = delete;

    void AddSuffix(const std::string& suffix);
    bool MatchSuffix(std::string_view lower_domain) const;
    void Clear();
    [[nodiscard]] size_t Size() const { return rule_count_; }

private:
    struct TrieNode {
        std::vector<std::pair<char, std::unique_ptr<TrieNode>>> children;
        bool terminal = false;
    };
    std::unique_ptr<TrieNode> root_;
    size_t rule_count_ = 0;
};

class DomainMatcher {
public:
    DomainMatcher();
    ~DomainMatcher() noexcept;

    DomainMatcher(DomainMatcher&&) noexcept = default;
    DomainMatcher& operator=(DomainMatcher&&) noexcept = default;
    DomainMatcher(const DomainMatcher&) = delete;
    DomainMatcher& operator=(const DomainMatcher&) = delete;

    void AddDomain  (const std::string& domain);
    void AddSuffix  (const std::string& suffix);
    void AddKeyword (const std::string& keyword);
    void AddRegex   (const std::string& pattern);

    [[nodiscard]] bool Match(std::string_view domain) const;
    void Clear();

    [[nodiscard]] bool Empty() const {
        return domains_.empty() && suffix_trie_.Size() == 0
            && keywords_.empty() && regexes_.empty();
    }

private:
    std::unordered_set<std::string, TransparentStringHash, TransparentStringEq> domains_;
    DomainTrie suffix_trie_;
    std::vector<std::string> keywords_;
    std::vector<std::regex> regexes_;
};

// ============================================================================
// IP 匹配器 — IPv4 Radix Trie 加速（O(32) 查询）
// ============================================================================
class IPMatcher {
public:
    IPMatcher();
    ~IPMatcher() noexcept;

    void AddCIDR(const std::string& cidr);

    // 规则加载完成后调用，构建 radix trie
    void BuildIndex();

    [[nodiscard]] bool Match(std::string_view ip) const;
    [[nodiscard]] bool MatchIPv4(uint32_t ip) const;
    void Clear();

    [[nodiscard]] bool Empty() const { return rules_.empty(); }

private:
    struct CIDRRule {
        uint32_t network;
        uint32_t mask;
    };
    std::vector<CIDRRule> rules_;

    // Radix trie 节点（存储规则索引）
    struct TrieNode {
        int children[2]{-1, -1};
        int rule_index = -1;  // 匹配的规则索引，-1 表示非终端
    };
    std::vector<TrieNode> trie_nodes_;
    bool index_built_ = false;
};

// ============================================================================
// 前向声明
// ============================================================================
namespace geo { class GeoManager; }

// ============================================================================
// 路由条件（值语义，std::variant，零堆分配）
//
// 每种条件独立实现，多个条件通过 CompoundRoutingRule 以 AND 语义组合。
// 单个条件内部多个值是 OR 语义。
// ============================================================================

// 域名条件：完整/后缀/关键词/正则匹配（OR within，仅对域名目标）
class DomainCondition {
public:
    explicit DomainCondition(DomainMatcher matcher)
        : matcher_(std::move(matcher)) {}

    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* /*geo*/) const {
        const auto& target = ctx.EffectiveTarget();
        if (!target.IsDomain()) return false;
        return matcher_.Match(target.host);
    }

private:
    DomainMatcher matcher_;
};

// GeoSite 条件（OR within，仅对域名目标）
class GeoSiteCondition {
public:
    explicit GeoSiteCondition(std::vector<std::string> tags)
        : tags_(std::move(tags)) {}

    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* geo) const;

private:
    std::vector<std::string> tags_;
};

// IP/CIDR 条件（OR within，仅对 IP 目标）
class IPCondition {
public:
    explicit IPCondition(IPMatcher matcher)
        : matcher_(std::move(matcher)) {}

    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* /*geo*/) const {
        const auto& target = ctx.EffectiveTarget();
        if (target.IsDomain()) return false;
        return matcher_.Match(target.host);
    }

private:
    IPMatcher matcher_;
};

// GeoIP 条件（OR within，仅对 IP 目标）
class GeoIPCondition {
public:
    explicit GeoIPCondition(std::vector<std::string> tags)
        : tags_(std::move(tags)) {}

    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* geo) const;

private:
    std::vector<std::string> tags_;
};

// 端口条件（OR within，支持单端口和范围 "1000-2000"）
class PortCondition {
public:
    explicit PortCondition(const std::vector<std::string>& ports);

    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* /*geo*/) const {
        const uint16_t port = ctx.EffectiveTarget().port;
        for (const auto& [start, end] : ranges_) {
            if (port >= start && port <= end) return true;
        }
        return false;
    }

    [[nodiscard]] const auto& ranges() const noexcept { return ranges_; }

private:
    std::vector<std::pair<uint16_t, uint16_t>> ranges_;
};

// 网络类型条件（OR within，"tcp"/"udp"）
class NetworkCondition {
public:
    explicit NetworkCondition(std::vector<std::string> networks) {
        for (const auto& net : networks) {
            if (net == "tcp") {
                mask_ |= 0x1;
            } else if (net == "udp") {
                mask_ |= 0x2;
            } else if (net == "tcp,udp" || net == "udp,tcp") {
                mask_ |= 0x3;
            }
        }
    }

    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* /*geo*/) const {
        const uint8_t bit = (ctx.network == Network::UDP) ? 0x2 : 0x1;
        return (mask_ & bit) != 0;
    }

private:
    uint8_t mask_ = 0;
};

// 入站标签条件（OR within）
class InboundTagCondition {
public:
    explicit InboundTagCondition(std::vector<std::string> tags)
        : tags_(std::move(tags)) {}

    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* /*geo*/) const {
        // 匹配：条件中任一 tag 与会话任一 inbound_tag 相同
        for (const auto& t : tags_) {
            for (const auto& it : ctx.inbound_tags) {
                if (it == t) return true;
            }
        }
        return false;
    }

private:
    std::vector<std::string> tags_;
};

// 来源 IP/CIDR 条件（OR within，匹配客户端 IP）
class SourceIPCondition {
public:
    explicit SourceIPCondition(IPMatcher matcher)
        : matcher_(std::move(matcher)) {}

    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* /*geo*/) const {
        if (ctx.client_ip.empty()) return false;
        return matcher_.Match(ctx.client_ip);
    }

private:
    IPMatcher matcher_;
};

// 来源端口条件（OR within，匹配客户端端口）
class SourcePortCondition {
public:
    explicit SourcePortCondition(const std::vector<std::string>& ports)
        : inner_(ports) {}

    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* /*geo*/) const {
        // 复用 PortCondition 的匹配逻辑，但匹配源端口
        const uint16_t port = ctx.src_addr.port();
        for (const auto& [start, end] : inner_.ranges()) {
            if (port >= start && port <= end) return true;
        }
        return false;
    }

private:
    PortCondition inner_;
};

// 嗅探协议条件（OR within，匹配 sniff_result.protocol）
class ProtocolCondition {
public:
    explicit ProtocolCondition(std::vector<std::string> protocols)
        : protocols_(std::move(protocols)) {}

    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* /*geo*/) const {
        if (!ctx.sniff_result.success) return false;
        for (const auto& p : protocols_) {
            if (ctx.sniff_result.protocol == p) return true;
        }
        return false;
    }

private:
    std::vector<std::string> protocols_;
};

// 用户 email 条件（OR within）
class UserCondition {
public:
    explicit UserCondition(std::vector<std::string> users)
        : users_(std::move(users)) {}

    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* /*geo*/) const {
        for (const auto& u : users_) {
            if (ctx.user_email == u) return true;
        }
        return false;
    }

private:
    std::vector<std::string> users_;
};

// ============================================================================
// Condition variant：值语义，无堆分配，std::visit 分发
// ============================================================================
using Condition = std::variant<
    DomainCondition, GeoSiteCondition, IPCondition, GeoIPCondition,
    PortCondition, NetworkCondition, InboundTagCondition, UserCondition,
    SourceIPCondition, SourcePortCondition, ProtocolCondition>;

// variant 分发：检查条件是否匹配
[[nodiscard]] inline bool ConditionMatch(
    const Condition& cond,
    const SessionContext& ctx,
    const geo::GeoManager* geo = nullptr) {
    return std::visit([&](const auto& c) { return c.Match(ctx, geo); }, cond);
}

// ============================================================================
// CompoundRoutingRule - AND 组合路由规则（Xray RoutingRule 设计）
//
// 规则中所有 conditions 必须同时满足（AND 语义）才认为规则匹配。
// 单个 condition 内部的多个值是 OR 语义（由各 ICondition 实现负责）。
//
// 示例：domain 条件 AND port 条件 → 仅匹配访问特定域名的特定端口连接。
// ============================================================================
struct CompoundRoutingRule {
    // AND 语义：所有条件必须满足
    std::vector<Condition> conditions;
    std::string outbound_tag;

    // 检查是否匹配（空规则 = 不匹配）
    [[nodiscard]] bool Match(
        const SessionContext& ctx,
        const geo::GeoManager* geo = nullptr) const {
        if (conditions.empty()) return false;
        for (const auto& cond : conditions) {
            if (!ConditionMatch(cond, ctx, geo)) return false;
        }
        return true;
    }
};

// ============================================================================
// 路由器
// ============================================================================
class Router {
public:
    Router();
    ~Router() noexcept;

    // 添加复合路由规则（规则按添加顺序匹配，第一个匹配的规则生效）
    void AddCompoundRule(CompoundRoutingRule rule);

    // 设置默认出站（无规则匹配时使用）
    void SetDefaultOutbound(const std::string& tag) { default_outbound_ = tag; }

    // 设置 GeoManager（用于 GeoIP/GeoSite 匹配）
    void SetGeoManager(geo::GeoManager* geo_manager) { geo_manager_ = geo_manager; }

    // 路由决策（顺序检查复合规则，无匹配时返回默认出站）
    [[nodiscard]] std::string Route(const SessionContext& ctx) const;

    // 获取默认出站
    [[nodiscard]] std::string DefaultOutbound() const { return default_outbound_; }

    // 工具函数（public 供 IPMatcher 使用）
    [[nodiscard]] static bool ParseCIDR(const std::string& cidr, uint32_t& network, uint32_t& mask);
    [[nodiscard]] static std::optional<uint32_t> ParseIPv4(std::string_view ip);

private:
    std::vector<CompoundRoutingRule> compound_rules_;
    std::string default_outbound_ = "direct";
    geo::GeoManager* geo_manager_ = nullptr;
};

}  // namespace acpp
