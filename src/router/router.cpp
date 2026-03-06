#include "acppnode/router/router.hpp"
#include "acppnode/geo/geodata.hpp"
#include "acppnode/infra/log.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <algorithm>
#include <cctype>

namespace acpp {

namespace {
void ToLower(std::string& s) {
    std::ranges::transform(s, s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
}
}  // namespace

// ============================================================================
// DomainTrie 实现 - 反向 Trie 树用于高效后缀匹配
// ============================================================================

DomainTrie::DomainTrie() : root_(std::make_unique<TrieNode>()) {}

DomainTrie::~DomainTrie() noexcept = default;

void DomainTrie::AddSuffix(const std::string& suffix, const std::string& outbound) {
    // 转小写并确保以点开头
    std::string lower = suffix;
    ToLower(lower);

    if (!lower.empty() && lower[0] != '.') {
        lower = "." + lower;
    }

    // 反向插入到 Trie
    TrieNode* node = root_.get();
    for (auto it = lower.rbegin(); it != lower.rend(); ++it) {
        char c = *it;
        if (!node->children[c]) {
            node->children[c] = std::make_unique<TrieNode>();
        }
        node = node->children[c].get();
    }
    node->outbound = outbound;
    rule_count_++;
}

std::optional<std::string> DomainTrie::MatchSuffix(const std::string& domain) const {
    // 转小写，添加前导点
    std::string lower = "." + domain;
    ToLower(lower);

    // 反向遍历域名，在 Trie 中查找最长匹配
    const TrieNode* node = root_.get();
    std::optional<std::string> result;

    for (auto it = lower.rbegin(); it != lower.rend(); ++it) {
        char c = *it;
        auto child = node->children.find(c);
        if (child == node->children.end()) {
            break;
        }
        node = child->second.get();
        if (node->outbound) {
            result = node->outbound;
        }
    }

    return result;
}

void DomainTrie::Clear() {
    root_ = std::make_unique<TrieNode>();
    rule_count_ = 0;
}

// ============================================================================
// DomainMatcher 实现
// ============================================================================

DomainMatcher::DomainMatcher() = default;
DomainMatcher::~DomainMatcher() noexcept = default;

void DomainMatcher::AddDomain(const std::string& domain, const std::string& outbound) {
    std::string lower = domain;
    ToLower(lower);
    domains_[lower] = outbound;
}

void DomainMatcher::AddSuffix(const std::string& suffix, const std::string& outbound) {
    suffix_trie_.AddSuffix(suffix, outbound);
}

void DomainMatcher::AddKeyword(const std::string& keyword, const std::string& outbound) {
    std::string lower = keyword;
    ToLower(lower);
    keywords_.emplace_back(lower, outbound);
}

void DomainMatcher::AddRegex(const std::string& pattern, const std::string& outbound) {
    try {
        regexes_.emplace_back(std::regex(pattern, std::regex::icase), outbound);
    } catch (const std::regex_error& e) {
        LOG_WARN("Router: invalid regex pattern '{}': {}", pattern, e.what());
    }
}

std::optional<std::string> DomainMatcher::Match(const std::string& domain) const {
    std::string lower = domain;
    ToLower(lower);

    // 1. 完全匹配
    auto it = domains_.find(lower);
    if (it != domains_.end()) {
        return it->second;
    }

    // 2. 后缀匹配（Trie，O(n)）
    auto suffix_result = suffix_trie_.MatchSuffix(lower);
    if (suffix_result) {
        return suffix_result;
    }

    // 3. 关键词匹配
    for (const auto& [keyword, outbound] : keywords_) {
        if (lower.find(keyword) != std::string::npos) {
            return outbound;
        }
    }

    // 4. 正则匹配
    for (const auto& [regex, outbound] : regexes_) {
        if (std::regex_search(lower, regex)) {
            return outbound;
        }
    }

    return std::nullopt;
}

void DomainMatcher::Clear() {
    domains_.clear();
    suffix_trie_.Clear();
    keywords_.clear();
    regexes_.clear();
}

// ============================================================================
// IPMatcher 实现
// ============================================================================

IPMatcher::IPMatcher() = default;
IPMatcher::~IPMatcher() noexcept = default;

void IPMatcher::AddCIDR(const std::string& cidr, const std::string& outbound) {
    uint32_t network, mask;
    if (Router::ParseCIDR(cidr, network, mask)) {
        rules_.push_back({network, mask, outbound});
    }
}

void IPMatcher::BuildIndex() {
    if (rules_.empty()) return;

    trie_nodes_.clear();
    trie_nodes_.push_back({});  // 根节点

    for (int i = 0; i < static_cast<int>(rules_.size()); ++i) {
        const auto& rule = rules_[i];
        // 从 mask 推算前缀长度
        uint8_t prefix = 0;
        uint32_t m = rule.mask;
        while (m & 0x80000000U) { ++prefix; m <<= 1; }

        int node = 0;
        for (uint8_t bit_idx = 0; bit_idx < prefix; ++bit_idx) {
            int bit = (rule.network >> (31 - bit_idx)) & 1;
            if (trie_nodes_[node].children[bit] < 0) {
                trie_nodes_[node].children[bit] = static_cast<int>(trie_nodes_.size());
                trie_nodes_.push_back({});
            }
            node = trie_nodes_[node].children[bit];
        }
        // 第一个匹配的规则优先（保持顺序语义）
        if (trie_nodes_[node].rule_index < 0) {
            trie_nodes_[node].rule_index = i;
        }
    }

    index_built_ = true;
}

std::optional<std::string> IPMatcher::Match(const std::string& ip) const {
    auto ip_opt = Router::ParseIPv4(ip);
    if (!ip_opt) {
        return std::nullopt;
    }
    return MatchIPv4(*ip_opt);
}

std::optional<std::string> IPMatcher::MatchIPv4(uint32_t ip) const {
    if (index_built_ && !trie_nodes_.empty()) {
        // Radix trie 查询：沿路径找最长匹配前缀
        int node = 0;
        int last_match = -1;
        if (trie_nodes_[0].rule_index >= 0) {
            last_match = trie_nodes_[0].rule_index;
        }
        for (uint8_t i = 0; i < 32; ++i) {
            int bit = (ip >> (31 - i)) & 1;
            int next = trie_nodes_[node].children[bit];
            if (next < 0) break;
            node = next;
            if (trie_nodes_[node].rule_index >= 0) {
                last_match = trie_nodes_[node].rule_index;
            }
        }
        if (last_match >= 0) {
            return rules_[last_match].outbound;
        }
        return std::nullopt;
    }

    // 降级：线性匹配
    for (const auto& rule : rules_) {
        if ((ip & rule.mask) == rule.network) {
            return rule.outbound;
        }
    }
    return std::nullopt;
}

void IPMatcher::Clear() {
    rules_.clear();
    trie_nodes_.clear();
    index_built_ = false;
}

// ============================================================================
// Router 实现
// ============================================================================

Router::Router() = default;
Router::~Router() noexcept = default;

bool Router::ParseCIDR(const std::string& cidr, uint32_t& network, uint32_t& mask) {
    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        // 单个 IP，等同于 /32
        auto ip = ParseIPv4(cidr);
        if (!ip) return false;
        network = *ip;
        mask = 0xFFFFFFFF;
        return true;
    }

    std::string ip_part = cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(cidr.substr(slash_pos + 1));

    if (prefix_len < 0 || prefix_len > 32) {
        return false;
    }

    auto ip = ParseIPv4(ip_part);
    if (!ip) return false;

    mask    = (prefix_len == 0) ? 0U : (0xFFFFFFFFU << (32 - prefix_len));
    network = *ip & mask;
    return true;
}

std::optional<uint32_t> Router::ParseIPv4(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return std::nullopt;
    }
    return ntohl(addr.s_addr);
}

std::string Router::Route(const SessionContext& ctx) const {
    const auto& target = ctx.EffectiveTarget();

    // 顺序检查复合规则（AND 语义）
    for (const auto& rule : compound_rules_) {
        if (rule.Match(ctx, geo_manager_)) {
            LOG_ACCESS_DEBUG("Router: {} matched compound rule -> {}",
                      target.ToString(), rule.outbound_tag);
            return rule.outbound_tag;
        }
    }

    // 无匹配，返回默认出站
    LOG_ACCESS_DEBUG("Router: {} -> {} (default)",
              target.ToString(), default_outbound_);
    return default_outbound_;
}

void Router::AddCompoundRule(CompoundRoutingRule rule) {
    compound_rules_.push_back(std::move(rule));
}

// ============================================================================
// ICondition 具体实现（GeoSite / GeoIP 需要 GeoManager）
// ============================================================================

PortCondition::PortCondition(const std::vector<std::string>& ports) {
    for (const auto& p : ports) {
        auto dash = p.find('-');
        if (dash != std::string::npos) {
            ranges_.push_back({
                static_cast<uint16_t>(std::stoi(p.substr(0, dash))),
                static_cast<uint16_t>(std::stoi(p.substr(dash + 1)))
            });
        } else {
            auto port = static_cast<uint16_t>(std::stoi(p));
            ranges_.push_back({port, port});
        }
    }
}

bool GeoSiteCondition::Match(
    const SessionContext& ctx,
    const geo::GeoManager* geo) const {
    const auto& target = ctx.EffectiveTarget();
    if (!geo || !target.IsDomain()) return false;
    for (const auto& tag : tags_) {
        if (geo->MatchGeoSite(tag, target.host)) return true;
    }
    return false;
}

bool GeoIPCondition::Match(
    const SessionContext& ctx,
    const geo::GeoManager* geo) const {
    const auto& target = ctx.EffectiveTarget();
    if (!geo || target.IsDomain()) return false;
    boost::system::error_code ec;
    auto addr = net::ip::make_address(target.host, ec);
    if (ec) return false;
    for (const auto& tag : tags_) {
        if (geo->MatchGeoIP(tag, addr)) return true;
    }
    return false;
}

}  // namespace acpp
