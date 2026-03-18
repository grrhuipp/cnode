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
#include <cstring>

namespace acpp {

namespace {
inline char ToLowerAscii(unsigned char c) {
    return static_cast<char>(std::tolower(c));
}

void ToLowerInPlace(std::string& s) {
    std::ranges::transform(s, s.begin(), ToLowerAscii);
}
}  // namespace

// ============================================================================
// DomainTrie 实现 - 反向 Trie 树用于高效后缀匹配
// ============================================================================

DomainTrie::DomainTrie() : root_(std::make_unique<TrieNode>()) {}

DomainTrie::~DomainTrie() noexcept = default;

void DomainTrie::AddSuffix(const std::string& suffix) {
    std::string lower = suffix;
    ToLowerInPlace(lower);

    TrieNode* node = root_.get();
    for (auto it = lower.rbegin(); it != lower.rend(); ++it) {
        TrieNode* next = nullptr;
        for (auto& [child_char, child_node] : node->children) {
            if (child_char == *it) {
                next = child_node.get();
                break;
            }
        }
        if (!next) {
            node->children.emplace_back(*it, std::make_unique<TrieNode>());
            next = node->children.back().second.get();
        }
        node = next;
    }
    node->terminal = true;
    rule_count_++;
}

bool DomainTrie::MatchSuffix(std::string_view lower_domain) const {
    const TrieNode* node = root_.get();
    for (auto it = lower_domain.rbegin(); it != lower_domain.rend(); ++it) {
        const TrieNode* next = nullptr;
        for (const auto& [child_char, child_node] : node->children) {
            if (child_char == *it) {
                next = child_node.get();
                break;
            }
        }
        node = next;
        if (!node) {
            return false;
        }

        if (node->terminal) {
            auto next_it = std::next(it);
            if (next_it == lower_domain.rend() || *next_it == '.') {
                return true;
            }
        }
    }

    return node->terminal;
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

void DomainMatcher::AddDomain(const std::string& domain) {
    std::string lower = domain;
    ToLowerInPlace(lower);
    domains_.insert(std::move(lower));
}

void DomainMatcher::AddSuffix(const std::string& suffix) {
    suffix_trie_.AddSuffix(suffix);
}

void DomainMatcher::AddKeyword(const std::string& keyword) {
    std::string lower = keyword;
    ToLowerInPlace(lower);
    keywords_.push_back(std::move(lower));
}

void DomainMatcher::AddRegex(const std::string& pattern) {
    try {
        regexes_.emplace_back(pattern, std::regex::icase);
    } catch (const std::regex_error& e) {
        LOG_WARN("Router: invalid regex pattern '{}': {}", pattern, e.what());
    }
}

bool DomainMatcher::Match(std::string_view domain) const {
    char stack_buf[256];
    std::string heap_buf;
    char* lower_ptr = stack_buf;

    if (domain.size() >= sizeof(stack_buf)) {
        heap_buf.resize(domain.size());
        lower_ptr = heap_buf.data();
    }

    for (size_t i = 0; i < domain.size(); ++i) {
        lower_ptr[i] = ToLowerAscii(static_cast<unsigned char>(domain[i]));
    }
    const std::string_view lower(lower_ptr, domain.size());

    if (domains_.find(lower) != domains_.end()) {
        return true;
    }

    if (suffix_trie_.MatchSuffix(lower)) {
        return true;
    }

    for (const auto& keyword : keywords_) {
        if (lower.find(keyword) != std::string::npos) {
            return true;
        }
    }

    for (const auto& regex : regexes_) {
        if (std::regex_search(lower.begin(), lower.end(), regex)) {
            return true;
        }
    }

    return false;
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

void IPMatcher::AddCIDR(const std::string& cidr) {
    uint32_t network, mask;
    if (Router::ParseCIDR(cidr, network, mask)) {
        rules_.push_back({network, mask});
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

bool IPMatcher::Match(std::string_view ip) const {
    auto ip_opt = Router::ParseIPv4(ip);
    if (!ip_opt) {
        return false;
    }
    return MatchIPv4(*ip_opt);
}

bool IPMatcher::MatchIPv4(uint32_t ip) const {
    if (index_built_ && !trie_nodes_.empty()) {
        int node = 0;
        if (trie_nodes_[0].rule_index >= 0) {
            return true;
        }
        for (uint8_t i = 0; i < 32; ++i) {
            int bit = (ip >> (31 - i)) & 1;
            int next = trie_nodes_[node].children[bit];
            if (next < 0) {
                return false;
            }
            node = next;
            if (trie_nodes_[node].rule_index >= 0) {
                return true;
            }
        }
        return false;
    }

    for (const auto& rule : rules_) {
        if ((ip & rule.mask) == rule.network) {
            return true;
        }
    }
    return false;
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

std::optional<uint32_t> Router::ParseIPv4(std::string_view ip) {
    char stack_buf[16];
    std::string heap_buf;
    const char* ip_cstr = stack_buf;

    if (ip.size() < sizeof(stack_buf)) {
        std::memcpy(stack_buf, ip.data(), ip.size());
        stack_buf[ip.size()] = '\0';
    } else {
        heap_buf.assign(ip);
        ip_cstr = heap_buf.c_str();
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_cstr, &addr) != 1) {
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
