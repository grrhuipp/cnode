#include "acppnode/app/router/router.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/geo/geodata.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <algorithm>
#include <cstring>
#include <optional>
#include <regex>
#include <string>
#include <variant>
#include <vector>

namespace acpp::app::router {

namespace {
inline char ToLowerAscii(unsigned char c) {
    return static_cast<char>((c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c);
}

void ToLowerInPlace(std::string& s) {
    std::ranges::transform(s, s.begin(), ToLowerAscii);
}

auto LowerBoundTrieChild(auto& children, char ch) {
    return std::lower_bound(
        children.begin(), children.end(), ch,
        [](const auto& child, char value) {
            return child.ch < value;
        });
}

bool MatchIPv6Prefix(const net::ip::address_v6::bytes_type& ip,
                     const net::ip::address_v6::bytes_type& network,
                     uint8_t prefix) {
    const size_t full_bytes = prefix / 8;
    const uint8_t remaining_bits = prefix % 8;

    if (full_bytes > 0 && std::memcmp(ip.data(), network.data(), full_bytes) != 0) {
        return false;
    }
    if (remaining_bits == 0) {
        return true;
    }

    const uint8_t mask = static_cast<uint8_t>(0xFFu << (8 - remaining_bits));
    return (ip[full_bytes] & mask) == (network[full_bytes] & mask);
}

void MaskIPv6Network(net::ip::address_v6::bytes_type& bytes, uint8_t prefix) {
    const size_t full_bytes = prefix / 8;
    const uint8_t remaining_bits = prefix % 8;

    if (full_bytes >= bytes.size()) {
        return;
    }

    if (remaining_bits != 0) {
        bytes[full_bytes] &= static_cast<uint8_t>(0xFFu << (8 - remaining_bits));
    }

    const size_t zero_start = full_bytes + (remaining_bits != 0 ? 1 : 0);
    for (size_t i = zero_start; i < bytes.size(); ++i) {
        bytes[i] = 0;
    }
}

using StringVector = memory::ThreadLocalVector<std::string>;

StringVector ToRuntimeStrings(std::vector<std::string> values) {
    StringVector runtime;
    runtime.reserve(values.size());
    for (auto& value : values) {
        runtime.emplace_back(std::move(value));
    }
    return runtime;
}

void SortUniqueStrings(StringVector& values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

[[nodiscard]] bool ContainsSortedString(
    const StringVector& values,
    std::string_view value) {
    const auto it = std::lower_bound(
        values.begin(), values.end(), value,
        [](const std::string& lhs, std::string_view rhs) {
            return std::string_view(lhs) < rhs;
        });
    return it != values.end() && std::string_view(*it) == value;
}

[[nodiscard]] std::optional<uint32_t> ParseIPv4(std::string_view ip) {
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

[[nodiscard]] bool ParseCIDR(const std::string& cidr, uint32_t& network, uint32_t& mask) {
    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
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

    mask = (prefix_len == 0) ? 0U : (0xFFFFFFFFU << (32 - prefix_len));
    network = *ip & mask;
    return true;
}

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
    struct TrieChild {
        char ch;
        size_t node_index;
    };

    struct TrieNode {
        memory::ThreadLocalVector<TrieChild> children;
        bool terminal = false;
    };

    memory::ThreadLocalVector<TrieNode> nodes_;
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

    void AddDomain(const std::string& domain);
    void AddSuffix(const std::string& suffix);
    void AddKeyword(const std::string& keyword);
    void AddRegex(const std::string& pattern);

    [[nodiscard]] bool Match(std::string_view domain) const;
    void Clear();

    [[nodiscard]] bool Empty() const {
        return domains_.empty() && suffix_trie_.Size() == 0
            && keywords_.empty() && regexes_.empty();
    }

private:
    memory::ThreadLocalUnorderedSet<std::string, TransparentStringHash, TransparentStringEq> domains_;
    DomainTrie suffix_trie_;
    StringVector keywords_;
    memory::ThreadLocalVector<std::regex> regexes_;
};

class IPMatcher {
public:
    IPMatcher();
    ~IPMatcher() noexcept;

    void AddCIDR(const std::string& cidr);
    void BuildIndex();

    [[nodiscard]] bool Match(const net::ip::address& ip) const;
    [[nodiscard]] bool MatchIPv4(uint32_t ip) const;
    [[nodiscard]] bool MatchIPv6(const net::ip::address_v6::bytes_type& ip) const;
    void Clear();

    [[nodiscard]] bool Empty() const { return rules_.empty() && rules_v6_.empty(); }

private:
    struct CIDRRule {
        uint32_t network;
        uint32_t mask;
    };
    memory::ThreadLocalVector<CIDRRule> rules_;

    struct CIDRRuleV6 {
        net::ip::address_v6::bytes_type network{};
        uint8_t prefix = 0;
    };
    memory::ThreadLocalVector<CIDRRuleV6> rules_v6_;

    struct TrieNode {
        int children[2]{-1, -1};
        int rule_index = -1;
    };
    memory::ThreadLocalVector<TrieNode> trie_nodes_;
    memory::ThreadLocalVector<TrieNode> trie_nodes_v6_;
    bool index_built_ = false;
};

class DomainCondition {
public:
    explicit DomainCondition(DomainMatcher matcher)
        : matcher_(std::move(matcher)) {}

    [[nodiscard]] bool Match(
        const session::Context& ctx,
        const ::acpp::geo::GeoManager* /*geo*/) const {
        const auto& target = ctx.outbound.target;
        if (!target.IsDomain()) return false;
        return matcher_.Match(target.host);
    }

private:
    DomainMatcher matcher_;
};

class GeoSiteCondition {
public:
    explicit GeoSiteCondition(std::vector<std::string> tags);

    [[nodiscard]] bool Match(
        const session::Context& ctx,
        const ::acpp::geo::GeoManager* geo) const;

private:
    StringVector tags_;
};

class IPCondition {
public:
    explicit IPCondition(IPMatcher matcher)
        : matcher_(std::move(matcher)) {}

    [[nodiscard]] bool Match(
        const session::Context& ctx,
        const ::acpp::geo::GeoManager* /*geo*/) const {
        const auto& target = ctx.outbound.target;
        if (target.IsDomain()) return false;
        if (target.resolved_addr) return matcher_.Match(*target.resolved_addr);
        return false;
    }

private:
    IPMatcher matcher_;
};

class GeoIPCondition {
public:
    explicit GeoIPCondition(std::vector<std::string> tags);

    [[nodiscard]] bool Match(
        const session::Context& ctx,
        const ::acpp::geo::GeoManager* geo) const;

private:
    StringVector tags_;
};

class SourceIPCondition {
public:
    explicit SourceIPCondition(IPMatcher matcher)
        : matcher_(std::move(matcher)) {}

    [[nodiscard]] bool Match(
        const session::Context& ctx,
        const ::acpp::geo::GeoManager* /*geo*/) const {
        if (ctx.inbound.source_addr.is_unspecified()) return false;
        return matcher_.Match(ctx.inbound.source_addr);
    }

private:
    IPMatcher matcher_;
};

using Condition = std::variant<
    DomainCondition, GeoSiteCondition, IPCondition, GeoIPCondition,
    SourceIPCondition>;

[[nodiscard]] bool ConditionMatch(
    const Condition& cond,
    const session::Context& ctx,
    const ::acpp::geo::GeoManager* geo = nullptr) {
    return std::visit([&](const auto& c) { return c.Match(ctx, geo); }, cond);
}

struct CompoundRoutingRule {
    void SetNetworkCondition(const std::vector<std::string>& networks) {
        has_network_condition = true;
        network_mask = 0;
        for (const auto& network : networks) {
            if (network == constants::protocol::kTcp) {
                network_mask |= kNetworkTcp;
            } else if (network == constants::protocol::kUdp) {
                network_mask |= kNetworkUdp;
            } else if (network == "tcp,udp" || network == "udp,tcp") {
                network_mask |= kNetworkTcp | kNetworkUdp;
            }
        }
    }

    void SetProtocolCondition(const std::vector<std::string>& protocols) {
        has_protocol_condition = true;
        protocol_mask = 0;
        protocol_values.clear();
        protocol_values.reserve(protocols.size());
        for (const auto& protocol : protocols) {
            protocol_mask |= ProtocolBit(protocol);
            protocol_values.emplace_back(protocol);
        }
        SortUniqueStrings(protocol_values);
    }

    void SetInboundTagCondition(const std::vector<std::string>& tags) {
        has_inbound_tag_condition = true;
        inbound_tag_values.clear();
        inbound_tag_values.reserve(tags.size());
        for (const auto& tag : tags) {
            inbound_tag_values.emplace_back(tag);
        }
        SortUniqueStrings(inbound_tag_values);
    }

    void SetUserCondition(const std::vector<std::string>& users) {
        has_user_condition = true;
        user_values.clear();
        user_values.reserve(users.size());
        for (const auto& user : users) {
            user_values.emplace_back(user);
        }
        SortUniqueStrings(user_values);
    }

    void SetPortCondition(const std::vector<std::string>& ports) {
        has_port_condition = true;
        AssignPortRanges(port_ranges, ports);
    }

    void SetSourcePortCondition(const std::vector<std::string>& ports) {
        has_source_port_condition = true;
        AssignPortRanges(source_port_ranges, ports);
    }

    [[nodiscard]] bool HasAnyCondition() const noexcept {
        return has_network_condition || has_protocol_condition ||
               has_inbound_tag_condition || has_user_condition ||
               has_port_condition || has_source_port_condition ||
               !conditions.empty();
    }

    memory::ThreadLocalVector<Condition> conditions;
    std::string outbound_tag;
    bool has_network_condition = false;
    bool has_protocol_condition = false;
    bool has_inbound_tag_condition = false;
    bool has_user_condition = false;
    bool has_port_condition = false;
    bool has_source_port_condition = false;
    uint8_t network_mask = 0;
    uint8_t protocol_mask = 0;
    StringVector protocol_values;
    StringVector inbound_tag_values;
    StringVector user_values;
    memory::ThreadLocalVector<std::pair<uint16_t, uint16_t>> port_ranges;
    memory::ThreadLocalVector<std::pair<uint16_t, uint16_t>> source_port_ranges;

    [[nodiscard]] bool Match(
        const session::Context& ctx,
        const ::acpp::geo::GeoManager* geo = nullptr) const {
        if (!HasAnyCondition()) return false;
        if (has_network_condition && !MatchNetwork(ctx)) return false;
        if (has_protocol_condition && !MatchProtocol(ctx)) return false;
        if (has_inbound_tag_condition && !MatchInboundTag(ctx)) return false;
        if (has_user_condition && !MatchUser(ctx)) return false;
        if (has_source_port_condition && !MatchPortRanges(source_port_ranges, ctx.inbound.source_port)) {
            return false;
        }
        if (has_port_condition && !MatchPortRanges(port_ranges, ctx.outbound.target.port)) {
            return false;
        }
        for (const auto& cond : conditions) {
            if (!ConditionMatch(cond, ctx, geo)) return false;
        }
        return true;
    }

private:
    static constexpr uint8_t kNetworkTcp = 1u << 0;
    static constexpr uint8_t kNetworkUdp = 1u << 1;
    static constexpr uint8_t kProtocolTls = 1u << 0;
    static constexpr uint8_t kProtocolHttp = 1u << 1;

    [[nodiscard]] bool MatchNetwork(const session::Context& ctx) const noexcept {
        const uint8_t bit = (ctx.content.network == Network::UDP) ? kNetworkUdp : kNetworkTcp;
        return (network_mask & bit) != 0;
    }

    [[nodiscard]] bool MatchProtocol(const session::Context& ctx) const {
        if (ctx.content.protocol.empty()) return false;

        const uint8_t bit = ProtocolBit(ctx.content.protocol);
        if (bit != 0) {
            return (protocol_mask & bit) != 0;
        }
        return ContainsSortedString(protocol_values, ctx.content.protocol);
    }

    [[nodiscard]] bool MatchInboundTag(const session::Context& ctx) const {
        if (ContainsSortedString(inbound_tag_values, ctx.inbound.tag)) {
            return true;
        }

        if (ctx.inbound.tags) {
            for (const auto& tag : *ctx.inbound.tags) {
                if (tag == ctx.inbound.tag) continue;
                if (ContainsSortedString(inbound_tag_values, tag)) {
                    return true;
                }
            }
        }
        return false;
    }

    [[nodiscard]] bool MatchUser(const session::Context& ctx) const {
        return ContainsSortedString(user_values, ctx.inbound.user_email);
    }

    static void AssignPortRanges(
        memory::ThreadLocalVector<std::pair<uint16_t, uint16_t>>& ranges,
        const std::vector<std::string>& ports) {
        ranges.clear();
        ranges.reserve(ports.size());
        for (const auto& value : ports) {
            auto dash = value.find('-');
            if (dash != std::string::npos) {
                ranges.push_back({
                    static_cast<uint16_t>(std::stoi(value.substr(0, dash))),
                    static_cast<uint16_t>(std::stoi(value.substr(dash + 1))),
                });
            } else {
                auto port = static_cast<uint16_t>(std::stoi(value));
                ranges.push_back({port, port});
            }
        }
    }

    [[nodiscard]] static bool MatchPortRanges(
        const memory::ThreadLocalVector<std::pair<uint16_t, uint16_t>>& ranges,
        uint16_t port) noexcept {
        for (const auto& [start, end] : ranges) {
            if (port >= start && port <= end) return true;
        }
        return false;
    }

    [[nodiscard]] static constexpr uint8_t ProtocolBit(std::string_view protocol) noexcept {
        if (protocol == constants::protocol::kTls) {
            return kProtocolTls;
        }
        if (protocol == constants::protocol::kHttp) {
            return kProtocolHttp;
        }
        return 0;
    }
};
}  // namespace

// ============================================================================
// DomainTrie 实现 - 反向 Trie 树用于高效后缀匹配
// ============================================================================

DomainTrie::DomainTrie() {
    nodes_.push_back({});
}

DomainTrie::~DomainTrie() noexcept = default;

void DomainTrie::AddSuffix(const std::string& suffix) {
    std::string lower = suffix;
    ToLowerInPlace(lower);

    size_t node_index = 0;
    for (auto it = lower.rbegin(); it != lower.rend(); ++it) {
        auto& children = nodes_[node_index].children;
        auto child_it = LowerBoundTrieChild(children, *it);
        if (child_it == children.end() || child_it->ch != *it) {
            const size_t child_index = nodes_.size();
            nodes_.push_back({});
            auto& refreshed_children = nodes_[node_index].children;
            auto insert_it = LowerBoundTrieChild(refreshed_children, *it);
            refreshed_children.insert(insert_it, TrieChild{*it, child_index});
            node_index = child_index;
        } else {
            node_index = child_it->node_index;
        }
    }
    nodes_[node_index].terminal = true;
    rule_count_++;
}

bool DomainTrie::MatchSuffix(std::string_view lower_domain) const {
    if (nodes_.empty()) return false;

    size_t node_index = 0;
    for (auto it = lower_domain.rbegin(); it != lower_domain.rend(); ++it) {
        const auto& node = nodes_[node_index];
        auto child_it = LowerBoundTrieChild(node.children, *it);
        if (child_it == node.children.end() || child_it->ch != *it) {
            return false;
        }
        node_index = child_it->node_index;
        const auto& child_node = nodes_[node_index];

        if (child_node.terminal) {
            auto next_it = std::next(it);
            if (next_it == lower_domain.rend() || *next_it == '.') {
                return true;
            }
        }
    }

    return nodes_[node_index].terminal;
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

bool DomainMatcher::Match(std::string_view domain) const {
    char stack_buf[256];
    memory::ThreadLocalVector<char> heap_buf;
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

// ============================================================================
// IPMatcher 实现
// ============================================================================

IPMatcher::IPMatcher() = default;
IPMatcher::~IPMatcher() noexcept = default;

void IPMatcher::AddCIDR(const std::string& cidr) {
    uint32_t network, mask;
    if (ParseCIDR(cidr, network, mask)) {
        rules_.push_back({network, mask});
        return;
    }

    std::string ip_part;
    uint8_t prefix = 128;
    const size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        ip_part = cidr;
    } else {
        ip_part = cidr.substr(0, slash_pos);
        int prefix_len = std::stoi(cidr.substr(slash_pos + 1));
        if (prefix_len < 0 || prefix_len > 128) {
            return;
        }
        prefix = static_cast<uint8_t>(prefix_len);
    }

    IoErrorCode ec;
    auto addr = net::ip::make_address(ip_part, ec);
    if (ec || !addr.is_v6()) {
        return;
    }

    auto bytes = addr.to_v6().to_bytes();
    MaskIPv6Network(bytes, prefix);
    rules_v6_.push_back({bytes, prefix});
}

void IPMatcher::BuildIndex() {
    trie_nodes_.clear();
    trie_nodes_v6_.clear();

    if (!rules_.empty()) {
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
    }

    if (!rules_v6_.empty()) {
        trie_nodes_v6_.push_back({});  // 根节点

        for (int i = 0; i < static_cast<int>(rules_v6_.size()); ++i) {
            const auto& rule = rules_v6_[i];
            int node = 0;
            for (uint8_t bit_idx = 0; bit_idx < rule.prefix; ++bit_idx) {
                const uint8_t byte = rule.network[bit_idx / 8];
                const int bit = (byte >> (7 - (bit_idx % 8))) & 1;
                if (trie_nodes_v6_[node].children[bit] < 0) {
                    trie_nodes_v6_[node].children[bit] =
                        static_cast<int>(trie_nodes_v6_.size());
                    trie_nodes_v6_.push_back({});
                }
                node = trie_nodes_v6_[node].children[bit];
            }
            if (trie_nodes_v6_[node].rule_index < 0) {
                trie_nodes_v6_[node].rule_index = i;
            }
        }
    }

    index_built_ = true;
}

bool IPMatcher::Match(const net::ip::address& ip) const {
    if (ip.is_v4()) {
        auto bytes = ip.to_v4().to_bytes();
        const uint32_t ip_val = (static_cast<uint32_t>(bytes[0]) << 24) |
                                (static_cast<uint32_t>(bytes[1]) << 16) |
                                (static_cast<uint32_t>(bytes[2]) << 8)  |
                                static_cast<uint32_t>(bytes[3]);
        return MatchIPv4(ip_val);
    }

    return MatchIPv6(ip.to_v6().to_bytes());
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

bool IPMatcher::MatchIPv6(const net::ip::address_v6::bytes_type& ip) const {
    if (index_built_ && !trie_nodes_v6_.empty()) {
        int node = 0;
        if (trie_nodes_v6_[0].rule_index >= 0) {
            return true;
        }
        for (uint8_t bit_idx = 0; bit_idx < 128; ++bit_idx) {
            const uint8_t byte = ip[bit_idx / 8];
            const int bit = (byte >> (7 - (bit_idx % 8))) & 1;
            const int next = trie_nodes_v6_[node].children[bit];
            if (next < 0) {
                return false;
            }
            node = next;
            if (trie_nodes_v6_[node].rule_index >= 0) {
                return true;
            }
        }
        return false;
    }

    for (const auto& rule : rules_v6_) {
        if (MatchIPv6Prefix(ip, rule.network, rule.prefix)) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Router 实现
// ============================================================================

struct Router::Impl {
    memory::ThreadLocalVector<CompoundRoutingRule> compound_rules;
    std::string default_outbound_tag{std::string(constants::protocol::kDirect)};
    ::acpp::geo::GeoManager* geo_manager = nullptr;
};

Router::Router()
    : impl_(std::make_unique<Impl>()) {}
Router::~Router() noexcept = default;
Router::Router(Router&&) noexcept = default;
Router& Router::operator=(Router&&) noexcept = default;

std::string_view Router::Route(const session::Context& ctx) const {
    return Route(ctx, impl_->default_outbound_tag);
}

std::string_view Router::Route(
    const session::Context& ctx,
    std::string_view default_outbound_tag) const {
    const auto& target = ctx.outbound.target;
    if (default_outbound_tag.empty()) {
        default_outbound_tag = impl_->default_outbound_tag;
    }

    // 顺序检查复合规则（AND 语义）
    for (const auto& rule : impl_->compound_rules) {
        if (rule.Match(ctx, impl_->geo_manager)) {
            LOG_ACCESS_DEBUG("Router: {} matched compound rule -> {}",
                      target, rule.outbound_tag);
            return rule.outbound_tag;
        }
    }

    // 无匹配，返回默认出站
    LOG_ACCESS_DEBUG("Router: {} -> {} (default)",
              target, default_outbound_tag);
    return default_outbound_tag;
}

void Router::Configure(
    const RoutingConfig& routing,
    std::string_view default_outbound_tag,
    ::acpp::geo::GeoManager* geo_manager) {
    impl_->compound_rules.clear();
    impl_->default_outbound_tag = std::string(constants::protocol::kDirect);
    impl_->geo_manager = geo_manager;

    if (!default_outbound_tag.empty()) {
        impl_->default_outbound_tag = std::string(default_outbound_tag);
    }

    for (const auto& rc : routing.rules) {
        CompoundRoutingRule compound;
        compound.outbound_tag = rc.outbound_tag;

        if (!rc.network.empty()) {
            compound.SetNetworkCondition(rc.network);
        }

        if (!rc.inbound_tag.empty()) {
            compound.SetInboundTagCondition(rc.inbound_tag);
        }

        if (!rc.user.empty()) {
            compound.SetUserCondition(rc.user);
        }

        if (!rc.source_port.empty()) {
            compound.SetSourcePortCondition(rc.source_port);
        }

        if (!rc.port.empty()) {
            compound.SetPortCondition(rc.port);
        }

        if (!rc.protocol.empty()) {
            compound.SetProtocolCondition(rc.protocol);
        }

        {
            IPMatcher source_ip_matcher;
            for (const auto& value : rc.source) {
                source_ip_matcher.AddCIDR(value);
            }
            if (!source_ip_matcher.Empty()) {
                source_ip_matcher.BuildIndex();
                compound.conditions.push_back(SourceIPCondition{std::move(source_ip_matcher)});
            }
        }

        IPMatcher ip_matcher;
        for (const auto& value : rc.ip) {
            ip_matcher.AddCIDR(value);
        }
        if (!ip_matcher.Empty()) {
            ip_matcher.BuildIndex();
            compound.conditions.push_back(IPCondition{std::move(ip_matcher)});
        }

        DomainMatcher domain_matcher;
        for (const auto& value : rc.domain) {
            domain_matcher.AddSuffix(value);
        }
        for (const auto& value : rc.domain_suffix) {
            domain_matcher.AddSuffix(value);
        }
        for (const auto& value : rc.domain_keyword) {
            domain_matcher.AddKeyword(value);
        }
        for (const auto& value : rc.domain_full) {
            domain_matcher.AddDomain(value);
        }
        if (!domain_matcher.Empty()) {
            compound.conditions.push_back(DomainCondition{std::move(domain_matcher)});
        }

        if (!rc.geosite.empty()) {
            compound.conditions.push_back(GeoSiteCondition{rc.geosite});
        }

        if (!rc.geoip.empty()) {
            compound.conditions.push_back(GeoIPCondition{rc.geoip});
        }

        if (compound.HasAnyCondition()) {
            impl_->compound_rules.push_back(std::move(compound));
        }
    }
}

std::string_view Router::DefaultOutbound() const {
    return impl_->default_outbound_tag;
}

// ============================================================================
// ICondition 具体实现（GeoSite / GeoIP 需要 GeoManager）
// ============================================================================

bool GeoSiteCondition::Match(
    const session::Context& ctx,
    const ::acpp::geo::GeoManager* geo) const {
    const auto& target = ctx.outbound.target;
    if (!geo || !target.IsDomain()) return false;
    for (const auto& tag : tags_) {
        if (geo->MatchGeoSite(tag, target.host)) return true;
    }
    return false;
}

GeoSiteCondition::GeoSiteCondition(std::vector<std::string> tags)
    : tags_(ToRuntimeStrings(std::move(tags))) {
    for (auto& tag : tags_) {
        ToLowerInPlace(tag);
    }
}

bool GeoIPCondition::Match(
    const session::Context& ctx,
    const ::acpp::geo::GeoManager* geo) const {
    const auto& target = ctx.outbound.target;
    if (!geo || target.IsDomain()) return false;
    if (!target.resolved_addr) return false;
    for (const auto& tag : tags_) {
        if (geo->MatchGeoIP(tag, *target.resolved_addr)) return true;
    }
    return false;
}

GeoIPCondition::GeoIPCondition(std::vector<std::string> tags)
    : tags_(ToRuntimeStrings(std::move(tags))) {
    for (auto& tag : tags_) {
        ToLowerInPlace(tag);
    }
}

}  // namespace acpp::app::router
