#pragma once

#include "common/asio_types.hpp"
#include "common/string_hash.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory_resource>
#include <regex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace geo {

// ============================================================================
// CidrSet - IPv4/IPv6 前缀集合，回答“地址是否落入任一前缀”。
// 路由 ip/source 条件与 GeoIP 分类共用这一份实现。构建完成后只读。
// ============================================================================
class CidrSet {
public:
    explicit CidrSet(
        std::pmr::memory_resource* resource = std::pmr::get_default_resource());

    // network 为 4（IPv4）或 16（IPv6）字节网络序地址，prefix 不得超过其位宽。
    void Insert(std::span<const uint8_t> network, uint8_t prefix);

    [[nodiscard]] bool Match(const net::ip::address& ip) const noexcept;
    [[nodiscard]] bool Empty() const noexcept { return v4_.empty() && v6_.empty(); }

private:
    struct Node {
        int32_t children[2]{-1, -1};
        bool terminal = false;
    };
    using Trie = std::pmr::vector<Node>;

    static void InsertBits(Trie& trie, std::span<const uint8_t> network, uint8_t prefix);
    [[nodiscard]] static bool MatchBits(const Trie& trie,
                                        std::span<const uint8_t> address) noexcept;

    Trie v4_;
    Trie v6_;
};

// ============================================================================
// DomainRuleSet - full / suffix / keyword / regex 域名条件，任一命中即匹配。
// 规则与查询统一按 DNS 主机名规范化（去根点、ASCII 小写）；suffix 只在标签
// 边界命中。路由 domain 条件与 GeoSite 分类共用这一份实现。构建完成后只读。
// ============================================================================
class DomainRuleSet {
public:
    explicit DomainRuleSet(
        std::pmr::memory_resource* resource = std::pmr::get_default_resource());

    void AddFull(std::string_view domain);
    void AddSuffix(std::string_view suffix);
    void AddKeyword(std::string_view keyword);
    // 无效 pattern 抛出 std::regex_error。
    void AddRegex(const std::string& pattern);

    [[nodiscard]] bool Match(std::string_view domain) const;
    [[nodiscard]] bool Empty() const noexcept {
        return full_.empty() && suffix_nodes_.empty() && keywords_.empty() &&
               regexes_.empty();
    }

private:
    struct SuffixChild {
        char ch;
        uint32_t node_index;
    };
    struct SuffixNode {
        std::pmr::vector<SuffixChild> children;
        bool terminal = false;
    };

    [[nodiscard]] bool MatchSuffix(std::string_view lower_domain) const noexcept;

    std::pmr::unordered_set<std::pmr::string, TransparentStringHash, TransparentStringEq> full_;
    std::pmr::vector<SuffixNode> suffix_nodes_;
    std::pmr::vector<std::pmr::string> keywords_;
    std::pmr::vector<std::regex> regexes_;
};

// ============================================================================
// GeoDatabase - 启动期从 geoip.dat / geosite.dat 加载路由引用的分类，之后只读，
// 可被所有 Worker 并发查询。
// ============================================================================
class GeoDatabase {
public:
    // 只加载 tags 列出的分类（大小写不敏感）。文件不可读、protobuf 损坏、
    // 请求的 tag 缺失或重复时抛出 std::runtime_error，不发布部分数据。
    // GeoSite 的 regexp 条目不加载。
    GeoDatabase(const std::filesystem::path& geoip_path,
                std::span<const std::string> geoip_tags,
                const std::filesystem::path& geosite_path,
                std::span<const std::string> geosite_tags);
    ~GeoDatabase();

    GeoDatabase(const GeoDatabase&) = delete;
    GeoDatabase& operator=(const GeoDatabase&) = delete;

    // 冷路径：tag 大小写不敏感；未加载返回 nullptr。返回指针与数据库同寿命。
    [[nodiscard]] const CidrSet* FindGeoIP(std::string_view tag) const;
    [[nodiscard]] const DomainRuleSet* FindGeoSite(std::string_view tag) const;

    struct Stats {
        size_t geoip_tags_loaded = 0;
        size_t geosite_tags_loaded = 0;
    };
    [[nodiscard]] Stats GetStats() const noexcept;

private:
    std::unordered_map<std::string, CidrSet, TransparentStringHash, TransparentStringEq> geoip_;
    std::unordered_map<std::string, DomainRuleSet, TransparentStringHash, TransparentStringEq>
        geosite_;
};

}  // namespace geo
