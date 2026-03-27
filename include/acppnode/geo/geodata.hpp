#pragma once

#include "acppnode/common.hpp"
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <filesystem>
#include <optional>
#include <atomic>

namespace acpp {
namespace geo {

// ============================================================================
// IP CIDR 表示
// ============================================================================
struct CIDR {
    std::array<uint8_t, 4> addr;
    uint8_t prefix;
    
    bool Contains(const net::ip::address& ip) const;
};

// ============================================================================
// IPv4 Radix Trie — 位前缀树，O(32) 最坏查询
// ============================================================================
class IPv4RadixTrie {
public:
    void Insert(uint32_t ip, uint8_t prefix);
    bool Match(uint32_t ip) const;
    bool Empty() const { return nodes_.size() <= 1; }

private:
    struct Node {
        int children[2]{-1, -1};
        bool terminal = false;
    };
    std::vector<Node> nodes_{1};  // nodes_[0] = 根节点
};

// ============================================================================
// GeoIP 数据
// ============================================================================
class GeoIPData {
public:
    // 添加 CIDR
    void AddCIDR(const CIDR& cidr);
    void AddCIDR(const std::string& cidr_str);

    // 构建完成后调用，构建 IPv4 radix trie 加速查询
    void BuildIndex();

    // 检查 IP 是否匹配
    bool Match(const net::ip::address& ip) const;
    bool Match(const std::string& ip_str) const;

    size_t Size() const { return cidrs_v4_.size(); }

private:
    std::vector<CIDR> cidrs_v4_;
    IPv4RadixTrie trie_v4_;        // IPv4 加速查询
    bool index_built_ = false;
};

// ============================================================================
// GeoSite 数据
// ============================================================================
// ============================================================================
// 域名后缀 Trie — 反向字符 trie，O(域名长度) 查询
// ============================================================================
class SuffixTrie {
public:
    void Insert(const std::string& domain);
    bool Match(std::string_view domain) const;
    bool Empty() const { return nodes_.size() <= 1; }

private:
    // 紧凑表示：每个节点的子节点存储在 flat map 中
    struct Node {
        std::unordered_map<char, int> children;
        bool terminal = false;
    };
    std::vector<Node> nodes_{1};  // nodes_[0] = 根节点
};

class GeoSiteData {
public:
    enum class Type {
        PLAIN,      // 包含匹配
        DOMAIN,     // 域名后缀匹配
        FULL,       // 完全匹配
        REGEXP      // 正则匹配（暂不支持）
    };

    struct Entry {
        Type type;
        std::string value;
    };

    // 添加规则
    void AddEntry(Type type, const std::string& value);

    // 检查域名是否匹配
    bool Match(const std::string& domain) const;

    size_t Size() const { return entries_.size(); }

private:
    std::vector<Entry> entries_;
    std::unordered_set<std::string> full_domains_;     // 完全匹配快速查找
    SuffixTrie suffix_trie_;                           // 后缀匹配（反向 trie）
    std::vector<std::string> plain_keywords_;          // PLAIN 包含匹配
};

// ============================================================================
// GeoIP 懒加载器 (优化版: 加载完成后无锁查询)
// ============================================================================
class GeoIPLoader {
public:
    explicit GeoIPLoader(const std::filesystem::path& dat_path);
    
    // 获取或加载指定 tag 的数据
    // tag 格式: "cn", "us", "private" 等
    std::shared_ptr<GeoIPData> Get(const std::string& tag);
    
    // 检查 tag 是否存在（不加载）
    bool HasTag(const std::string& tag);
    
    // 获取所有可用的 tag
    std::vector<std::string> GetAllTags();
    
    // 统计
    size_t LoadedCount() const;
    
    // 标记加载完成（之后的查询无需锁）
    void Finalize() { finalized_.store(true, std::memory_order_release); }
    bool IsFinalized() const { return finalized_.load(std::memory_order_acquire); }
    
private:
    bool LoadIndex();
    std::shared_ptr<GeoIPData> LoadTag(const std::string& tag);
    
    std::filesystem::path dat_path_;
    bool index_loaded_ = false;
    
    // tag -> 文件偏移和大小
    struct TagInfo {
        uint64_t offset;
        uint64_t size;
    };
    std::unordered_map<std::string, TagInfo> tag_index_;
    
    // 已加载的数据
    mutable std::shared_mutex mutex_;  // 仅在加载阶段使用
    std::unordered_map<std::string, std::shared_ptr<GeoIPData>> loaded_;
    
    // 加载完成标志
    std::atomic<bool> finalized_{false};
};

// ============================================================================
// GeoSite 懒加载器 (优化版: 加载完成后无锁查询)
// ============================================================================
class GeoSiteLoader {
public:
    explicit GeoSiteLoader(const std::filesystem::path& dat_path);
    
    // 获取或加载指定 tag 的数据
    // tag 格式: "category-ads", "cn", "google" 等
    std::shared_ptr<GeoSiteData> Get(const std::string& tag);
    
    // 检查 tag 是否存在（不加载）
    bool HasTag(const std::string& tag);
    
    // 获取所有可用的 tag
    std::vector<std::string> GetAllTags();
    
    // 统计
    size_t LoadedCount() const;
    
    // 标记加载完成（之后的查询无需锁）
    void Finalize() { finalized_.store(true, std::memory_order_release); }
    bool IsFinalized() const { return finalized_.load(std::memory_order_acquire); }
    
private:
    bool LoadIndex();
    std::shared_ptr<GeoSiteData> LoadTag(const std::string& tag);
    
    std::filesystem::path dat_path_;
    bool index_loaded_ = false;
    
    struct TagInfo {
        uint64_t offset;
        uint64_t size;
    };
    std::unordered_map<std::string, TagInfo> tag_index_;
    
    mutable std::shared_mutex mutex_;  // 仅在加载阶段使用
    std::unordered_map<std::string, std::shared_ptr<GeoSiteData>> loaded_;
    
    // 加载完成标志
    std::atomic<bool> finalized_{false};
};

// ============================================================================
// 全局 Geo 管理器
// ============================================================================
class GeoManager {
public:
    GeoManager() = default;
    
    // 初始化
    bool Init(const std::filesystem::path& geoip_path,
              const std::filesystem::path& geosite_path);
    
    // 预加载指定的 tag（从路由规则中提取）
    // 预加载完成后会自动调用 Finalize() 启用无锁查询
    void PreloadTags(const std::vector<std::string>& geoip_tags,
                     const std::vector<std::string>& geosite_tags);
    
    // 匹配（const：内部 loader 为 mutable，懒加载线程安全）
    bool MatchGeoIP(const std::string& tag, const net::ip::address& ip) const;
    bool MatchGeoIP(const std::string& tag, const std::string& ip_str) const;
    bool MatchGeoSite(const std::string& tag, const std::string& domain) const;
    
    // 统计
    struct Stats {
        size_t geoip_tags_loaded;
        size_t geosite_tags_loaded;
        size_t geoip_total_cidrs;
        size_t geosite_total_entries;
    };
    Stats GetStats() const;
    
private:
    mutable std::unique_ptr<GeoIPLoader> geoip_loader_;
    mutable std::unique_ptr<GeoSiteLoader> geosite_loader_;
};

}  // namespace geo
}  // namespace acpp
