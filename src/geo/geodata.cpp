#include "acppnode/geo/geodata.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛
#include "acppnode/common/string_hash.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace acpp {
namespace geo {

// ============================================================================
// IP CIDR 表示
// ============================================================================
struct CIDR {
    std::array<uint8_t, 16> addr{};
    uint8_t prefix = 0;
    bool is_v6 = false;
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
    std::vector<Node> nodes_{1};
};

// ============================================================================
// IPv6 Radix Trie — 位前缀树，O(128) 最坏查询
// ============================================================================
class IPv6RadixTrie {
public:
    void Insert(const std::array<uint8_t, 16>& ip, uint8_t prefix);
    bool Match(const std::array<uint8_t, 16>& ip) const;
    bool Empty() const { return nodes_.size() <= 1; }

private:
    struct Node {
        int children[2]{-1, -1};
        bool terminal = false;
    };
    std::vector<Node> nodes_{1};
};

// ============================================================================
// GeoIP 数据
// ============================================================================
class GeoIPData {
public:
    void AddCIDR(const CIDR& cidr);
    bool Match(const net::ip::address& ip) const;
    size_t Size() const noexcept { return count_; }

private:
    IPv4RadixTrie trie_v4_;
    IPv6RadixTrie trie_v6_;
    size_t count_ = 0;
};

// ============================================================================
// 域名后缀 Trie — 反向字符 trie，O(域名长度) 查询
// ============================================================================
class SuffixTrie {
public:
    void Insert(const std::string& domain);
    bool Match(std::string_view domain) const;
    bool Empty() const { return nodes_.size() <= 1; }

private:
    struct Child {
        char ch;
        int node_index;
    };

    struct Node {
        std::vector<Child> children;
        bool terminal = false;
    };
    std::vector<Node> nodes_{1};
};

class GeoSiteData {
public:
    enum class Type {
        PLAIN,
        DomainSuffix,
        FULL,
        REGEXP
    };

    void AddEntry(Type type, const std::string& value);
    bool Match(std::string_view domain) const;
    size_t Size() const noexcept { return count_; }

private:
    std::unordered_set<std::string, TransparentStringHash,
                       TransparentStringEq> full_domains_;
    SuffixTrie suffix_trie_;
    std::vector<std::string> plain_keywords_;
    size_t count_ = 0;
};

// ============================================================================
// GeoIP 只读加载器（启动期预加载后冻结）
// ============================================================================
class GeoIPLoader {
public:
    explicit GeoIPLoader(const std::filesystem::path& dat_path);

    void Preload(const std::vector<std::string>& tags);
    [[nodiscard]] const GeoIPData* Get(std::string_view lower_tag) const noexcept;
    [[nodiscard]] size_t LoadedCount() const noexcept { return loaded_.size(); }

private:
    bool LoadIndex();
    void LoadTag(const std::string& lower_tag);

    std::filesystem::path dat_path_;
    bool index_loaded_ = false;

    struct TagInfo {
        uint64_t offset;
        uint64_t size;
    };
    std::unordered_map<std::string, TagInfo, TransparentStringHash, TransparentStringEq> tag_index_;
    std::unordered_map<std::string, std::unique_ptr<GeoIPData>,
                       TransparentStringHash, TransparentStringEq> loaded_;
};

// ============================================================================
// GeoSite 只读加载器（启动期预加载后冻结）
// ============================================================================
class GeoSiteLoader {
public:
    explicit GeoSiteLoader(const std::filesystem::path& dat_path);

    void Preload(const std::vector<std::string>& tags);
    [[nodiscard]] const GeoSiteData* Get(std::string_view lower_tag) const noexcept;
    [[nodiscard]] size_t LoadedCount() const noexcept { return loaded_.size(); }

private:
    bool LoadIndex();
    void LoadTag(const std::string& lower_tag);

    std::filesystem::path dat_path_;
    bool index_loaded_ = false;

    struct TagInfo {
        uint64_t offset;
        uint64_t size;
    };
    std::unordered_map<std::string, TagInfo, TransparentStringHash, TransparentStringEq> tag_index_;
    std::unordered_map<std::string, std::unique_ptr<GeoSiteData>,
                       TransparentStringHash, TransparentStringEq> loaded_;
};

struct GeoManager::Impl {
    std::unique_ptr<GeoIPLoader> geoip_loader;
    std::unique_ptr<GeoSiteLoader> geosite_loader;
};

namespace {

char LowerAscii(unsigned char c) {
    return static_cast<char>(std::tolower(c));
}

std::string LowerTag(std::string_view tag) {
    std::string lower(tag);
    std::ranges::transform(lower, lower.begin(), LowerAscii);
    return lower;
}

auto LowerBoundSuffixChild(auto& children, char ch) {
    return std::lower_bound(
        children.begin(), children.end(), ch,
        [](const auto& child, char value) {
            return child.ch < value;
        });
}

}  // anonymous namespace

// ============================================================================
// IPv4 Radix Trie 实现
// ============================================================================

void IPv4RadixTrie::Insert(uint32_t ip, uint8_t prefix) {
    int node = 0;
    for (uint8_t i = 0; i < prefix; ++i) {
        int bit = (ip >> (31 - i)) & 1;
        if (nodes_[node].children[bit] < 0) {
            nodes_[node].children[bit] = static_cast<int>(nodes_.size());
            nodes_.push_back({});
        }
        node = nodes_[node].children[bit];
    }
    nodes_[node].terminal = true;
}

bool IPv4RadixTrie::Match(uint32_t ip) const {
    int node = 0;
    for (uint8_t i = 0; i < 32; ++i) {
        if (nodes_[node].terminal) return true;
        int bit = (ip >> (31 - i)) & 1;
        int next = nodes_[node].children[bit];
        if (next < 0) return false;
        node = next;
    }
    return nodes_[node].terminal;
}

// ============================================================================
// IPv6 Radix Trie 实现
// ============================================================================

void IPv6RadixTrie::Insert(const std::array<uint8_t, 16>& ip, uint8_t prefix) {
    int node = 0;
    for (uint8_t i = 0; i < prefix; ++i) {
        const uint8_t byte = ip[i / 8];
        const int bit = (byte >> (7 - (i % 8))) & 1;
        if (nodes_[node].children[bit] < 0) {
            nodes_[node].children[bit] = static_cast<int>(nodes_.size());
            nodes_.push_back({});
        }
        node = nodes_[node].children[bit];
    }
    nodes_[node].terminal = true;
}

bool IPv6RadixTrie::Match(const std::array<uint8_t, 16>& ip) const {
    int node = 0;
    for (uint8_t i = 0; i < 128; ++i) {
        if (nodes_[node].terminal) return true;
        const uint8_t byte = ip[i / 8];
        const int bit = (byte >> (7 - (i % 8))) & 1;
        const int next = nodes_[node].children[bit];
        if (next < 0) return false;
        node = next;
    }
    return nodes_[node].terminal;
}

// ============================================================================
// SuffixTrie 实现（域名后缀匹配用）
// ============================================================================

void SuffixTrie::Insert(const std::string& domain) {
    int node = 0;
    // 反向遍历域名字符，构建反向 trie
    for (auto it = domain.rbegin(); it != domain.rend(); ++it) {
        char c = static_cast<char>(::tolower(static_cast<unsigned char>(*it)));
        auto& children = nodes_[node].children;
        auto child_it = LowerBoundSuffixChild(children, c);
        if (child_it == children.end() || child_it->ch != c) {
            int new_id = static_cast<int>(nodes_.size());
            nodes_.push_back({});
            auto& refreshed_children = nodes_[node].children;
            auto insert_it = LowerBoundSuffixChild(refreshed_children, c);
            refreshed_children.insert(insert_it, SuffixTrie::Child{c, new_id});
            node = new_id;
        } else {
            node = child_it->node_index;
        }
    }
    // 标记为域名边界（需要在 '.' 处才算真正的后缀匹配）
    nodes_[node].terminal = true;
}

bool SuffixTrie::Match(std::string_view domain) const {
    if (nodes_.size() <= 1) return false;

    int node = 0;
    // 反向遍历已小写化的域名，在 trie 中查找
    for (auto it = domain.rbegin(); it != domain.rend(); ++it) {
        const char c = *it;
        const auto& children = nodes_[node].children;
        auto child_it = LowerBoundSuffixChild(children, c);
        if (child_it == children.end() || child_it->ch != c) return false;
        node = child_it->node_index;

        if (nodes_[node].terminal) {
            auto next_it = std::next(it);
            if (next_it == domain.rend() || *next_it == '.') {
                return true;
            }
        }
    }
    return nodes_[node].terminal;
}

// ============================================================================
// GeoIPData 实现
// ============================================================================

void GeoIPData::AddCIDR(const CIDR& cidr) {
    if (cidr.is_v6) {
        if (cidr.prefix > 128) return;
        trie_v6_.Insert(cidr.addr, cidr.prefix);
        ++count_;
    } else {
        if (cidr.prefix > 32) return;
        const uint32_t ip = (static_cast<uint32_t>(cidr.addr[0]) << 24) |
                            (static_cast<uint32_t>(cidr.addr[1]) << 16) |
                            (static_cast<uint32_t>(cidr.addr[2]) << 8)  |
                            static_cast<uint32_t>(cidr.addr[3]);
        trie_v4_.Insert(ip, cidr.prefix);
        ++count_;
    }
}

bool GeoIPData::Match(const net::ip::address& ip) const {
    if (ip.is_v4()) {
        const auto bytes = ip.to_v4().to_bytes();
        const uint32_t ip_val = (static_cast<uint32_t>(bytes[0]) << 24) |
                                (static_cast<uint32_t>(bytes[1]) << 16) |
                                (static_cast<uint32_t>(bytes[2]) << 8)  |
                                static_cast<uint32_t>(bytes[3]);
        return trie_v4_.Match(ip_val);
    }
    if (ip.is_v6()) {
        return trie_v6_.Match(ip.to_v6().to_bytes());
    }
    return false;
}

// ============================================================================
// GeoSiteData 实现
// ============================================================================

void GeoSiteData::AddEntry(Type type, const std::string& value) {
    ++count_;
    if (type == Type::FULL) {
        full_domains_.insert(LowerTag(value));
    } else if (type == Type::DomainSuffix) {
        suffix_trie_.Insert(value);
    } else if (type == Type::PLAIN) {
        plain_keywords_.push_back(LowerTag(value));
    }
}

bool GeoSiteData::Match(std::string_view domain) const {
    char stack_buf[256];
    std::string heap_buf;
    char* lower_ptr;

    if (domain.size() <= sizeof(stack_buf)) {
        lower_ptr = stack_buf;
    } else {
        heap_buf.resize(domain.size());
        lower_ptr = heap_buf.data();
    }

    for (size_t i = 0; i < domain.size(); ++i) {
        lower_ptr[i] = LowerAscii(static_cast<unsigned char>(domain[i]));
    }
    std::string_view lower_domain(lower_ptr, domain.size());

    if (full_domains_.contains(lower_domain)) {
        return true;
    }
    if (suffix_trie_.Match(lower_domain)) {
        return true;
    }
    for (const auto& keyword : plain_keywords_) {
        if (lower_domain.find(keyword) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// V2Ray dat 文件格式
// ============================================================================
//
// GeoIP dat 文件格式 (protobuf):
// message GeoIP {
//   string country_code = 1;
//   repeated CIDR cidr = 2;
// }
// message GeoIPList {
//   repeated GeoIP entry = 1;
// }
//
// GeoSite dat 文件格式 (protobuf):
// message Domain {
//   Type type = 1;
//   string value = 2;
// }
// message GeoSite {
//   string country_code = 1;
//   repeated Domain domain = 2;
// }
// message GeoSiteList {
//   repeated GeoSite entry = 1;
// }
//
// 我们使用简化的解析，不依赖 protobuf 库
// ============================================================================

namespace {

// Protobuf varint 解码
uint64_t ReadVarint(const uint8_t*& ptr, const uint8_t* end) {
    uint64_t result = 0;
    int shift = 0;
    while (ptr < end) {
        uint8_t byte = *ptr++;
        result |= static_cast<uint64_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) {
            break;
        }
        shift += 7;
    }
    return result;
}

// 读取 length-delimited 字段
std::pair<const uint8_t*, size_t> ReadLengthDelimited(const uint8_t*& ptr, const uint8_t* end) {
    uint64_t len = ReadVarint(ptr, end);
    const uint8_t* data = ptr;
    ptr += len;
    return {data, static_cast<size_t>(len)};
}

// 跳过一个字段
void SkipField(const uint8_t*& ptr, const uint8_t* end, int wire_type) {
    switch (wire_type) {
        case 0:  // Varint
            ReadVarint(ptr, end);
            break;
        case 1:  // 64-bit
            ptr += 8;
            break;
        case 2:  // Length-delimited
            {
                uint64_t len = ReadVarint(ptr, end);
                ptr += len;
            }
            break;
        case 5:  // 32-bit
            ptr += 4;
            break;
        default:
            break;
    }
}

}  // anonymous namespace

// ============================================================================
// GeoIPLoader 实现
// ============================================================================

GeoIPLoader::GeoIPLoader(const std::filesystem::path& dat_path)
    : dat_path_(dat_path) {
}

bool GeoIPLoader::LoadIndex() {
    if (index_loaded_) {
        return true;
    }

    std::ifstream file(dat_path_, std::ios::binary);
    if (!file) {
        LOG_ERROR("GeoIP: failed to open {}", dat_path_.string());
        return false;
    }

    // 读取整个文件
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(file_size);
    file.read(unsafe::ptr_cast<char>(data.data()), file_size);

    const uint8_t* ptr = data.data();
    const uint8_t* end = ptr + file_size;

    // 解析 GeoIPList
    while (ptr < end) {
        uint64_t tag_value = ReadVarint(ptr, end);
        uint32_t field_number = static_cast<uint32_t>(tag_value >> 3);
        uint32_t wire_type = static_cast<uint32_t>(tag_value & 0x7);

        if (field_number == 1 && wire_type == 2) {
            // GeoIP entry
            auto [entry_data, entry_len] = ReadLengthDelimited(ptr, end);
            const uint8_t* entry_ptr = entry_data;
            const uint8_t* entry_end = entry_data + entry_len;

            std::string country_code;

            while (entry_ptr < entry_end) {
                uint64_t sub_tag = ReadVarint(entry_ptr, entry_end);
                uint32_t sub_field = static_cast<uint32_t>(sub_tag >> 3);
                uint32_t sub_wire = static_cast<uint32_t>(sub_tag & 0x7);

                if (sub_field == 1 && sub_wire == 2) {
                    // country_code
                    auto [cc_data, cc_len] = ReadLengthDelimited(entry_ptr, entry_end);
                    country_code.assign(unsafe::ptr_cast<const char>(cc_data), cc_len);
                    // 转小写
                    std::ranges::transform(country_code, country_code.begin(), LowerAscii);
                } else if (sub_field == 2 && sub_wire == 2) {
                    // CIDR (skip for now, just record position)
                    SkipField(entry_ptr, entry_end, sub_wire);
                } else {
                    SkipField(entry_ptr, entry_end, sub_wire);
                }
            }

            if (!country_code.empty()) {
                TagInfo info;
                info.offset = entry_data - data.data();
                info.size = entry_len;
                tag_index_[country_code] = info;
            }
        } else {
            SkipField(ptr, end, wire_type);
        }
    }

    index_loaded_ = true;
    LOG_DEBUG("GeoIP: indexed {} tags from {}", tag_index_.size(), dat_path_.string());
    return true;
}

void GeoIPLoader::Preload(const std::vector<std::string>& tags) {
    for (const auto& tag : tags) {
        LoadTag(LowerTag(tag));
    }
    tag_index_.clear();
    tag_index_.rehash(0);
}

const GeoIPData* GeoIPLoader::Get(std::string_view lower_tag) const noexcept {
    const auto it = loaded_.find(lower_tag);
    return (it != loaded_.end()) ? it->second.get() : nullptr;
}

void GeoIPLoader::LoadTag(const std::string& tag) {
    if (loaded_.contains(tag)) {
        return;
    }

    if (!LoadIndex()) {
        return;
    }

    const auto tag_it = tag_index_.find(tag);
    if (tag_it == tag_index_.end()) {
        LOG_DEBUG("GeoIP: tag '{}' not found", tag);
        return;
    }

    std::ifstream file(dat_path_, std::ios::binary);
    if (!file) {
        return;
    }

    file.seekg(tag_it->second.offset);
    std::vector<uint8_t> data(tag_it->second.size);
    file.read(unsafe::ptr_cast<char>(data.data()), data.size());

    auto geoip_data = std::make_unique<GeoIPData>();
    auto* geoip_ptr = geoip_data.get();
    const uint8_t* ptr = data.data();
    const uint8_t* end = ptr + data.size();

    while (ptr < end) {
        uint64_t tag_value = ReadVarint(ptr, end);
        uint32_t field_number = static_cast<uint32_t>(tag_value >> 3);
        uint32_t wire_type = static_cast<uint32_t>(tag_value & 0x7);

        if (field_number == 2 && wire_type == 2) {
            // CIDR
            auto [cidr_data, cidr_len] = ReadLengthDelimited(ptr, end);
            const uint8_t* cidr_ptr = cidr_data;
            const uint8_t* cidr_end = cidr_data + cidr_len;

            CIDR cidr;
            cidr.addr.fill(0);
            cidr.prefix = 0;

            while (cidr_ptr < cidr_end) {
                uint64_t sub_tag = ReadVarint(cidr_ptr, cidr_end);
                uint32_t sub_field = static_cast<uint32_t>(sub_tag >> 3);
                uint32_t sub_wire = static_cast<uint32_t>(sub_tag & 0x7);

                if (sub_field == 1 && sub_wire == 2) {
                    // ip bytes
                    auto [ip_data, ip_len] = ReadLengthDelimited(cidr_ptr, cidr_end);
                    if (ip_len == 4) {
                        std::memcpy(cidr.addr.data(), ip_data, 4);
                        cidr.is_v6 = false;
                    } else if (ip_len == 16) {
                        std::memcpy(cidr.addr.data(), ip_data, 16);
                        cidr.is_v6 = true;
                    }
                } else if (sub_field == 2 && sub_wire == 0) {
                    // prefix
                    cidr.prefix = static_cast<uint8_t>(ReadVarint(cidr_ptr, cidr_end));
                } else {
                    SkipField(cidr_ptr, cidr_end, sub_wire);
                }
            }

            geoip_data->AddCIDR(cidr);
        } else {
            SkipField(ptr, end, wire_type);
        }
    }

    loaded_[tag] = std::move(geoip_data);
    LOG_DEBUG("GeoIP: loaded tag '{}' with {} CIDRs", tag, geoip_ptr->Size());
}

// ============================================================================
// GeoSiteLoader 实现
// ============================================================================

GeoSiteLoader::GeoSiteLoader(const std::filesystem::path& dat_path)
    : dat_path_(dat_path) {
}

bool GeoSiteLoader::LoadIndex() {
    if (index_loaded_) {
        return true;
    }

    std::ifstream file(dat_path_, std::ios::binary);
    if (!file) {
        LOG_ERROR("GeoSite: failed to open {}", dat_path_.string());
        return false;
    }

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(file_size);
    file.read(unsafe::ptr_cast<char>(data.data()), file_size);

    const uint8_t* ptr = data.data();
    const uint8_t* end = ptr + file_size;

    while (ptr < end) {
        uint64_t tag_value = ReadVarint(ptr, end);
        uint32_t field_number = static_cast<uint32_t>(tag_value >> 3);
        uint32_t wire_type = static_cast<uint32_t>(tag_value & 0x7);

        if (field_number == 1 && wire_type == 2) {
            auto [entry_data, entry_len] = ReadLengthDelimited(ptr, end);
            const uint8_t* entry_ptr = entry_data;
            const uint8_t* entry_end = entry_data + entry_len;

            std::string country_code;

            while (entry_ptr < entry_end) {
                uint64_t sub_tag = ReadVarint(entry_ptr, entry_end);
                uint32_t sub_field = static_cast<uint32_t>(sub_tag >> 3);
                uint32_t sub_wire = static_cast<uint32_t>(sub_tag & 0x7);

                if (sub_field == 1 && sub_wire == 2) {
                    auto [cc_data, cc_len] = ReadLengthDelimited(entry_ptr, entry_end);
                    country_code.assign(unsafe::ptr_cast<const char>(cc_data), cc_len);
                    std::ranges::transform(country_code, country_code.begin(), LowerAscii);
                } else {
                    SkipField(entry_ptr, entry_end, sub_wire);
                }
            }

            if (!country_code.empty()) {
                TagInfo info;
                info.offset = entry_data - data.data();
                info.size = entry_len;
                tag_index_[country_code] = info;
            }
        } else {
            SkipField(ptr, end, wire_type);
        }
    }

    index_loaded_ = true;
    LOG_DEBUG("GeoSite: indexed {} tags from {}", tag_index_.size(), dat_path_.string());
    return true;
}

void GeoSiteLoader::Preload(const std::vector<std::string>& tags) {
    for (const auto& tag : tags) {
        LoadTag(LowerTag(tag));
    }
    tag_index_.clear();
    tag_index_.rehash(0);
}

const GeoSiteData* GeoSiteLoader::Get(std::string_view lower_tag) const noexcept {
    const auto it = loaded_.find(lower_tag);
    return (it != loaded_.end()) ? it->second.get() : nullptr;
}

void GeoSiteLoader::LoadTag(const std::string& tag) {
    if (loaded_.contains(tag)) {
        return;
    }

    if (!LoadIndex()) {
        return;
    }

    const auto tag_it = tag_index_.find(tag);
    if (tag_it == tag_index_.end()) {
        LOG_DEBUG("GeoSite: tag '{}' not found", tag);
        return;
    }

    std::ifstream file(dat_path_, std::ios::binary);
    if (!file) {
        return;
    }

    file.seekg(tag_it->second.offset);
    std::vector<uint8_t> data(tag_it->second.size);
    file.read(unsafe::ptr_cast<char>(data.data()), data.size());

    auto geosite_data = std::make_unique<GeoSiteData>();
    auto* geosite_ptr = geosite_data.get();
    const uint8_t* ptr = data.data();
    const uint8_t* end = ptr + data.size();

    while (ptr < end) {
        uint64_t tag_value = ReadVarint(ptr, end);
        uint32_t field_number = static_cast<uint32_t>(tag_value >> 3);
        uint32_t wire_type = static_cast<uint32_t>(tag_value & 0x7);

        if (field_number == 2 && wire_type == 2) {
            // Domain
            auto [domain_data, domain_len] = ReadLengthDelimited(ptr, end);
            const uint8_t* domain_ptr = domain_data;
            const uint8_t* domain_end = domain_data + domain_len;

            GeoSiteData::Type type = GeoSiteData::Type::PLAIN;
            std::string value;

            while (domain_ptr < domain_end) {
                uint64_t sub_tag = ReadVarint(domain_ptr, domain_end);
                uint32_t sub_field = static_cast<uint32_t>(sub_tag >> 3);
                uint32_t sub_wire = static_cast<uint32_t>(sub_tag & 0x7);

                if (sub_field == 1 && sub_wire == 0) {
                    // type
                    uint64_t type_val = ReadVarint(domain_ptr, domain_end);
                    switch (type_val) {
                        case 0: type = GeoSiteData::Type::PLAIN; break;
                        case 1: type = GeoSiteData::Type::REGEXP; break;
                        case 2: type = GeoSiteData::Type::DomainSuffix; break;
                        case 3: type = GeoSiteData::Type::FULL; break;
                        default: break;
                    }
                } else if (sub_field == 2 && sub_wire == 2) {
                    // value
                    auto [val_data, val_len] = ReadLengthDelimited(domain_ptr, domain_end);
                    value.assign(unsafe::ptr_cast<const char>(val_data), val_len);
                } else {
                    SkipField(domain_ptr, domain_end, sub_wire);
                }
            }

            if (!value.empty()) {
                geosite_data->AddEntry(type, value);
            }
        } else {
            SkipField(ptr, end, wire_type);
        }
    }

    loaded_[tag] = std::move(geosite_data);
    LOG_DEBUG("GeoSite: loaded tag '{}' with {} entries", tag, geosite_ptr->Size());
}
// ============================================================================
// GeoManager 实现
// ============================================================================

GeoManager::GeoManager()
    : impl_(std::make_unique<Impl>()) {
}

GeoManager::~GeoManager() = default;

bool GeoManager::Init(const std::filesystem::path& geoip_path,
                      const std::filesystem::path& geosite_path) {
    if (std::filesystem::exists(geoip_path)) {
        impl_->geoip_loader = std::make_unique<GeoIPLoader>(geoip_path);
        LOG_DEBUG("GeoIP: loaded from {}", geoip_path.string());
    }

    if (std::filesystem::exists(geosite_path)) {
        impl_->geosite_loader = std::make_unique<GeoSiteLoader>(geosite_path);
        LOG_DEBUG("GeoSite: loaded from {}", geosite_path.string());
    }

    return impl_->geoip_loader || impl_->geosite_loader;
}

void GeoManager::PreloadTags(const std::vector<std::string>& geoip_tags,
                             const std::vector<std::string>& geosite_tags) {
    if (impl_->geoip_loader) {
        impl_->geoip_loader->Preload(geoip_tags);
        LOG_DEBUG("GeoIP finalized: {} tags loaded, lock-free queries enabled",
                 impl_->geoip_loader->LoadedCount());
    }

    if (impl_->geosite_loader) {
        impl_->geosite_loader->Preload(geosite_tags);
        LOG_DEBUG("GeoSite finalized: {} tags loaded, lock-free queries enabled",
                 impl_->geosite_loader->LoadedCount());
    }
}

GeoManager::GeoIPTagHandle GeoManager::ResolveGeoIPTag(std::string_view tag) const {
    if (!impl_->geoip_loader) {
        return {};
    }
    const auto lower_tag = LowerTag(tag);
    return GeoIPTagHandle{impl_->geoip_loader->Get(lower_tag)};
}

GeoManager::GeoSiteTagHandle GeoManager::ResolveGeoSiteTag(std::string_view tag) const {
    if (!impl_->geosite_loader) {
        return {};
    }
    const auto lower_tag = LowerTag(tag);
    return GeoSiteTagHandle{impl_->geosite_loader->Get(lower_tag)};
}

bool GeoManager::MatchGeoIP(GeoIPTagHandle handle, const net::ip::address& ip) const {
    const auto* data = static_cast<const GeoIPData*>(handle.data);
    return data && data->Match(ip);
}

bool GeoManager::MatchGeoSite(GeoSiteTagHandle handle, std::string_view domain) const {
    const auto* data = static_cast<const GeoSiteData*>(handle.data);
    return data && data->Match(domain);
}

GeoManager::Stats GeoManager::GetStats() const noexcept {
    Stats stats{};
    if (impl_->geoip_loader) {
        stats.geoip_tags_loaded = impl_->geoip_loader->LoadedCount();
    }
    if (impl_->geosite_loader) {
        stats.geosite_tags_loaded = impl_->geosite_loader->LoadedCount();
    }
    return stats;
}

}  // namespace geo
}  // namespace acpp
