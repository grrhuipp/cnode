#include "acppnode/geo/geodata.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛
#include <fstream>
#include <algorithm>
#include <cstring>
#include <string_view>

namespace acpp {
namespace geo {

namespace {

bool MatchPrefix(const uint8_t* ip, const uint8_t* cidr, uint8_t prefix) {
    size_t full_bytes = prefix / 8;
    size_t remaining_bits = prefix % 8;
    
    // 比较完整字节
    if (std::memcmp(ip, cidr, full_bytes) != 0) {
        return false;
    }
    
    // 比较剩余位
    if (remaining_bits > 0) {
        uint8_t mask = 0xFF << (8 - remaining_bits);
        if ((ip[full_bytes] & mask) != (cidr[full_bytes] & mask)) {
            return false;
        }
    }
    
    return true;
}

}  // anonymous namespace

// ============================================================================
// CIDR 实现
// ============================================================================

bool CIDR::Contains(const net::ip::address& ip) const {
    if (!ip.is_v4()) {
        return false;
    }

    auto ip_bytes = ip.to_v4().to_bytes();
    return MatchPrefix(ip_bytes.data(), addr.data(), prefix);
}

namespace {

// 解析 CIDR 字符串
std::optional<CIDR> ParseCIDR(const std::string& str) {
    auto slash_pos = str.find('/');
    if (slash_pos == std::string::npos) {
        return std::nullopt;
    }
    
    std::string ip_str = str.substr(0, slash_pos);
    std::string prefix_str = str.substr(slash_pos + 1);
    
    boost::system::error_code ec;
    auto addr = net::ip::make_address(ip_str, ec);
    if (ec) {
        return std::nullopt;
    }
    
    int prefix = std::stoi(prefix_str);
    
    CIDR cidr;
    cidr.prefix = static_cast<uint8_t>(prefix);
    if (!addr.is_v4()) {
        return std::nullopt;
    }

    auto bytes = addr.to_v4().to_bytes();
    std::memcpy(cidr.addr.data(), bytes.data(), 4);
    
    return cidr;
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
// SuffixTrie 实现（域名后缀匹配用）
// ============================================================================

void SuffixTrie::Insert(const std::string& domain) {
    int node = 0;
    // 反向遍历域名字符，构建反向 trie
    for (auto it = domain.rbegin(); it != domain.rend(); ++it) {
        char c = static_cast<char>(::tolower(static_cast<unsigned char>(*it)));
        auto& children = nodes_[node].children;
        auto child_it = children.find(c);
        if (child_it == children.end()) {
            int new_id = static_cast<int>(nodes_.size());
            children[c] = new_id;
            nodes_.push_back({});
            node = new_id;
        } else {
            node = child_it->second;
        }
    }
    // 标记为域名边界（需要在 '.' 处才算真正的后缀匹配）
    nodes_[node].terminal = true;
}

bool SuffixTrie::Match(std::string_view domain) const {
    if (nodes_.size() <= 1) return false;

    int node = 0;
    // 反向遍历域名，在 trie 中查找
    for (auto it = domain.rbegin(); it != domain.rend(); ++it) {
        char c = static_cast<char>(::tolower(static_cast<unsigned char>(*it)));
        auto& children = nodes_[node].children;
        auto child_it = children.find(c);
        if (child_it == children.end()) return false;
        node = child_it->second;

        // 在 '.' 边界或域名开头检查是否匹配
        if (nodes_[node].terminal) {
            // 检查是否是完整域名或子域名（前一个字符是 '.' 或已到开头）
            auto next_it = std::next(it);
            if (next_it == domain.rend() || *next_it == '.') {
                return true;
            }
        }
    }
    // 完全匹配整个域名
    return nodes_[node].terminal;
}

// ============================================================================
// GeoIPData 实现
// ============================================================================

void GeoIPData::AddCIDR(const CIDR& cidr) {
    cidrs_v4_.push_back(cidr);
}

void GeoIPData::AddCIDR(const std::string& cidr_str) {
    auto cidr = ParseCIDR(cidr_str);
    if (cidr) {
        AddCIDR(*cidr);
    }
}

void GeoIPData::BuildIndex() {
    if (index_built_) return;

    // 构建 IPv4 radix trie
    trie_v4_ = IPv4RadixTrie{};
    for (const auto& cidr : cidrs_v4_) {
        uint32_t ip = (static_cast<uint32_t>(cidr.addr[0]) << 24) |
                      (static_cast<uint32_t>(cidr.addr[1]) << 16) |
                      (static_cast<uint32_t>(cidr.addr[2]) << 8)  |
                      static_cast<uint32_t>(cidr.addr[3]);
        trie_v4_.Insert(ip, cidr.prefix);
    }

    index_built_ = true;
}

bool GeoIPData::Match(const net::ip::address& ip) const {
    if (!ip.is_v4()) {
        return false;
    }

    if (index_built_) {
        auto bytes = ip.to_v4().to_bytes();
        uint32_t ip_val = (static_cast<uint32_t>(bytes[0]) << 24) |
                          (static_cast<uint32_t>(bytes[1]) << 16) |
                          (static_cast<uint32_t>(bytes[2]) << 8)  |
                          static_cast<uint32_t>(bytes[3]);
        return trie_v4_.Match(ip_val);
    }
    for (const auto& cidr : cidrs_v4_) {
        if (cidr.Contains(ip)) {
            return true;
        }
    }
    return false;
}

bool GeoIPData::Match(const std::string& ip_str) const {
    boost::system::error_code ec;
    auto ip = net::ip::make_address(ip_str, ec);
    if (ec) {
        return false;
    }
    return Match(ip);
}

// ============================================================================
// GeoSiteData 实现
// ============================================================================

void GeoSiteData::AddEntry(Type type, const std::string& value) {
    Entry entry{type, value};
    entries_.push_back(entry);

    // 建立快速查找索引
    if (type == Type::FULL) {
        full_domains_.insert(value);
    } else if (type == Type::DOMAIN) {
        suffix_trie_.Insert(value);
    } else if (type == Type::PLAIN) {
        // 小写存储用于包含匹配
        std::string lower = value;
        for (auto& c : lower)
            c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        plain_keywords_.push_back(std::move(lower));
    }
}

bool GeoSiteData::Match(const std::string& domain) const {
    // 使用栈上 buffer 进行小写转换，避免堆分配
    char stack_buf[128];
    std::string heap_buf;
    char* lower_ptr;

    if (domain.size() < sizeof(stack_buf)) {
        lower_ptr = stack_buf;
    } else {
        heap_buf.resize(domain.size());
        lower_ptr = heap_buf.data();
    }

    for (size_t i = 0; i < domain.size(); ++i) {
        lower_ptr[i] = static_cast<char>(::tolower(static_cast<unsigned char>(domain[i])));
    }
    std::string_view lower_domain(lower_ptr, domain.size());

    // 1. 完全匹配（O(1) 哈希查找）
    if (full_domains_.count(std::string(lower_domain)) > 0) {
        return true;
    }

    // 2. 后缀匹配（反向 trie，O(域名长度)）
    if (suffix_trie_.Match(lower_domain)) {
        return true;
    }

    // 3. 包含匹配（PLAIN 关键词线性扫描）
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
                    std::transform(country_code.begin(), country_code.end(),
                                   country_code.begin(), ::tolower);
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

std::shared_ptr<GeoIPData> GeoIPLoader::Get(const std::string& tag) {
    std::string lower_tag = tag;
    std::transform(lower_tag.begin(), lower_tag.end(), lower_tag.begin(), ::tolower);
    
    // 无锁快速路径：加载完成后不需要锁
    if (finalized_.load(std::memory_order_acquire)) {
        auto it = loaded_.find(lower_tag);
        return (it != loaded_.end()) ? it->second : nullptr;
    }
    
    // 加载阶段需要锁
    {
        std::shared_lock lock(mutex_);
        auto it = loaded_.find(lower_tag);
        if (it != loaded_.end()) {
            return it->second;
        }
    }
    
    // 加载
    return LoadTag(lower_tag);
}

std::shared_ptr<GeoIPData> GeoIPLoader::LoadTag(const std::string& tag) {
    std::unique_lock lock(mutex_);
    
    // 双重检查
    auto it = loaded_.find(tag);
    if (it != loaded_.end()) {
        return it->second;
    }
    
    if (!LoadIndex()) {
        return nullptr;
    }
    
    auto tag_it = tag_index_.find(tag);
    if (tag_it == tag_index_.end()) {
        LOG_DEBUG("GeoIP: tag '{}' not found", tag);
        return nullptr;
    }
    
    // 读取并解析
    std::ifstream file(dat_path_, std::ios::binary);
    if (!file) {
        return nullptr;
    }
    
    file.seekg(tag_it->second.offset);
    std::vector<uint8_t> data(tag_it->second.size);
    file.read(unsafe::ptr_cast<char>(data.data()), data.size());
    
    auto geoip_data = std::make_shared<GeoIPData>();
    
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
            std::memset(cidr.addr.data(), 0, 4);
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

    // 构建 IPv4 radix trie 索引加速查询
    geoip_data->BuildIndex();

    loaded_[tag] = geoip_data;
    LOG_DEBUG("GeoIP: loaded tag '{}' with {} CIDRs", tag, geoip_data->Size());
    
    return geoip_data;
}

bool GeoIPLoader::HasTag(const std::string& tag) {
    if (!index_loaded_) {
        LoadIndex();
    }
    
    std::string lower_tag = tag;
    std::transform(lower_tag.begin(), lower_tag.end(), lower_tag.begin(), ::tolower);
    return tag_index_.count(lower_tag) > 0;
}

std::vector<std::string> GeoIPLoader::GetAllTags() {
    if (!index_loaded_) {
        LoadIndex();
    }
    
    std::vector<std::string> tags;
    for (const auto& [tag, _] : tag_index_) {
        tags.push_back(tag);
    }
    return tags;
}

size_t GeoIPLoader::LoadedCount() const {
    if (finalized_.load(std::memory_order_acquire)) {
        return loaded_.size();
    }
    std::shared_lock lock(mutex_);
    return loaded_.size();
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
                    std::transform(country_code.begin(), country_code.end(),
                                   country_code.begin(), ::tolower);
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

std::shared_ptr<GeoSiteData> GeoSiteLoader::Get(const std::string& tag) {
    std::string lower_tag = tag;
    std::transform(lower_tag.begin(), lower_tag.end(), lower_tag.begin(), ::tolower);
    
    // 无锁快速路径：加载完成后不需要锁
    if (finalized_.load(std::memory_order_acquire)) {
        auto it = loaded_.find(lower_tag);
        return (it != loaded_.end()) ? it->second : nullptr;
    }
    
    // 加载阶段需要锁
    {
        std::shared_lock lock(mutex_);
        auto it = loaded_.find(lower_tag);
        if (it != loaded_.end()) {
            return it->second;
        }
    }
    
    return LoadTag(lower_tag);
}

std::shared_ptr<GeoSiteData> GeoSiteLoader::LoadTag(const std::string& tag) {
    std::unique_lock lock(mutex_);
    
    auto it = loaded_.find(tag);
    if (it != loaded_.end()) {
        return it->second;
    }
    
    if (!LoadIndex()) {
        return nullptr;
    }
    
    auto tag_it = tag_index_.find(tag);
    if (tag_it == tag_index_.end()) {
        LOG_DEBUG("GeoSite: tag '{}' not found", tag);
        return nullptr;
    }
    
    std::ifstream file(dat_path_, std::ios::binary);
    if (!file) {
        return nullptr;
    }
    
    file.seekg(tag_it->second.offset);
    std::vector<uint8_t> data(tag_it->second.size);
    file.read(unsafe::ptr_cast<char>(data.data()), data.size());
    
    auto geosite_data = std::make_shared<GeoSiteData>();
    
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
                        case 2: type = GeoSiteData::Type::DOMAIN; break;
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
    
    loaded_[tag] = geosite_data;
    LOG_DEBUG("GeoSite: loaded tag '{}' with {} entries", tag, geosite_data->Size());
    
    return geosite_data;
}

bool GeoSiteLoader::HasTag(const std::string& tag) {
    if (!index_loaded_) {
        LoadIndex();
    }
    
    std::string lower_tag = tag;
    std::transform(lower_tag.begin(), lower_tag.end(), lower_tag.begin(), ::tolower);
    return tag_index_.count(lower_tag) > 0;
}

std::vector<std::string> GeoSiteLoader::GetAllTags() {
    if (!index_loaded_) {
        LoadIndex();
    }
    
    std::vector<std::string> tags;
    for (const auto& [tag, _] : tag_index_) {
        tags.push_back(tag);
    }
    return tags;
}

size_t GeoSiteLoader::LoadedCount() const {
    if (finalized_.load(std::memory_order_acquire)) {
        return loaded_.size();
    }
    std::shared_lock lock(mutex_);
    return loaded_.size();
}

// ============================================================================
// GeoManager 实现
// ============================================================================

bool GeoManager::Init(const std::filesystem::path& geoip_path,
                      const std::filesystem::path& geosite_path) {
    if (std::filesystem::exists(geoip_path)) {
        geoip_loader_ = std::make_unique<GeoIPLoader>(geoip_path);
        LOG_DEBUG("GeoIP: loaded from {}", geoip_path.string());
    }
    
    if (std::filesystem::exists(geosite_path)) {
        geosite_loader_ = std::make_unique<GeoSiteLoader>(geosite_path);
        LOG_DEBUG("GeoSite: loaded from {}", geosite_path.string());
    }
    
    return geoip_loader_ || geosite_loader_;
}

void GeoManager::PreloadTags(const std::vector<std::string>& geoip_tags,
                             const std::vector<std::string>& geosite_tags) {
    if (geoip_loader_) {
        for (const auto& tag : geoip_tags) {
            geoip_loader_->Get(tag);
        }
        // 预加载完成，标记为 finalized（之后的查询无需锁）
        geoip_loader_->Finalize();
        LOG_DEBUG("GeoIP finalized: {} tags loaded, lock-free queries enabled", 
                 geoip_loader_->LoadedCount());
    }
    
    if (geosite_loader_) {
        for (const auto& tag : geosite_tags) {
            geosite_loader_->Get(tag);
        }
        // 预加载完成，标记为 finalized
        geosite_loader_->Finalize();
        LOG_DEBUG("GeoSite finalized: {} tags loaded, lock-free queries enabled",
                 geosite_loader_->LoadedCount());
    }
}

bool GeoManager::MatchGeoIP(const std::string& tag, const net::ip::address& ip) const {
    if (!geoip_loader_) {
        return false;
    }
    
    auto data = geoip_loader_->Get(tag);
    if (!data) {
        return false;
    }
    
    return data->Match(ip);
}

bool GeoManager::MatchGeoIP(const std::string& tag, const std::string& ip_str) const {
    boost::system::error_code ec;
    auto ip = net::ip::make_address(ip_str, ec);
    if (ec) {
        return false;
    }
    return MatchGeoIP(tag, ip);
}

bool GeoManager::MatchGeoSite(const std::string& tag, const std::string& domain) const {
    if (!geosite_loader_) {
        return false;
    }
    
    auto data = geosite_loader_->Get(tag);
    if (!data) {
        return false;
    }
    
    return data->Match(domain);
}

GeoManager::Stats GeoManager::GetStats() const {
    Stats stats{};
    
    if (geoip_loader_) {
        stats.geoip_tags_loaded = geoip_loader_->LoadedCount();
    }
    
    if (geosite_loader_) {
        stats.geosite_tags_loaded = geosite_loader_->LoadedCount();
    }
    
    return stats;
}

}  // namespace geo
}  // namespace acpp
