#include "acppnode/geo/geodata.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/common/unsafe.hpp"

#include <algorithm>
#include <format>
#include <fstream>
#include <limits>
#include <stdexcept>

namespace acpp::geo {

// ============================================================================
// CidrSet
// ============================================================================

CidrSet::CidrSet(std::pmr::memory_resource* resource)
    : v4_(resource), v6_(resource) {}

void CidrSet::Insert(std::span<const uint8_t> network, uint8_t prefix) {
    if ((network.size() != 4 && network.size() != 16) || prefix > network.size() * 8) {
        throw std::invalid_argument("CIDR network must be 4 or 16 bytes with prefix within its width");
    }
    InsertBits(network.size() == 4 ? v4_ : v6_, network, prefix);
}

bool CidrSet::Match(const net::ip::address& ip) const noexcept {
    if (ip.is_v4()) {
        const auto bytes = ip.to_v4().to_bytes();
        return MatchBits(v4_, bytes);
    }
    const auto bytes = ip.to_v6().to_bytes();
    return MatchBits(v6_, bytes);
}

void CidrSet::InsertBits(Trie& trie, std::span<const uint8_t> network, uint8_t prefix) {
    if (trie.empty()) {
        trie.emplace_back();
    }
    int32_t node = 0;
    for (uint8_t i = 0; i < prefix; ++i) {
        const int bit = (network[i / 8] >> (7 - i % 8)) & 1;
        int32_t next = trie[node].children[bit];
        if (next < 0) {
            next = static_cast<int32_t>(trie.size());
            trie.emplace_back();
            trie[node].children[bit] = next;
        }
        node = next;
    }
    trie[node].terminal = true;
}

bool CidrSet::MatchBits(const Trie& trie, std::span<const uint8_t> address) noexcept {
    if (trie.empty()) {
        return false;
    }
    const size_t bits = address.size() * 8;
    int32_t node = 0;
    for (size_t i = 0;; ++i) {
        if (trie[node].terminal) {
            return true;
        }
        if (i == bits) {
            return false;
        }
        node = trie[node].children[(address[i / 8] >> (7 - i % 8)) & 1];
        if (node < 0) {
            return false;
        }
    }
}

// ============================================================================
// DomainRuleSet
// ============================================================================

DomainRuleSet::DomainRuleSet(std::pmr::memory_resource* resource)
    : full_(resource), suffix_nodes_(resource), keywords_(resource), regexes_(resource) {}

void DomainRuleSet::AddFull(std::string_view domain) {
    std::pmr::string lower(domain, full_.get_allocator());
    domain::NormalizeDnsHostnameInPlace(lower);
    full_.insert(std::move(lower));
}

void DomainRuleSet::AddSuffix(std::string_view suffix) {
    std::string lower(suffix);
    domain::NormalizeDnsHostnameInPlace(lower);

    // 子节点向量必须与节点表同属一个 memory_resource。
    const auto new_node = [this] {
        suffix_nodes_.push_back(SuffixNode{
            .children = std::pmr::vector<SuffixChild>(suffix_nodes_.get_allocator()),
        });
    };
    if (suffix_nodes_.empty()) {
        new_node();
    }
    uint32_t node = 0;
    for (auto it = lower.rbegin(); it != lower.rend(); ++it) {
        const char ch = *it;
        auto& children = suffix_nodes_[node].children;
        const auto child = std::ranges::lower_bound(children, ch, {}, &SuffixChild::ch);
        if (child != children.end() && child->ch == ch) {
            node = child->node_index;
            continue;
        }
        const auto position = child - children.begin();
        const auto next = static_cast<uint32_t>(suffix_nodes_.size());
        new_node();  // 使 children 引用失效，下面重新取。
        auto& refreshed = suffix_nodes_[node].children;
        refreshed.insert(refreshed.begin() + position, SuffixChild{ch, next});
        node = next;
    }
    suffix_nodes_[node].terminal = true;
}

void DomainRuleSet::AddKeyword(std::string_view keyword) {
    auto& lower = keywords_.emplace_back(keyword);
    std::ranges::transform(lower, lower.begin(), [](char ch) {
        return domain::ToLowerAscii(static_cast<unsigned char>(ch));
    });
}

void DomainRuleSet::AddRegex(const std::string& pattern) {
    regexes_.emplace_back(pattern, std::regex::ECMAScript | std::regex::icase);
}

bool DomainRuleSet::Match(std::string_view domain) const {
    domain = domain::WithoutTrailingRootDot(domain);
    if (domain.empty()) {
        return false;
    }

    char stack_buf[256];
    std::pmr::string heap_buf;
    char* lower = stack_buf;
    if (domain.size() > sizeof(stack_buf)) {
        heap_buf.resize(domain.size());
        lower = heap_buf.data();
    }
    std::ranges::transform(domain, lower, [](char ch) {
        return domain::ToLowerAscii(static_cast<unsigned char>(ch));
    });
    const std::string_view lower_domain(lower, domain.size());

    if (full_.contains(lower_domain) || MatchSuffix(lower_domain)) {
        return true;
    }
    for (const auto& keyword : keywords_) {
        if (lower_domain.find(keyword) != std::string_view::npos) {
            return true;
        }
    }
    for (const auto& regex : regexes_) {
        if (std::regex_search(lower_domain.begin(), lower_domain.end(), regex)) {
            return true;
        }
    }
    return false;
}

bool DomainRuleSet::MatchSuffix(std::string_view lower_domain) const noexcept {
    if (suffix_nodes_.empty()) {
        return false;
    }
    uint32_t node = 0;
    for (auto it = lower_domain.rbegin(); it != lower_domain.rend(); ++it) {
        const auto& children = suffix_nodes_[node].children;
        const auto child = std::ranges::lower_bound(children, *it, {}, &SuffixChild::ch);
        if (child == children.end() || child->ch != *it) {
            return false;
        }
        node = child->node_index;
        if (suffix_nodes_[node].terminal) {
            const auto next = std::next(it);
            if (next == lower_domain.rend() || *next == '.') {
                return true;
            }
        }
    }
    return false;
}

// ============================================================================
// geoip.dat / geosite.dat（v2ray protobuf）
//
// message GeoIP      { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3; }
// message CIDR       { bytes ip = 1; uint32 prefix = 2; }
// message GeoIPList  { repeated GeoIP entry = 1; }
// message Domain     { Type type = 1; string value = 2; repeated Attribute attribute = 3; }
//                    // Type: Plain = 0, Regex = 1, Domain = 2, Full = 3
// message GeoSite    { string country_code = 1; repeated Domain domain = 2; }
// message GeoSiteList{ repeated GeoSite entry = 1; }
// ============================================================================

namespace {

constexpr uint32_t kWireVarint = 0;
constexpr uint32_t kWireFixed64 = 1;
constexpr uint32_t kWireBytes = 2;
constexpr uint32_t kWireFixed32 = 5;
constexpr uint64_t kMaxFieldNumber = (uint64_t{1} << 29) - 1;

[[noreturn]] void ThrowCorrupt(const std::filesystem::path& path, std::string_view what) {
    throw std::runtime_error(std::format("geodata '{}' is corrupt: {}", path.string(), what));
}

struct ProtoField {
    uint64_t number;
    uint32_t wire_type;
};

// 只覆盖 geodata 用到的 protobuf wire 子集；任何越界、截断或未知 wire type
// 都按文件损坏拒绝，不信任声明长度。
class ProtoReader {
public:
    ProtoReader(std::span<const uint8_t> bytes, const std::filesystem::path& path) noexcept
        : cur_(bytes.data()), end_(bytes.data() + bytes.size()), path_(path) {}

    [[nodiscard]] bool AtEnd() const noexcept { return cur_ == end_; }

    [[nodiscard]] ProtoField NextField() {
        const uint64_t key = Varint();
        const ProtoField field{key >> 3, static_cast<uint32_t>(key & 0x7)};
        if (field.number == 0 || field.number > kMaxFieldNumber) {
            ThrowCorrupt(path_, "invalid protobuf field number");
        }
        return field;
    }

    [[nodiscard]] uint64_t Varint() {
        uint64_t value = 0;
        for (unsigned shift = 0; shift < 64; shift += 7) {
            if (cur_ == end_) {
                ThrowCorrupt(path_, "truncated varint");
            }
            const uint8_t byte = *cur_++;
            value |= static_cast<uint64_t>(byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) {
                return value;
            }
        }
        ThrowCorrupt(path_, "varint longer than 10 bytes");
    }

    [[nodiscard]] std::span<const uint8_t> Bytes() {
        const uint64_t length = Varint();
        if (length > static_cast<uint64_t>(end_ - cur_)) {
            ThrowCorrupt(path_, "length-delimited field exceeds its message");
        }
        const std::span<const uint8_t> bytes(cur_, static_cast<size_t>(length));
        cur_ += length;
        return bytes;
    }

    void Skip(uint32_t wire_type) {
        switch (wire_type) {
            case kWireVarint: (void)Varint(); return;
            case kWireFixed64: Advance(8); return;
            case kWireBytes: (void)Bytes(); return;
            case kWireFixed32: Advance(4); return;
            default: ThrowCorrupt(path_, "unsupported protobuf wire type");
        }
    }

private:
    void Advance(size_t count) {
        if (count > static_cast<size_t>(end_ - cur_)) {
            ThrowCorrupt(path_, "truncated fixed-width field");
        }
        cur_ += count;
    }

    const uint8_t* cur_;
    const uint8_t* end_;
    const std::filesystem::path& path_;
};

[[nodiscard]] std::string_view AsText(std::span<const uint8_t> bytes) noexcept {
    return {unsafe::ptr_cast<const char>(bytes.data()), bytes.size()};
}

[[nodiscard]] std::string LowerTag(std::string_view tag) {
    std::string lower(tag);
    std::ranges::transform(lower, lower.begin(), [](char ch) {
        return domain::ToLowerAscii(static_cast<unsigned char>(ch));
    });
    return lower;
}

[[nodiscard]] std::vector<uint8_t> ReadWholeFile(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error(std::format("failed to open geodata '{}'", path.string()));
    }
    const std::streamoff size = file.tellg();
    if (size < 0) {
        throw std::runtime_error(std::format("failed to size geodata '{}'", path.string()));
    }
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    file.seekg(0);
    if (!file.read(unsafe::ptr_cast<char>(bytes.data()), static_cast<std::streamsize>(size))) {
        throw std::runtime_error(std::format("failed to read geodata '{}'", path.string()));
    }
    return bytes;
}

[[nodiscard]] std::string_view EntryCountryCode(std::span<const uint8_t> entry,
                                                const std::filesystem::path& path) {
    ProtoReader reader(entry, path);
    std::string_view code;
    while (!reader.AtEnd()) {
        const auto field = reader.NextField();
        if (field.number == 1 && field.wire_type == kWireBytes) {
            code = AsText(reader.Bytes());
        } else {
            reader.Skip(field.wire_type);
        }
    }
    return code;
}

void AddGeoIPCidr(std::span<const uint8_t> message, const std::filesystem::path& path,
                  CidrSet& set) {
    ProtoReader reader(message, path);
    std::span<const uint8_t> ip;
    uint64_t prefix = 0;
    while (!reader.AtEnd()) {
        const auto field = reader.NextField();
        if (field.number == 1 && field.wire_type == kWireBytes) {
            ip = reader.Bytes();
        } else if (field.number == 2 && field.wire_type == kWireVarint) {
            prefix = reader.Varint();
        } else {
            reader.Skip(field.wire_type);
        }
    }
    if (ip.size() != 4 && ip.size() != 16) {
        ThrowCorrupt(path, "CIDR address must be 4 or 16 bytes");
    }
    if (prefix > ip.size() * 8) {
        ThrowCorrupt(path, "CIDR prefix exceeds address width");
    }
    set.Insert(ip, static_cast<uint8_t>(prefix));
}

void FillGeoIP(std::span<const uint8_t> entry, const std::filesystem::path& path,
               CidrSet& set) {
    ProtoReader reader(entry, path);
    while (!reader.AtEnd()) {
        const auto field = reader.NextField();
        if (field.number == 2 && field.wire_type == kWireBytes) {
            AddGeoIPCidr(reader.Bytes(), path, set);
        } else if (field.number == 3 && field.wire_type == kWireVarint) {
            if (reader.Varint() != 0) {
                throw std::runtime_error(std::format(
                    "geodata '{}' uses unsupported reverse_match", path.string()));
            }
        } else {
            reader.Skip(field.wire_type);
        }
    }
}

void AddGeoSiteDomain(std::span<const uint8_t> message, const std::filesystem::path& path,
                      DomainRuleSet& set) {
    ProtoReader reader(message, path);
    uint64_t type = 0;
    std::string_view value;
    while (!reader.AtEnd()) {
        const auto field = reader.NextField();
        if (field.number == 1 && field.wire_type == kWireVarint) {
            type = reader.Varint();
        } else if (field.number == 2 && field.wire_type == kWireBytes) {
            value = AsText(reader.Bytes());
        } else {
            reader.Skip(field.wire_type);
        }
    }
    if (type > 3) {
        ThrowCorrupt(path, "unknown geosite domain type");
    }
    if (value.empty()) {
        return;
    }
    switch (type) {
        case 0: set.AddKeyword(value); break;
        case 1: break;  // Regex：不加载，见 GeoDatabase 契约。
        case 2: set.AddSuffix(value); break;
        case 3: set.AddFull(value); break;
    }
}

void FillGeoSite(std::span<const uint8_t> entry, const std::filesystem::path& path,
                 DomainRuleSet& set) {
    ProtoReader reader(entry, path);
    while (!reader.AtEnd()) {
        const auto field = reader.NextField();
        if (field.number == 2 && field.wire_type == kWireBytes) {
            AddGeoSiteDomain(reader.Bytes(), path, set);
        } else {
            reader.Skip(field.wire_type);
        }
    }
}

// GeoIPList 与 GeoSiteList 同构（repeated entry = 1，entry 带 country_code = 1）：
// 单遍扫描列表，只解析被请求的分类。
template <class Set>
void LoadCategories(
    const std::filesystem::path& path,
    std::span<const std::string> tags,
    std::string_view kind,
    std::unordered_map<std::string, Set, TransparentStringHash, TransparentStringEq>& out,
    void (*fill)(std::span<const uint8_t>, const std::filesystem::path&, Set&)) {
    std::vector<std::string> wanted;
    wanted.reserve(tags.size());
    for (const auto& tag : tags) {
        wanted.push_back(LowerTag(tag));
    }
    std::ranges::sort(wanted);
    const auto duplicates = std::ranges::unique(wanted);
    wanted.erase(duplicates.begin(), duplicates.end());
    if (wanted.empty()) {
        return;
    }

    const auto bytes = ReadWholeFile(path);
    ProtoReader list(bytes, path);
    while (!list.AtEnd()) {
        const auto field = list.NextField();
        if (field.number != 1 || field.wire_type != kWireBytes) {
            list.Skip(field.wire_type);
            continue;
        }
        const auto entry = list.Bytes();
        auto code = LowerTag(EntryCountryCode(entry, path));
        if (!std::ranges::binary_search(wanted, code)) {
            continue;
        }
        auto [it, inserted] = out.try_emplace(std::move(code), memory::process_resource());
        if (!inserted) {
            ThrowCorrupt(path, std::format("duplicate {} tag '{}'", kind, it->first));
        }
        fill(entry, path, it->second);
    }

    for (const auto& tag : wanted) {
        if (!out.contains(tag)) {
            throw std::runtime_error(std::format(
                "{} tag '{}' was not found in '{}'", kind, tag, path.string()));
        }
    }
}

}  // namespace

// ============================================================================
// GeoDatabase
// ============================================================================

GeoDatabase::GeoDatabase(const std::filesystem::path& geoip_path,
                         std::span<const std::string> geoip_tags,
                         const std::filesystem::path& geosite_path,
                         std::span<const std::string> geosite_tags) {
    LoadCategories<CidrSet>(geoip_path, geoip_tags, "geoip", geoip_, &FillGeoIP);
    LoadCategories<DomainRuleSet>(geosite_path, geosite_tags, "geosite", geosite_, &FillGeoSite);
}

GeoDatabase::~GeoDatabase() = default;

const CidrSet* GeoDatabase::FindGeoIP(std::string_view tag) const {
    const auto it = geoip_.find(LowerTag(tag));
    return it == geoip_.end() ? nullptr : &it->second;
}

const DomainRuleSet* GeoDatabase::FindGeoSite(std::string_view tag) const {
    const auto it = geosite_.find(LowerTag(tag));
    return it == geosite_.end() ? nullptr : &it->second;
}

GeoDatabase::Stats GeoDatabase::GetStats() const noexcept {
    return Stats{
        .geoip_tags_loaded = geoip_.size(),
        .geosite_tags_loaded = geosite_.size(),
    };
}

}  // namespace acpp::geo
