#include <gtest/gtest.h>

#include "geo/geodata.hpp"
#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using ::geo::GeoDatabase;
namespace fs = std::filesystem;

void AppendVarint(std::string& out, uint64_t value) {
    while (value >= 0x80) {
        out.push_back(static_cast<char>((value & 0x7F) | 0x80));
        value >>= 7;
    }
    out.push_back(static_cast<char>(value));
}

void AppendBytes(std::string& out, uint32_t field, std::string_view value) {
    AppendVarint(out, (uint64_t{field} << 3) | 2);
    AppendVarint(out, value.size());
    out.append(value);
}

void AppendUint(std::string& out, uint32_t field, uint64_t value) {
    AppendVarint(out, uint64_t{field} << 3);
    AppendVarint(out, value);
}

std::string Cidr(std::string_view ip, uint64_t prefix) {
    std::string message;
    AppendBytes(message, 1, ip);
    AppendUint(message, 2, prefix);
    return message;
}

std::string Domain(uint64_t type, std::string_view value) {
    std::string message;
    AppendUint(message, 1, type);
    AppendBytes(message, 2, value);
    return message;
}

std::string Entry(std::string_view code, const std::vector<std::string>& items) {
    std::string entry;
    AppendBytes(entry, 1, code);
    for (const auto& item : items) {
        AppendBytes(entry, 2, item);
    }
    return entry;
}

std::string List(const std::vector<std::string>& entries) {
    std::string list;
    for (const auto& entry : entries) {
        AppendBytes(list, 1, entry);
    }
    return list;
}

const std::string kV4Net{"\x01\x02\x03\x00", 4};
const std::string kV6Net{"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16};

class TempDir {
public:
    TempDir() {
        std::string pattern = (fs::temp_directory_path() / "cnode_geodata_test_XXXXXX").string();
        const char* created = ::mkdtemp(pattern.data());
        if (!created) throw std::runtime_error("cannot create geodata test directory");
        path_ = created;
    }
    ~TempDir() {
        std::error_code ignored;
        fs::remove_all(path_, ignored);
    }

    fs::path Write(std::string_view name, std::string_view bytes) const {
        const auto file = path_ / name;
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        return file;
    }

    [[nodiscard]] fs::path Path(std::string_view name) const { return path_ / name; }

private:
    fs::path path_;
};

TEST(Geodata, LoadsOnlyRequestedIpCategoriesAndMatchesBothFamilies) {
    const TempDir dir;
    const auto geoip = dir.Write("geoip.dat", List({
        Entry("CN", {Cidr(kV4Net, 24), Cidr(kV6Net, 32)}),
        Entry("US", {Cidr(std::string("\x08\x08\x08\x08", 4), 32)}),
    }));
    const GeoDatabase db(geoip, std::vector<std::string>{"cn"},
                         dir.Write("empty.dat", ""), std::vector<std::string>{});
    EXPECT_EQ(db.GetStats().geoip_tags_loaded, 1);
    EXPECT_EQ(db.FindGeoIP("us"), nullptr);
    const auto* cn = db.FindGeoIP("CN");
    ASSERT_NE(cn, nullptr);
    EXPECT_TRUE(cn->Match(asio::ip::make_address("1.2.3.200")));
    EXPECT_FALSE(cn->Match(asio::ip::make_address("1.2.4.1")));
    EXPECT_TRUE(cn->Match(asio::ip::make_address("2001:db8:1::1")));
    EXPECT_FALSE(cn->Match(asio::ip::make_address("2001:db9::1")));
}

TEST(Geodata, MatchesDomainCategoriesWithLabelBoundaries) {
    const TempDir dir;
    const auto geosite = dir.Write("geosite.dat", List({
        Entry("TEST", {Domain(2, "Example.com"), Domain(3, "full.org"),
                       Domain(0, "kw"), Domain(1, "^re")}),
    }));
    const GeoDatabase db(dir.Write("empty.dat", ""), std::vector<std::string>{},
                         geosite, std::vector<std::string>{"Test"});
    EXPECT_EQ(db.GetStats().geosite_tags_loaded, 1);
    const auto* site = db.FindGeoSite("TEST");
    ASSERT_NE(site, nullptr);
    EXPECT_TRUE(site->Match("a.example.com"));
    EXPECT_TRUE(site->Match("EXAMPLE.com."));
    EXPECT_FALSE(site->Match("badexample.com"));
    EXPECT_TRUE(site->Match("FULL.org"));
    EXPECT_FALSE(site->Match("x.full.org"));
    EXPECT_TRUE(site->Match("abkwcd.net"));
    EXPECT_FALSE(site->Match("re.net"));
}

class InvalidGeodata : public ::testing::TestWithParam<int> {};
TEST_P(InvalidGeodata, RejectsCorruptOrIncompleteRequestedData) {
    const TempDir dir;
    const std::vector<std::string> cn{"cn"};
    const std::vector<std::string> none;
    const auto empty_site = dir.Write("empty_site.dat", "");
    auto bytes = List({Entry("CN", {Cidr(kV4Net, 24)})});
    auto requested = cn;
    switch (GetParam()) {
    case 0: requested = {"jp"}; break;
    case 1: bytes.pop_back(); break;
    case 2:
        bytes.clear();
        AppendVarint(bytes, (1 << 3) | 2);
        AppendVarint(bytes, 1000);
        bytes.append("CN");
        break;
    case 3: bytes = List({Entry("CN", {Cidr(kV4Net, 33)})}); break;
    case 4: bytes = List({Entry("CN", {Cidr(std::string("\x01\x02\x03", 3), 8)})}); break;
    case 5:
        bytes = List({Entry("CN", {Cidr(kV4Net, 24)}),
                      Entry("cn", {Cidr(kV4Net, 16)})});
        break;
    }
    const auto file = dir.Write("geoip.dat", bytes);
    EXPECT_THROW((GeoDatabase(file, requested, empty_site, none)), std::runtime_error);
}
INSTANTIATE_TEST_SUITE_P(FileErrors, InvalidGeodata, ::testing::Values(0, 1, 2, 3, 4, 5),
    ([](const ::testing::TestParamInfo<int>& info) {
        constexpr const char* names[]{"MissingTag", "Truncated", "OverlongField",
                                     "WidePrefix", "InvalidAddressLength", "DuplicateTag"};
        return names[info.param];
    }));

TEST(Geodata, RejectsUnreadableRequestedGeositeFile) {
    const TempDir dir;
    const auto geoip = dir.Write("geoip.dat", List({Entry("CN", {Cidr(kV4Net, 24)})}));
    EXPECT_THROW((GeoDatabase(geoip, std::vector<std::string>{"cn"}, dir.Path("absent.dat"),
                              std::vector<std::string>{"cn"})), std::runtime_error);
}
}  // namespace
