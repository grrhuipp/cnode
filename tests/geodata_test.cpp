#include <gtest/gtest.h>

#include "geo/geodata.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
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

void Require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
    }
}

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
    TempDir()
        : path_(fs::temp_directory_path() /
                ("cnode_geodata_test_" + std::to_string(std::rand()))) {
        fs::create_directories(path_);
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

template <class Fn>
bool ThrowsRuntimeError(Fn&& fn) {
    try {
        fn();
    } catch (const std::runtime_error&) {
        return true;
    }
    return false;
}

void TestLoadsRequestedCategories(const TempDir& dir) {
    const auto geoip = dir.Write("geoip.dat", List({
        Entry("CN", {Cidr(kV4Net, 24), Cidr(kV6Net, 32)}),
        Entry("US", {Cidr(std::string("\x08\x08\x08\x08", 4), 32)}),
    }));
    const auto geosite = dir.Write("geosite.dat", List({
        Entry("TEST", {Domain(2, "Example.com"), Domain(3, "full.org"),
                       Domain(0, "kw"), Domain(1, "^re")}),
    }));
    const std::vector<std::string> ip_tags{"cn"};
    const std::vector<std::string> site_tags{"Test"};
    const GeoDatabase db(geoip, ip_tags, geosite, site_tags);

    Require(db.GetStats().geoip_tags_loaded == 1 && db.GetStats().geosite_tags_loaded == 1,
            "only requested categories are loaded");
    Require(db.FindGeoIP("us") == nullptr, "unrequested geoip tags stay unloaded");

    const auto* cn = db.FindGeoIP("CN");
    Require(cn != nullptr, "geoip tags resolve case-insensitively");
    Require(cn->Match(asio::ip::make_address("1.2.3.200")), "IPv4 prefix matches");
    Require(!cn->Match(asio::ip::make_address("1.2.4.1")), "IPv4 outside prefix misses");
    Require(cn->Match(asio::ip::make_address("2001:db8:1::1")), "IPv6 prefix matches");
    Require(!cn->Match(asio::ip::make_address("2001:db9::1")), "IPv6 outside prefix misses");

    const auto* site = db.FindGeoSite("TEST");
    Require(site != nullptr, "geosite tags resolve case-insensitively");
    Require(site->Match("a.example.com") && site->Match("EXAMPLE.com."),
            "domain entries match the name and its subdomains");
    Require(!site->Match("badexample.com"), "domain entries respect label boundaries");
    Require(site->Match("FULL.org") && !site->Match("x.full.org"),
            "full entries match exactly");
    Require(site->Match("abkwcd.net"), "plain entries match as keywords");
    Require(!site->Match("re.net"), "regexp entries are not loaded");
}

void TestRejectsCorruptOrIncompleteData(const TempDir& dir) {
    const std::vector<std::string> cn{"cn"};
    const std::vector<std::string> none;
    const auto empty_site = dir.Write("empty_site.dat", "");
    const auto valid = List({Entry("CN", {Cidr(kV4Net, 24)})});

    Require(ThrowsRuntimeError([&] {
                GeoDatabase db(dir.Write("missing_tag.dat", valid),
                               std::vector<std::string>{"jp"}, empty_site, none);
            }),
            "a requested tag absent from the file is rejected");
    Require(ThrowsRuntimeError([&] {
                GeoDatabase db(dir.Write("truncated.dat", valid.substr(0, valid.size() - 1)),
                               cn, empty_site, none);
            }),
            "a truncated file is rejected");

    std::string overlong;
    AppendVarint(overlong, (1 << 3) | 2);
    AppendVarint(overlong, 1000);
    overlong.append("CN");
    Require(ThrowsRuntimeError([&] {
                GeoDatabase db(dir.Write("overlong.dat", overlong), cn, empty_site, none);
            }),
            "a declared length beyond the file is rejected");
    Require(ThrowsRuntimeError([&] {
                GeoDatabase db(dir.Write("prefix.dat", List({Entry("CN", {Cidr(kV4Net, 33)})})),
                               cn, empty_site, none);
            }),
            "a CIDR prefix wider than its address is rejected");
    Require(ThrowsRuntimeError([&] {
                GeoDatabase db(dir.Write("address.dat",
                                         List({Entry("CN", {Cidr(std::string("\x01\x02\x03", 3), 8)})})),
                               cn, empty_site, none);
            }),
            "a CIDR address of invalid length is rejected");
    Require(ThrowsRuntimeError([&] {
                GeoDatabase db(dir.Write("duplicate.dat",
                                         List({Entry("CN", {Cidr(kV4Net, 24)}),
                                               Entry("cn", {Cidr(kV4Net, 16)})})),
                               cn, empty_site, none);
            }),
            "a duplicated requested tag is rejected");
    Require(ThrowsRuntimeError([&] {
                GeoDatabase db(dir.Write("unused.dat", valid), cn,
                               dir.Path("absent.dat"), std::vector<std::string>{"cn"});
            }),
            "an unreadable geosite file is rejected when geosite tags are requested");
}

}  // namespace

TEST(Geodata, Contract) {
    const TempDir dir;
    TestLoadsRequestedCategories(dir);
    TestRejectsCorruptOrIncompleteData(dir);
}
