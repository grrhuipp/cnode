#include "padding.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string_view>
#include <string>

namespace {
bool measuring = false;
size_t largest_request = 0;
size_t total_requested = 0;
size_t rejected_requests = 0;
constexpr size_t kAllocationLimit = 1024 * 1024;
size_t checks = 0;
size_t failures = 0;
void Check(bool value, const char* name) {
    ++checks;
    if (!value) { ++failures; std::printf("padding-policy FAIL: %s\n", name); }
}
}

void* operator new(std::size_t size) {
    if (measuring) {
        largest_request = std::max(largest_request, size);
        total_requested += size;
        if (size > kAllocationLimit) {
            ++rejected_requests;
            throw std::bad_alloc();
        }
    }
    if (void* result = std::malloc(size ? size : 1)) return result;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { ::operator delete(value); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void operator delete(void* value, const std::nothrow_t&) noexcept { ::operator delete(value); }

int main() {
    (void)acpp::anytls::DefaultPaddingScheme();
    constexpr std::array cases{
        std::string_view("stop=8\n0=30-30\n1=64-65\n7=96-96\n"),
        std::string_view("stop=2\n1=64-65\n2147483647=64-65\n"),
        std::string_view("stop=2147483647\n2147483646=64-65\n0=30-30\n"),
        std::string_view("stop=2\n2147483647=64-65\n1=64-65\n2147483647=96-96\n"),
        std::string_view("stop=2147483647\n1073741823=64-65\n2147483646=96-96\n"),
        std::string_view("stop=4294967295\n4294967294=64-65\n4294967295=96-96\n"),
    };
    bool passed = true;
    for (size_t index = 0; index < cases.size(); ++index) {
        largest_request = total_requested = rejected_requests = 0;
        bool parsed = false;
        measuring = true;
        try {
            parsed = acpp::anytls::ParsePaddingScheme(cases[index]).has_value();
        } catch (const std::bad_alloc&) {
        }
        measuring = false;
        const bool bounded = parsed && rejected_requests == 0 && total_requested <= 64 * 1024;
        passed &= bounded;
        std::printf("padding-allocation case=%zu raw=%zu largest=%zu total=%zu denied=%zu parsed=%d: %s\n",
            index, cases[index].size(), largest_request, total_requested, rejected_requests,
            parsed, bounded ? "PASS" : "FAIL");
    }

    using namespace acpp::anytls;
    const PaddingScheme empty;
    Check(empty.RecordFor(0).empty() && empty.RecordFor(UINT32_MAX).empty() &&
          empty.SampleAuthPaddingSize() == 0, "disabled scheme");
    constexpr std::array invalid{
        "", "stop=0\n0=30-30", "stop=-1\n0=30-30", "stop=4294967296\n0=30-30",
        "stop=\n0=30-30", "stop=+1\n0=30-30", "stop=1x\n0=30-30",
        "0=30-30", "stop=1\n0=-1-30", "stop=1\n0=30-", "stop=1\n0=30-2147483648",
        "stop=2\n0=c,99-99\n1=64-65", "stop=2\n0=65536-65536\n1=64-65",
        "stop=2\n0=65534-65537\n1=64-65", "stop=2\n0=45-45,50-50\n1=64-65",
        "stop=2\n0=0-10\n1=64-65", "stop=2\n0=garbage\n1=64-65",
        "stop=2\n0=\n1=64-65", "stop=2\n0=45-45,\n1=64-65",
        "stop=2\n0=45-45\n0=bad\n1=64-65", "stop=2\n0=bad\n0=45-45\n1=64-65",
        "stop=2\n1=65536-65536", "stop=2\n1=65534-65537", "stop=2\n1=1-2147483647",
        "stop=2\n1=256-256,c,65536-65536", "stop=2\n1=256-256\n1=65536-65536",
        "stop=2\n1=65536-65536\n1=256-256",
        "stop=2\n1=30-30\nstop=invalid", "stop=2\n1=30-30\nstop=0\nstop=2"};
    for (const auto raw : invalid) Check(!ParsePaddingScheme(raw), raw);
    for (const auto text : {"stop=1\n", "stop=2\n1=0-10", "stop=2\n-1=30-30",
            "stop=2\n4294967296=30-30", "stop=2\n1x=30-30", "stop=2\n+1=30-30"}) {
        const auto parsed = ParsePaddingScheme(text);
        Check(parsed && parsed->Raw() == text && parsed->Digest().size() == 32 &&
              parsed->SampleAuthPaddingSize() == 0 && parsed->RecordFor(0).empty() &&
              parsed->RecordFor(1).empty(), "empty policy and ignored data entries");
    }
    const std::string raw = " \tstop=4294967295\r\n\n4294967294=64-65\n7=96-96\n"
        "0=45-45\n7=80-80\n7=invalid\n1= 120-100 , c , 32-32 \r\n4294967295=99-99\n";
    const auto scheme = ParsePaddingScheme(raw);
    Check(scheme.has_value(), "sparse scheme parsed");
    if (scheme) {
        Check(scheme->Raw() == raw && scheme->Digest().size() == 32, "exact wire metadata");
        Check(scheme->SampleAuthPaddingSize() == 45 && scheme->RecordFor(0).empty(),
              "auth padding is separate from frame records");
        Check(scheme->RecordFor(2).empty() && scheme->RecordFor(UINT32_MAX).empty(), "gap and stop are inactive");
        Check(scheme->RecordFor(7).size() == 1 && scheme->RecordFor(7)[0].SampleSize() == 80,
              "last valid duplicate wins");
        Check(scheme->RecordFor(UINT32_MAX - 1).size() == 1 &&
              scheme->RecordFor(UINT32_MAX - 1)[0].SampleSize() == 64, "large active index");
        const auto ranges = scheme->RecordFor(1);
        Check(ranges.size() == 3, "range and copy tokens");
        if (ranges.size() == 3) {
            Check(ranges[1].SampleSize() == -1 && ranges[2].SampleSize() == 32, "copy and constant sizes");
            for (size_t index = 0; index < 2048; ++index) {
                const auto size = ranges[0].SampleSize();
                Check(size >= 100 && size < 120, "reversed range is half open");
            }
        }
        largest_request = total_requested = rejected_requests = 0;
        measuring = true;
        for (uint32_t index = 0; index < 10000; ++index) (void)scheme->RecordFor(index);
        measuring = false;
        Check(total_requested == 0, "lookup does not allocate");
    }
    for (const auto text : {"stop=1\n0=0-0", "stop=1\n1=99-99", "stop=2\n1=99-99"}) {
        const auto parsed = ParsePaddingScheme(text);
        Check(parsed && parsed->SampleAuthPaddingSize() == 0, "no implicit auth fallback");
    }
    for (const auto text : {"stop=2\n0=45-77\n1=99-99", "stop=1\n0= 77-45 \r\n"}) {
        const auto parsed = ParsePaddingScheme(text);
        Check(parsed.has_value(), "auth range parsed");
        if (!parsed) continue;
        std::array<bool, 32> observed{};
        for (size_t index = 0; index < 2048; ++index) {
            const auto size = parsed->SampleAuthPaddingSize();
            Check(size >= 45 && size < 77, "auth sampling is half open");
            if (size >= 45 && size < 77) observed[size - 45] = true;
        }
        Check(std::count(observed.begin(), observed.end(), true) >= 2, "auth range is sampled");
    }
    const auto boundary = ParsePaddingScheme("stop=2\n0=65535-65535\nstop=1");
    Check(boundary && boundary->SampleAuthPaddingSize() == 65535 && boundary->RecordFor(1).empty(), "auth boundary and last stop");
    const auto upper = ParsePaddingScheme("stop=1\n0=65536-65535");
    Check(upper && upper->SampleAuthPaddingSize() == 65535 && upper->RecordFor(0).empty(), "auth exclusive upper boundary");
    const auto duplicate = ParsePaddingScheme("stop=1\n0=45-45\n0=91-91");
    Check(duplicate && duplicate->SampleAuthPaddingSize() == 91, "last valid auth duplicate wins");
    for (const int size : {1, 7, 8, 8191, 8192, 8193, 16384, 65535}) {
        const auto text = "stop=2\n1=" + std::to_string(size) + "-" + std::to_string(size);
        const auto parsed = ParsePaddingScheme(text);
        Check(parsed && parsed->RecordFor(1).size() == 1 &&
              parsed->RecordFor(1)[0].SampleSize() == size, "frame size independent of buffer capacity");
    }
    for (const auto text : {"stop=2\n1=65535-65536", "stop=2\n1=65536-65535"}) {
        const auto parsed = ParsePaddingScheme(text);
        Check(parsed && parsed->RecordFor(1).size() == 1 &&
              parsed->RecordFor(1)[0].SampleSize() == 65535, "frame exclusive upper boundary");
    }
    const auto original = DefaultPaddingScheme();
    largest_request = total_requested = rejected_requests = 0;
    measuring = true;
    bool same = true;
    for (size_t index = 0; index < 10000; ++index) same &= DefaultPaddingScheme() == original;
    measuring = false;
    Check(same && total_requested == 0 && original->RecordFor(0).empty() &&
          original->RecordFor(8).empty() && original->SampleAuthPaddingSize() == 30,
          "default scheme shares immutable storage");
    std::string many = "stop=4294967295\n";
    for (uint32_t index = 0; index < 2048; ++index)
        many += std::to_string(UINT32_MAX - 1 - index * 1000000) + "=64-65\n";
    largest_request = total_requested = rejected_requests = 0;
    measuring = true;
    const auto dense = ParsePaddingScheme(many);
    measuring = false;
    Check(dense && rejected_requests == 0 && total_requested < many.size() * 16,
          "storage scales with actual entries");
    if (dense) for (uint32_t index = 0; index < 2048; ++index)
        Check(dense->RecordFor(UINT32_MAX - 1 - index * 1000000).size() == 1, "all sparse entries retained");
    std::printf("padding-policy checks=%zu failures=%zu scaling_raw=%zu scaling_total=%zu\n",
        checks, failures, many.size(), total_requested);
    return passed && failures == 0 ? 0 : 1;
}
