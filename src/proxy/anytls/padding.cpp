#include "padding.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <map>
#include <openssl/evp.h>
#include <random>
#include <utility>

namespace acpp::anytls {
namespace {

template<class Integer>
std::optional<Integer> ParseInteger(std::string_view text) {
    if (text.empty()) return std::nullopt;
    Integer value = 0;
    const auto [ptr, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || ptr != text.data() + text.size()) return std::nullopt;
    return value;
}

std::string_view Trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r'))
        text.remove_suffix(1);
    return text;
}

std::optional<std::string_view> NextToken(std::string_view& text, char delimiter) {
    while (!text.empty()) {
        const auto end = text.find(delimiter);
        const auto item = Trim(text.substr(0, end));
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        if (!item.empty()) return item;
    }
    return std::nullopt;
}

struct SizeRange {
    int min;
    int max;

    int LargestSize() const noexcept { return min == max ? max : max - 1; }
};

std::optional<SizeRange> ParseRange(std::string_view text) {
    text = Trim(text);
    const auto dash = text.find('-');
    if (dash == std::string_view::npos) return std::nullopt;
    auto lo = ParseInteger<int>(text.substr(0, dash));
    auto hi = ParseInteger<int>(text.substr(dash + 1));
    if (!lo || !hi) return std::nullopt;
    if (*lo > *hi) std::swap(lo, hi);
    return SizeRange{*lo, *hi};
}

int SampleRange(int lo, int hi) {
    if (lo == hi) return lo;
    static thread_local std::mt19937 rng{std::random_device{}()};
    return std::uniform_int_distribution<int>(lo, hi - 1)(rng);
}

std::optional<std::vector<PaddingRecord>> ParseRanges(std::string_view text) {
    std::vector<PaddingRecord> ranges;
    while (const auto token = NextToken(text, ',')) {
        if (*token == "c") {
            ranges.push_back(PaddingRecord{.copy_payload = true});
            continue;
        }
        const auto range = ParseRange(*token);
        if (!range || range->min <= 0) continue;
        // Any record may become a pure Waste with one uint16 payload length.
        if (range->LargestSize() > UINT16_MAX) return std::nullopt;
        ranges.push_back(PaddingRecord{false, range->min, range->max});
    }
    return ranges;
}

} // namespace

int PaddingRecord::SampleSize() const {
    if (copy_payload) return -1;
    if (min_size <= 0 || max_size_exclusive <= 0) return 0;
    return SampleRange(min_size, max_size_exclusive);
}

std::span<const PaddingRecord> PaddingScheme::RecordFor(uint32_t index) const noexcept {
    if (index >= stop_) return {};
    const auto found = std::lower_bound(records_.begin(), records_.end(), index,
        [](const PacketPadding& record, uint32_t value) { return record.index < value; });
    return found != records_.end() && found->index == index
        ? std::span<const PaddingRecord>(found->ranges) : std::span<const PaddingRecord>{};
}

uint16_t PaddingScheme::SampleAuthPaddingSize() const {
    return static_cast<uint16_t>(SampleRange(auth_padding_.min_size,
        static_cast<int>(auth_padding_.max_size_exclusive)));
}

std::optional<PaddingScheme> ParsePaddingScheme(std::string_view raw) {
    if (raw.empty()) return std::nullopt;
    PaddingScheme scheme;
    std::map<uint32_t, std::vector<PaddingRecord>> records;
    auto text = raw;
    while (const auto line = NextToken(text, '\n')) {
        const auto separator = line->find('=');
        if (separator == std::string_view::npos) continue;
        const auto key = line->substr(0, separator);
        const auto value = line->substr(separator + 1);
        if (key == "stop") {
            const auto stop = ParseInteger<uint32_t>(value);
            if (!stop || *stop == 0) return std::nullopt;
            scheme.stop_ = *stop;
        } else if (const auto index = ParseInteger<uint32_t>(key)) {
            if (*index == 0) {
                // Authentication carries one uint16 length, never frame splitting or 'c'.
                const auto range = ParseRange(value);
                if (!range || range->min < 0 || (range->min == 0 && range->max != 0))
                    return std::nullopt;
                if (range->LargestSize() > UINT16_MAX) return std::nullopt;
                scheme.auth_padding_ = {static_cast<uint16_t>(range->min),
                    static_cast<uint32_t>(range->max)};
                continue;
            }
            auto ranges = ParseRanges(value);
            if (!ranges) return std::nullopt;
            // Preserve the last valid entry, including when a later duplicate is invalid.
            if (!ranges->empty()) records.insert_or_assign(*index, std::move(*ranges));
        }
    }
    if (scheme.stop_ == 0) return std::nullopt;
    scheme.raw_.assign(raw);
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size = 0;
    if (EVP_Digest(raw.data(), raw.size(), digest.data(), &size, EVP_md5(), nullptr) != 1)
        return std::nullopt;
    static constexpr char kHex[] = "0123456789abcdef";
    scheme.md5_.reserve(size * 2);
    for (unsigned int index = 0; index < size; ++index) {
        scheme.md5_.push_back(kHex[digest[index] >> 4]);
        scheme.md5_.push_back(kHex[digest[index] & 0xf]);
    }
    scheme.records_.reserve(records.size());
    for (auto& [index, ranges] : records)
        scheme.records_.push_back({index, std::move(ranges)});
    return scheme;
}

std::shared_ptr<const PaddingScheme> DefaultPaddingScheme() {
    static const auto scheme = std::make_shared<const PaddingScheme>(ParsePaddingScheme(
        "stop=8\n"
        "0=30-30\n"
        "1=100-400\n"
        "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
        "3=9-9,500-1000\n"
        "4=500-1000\n"
        "5=500-1000\n"
        "6=500-1000\n"
        "7=500-1000").value());
    return scheme;
}

} // namespace acpp::anytls
