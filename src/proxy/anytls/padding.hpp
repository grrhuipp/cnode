#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace acpp::anytls {

struct PaddingRecord {
    bool copy_payload = false;
    int min_size = 0;
    int max_size_exclusive = 0;

    [[nodiscard]] int SampleSize() const;
};

// Prepared protocol policy. Storage follows actual entries, never packet indices.
// Published instances are shared as const; lookup neither allocates nor mutates.
class PaddingScheme final {
public:
    PaddingScheme() = default; // An empty scheme disables padding.

    [[nodiscard]] std::string_view Raw() const noexcept { return raw_; }
    [[nodiscard]] std::string_view Digest() const noexcept { return md5_; }
    [[nodiscard]] std::span<const PaddingRecord> RecordFor(uint32_t index) const noexcept;
    [[nodiscard]] uint16_t SampleAuthPaddingSize() const;

private:
    struct AuthPadding {
        uint16_t min_size = 0;
        uint32_t max_size_exclusive = 0;
    };
    struct PacketPadding {
        uint32_t index;
        std::vector<PaddingRecord> ranges;
    };

    std::string raw_;
    std::string md5_;
    uint32_t stop_ = 0;
    AuthPadding auth_padding_;
    std::vector<PacketPadding> records_;

    friend std::optional<PaddingScheme> ParsePaddingScheme(std::string_view raw);
};

[[nodiscard]] std::optional<PaddingScheme> ParsePaddingScheme(std::string_view raw);
[[nodiscard]] std::shared_ptr<const PaddingScheme> DefaultPaddingScheme();

} // namespace acpp::anytls
