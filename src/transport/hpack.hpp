#pragma once
#include "common/allocator.hpp"
#include "transport/http_headers.hpp"
#include <array>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include <cstdint>
#include <string>
#include <vector>

namespace transport {
void AppendHpackInt(std::vector<uint8_t>&, uint8_t, uint8_t, uint32_t);
void AppendHpackString(std::vector<uint8_t>&, std::string_view);
void AppendHpackIndexed(std::vector<uint8_t>&, uint32_t);
void AppendHpackLiteralIndexedName(std::vector<uint8_t>&, uint32_t, std::string_view);
void AppendHpackLiteralNewName(std::vector<uint8_t>&, std::string_view, std::string_view);
inline constexpr uint32_t kHpackStaticAuthority = 1;
inline constexpr uint32_t kHpackStaticMethodGet = 2;
inline constexpr uint32_t kHpackStaticMethodPost = 3;
inline constexpr uint32_t kHpackStaticPath = 4;
inline constexpr uint32_t kHpackStaticSchemeHttp = 6;
inline constexpr uint32_t kHpackStaticSchemeHttps = 7;
inline constexpr uint32_t kHpackStaticStatusOk = 8;
inline constexpr uint32_t kHpackStaticStatusBadRequest = 12;
inline constexpr uint32_t kHpackStaticContentType = 31;
inline constexpr uint32_t kHpackStaticUserAgent = 58;
inline constexpr uint32_t kHpackMaxDynamicTableSize = 4096;
inline constexpr size_t kHpackMaxHeaderFields = 256;
inline constexpr size_t kHpackMaxHeaderListSize = 64 * 1024;
struct HpackHeaderField {
    std::string name;
    std::string value;
};

// Connection-scoped HPACK decoder (RFC 7541). A failed Decode leaves the
// dynamic table unusable; callers must end the connection.
class HpackDecoder final {
public:
    template <typename Visitor>
    [[nodiscard]] bool Decode(std::span<const uint8_t> block, Visitor&& on_field) {
        size_t field_count = 0;
        size_t header_list_size = 0;
        const auto emit_field = [&](std::string_view name, std::string_view value) {
            const size_t field_size = name.size() + value.size() + 32;
            if (field_count >= kHpackMaxHeaderFields ||
                field_size > kHpackMaxHeaderListSize - header_list_size) {
                return false;
            }
            ++field_count;
            header_list_size += field_size;
            if constexpr (std::is_void_v<std::invoke_result_t<
                              Visitor&, std::string_view, std::string_view>>) {
                on_field(name, value);
                return true;
            } else {
                return static_cast<bool>(on_field(name, value));
            }
        };
        size_t offset = 0;
        bool allow_dynamic_resize = true;
        std::string name_scratch;
        std::string value_scratch;
        while (offset < block.size()) {
            const uint8_t first = block[offset];
            if ((first & 0x80) != 0) {
                allow_dynamic_resize = false;
                const auto index = ReadInteger(block, offset, 7);
                const auto entry = index ? Lookup(*index) : std::nullopt;
                if (!entry || !emit_field(entry->name, entry->value)) {
                    return false;
                }
                continue;
            }
            if ((first & 0x40) != 0) {
                allow_dynamic_resize = false;
                auto field = ReadLiteral(block, offset, 6);
                if (!field || !emit_field(field->name, field->value)) {
                    return false;
                }
                AddDynamic(std::move(*field));
                continue;
            }
            if ((first & 0x20) != 0) {
                if (!allow_dynamic_resize) {
                    return false;
                }
                auto size = ReadInteger(block, offset, 5);
                if (!size || !ResizeDynamic(*size)) {
                    return false;
                }
                continue;
            }
            allow_dynamic_resize = false;
            const auto name_index = ReadInteger(block, offset, 4);
            if (!name_index) {
                return false;
            }
            if (*name_index == 0) {
                name_scratch.clear();
                value_scratch.clear();
                auto name = ReadStringViewOrDecode(block, offset, name_scratch);
                auto value = name ? ReadStringViewOrDecode(block, offset, value_scratch) : std::nullopt;
                if (!value || !emit_field(*name, *value)) {
                    return false;
                }
            } else {
                const auto indexed = Lookup(*name_index);
                if (!indexed) {
                    return false;
                }
                value_scratch.clear();
                auto value = ReadStringViewOrDecode(block, offset, value_scratch);
                if (!value || !emit_field(indexed->name, *value)) {
                    return false;
                }
            }
        }
        return true;
    }

    void Clear() noexcept {
        dynamic_table_.clear();
        dynamic_size_ = 0;
    }

private:
    struct FieldView {
        std::string_view name;
        std::string_view value;
    };

    static constexpr std::array<FieldView, 61> kStaticTable{{
        {":authority", ""},
        {":method", "GET"},
        {":method", "POST"},
        {":path", "/"},
        {":path", "/index.html"},
        {":scheme", "http"},
        {":scheme", "https"},
        {":status", "200"},
        {":status", "204"},
        {":status", "206"},
        {":status", "304"},
        {":status", "400"},
        {":status", "404"},
        {":status", "500"},
        {"accept-charset", ""},
        {"accept-encoding", "gzip, deflate"},
        {"accept-language", ""},
        {"accept-ranges", ""},
        {"accept", ""},
        {"access-control-allow-origin", ""},
        {"age", ""},
        {"allow", ""},
        {"authorization", ""},
        {"cache-control", ""},
        {"content-disposition", ""},
        {"content-encoding", ""},
        {"content-language", ""},
        {"content-length", ""},
        {"content-location", ""},
        {"content-range", ""},
        {"content-type", ""},
        {"cookie", ""},
        {"date", ""},
        {"etag", ""},
        {"expect", ""},
        {"expires", ""},
        {"from", ""},
        {"host", ""},
        {"if-match", ""},
        {"if-modified-since", ""},
        {"if-none-match", ""},
        {"if-range", ""},
        {"if-unmodified-since", ""},
        {"last-modified", ""},
        {"link", ""},
        {"location", ""},
        {"max-forwards", ""},
        {"proxy-authenticate", ""},
        {"proxy-authorization", ""},
        {"range", ""},
        {"referer", ""},
        {"refresh", ""},
        {"retry-after", ""},
        {"server", ""},
        {"set-cookie", ""},
        {"strict-transport-security", ""},
        {"transfer-encoding", ""},
        {"user-agent", ""},
        {"vary", ""},
        {"via", ""},
        {"www-authenticate", ""},
    }};

    static constexpr std::array<uint32_t, 256> kHpackHuffmanCodes{{
        0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
        0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
        0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
        0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
        0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
        0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
        0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
        0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
        0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
        0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
        0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
        0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
        0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
        0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
        0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
        0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
        0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
        0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
        0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
        0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
        0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
        0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
        0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
        0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
        0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
        0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
        0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
        0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
        0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
        0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    }};

    static constexpr std::array<uint8_t, 256> kHpackHuffmanCodeLen{{
        13, 23, 28, 28, 28, 28, 28, 28,
        28, 24, 30, 28, 28, 30, 28, 28,
        28, 28, 28, 28, 28, 28, 30, 28,
        28, 28, 28, 28, 28, 28, 28, 28,
        6, 10, 10, 12, 13, 6, 8, 11,
        10, 10, 8, 11, 8, 6, 6, 6,
        5, 5, 5, 6, 6, 6, 6, 6,
        6, 6, 7, 8, 15, 6, 12, 10,
        13, 6, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7,
        8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6,
        6, 5, 7, 7, 6, 6, 6, 5,
        6, 7, 6, 5, 5, 6, 7, 7,
        7, 7, 7, 15, 11, 14, 13, 28,
        20, 22, 20, 20, 22, 22, 22, 23,
        22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23,
        23, 21, 22, 23, 22, 23, 23, 24,
        22, 21, 20, 22, 22, 23, 23, 21,
        23, 22, 22, 24, 21, 22, 23, 23,
        21, 21, 22, 21, 23, 22, 23, 23,
        20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25,
        26, 26, 26, 27, 27, 26, 24, 25,
        19, 21, 26, 27, 27, 26, 27, 24,
        21, 21, 26, 26, 28, 27, 27, 27,
        20, 24, 20, 21, 22, 21, 21, 23,
        22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27,
        27, 28, 27, 27, 27, 27, 27, 26,
    }};

    struct HuffmanTrieNode {
        uint16_t child[2];
        uint16_t symbol_plus_one;
    };

    static constexpr auto kHpackHuffmanTrie = []() consteval {
        std::array<HuffmanTrieNode, 520> trie{};
        uint16_t next_node = 1;
        for (size_t sym = 0; sym < kHpackHuffmanCodes.size(); ++sym) {
            const uint32_t code = kHpackHuffmanCodes[sym];
            const uint8_t len = kHpackHuffmanCodeLen[sym];
            uint16_t node = 0;
            for (int bit = static_cast<int>(len) - 1; bit >= 0; --bit) {
                const uint8_t b = static_cast<uint8_t>((code >> bit) & 0x1u);
                if (trie[node].child[b] == 0) {
                    trie[node].child[b] = next_node++;
                }
                node = trie[node].child[b];
            }
            trie[node].symbol_plus_one = static_cast<uint16_t>(sym + 1);
        }
        return trie;
    }();

    static std::optional<uint32_t> ReadInteger(std::span<const uint8_t> block,
                                               size_t& offset,
                                               uint8_t prefix_bits) {
        if (offset >= block.size()) {
            return std::nullopt;
        }
        const uint8_t mask = static_cast<uint8_t>((1u << prefix_bits) - 1u);
        uint32_t value = block[offset++] & mask;
        if (value < mask) {
            return value;
        }
        uint32_t shift = 0;
        while (offset < block.size() && shift <= 28) {
            const uint8_t byte = block[offset++];
            const uint32_t add = static_cast<uint32_t>(byte & 0x7f) << shift;
            if (value > std::numeric_limits<uint32_t>::max() - add) {
                return std::nullopt;
            }
            value += add;
            if ((byte & 0x80) == 0) {
                return value;
            }
            shift += 7;
        }
        return std::nullopt;
    }

    static std::optional<std::string> DecodeHuffman(
        std::span<const uint8_t> data) {
        std::string out;
        out.reserve(data.size());
        uint16_t node = 0;
        uint32_t code = 0;
        uint8_t bits = 0;
        for (uint8_t byte : data) {
            for (int bit = 7; bit >= 0; --bit) {
                const uint8_t b = static_cast<uint8_t>((byte >> bit) & 0x1u);
                code = (code << 1) | b;
                ++bits;
                node = kHpackHuffmanTrie[node].child[b];
                if (node == 0) {
                    return std::nullopt;
                }
                if (kHpackHuffmanTrie[node].symbol_plus_one != 0) {
                    out.push_back(static_cast<char>(
                        kHpackHuffmanTrie[node].symbol_plus_one - 1));
                    node = 0;
                    code = 0;
                    bits = 0;
                }
            }
        }
        // RFC 7541 5.2: padding is under 8 bits of the EOS prefix (all ones).
        if (bits > 7) {
            return std::nullopt;
        }
        if (bits > 0 && code != ((1u << bits) - 1u)) {
            return std::nullopt;
        }
        return out;
    }

    static std::optional<std::string_view> ReadStringViewOrDecode(
        std::span<const uint8_t> block,
        size_t& offset,
        std::string& scratch) {
        if (offset >= block.size()) {
            return std::nullopt;
        }
        const bool huffman = (block[offset] & 0x80) != 0;
        auto len = ReadInteger(block, offset, 7);
        if (!len || *len > block.size() - offset) {
            return std::nullopt;
        }
        std::span<const uint8_t> encoded(block.data() + offset, *len);
        offset += *len;
        if (huffman) {
            auto decoded = DecodeHuffman(encoded);
            if (!decoded) return std::nullopt;
            scratch = std::move(*decoded);
            return scratch;
        }
        return std::string_view(
            reinterpret_cast<const char*>(encoded.data()),
            encoded.size());
    }

    static std::optional<std::string> ReadString(
        std::span<const uint8_t> block,
        size_t& offset) {
        std::string scratch;
        auto view = ReadStringViewOrDecode(block, offset, scratch);
        if (!view) return std::nullopt;
        if (!scratch.empty() || view->empty()) return scratch;
        return std::string(*view);
    }

    // Static entries first, then the dynamic table newest-first (RFC 7541 2.3.3).
    std::optional<FieldView> Lookup(uint32_t index) const {
        if (index == 0) {
            return std::nullopt;
        }
        if (index <= kStaticTable.size()) {
            return kStaticTable[index - 1];
        }
        const uint32_t dynamic_index =
            index - static_cast<uint32_t>(kStaticTable.size()) - 1;
        if (dynamic_index >= dynamic_table_.size()) {
            return std::nullopt;
        }
        const auto& field = dynamic_table_[dynamic_index];
        return FieldView{field.name, field.value};
    }

    std::optional<HpackHeaderField> ReadLiteral(std::span<const uint8_t> block,
                                                size_t& offset,
                                                uint8_t prefix_bits) const {
        auto name_index = ReadInteger(block, offset, prefix_bits);
        if (!name_index) {
            return std::nullopt;
        }
        std::string name;
        if (*name_index == 0) {
            auto decoded = ReadString(block, offset);
            if (!decoded) {
                return std::nullopt;
            }
            name = std::move(*decoded);
        } else {
            const auto indexed = Lookup(*name_index);
            if (!indexed) {
                return std::nullopt;
            }
            name.assign(indexed->name);
        }
        auto value = ReadString(block, offset);
        if (!value) {
            return std::nullopt;
        }
        return HpackHeaderField{std::move(name), std::move(*value)};
    }

    void AddDynamic(HpackHeaderField&& field) {
        const size_t entry_size = field.name.size() + field.value.size() + 32;
        if (entry_size > dynamic_max_size_) {
            dynamic_table_.clear();
            dynamic_size_ = 0;
            return;
        }
        dynamic_table_.push_front(std::move(field));
        dynamic_size_ += entry_size;
        EvictDynamic();
    }

    [[nodiscard]] bool ResizeDynamic(uint32_t size) {
        if (size > kHpackMaxDynamicTableSize) {
            return false;
        }
        dynamic_max_size_ = size;
        EvictDynamic();
        return true;
    }

    void EvictDynamic() {
        while (dynamic_size_ > dynamic_max_size_ && !dynamic_table_.empty()) {
            const auto& field = dynamic_table_.back();
            dynamic_size_ -= field.name.size() + field.value.size() + 32;
            dynamic_table_.pop_back();
        }
    }

    common::RingDeque<HpackHeaderField> dynamic_table_;
    size_t dynamic_size_ = 0;
    size_t dynamic_max_size_ = kHpackMaxDynamicTableSize;
};
}  // namespace transport
