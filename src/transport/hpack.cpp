#include "transport/hpack.hpp"

namespace transport {
void AppendHpackInt(std::vector<uint8_t>& out,
                    uint8_t prefix_bits,
                    uint8_t first_mask,
                    uint32_t value) {
    const uint8_t max_prefix = static_cast<uint8_t>((1u << prefix_bits) - 1u);
    if (value < max_prefix) {
        out.push_back(static_cast<uint8_t>(first_mask | value));
        return;
    }

    out.push_back(static_cast<uint8_t>(first_mask | max_prefix));
    value -= max_prefix;
    while (value >= 128) {
        out.push_back(static_cast<uint8_t>((value & 0x7f) | 0x80));
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

void AppendHpackString(std::vector<uint8_t>& out, std::string_view value) {
    AppendHpackInt(out, 7, 0, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void AppendHpackIndexed(std::vector<uint8_t>& out, uint32_t index) {
    AppendHpackInt(out, 7, 0x80, index);
}

void AppendHpackLiteralIndexedName(std::vector<uint8_t>& out,
                                   uint32_t name_index,
                                   std::string_view value) {
    AppendHpackInt(out, 4, 0, name_index);
    AppendHpackString(out, value);
}

void AppendHpackLiteralNewName(std::vector<uint8_t>& out,
                               std::string_view name,
                               std::string_view value) {
    out.push_back(0);
    AppendHpackInt(out, 7, 0, static_cast<uint32_t>(name.size()));
    for (const unsigned char ch : name) out.push_back(common::ToLowerAscii(ch));
    AppendHpackString(out, value);
}
}  // namespace transport
