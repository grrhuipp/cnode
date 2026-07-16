#include "http2_initial_window.hpp"
#include "json_unsigned.hpp"

#include <utility>

namespace acpp {

std::expected<std::optional<uint32_t>, std::string>
ParseHttp2InitialWindow(const json::object& source) {
    auto parsed = ParseAliasedJsonUint64(
        source,
        {"initialWindowSize", "initial_window_size"},
        kHttp2MaxInitialWindow);
    if (!parsed) {
        return std::unexpected(std::move(parsed.error()));
    }
    if (!*parsed) {
        return std::optional<uint32_t>{};
    }
    return std::optional<uint32_t>{static_cast<uint32_t>(**parsed)};
}

}  // namespace acpp
