#include "acppnode/infra/runtime_config_types.hpp"

#include "acppnode/common/asio_types.hpp"

#include <algorithm>
#include <charconv>
#include <string>

namespace acpp {

std::optional<RoutingIpNetwork> RoutingIpNetwork::Parse(std::string_view value) {
    const auto slash = value.find('/');
    if (value.empty() ||
        (slash != std::string_view::npos &&
         value.find('/', slash + 1) != std::string_view::npos)) {
        return std::nullopt;
    }

    const auto address_text = value.substr(0, slash);
    IoErrorCode address_error;
    const auto address = net::ip::make_address(std::string(address_text), address_error);
    if (address_error) {
        return std::nullopt;
    }

    const uint32_t max_prefix = address.is_v4() ? 32U : 128U;
    uint32_t prefix = max_prefix;
    if (slash != std::string_view::npos) {
        const auto prefix_text = value.substr(slash + 1);
        const auto [end, error] = std::from_chars(
            prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
        if (prefix_text.empty() || error != std::errc{} ||
            end != prefix_text.data() + prefix_text.size() || prefix > max_prefix) {
            return std::nullopt;
        }
    }

    RoutingIpNetwork result;
    result.prefix_ = static_cast<uint8_t>(prefix);
    result.is_v6_ = address.is_v6();
    if (result.is_v6_) {
        const auto bytes = address.to_v6().to_bytes();
        std::ranges::copy(bytes, result.network_.begin());
    } else {
        const auto bytes = address.to_v4().to_bytes();
        std::ranges::copy(bytes, result.network_.begin());
    }

    const size_t full_bytes = prefix / 8;
    const uint8_t remaining_bits = static_cast<uint8_t>(prefix % 8);
    const size_t address_size = result.is_v6_ ? 16U : 4U;
    if (full_bytes < address_size) {
        if (remaining_bits != 0) {
            result.network_[full_bytes] &=
                static_cast<uint8_t>(0xFFU << (8 - remaining_bits));
        }
        const size_t zero_start = full_bytes + (remaining_bits != 0 ? 1U : 0U);
        std::fill(result.network_.begin() + zero_start,
                  result.network_.begin() + address_size, uint8_t{0});
    }
    return result;
}

}  // namespace acpp
