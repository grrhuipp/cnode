#include "acppnode/service/controller/panel_node_ids.hpp"

#include <format>
#include <limits>
#include <stdexcept>
#include <unordered_set>

namespace acpp {

PanelNodeIds PanelNodeIds::Parse(const json::value& value) {
    if (!value.is_array()) {
        throw std::invalid_argument("Panel NodeIDs must be an array");
    }
    if (value.as_array().empty()) {
        throw std::invalid_argument("Panel NodeIDs must not be empty");
    }

    PanelNodeIds result;
    std::unordered_set<int> unique;
    result.values_.reserve(value.as_array().size());
    unique.reserve(value.as_array().size());
    for (const auto& item : value.as_array()) {
        uint64_t raw = 0;
        if (item.is_int64()) {
            const int64_t signed_value = item.as_int64();
            if (signed_value <= 0) {
                throw std::invalid_argument("Panel NodeID must be positive");
            }
            raw = static_cast<uint64_t>(signed_value);
        } else if (item.is_uint64()) {
            raw = item.as_uint64();
        } else {
            throw std::invalid_argument("Panel NodeID must be an integer");
        }
        if (raw == 0 || raw > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
            throw std::invalid_argument(std::format(
                "Panel NodeID {} must be between 1 and {}",
                raw, std::numeric_limits<int>::max()));
        }
        const int node_id = static_cast<int>(raw);
        if (!unique.insert(node_id).second) {
            throw std::invalid_argument(std::format(
                "Panel NodeID {} is duplicated", node_id));
        }
        result.values_.push_back(node_id);
    }
    return result;
}

PanelNodeIds PanelNodeIds::Single(int node_id) {
    if (node_id <= 0) {
        throw std::invalid_argument("Panel NodeID must be positive");
    }
    PanelNodeIds result;
    result.values_.push_back(node_id);
    return result;
}

}  // namespace acpp
