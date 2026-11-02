#pragma once

#include "acppnode/infra/json.hpp"

#include <span>
#include <vector>

namespace acpp {

class PanelNodeIds {
public:
    PanelNodeIds() = default;

    [[nodiscard]] bool Empty() const noexcept { return values_.empty(); }
    [[nodiscard]] int Front() const noexcept { return values_.front(); }
    [[nodiscard]] std::span<const int> Values() const noexcept { return values_; }

    [[nodiscard]] static PanelNodeIds Parse(const json::value& value);
    [[nodiscard]] static PanelNodeIds Single(int node_id);

private:
    std::vector<int> values_;
};

}  // namespace acpp
