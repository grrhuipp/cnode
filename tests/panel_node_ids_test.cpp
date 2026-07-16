#include "acppnode/service/controller/panel_node_ids.hpp"

#include <limits>
#include <stdexcept>

namespace {

bool Rejects(acpp::json::value value) {
    try {
        (void)acpp::PanelNodeIds::Parse(value);
        return false;
    } catch (const std::invalid_argument&) {
        return true;
    }
}

}  // namespace

int main() {
    auto valid = acpp::PanelNodeIds::Parse(acpp::json::array{
        int64_t{1}, uint64_t{static_cast<uint64_t>(std::numeric_limits<int>::max())}});
    if (valid.Empty() || valid.Front() != 1 || valid.Values().size() != 2 ||
        valid.Values()[1] != std::numeric_limits<int>::max()) {
        return 1;
    }

    auto single = acpp::PanelNodeIds::Single(7);
    if (single.Values().size() != 1 || single.Front() != 7) return 2;

    if (!Rejects(acpp::json::array{})) return 3;
    if (!Rejects(int64_t{1})) return 4;
    if (!Rejects(acpp::json::array{int64_t{-1}})) return 5;
    if (!Rejects(acpp::json::array{int64_t{0}})) return 6;
    if (!Rejects(acpp::json::array{uint64_t{
            static_cast<uint64_t>(std::numeric_limits<int>::max()) + 1}})) return 7;
    if (!Rejects(acpp::json::array{int64_t{1}, "2"})) return 8;
    if (!Rejects(acpp::json::array{int64_t{1}, int64_t{1}})) return 9;

    try {
        (void)acpp::PanelNodeIds::Single(0);
        return 10;
    } catch (const std::invalid_argument&) {
    }
    return 0;
}
