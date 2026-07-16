#include "panel_schedule.hpp"

#include <chrono>

int main() {
    using acpp::controller::PanelInterval;
    using namespace std::chrono_literals;

    if (PanelInterval(45, 60) != 45s) return 1;
    if (PanelInterval(30, 60) != 30s) return 2;
    if (PanelInterval(0, 60) != 60s) return 3;
    if (PanelInterval(-1, 30) != 30s) return 4;
    return 0;
}
