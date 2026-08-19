#include "online_snapshot.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

}  // namespace

int main() {
    std::vector<acpp::OnlineDevice> devices{
        {8, "203.0.113.8"},
        {7, "203.0.113.2"},
        {7, "203.0.113.1"},
        {7, "203.0.113.1"},
        {0, "203.0.113.9"},
        {9, ""},
    };

    auto snapshot = acpp::controller::BuildOnlineSnapshot(std::move(devices));
    Check(snapshot.user_count == 2,
          "multiple IPs for one UID were counted as multiple users");
    Check(snapshot.entries.size() == 3,
          "online device entries were not deduplicated");
    Check(snapshot.entries[0].UID == 7 && snapshot.entries[0].IP == "203.0.113.1",
          "online entries are not deterministically sorted");
    Check(snapshot.entries[1].UID == 7 && snapshot.entries[1].IP == "203.0.113.2",
          "second device for one user was lost");
    Check(snapshot.entries[2].UID == 8 && snapshot.entries[2].IP == "203.0.113.8",
          "second online user was lost");

    std::cout << "online_snapshot_test: ok\n";
    return 0;
}
