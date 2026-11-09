#include "online_report.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace api::v2board {

OnlineReportPayload BuildOnlineReportPayload(
    std::span<const ::api::OnlineUser> online_devices,
    int node_id) {
    std::vector<::api::OnlineUser> valid;
    valid.reserve(online_devices.size());
    for (const auto& device : online_devices) {
        if (device.UID <= 0 || device.IP.empty()) {
            continue;
        }
        valid.push_back(device);
    }

    std::ranges::sort(valid, [](const ::api::OnlineUser& lhs, const ::api::OnlineUser& rhs) {
        if (lhs.UID != rhs.UID) return lhs.UID < rhs.UID;
        return lhs.IP < rhs.IP;
    });
    const auto duplicate_tail = std::ranges::unique(
        valid, [](const ::api::OnlineUser& lhs, const ::api::OnlineUser& rhs) {
            return lhs.UID == rhs.UID && lhs.IP == rhs.IP;
        });
    valid.erase(duplicate_tail.begin(), duplicate_tail.end());

    const std::string suffix = "_" + std::to_string(node_id);
    OnlineReportPayload result;
    result.device_count = valid.size();

    for (size_t i = 0; i < valid.size();) {
        const int64_t uid = valid[i].UID;
        size_t j = i;
        json::array alive_devices;
        while (j < valid.size() && valid[j].UID == uid) {
            alive_devices.push_back(valid[j].IP + suffix);
            ++j;
        }
        result.alive_body[std::to_string(uid)] = std::move(alive_devices);
        ++result.user_count;
        i = j;
    }
    return result;
}

}  // namespace api::v2board
