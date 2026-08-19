#include "online_report.hpp"

#include <map>
#include <set>
#include <string>

namespace acpp::api::v2board {

OnlineReportPayload BuildOnlineReportPayload(
    std::span<const ::acpp::api::OnlineUser> online_devices,
    int node_id) {
    std::map<int64_t, std::set<std::string>> grouped;
    for (const auto& device : online_devices) {
        if (device.UID <= 0 || device.IP.empty()) {
            continue;
        }
        grouped[device.UID].insert(
            device.IP + "_" + std::to_string(node_id));
    }

    OnlineReportPayload result;
    result.user_count = grouped.size();
    for (const auto& [uid, devices] : grouped) {
        json::array alive_devices;
        for (const auto& device : devices) {
            alive_devices.push_back(device);
            ++result.device_count;
        }
        const std::string uid_text = std::to_string(uid);
        result.alive_body[uid_text] = std::move(alive_devices);
    }
    return result;
}

}  // namespace acpp::api::v2board
