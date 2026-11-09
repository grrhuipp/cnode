#include "online_report.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace api::v2board {

namespace {

bool IsValidDevice(const ::api::OnlineUser& device) noexcept {
    return device.UID > 0 && !device.IP.empty();
}

bool DeviceLess(const ::api::OnlineUser& lhs, const ::api::OnlineUser& rhs) noexcept {
    if (lhs.UID != rhs.UID) return lhs.UID < rhs.UID;
    return lhs.IP < rhs.IP;
}

bool IsCanonicalDeviceList(std::span<const ::api::OnlineUser> devices) noexcept {
    for (size_t i = 0; i < devices.size(); ++i) {
        if (!IsValidDevice(devices[i])) {
            return false;
        }
        if (i > 0 && !DeviceLess(devices[i - 1], devices[i])) {
            return false;
        }
    }
    return true;
}

OnlineReportPayload BuildFromCanonicalDevices(
    std::span<const ::api::OnlineUser> devices,
    int node_id) {
    OnlineReportPayload result;
    if (devices.empty()) {
        return result;
    }
    const std::string suffix = "_" + std::to_string(node_id);
    result.device_count = devices.size();

    for (size_t i = 0; i < devices.size();) {
        const int64_t uid = devices[i].UID;
        size_t j = i;
        json::array alive_devices;
        while (j < devices.size() && devices[j].UID == uid) {
            alive_devices.push_back(devices[j].IP + suffix);
            ++j;
        }
        result.alive_body[std::to_string(uid)] = std::move(alive_devices);
        ++result.user_count;
        i = j;
    }
    return result;
}

}  // namespace

OnlineReportPayload BuildOnlineReportPayload(
    std::span<const ::api::OnlineUser> online_devices,
    int node_id) {
    if (IsCanonicalDeviceList(online_devices)) {
        return BuildFromCanonicalDevices(online_devices, node_id);
    }

    std::vector<::api::OnlineUser> valid;
    valid.reserve(online_devices.size());
    for (const auto& device : online_devices) {
        if (IsValidDevice(device)) {
            valid.push_back(device);
        }
    }

    std::ranges::sort(valid, DeviceLess);
    const auto duplicate_tail = std::ranges::unique(
        valid, [](const ::api::OnlineUser& lhs, const ::api::OnlineUser& rhs) {
            return lhs.UID == rhs.UID && lhs.IP == rhs.IP;
        });
    valid.erase(duplicate_tail.begin(), duplicate_tail.end());

    return BuildFromCanonicalDevices(valid, node_id);
}

}  // namespace api::v2board
