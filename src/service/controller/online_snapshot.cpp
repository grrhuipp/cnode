#include "online_snapshot.hpp"

#include <algorithm>
#include <optional>

namespace acpp::controller {

OnlineSnapshot BuildOnlineSnapshot(std::vector<OnlineDevice> devices) {
    std::sort(devices.begin(), devices.end());
    devices.erase(std::unique(devices.begin(), devices.end()), devices.end());

    OnlineSnapshot result;
    result.entries.reserve(devices.size());
    std::optional<int64_t> last_user_id;
    for (auto& device : devices) {
        if (device.user_id <= 0 || device.ip.empty()) {
            continue;
        }
        if (!last_user_id || *last_user_id != device.user_id) {
            ++result.user_count;
            last_user_id = device.user_id;
        }
        result.entries.push_back(api::OnlineUser{
            .UID = device.user_id,
            .IP = std::move(device.ip),
        });
    }
    return result;
}

}  // namespace acpp::controller
