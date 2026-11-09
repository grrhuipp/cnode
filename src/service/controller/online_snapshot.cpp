#include "online_snapshot.hpp"

#include <algorithm>
#include <optional>

namespace controller {

OnlineSnapshot BuildOnlineSnapshot(std::vector<OnlineDevice> devices) {
    std::erase_if(devices, [](const OnlineDevice& d) {
        return d.user_id <= 0 || d.ip.empty();
    });
    std::sort(devices.begin(), devices.end());
    devices.erase(std::unique(devices.begin(), devices.end()), devices.end());

    OnlineSnapshot result;
    result.entries.reserve(devices.size());
    std::optional<int64_t> last_user_id;
    for (auto& device : devices) {
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

}  // namespace controller
