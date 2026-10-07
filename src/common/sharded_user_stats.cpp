#include "acppnode/common/sharded_user_stats.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/string_hash.hpp"

#include <string>

namespace acpp {

struct UserOnlineTracker::Impl {
    using UserConnectionMap = memory::ThreadLocalUnorderedMap<uint64_t, uint32_t>;
    using TagConnectionMap =
        memory::ThreadLocalUnorderedMap<std::string,
                                        UserConnectionMap,
                                        TransparentStringHash,
                                        TransparentStringEq>;
    using DeviceIpMap =
        memory::ThreadLocalUnorderedMap<std::string,
                                        uint32_t,
                                        TransparentStringHash,
                                        TransparentStringEq>;
    using UserDeviceMap = memory::ThreadLocalUnorderedMap<uint64_t, DeviceIpMap>;
    using TagDeviceMap =
        memory::ThreadLocalUnorderedMap<std::string,
                                        UserDeviceMap,
                                        TransparentStringHash,
                                        TransparentStringEq>;

    TagConnectionMap connections;
    TagDeviceMap devices;
};

UserOnlineTracker::UserOnlineTracker() : impl_(std::make_unique<Impl>()) {}

UserOnlineTracker::~UserOnlineTracker() = default;

void UserOnlineTracker::OnUserConnected(std::string_view tag,
                                        uint64_t user_id,
                                        std::string_view client_ip) {
    auto& user_connections = impl_->connections[std::string(tag)];
    user_connections[user_id]++;

    if (!client_ip.empty()) {
        auto& user_devices = impl_->devices[std::string(tag)][user_id];
        user_devices[std::string(client_ip)]++;
    }
}

void UserOnlineTracker::OnUserDisconnected(std::string_view tag,
                                           uint64_t user_id,
                                           std::string_view client_ip) {
    auto tag_it = impl_->connections.find(tag);
    if (tag_it != impl_->connections.end()) {
        auto user_it = tag_it->second.find(user_id);
        if (user_it != tag_it->second.end() && --user_it->second == 0) {
            tag_it->second.erase(user_it);
            if (tag_it->second.empty()) {
                impl_->connections.erase(tag_it);
            }
        }
    }

    if (client_ip.empty()) {
        return;
    }

    auto device_tag_it = impl_->devices.find(tag);
    if (device_tag_it == impl_->devices.end()) {
        return;
    }
    auto device_user_it = device_tag_it->second.find(user_id);
    if (device_user_it == device_tag_it->second.end()) {
        return;
    }
    auto ip_it = device_user_it->second.find(client_ip);
    if (ip_it == device_user_it->second.end()) {
        return;
    }
    if (--ip_it->second == 0) {
        device_user_it->second.erase(ip_it);
    }
    if (device_user_it->second.empty()) {
        device_tag_it->second.erase(device_user_it);
    }
    if (device_tag_it->second.empty()) {
        impl_->devices.erase(device_tag_it);
    }
}

bool UserOnlineTracker::CanAcceptDevice(std::string_view tag,
                                        uint64_t user_id,
                                        std::string_view client_ip,
                                        uint32_t device_limit) const {
    if (device_limit == 0 || client_ip.empty()) {
        return true;
    }

    auto tag_it = impl_->devices.find(tag);
    if (tag_it == impl_->devices.end()) {
        return true;
    }
    auto user_it = tag_it->second.find(user_id);
    if (user_it == tag_it->second.end()) {
        return true;
    }
    if (user_it->second.find(client_ip) != user_it->second.end()) {
        return true;
    }
    return user_it->second.size() < device_limit;
}

size_t UserOnlineTracker::OnlineDeviceCount(std::string_view tag,
                                            uint64_t user_id) const {
    auto tag_it = impl_->devices.find(tag);
    if (tag_it == impl_->devices.end()) {
        return 0;
    }
    auto user_it = tag_it->second.find(user_id);
    if (user_it == tag_it->second.end()) {
        return 0;
    }
    return user_it->second.size();
}

std::vector<UserOnlineTracker::OnlineDevice>
UserOnlineTracker::GetOnlineDevices(std::string_view tag) const {
    std::vector<OnlineDevice> result;
    auto tag_it = impl_->devices.find(tag);
    if (tag_it == impl_->devices.end()) {
        return result;
    }

    size_t count = 0;
    for (const auto& [uid, ips] : tag_it->second) {
        count += ips.size();
    }
    result.reserve(count);

    for (const auto& [uid, ips] : tag_it->second) {
        for (const auto& [ip, active_count] : ips) {
            if (active_count > 0) {
                result.emplace_back(static_cast<int64_t>(uid), ip);
            }
        }
    }
    return result;
}

}  // namespace acpp
