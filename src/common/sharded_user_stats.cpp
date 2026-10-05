#include "acppnode/common/sharded_user_stats.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/string_hash.hpp"

#include <string>

namespace acpp {

struct UserOnlineTracker::Impl {
    void OnUserConnected(std::string_view tag, uint64_t user_id, std::string_view client_ip);
    void OnUserDisconnected(std::string_view tag, uint64_t user_id, std::string_view client_ip);
    bool CanAcceptDevice(std::string_view tag, uint64_t user_id, std::string_view client_ip, uint32_t device_limit) const;
    size_t OnlineDeviceCount(std::string_view tag, uint64_t user_id) const;
    std::vector<OnlineDevice> GetOnlineDevices(std::string_view tag) const;
    using UserConnectionMap = memory::DataUnorderedMap<uint64_t, uint32_t>;
    using TagConnectionMap =
        memory::DataUnorderedMap<std::string,
                                        UserConnectionMap,
                                        TransparentStringHash,
                                        TransparentStringEq>;
    using DeviceIpMap =
        memory::DataUnorderedMap<std::string,
                                        uint32_t,
                                        TransparentStringHash,
                                        TransparentStringEq>;
    using UserDeviceMap = memory::DataUnorderedMap<uint64_t, DeviceIpMap>;
    using TagDeviceMap =
        memory::DataUnorderedMap<std::string,
                                        UserDeviceMap,
                                        TransparentStringHash,
                                        TransparentStringEq>;

    TagConnectionMap connections;
    TagDeviceMap devices;
};

UserOnlineTracker::UserOnlineTracker(net::any_io_executor executor, size_t capacity)
    : impl_(std::make_unique<Impl>()), channel_(std::move(executor), capacity) {}

UserOnlineTracker::~UserOnlineTracker() = default;

void UserOnlineTracker::Impl::OnUserConnected(std::string_view tag,
                                        uint64_t user_id,
                                        std::string_view client_ip) {
    auto& user_connections = connections[std::string(tag)];
    user_connections[user_id]++;

    if (!client_ip.empty()) {
        auto& user_devices = devices[std::string(tag)][user_id];
        user_devices[std::string(client_ip)]++;
    }
}

void UserOnlineTracker::Impl::OnUserDisconnected(std::string_view tag,
                                           uint64_t user_id,
                                           std::string_view client_ip) {
    auto tag_it = connections.find(tag);
    if (tag_it != connections.end()) {
        auto user_it = tag_it->second.find(user_id);
        if (user_it != tag_it->second.end() && --user_it->second == 0) {
            tag_it->second.erase(user_it);
            if (tag_it->second.empty()) {
                connections.erase(tag_it);
            }
        }
    }

    if (client_ip.empty()) {
        return;
    }

    auto device_tag_it = devices.find(tag);
    if (device_tag_it == devices.end()) {
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
        devices.erase(device_tag_it);
    }
}

bool UserOnlineTracker::Impl::CanAcceptDevice(std::string_view tag,
                                        uint64_t user_id,
                                        std::string_view client_ip,
                                        uint32_t device_limit) const {
    if (device_limit == 0 || client_ip.empty()) {
        return true;
    }

    auto tag_it = devices.find(tag);
    if (tag_it == devices.end()) {
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

size_t UserOnlineTracker::Impl::OnlineDeviceCount(std::string_view tag,
                                            uint64_t user_id) const {
    auto tag_it = devices.find(tag);
    if (tag_it == devices.end()) {
        return 0;
    }
    auto user_it = tag_it->second.find(user_id);
    if (user_it == tag_it->second.end()) {
        return 0;
    }
    return user_it->second.size();
}

std::vector<OnlineDevice>
UserOnlineTracker::Impl::GetOnlineDevices(std::string_view tag) const {
    std::vector<OnlineDevice> result;
    auto tag_it = devices.find(tag);
    if (tag_it == devices.end()) {
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

net::awaitable<std::optional<UserOnlineTracker::Permit>> UserOnlineTracker::TryAcquire(
    std::string tag, uint64_t user_id, std::string client_ip, uint32_t device_limit) {
    auto reservation = channel_.TryReserve();
    if (!reservation) throw ServiceChannelFull();
    const bool acquired = co_await channel_.CallReserved(reservation,
        [this, tag, user_id, client_ip, device_limit] {
            if (!impl_->CanAcceptDevice(tag, user_id, client_ip, device_limit)) return false;
            if (user_id != 0) {
                try { impl_->OnUserConnected(tag, user_id, client_ip); }
                catch (...) { impl_->OnUserDisconnected(tag, user_id, client_ip); throw; }
            }
            return true;
        });
    if (!acquired) co_return std::nullopt;
    co_return Permit{.reservation = std::move(reservation), .tag = std::move(tag),
        .user_id = user_id, .client_ip = std::move(client_ip)};
}

net::awaitable<void> UserOnlineTracker::Release(Permit permit) {
    co_await channel_.CallReserved(permit.reservation,
        [this, tag = std::move(permit.tag), user_id = permit.user_id,
         client_ip = std::move(permit.client_ip)] {
            if (user_id != 0) impl_->OnUserDisconnected(tag, user_id, client_ip);
        });
}

net::awaitable<size_t> UserOnlineTracker::OnlineDeviceCount(
    std::string tag, uint64_t user_id) {
    return channel_.Call([this, tag = std::move(tag), user_id] {
        return impl_->OnlineDeviceCount(tag, user_id);
    });
}

net::awaitable<std::vector<OnlineDevice>> UserOnlineTracker::GetOnlineDevices(std::string tag) {
    return channel_.Call([this, tag = std::move(tag)] {
        return impl_->GetOnlineDevices(tag);
    });
}

net::awaitable<bool> UserOnlineLease::Acquire(std::string tag, uint64_t user_id,
                                            std::string ip, uint32_t limit) {
    permit_ = co_await owner_.TryAcquire(std::move(tag), user_id, std::move(ip), limit);
    co_return permit_.has_value();
}

net::awaitable<void> UserOnlineLease::Release() {
    if (permit_) {
        co_await owner_.Release(std::move(*permit_));
        permit_.reset();
    }
}

}  // namespace acpp
