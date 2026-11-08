#include "common/sharded_user_stats.hpp"

#include "common/allocator.hpp"
#include "common/string_hash.hpp"
#include "common/container_util.hpp"
#include "app/session_group_executor.hpp"

#include <string>
#include <unordered_map>


namespace {
struct DeviceQuota {
    using IpMap = std::unordered_map<std::string, uint32_t,
                                    TransparentStringHash, TransparentStringEq>;
    using Users = std::unordered_map<uint64_t, IpMap>;
    std::unordered_map<std::string, Users, TransparentStringHash, TransparentStringEq> devices;

    void Release(std::string_view tag, uint64_t user, std::string_view ip) noexcept {
        const auto tag_it = devices.find(tag);
        if (tag_it == devices.end()) return;
        const auto user_it = tag_it->second.find(user);
        if (user_it == tag_it->second.end()) return;
        const auto ip_it = user_it->second.find(ip);
        if (ip_it == user_it->second.end()) return;
        if (--ip_it->second == 0) {
            user_it->second.erase(ip_it);
            MaybeShrinkHashContainer(user_it->second, 8);
        }
        if (user_it->second.empty()) {
            tag_it->second.erase(user_it);
            MaybeShrinkHashContainer(tag_it->second, 8);
        }
        if (tag_it->second.empty()) {
            devices.erase(tag_it);
            MaybeShrinkHashContainer(devices, 8);
        }
    }
};

struct DeviceQuotaService final : net::execution_context::service {
    inline static net::execution_context::id id;
    explicit DeviceQuotaService(net::execution_context& context)
        : service(context), quota(std::make_shared<DeviceQuota>()) {}
    void shutdown() override { quota.reset(); }
    std::shared_ptr<DeviceQuota> quota;
};

struct DeviceReturn final : GroupCoordinator::ReservedOperation {
    GroupCoordinator* coordinator = nullptr;
    std::shared_ptr<DeviceQuota> quota;
    std::string tag;
    std::string ip;
    uint64_t user = 0;
    bool admitted = false;
    void Invoke() noexcept override { quota->Release(tag, user, ip); }
};

struct DeviceReservation {
    std::unique_ptr<DeviceReturn> node;
    ~DeviceReservation() {
        if (node && node->admitted) {
            auto* coordinator = node->coordinator;
            coordinator->PostReserved(std::move(node));
        }
    }
};
} // namespace

struct UserOnlineTracker::Impl : memory::ThreadAllocated {
    using DeviceIpMap =
        memory::ThreadLocalUnorderedMap<memory::ThreadLocalString,
                                        uint32_t,
                                        TransparentStringHash,
                                        TransparentStringEq>;
    using UserDeviceMap = memory::ThreadLocalUnorderedMap<uint64_t, DeviceIpMap>;
    using TagDeviceMap =
        memory::ThreadLocalUnorderedMap<memory::ThreadLocalString,
                                        UserDeviceMap,
                                        TransparentStringHash,
                                        TransparentStringEq>;

    TagDeviceMap devices;
};

UserOnlineTracker::UserOnlineTracker() : impl_(std::make_unique<Impl>()) {}

UserOnlineTracker::~UserOnlineTracker() = default;

net::awaitable<std::optional<UserOnlineSessionGuard>> UserOnlineTracker::TryConnectSession(
    std::string_view tag,
    int64_t user_id,
    std::string_view client_ip,
    uint32_t device_limit) {
    if (user_id <= 0 || client_ip.empty()) {
        co_return std::optional<UserOnlineSessionGuard>(std::in_place);
    }
    std::string owned_tag(tag);
    std::string owned_client_ip(client_ip);
    // Held across the admission: the domain owns the coordinator reference.
    auto domain = ExecutionDomain::Current();
    if (!domain) throw std::logic_error("user admission requires an execution domain");
    co_return co_await TryConnectSession(
        domain->Coordinator(), owned_tag, user_id, owned_client_ip, device_limit);
}

net::awaitable<std::optional<UserOnlineSessionGuard>> UserOnlineTracker::TryConnectSession(
    GroupCoordinator& coordinator,
    std::string_view tag,
    int64_t user_id,
    std::string_view client_ip,
    uint32_t device_limit) {
    if (user_id <= 0 || client_ip.empty()) {
        co_return std::optional<UserOnlineSessionGuard>(std::in_place);
    }
    const std::string owned_tag(tag);
    const std::string owned_client_ip(client_ip);
    const auto uid = static_cast<uint64_t>(user_id);
    // Prepare the guard's owned strings before reserving either counter.
    std::optional<UserOnlineSessionGuard> guard(
        std::in_place, owned_tag, uid, owned_client_ip);
    auto reservation = std::make_shared<DeviceReservation>();
    reservation->node = std::make_unique<DeviceReturn>();
    auto& node = *reservation->node;
    node.coordinator = &coordinator;
    node.tag = owned_tag;
    node.ip = owned_client_ip;
    node.user = uid;
    guard->quota_reservation_ = reservation;
    const bool admitted = co_await coordinator.PostCall(
        [reservation, device_limit] {
            auto& node = *reservation->node;
            node.quota = net::use_service<DeviceQuotaService>(
                node.coordinator->Services()).quota;
            auto [tag_it, tag_inserted] = node.quota->devices.try_emplace(node.tag);
            try {
                auto [user_it, user_inserted] = tag_it->second.try_emplace(node.user);
                try {
                    auto& all_ips = user_it->second;
                    const auto global_ip = all_ips.find(node.ip);
                    if (global_ip == all_ips.end() && device_limit != 0 &&
                        all_ips.size() >= device_limit) {
                        if (user_inserted && all_ips.empty()) tag_it->second.erase(user_it);
                        if (tag_inserted && tag_it->second.empty()) node.quota->devices.erase(tag_it);
                        return false;
                    }
                    ++all_ips.try_emplace(node.ip, 0u).first->second;
                } catch (...) {
                    if (user_inserted && user_it->second.empty()) tag_it->second.erase(user_it);
                    throw;
                }
            } catch (...) {
                if (tag_inserted && tag_it->second.empty()) node.quota->devices.erase(tag_it);
                throw;
            }
            node.admitted = true;
            return true;
        });
    if (!admitted) co_return std::nullopt;
    memory::ScopedWorkerAllocation worker_allocation;
    auto tag_it = impl_->devices.find(owned_tag);
    bool tag_inserted = false;
    if (tag_it == impl_->devices.end()) {
        std::tie(tag_it, tag_inserted) =
            impl_->devices.try_emplace(memory::ThreadLocalString(owned_tag));
    }
    try {
        auto [user_it, user_inserted] = tag_it->second.try_emplace(uid);
        try {
            ++user_it->second.try_emplace(memory::ThreadLocalString(owned_client_ip), 0u).first->second;
        } catch (...) {
            if (user_inserted && user_it->second.empty()) tag_it->second.erase(user_it);
            throw;
        }
    } catch (...) {
        if (tag_inserted && tag_it->second.empty()) impl_->devices.erase(tag_it);
        throw;
    }
    guard->Arm(*this);
    co_return std::move(guard);
}

void UserOnlineTracker::OnUserDisconnected(std::string_view tag,
                                           uint64_t user_id,
                                           std::string_view client_ip) noexcept {
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
        MaybeShrinkHashContainer(device_user_it->second, 8);
    }
    if (device_user_it->second.empty()) {
        device_tag_it->second.erase(device_user_it);
        MaybeShrinkHashContainer(device_tag_it->second, 8);
    }
    if (device_tag_it->second.empty()) {
        impl_->devices.erase(device_tag_it);
        MaybeShrinkHashContainer(impl_->devices, 8);
    }
}

size_t UserOnlineTracker::OnlineDeviceCount(std::string_view tag,
                                            uint64_t user_id) const {
    const auto tag_it = impl_->devices.find(tag);
    if (tag_it == impl_->devices.end()) return 0;
    const auto user_it = tag_it->second.find(user_id);
    return user_it == tag_it->second.end() ? 0 : user_it->second.size();
}

std::vector<OnlineDevice>
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
                result.emplace_back(static_cast<int64_t>(uid), std::string(std::string_view(ip)));
            }
        }
    }
    return result;
}

