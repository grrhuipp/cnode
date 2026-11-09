#include "common/sharded_user_stats.hpp"

#include "common/allocator.hpp"
#include "common/string_hash.hpp"
#include "common/container_util.hpp"
#include "app/session_group_executor.hpp"

#include <string>
#include <unordered_map>


namespace {
template <typename Map>
void ReleaseDeviceCount(Map& devices,
                        std::string_view tag,
                        uint64_t user_id,
                        std::string_view ip) noexcept {
    const auto tag_it = devices.find(tag);
    if (tag_it == devices.end()) return;
    const auto user_it = tag_it->second.find(user_id);
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

struct DeviceQuota {
    using IpMap = std::unordered_map<std::string, uint32_t,
                                    TransparentStringHash, TransparentStringEq>;
    using Users = std::unordered_map<uint64_t, IpMap>;
    std::unordered_map<std::string, Users, TransparentStringHash, TransparentStringEq> devices;

    void Release(std::string_view tag, uint64_t user, std::string_view ip) noexcept {
        ReleaseDeviceCount(devices, tag, user, ip);
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

} // namespace

struct UserOnlineTracker::DeviceReservation {
    std::unique_ptr<DeviceReturn> node;
    ~DeviceReservation() {
        if (node && node->admitted) {
            auto* coordinator = node->coordinator;
            coordinator->PostReserved(std::move(node));
        }
    }
};

void UserOnlineSessionGuard::Reset() noexcept {
    if (auto* tracker = std::exchange(tracker_, nullptr)) {
        if (quota_reservation_ && quota_reservation_->node) {
            const auto& node = *quota_reservation_->node;
            tracker->OnUserDisconnected(node.tag, node.user, node.ip);
        }
    }
    quota_reservation_.reset();
}

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
    auto executor = co_await net::this_coro::executor;
    auto* coordinator = GroupCoordinator::ForContext(
        net::query(executor, net::execution::context));
    if (!coordinator) throw std::logic_error("user admission requires a registered coordinator");
    const auto uid = static_cast<uint64_t>(user_id);
    std::optional<UserOnlineSessionGuard> guard(std::in_place);
    auto reservation = std::make_shared<DeviceReservation>();
    reservation->node = std::make_unique<DeviceReturn>();
    auto& node = *reservation->node;
    node.coordinator = coordinator;
    node.tag.assign(tag);
    node.ip.assign(client_ip);
    node.user = uid;
    guard->quota_reservation_ = reservation;
    const bool admitted = co_await coordinator->PostCall(
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
    auto tag_it = impl_->devices.find(node.tag);
    bool tag_inserted = false;
    if (tag_it == impl_->devices.end()) {
        std::tie(tag_it, tag_inserted) =
            impl_->devices.try_emplace(memory::ThreadLocalString(node.tag));
    }
    try {
        auto [user_it, user_inserted] = tag_it->second.try_emplace(uid);
        try {
            if (auto ip_it = user_it->second.find(node.ip); ip_it != user_it->second.end()) {
                ++ip_it->second;
            } else {
                user_it->second.emplace(memory::ThreadLocalString(node.ip), 1u);
            }
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
    ReleaseDeviceCount(impl_->devices, tag, user_id, client_ip);
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

