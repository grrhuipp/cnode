#include "acppnode/app/proxyman/inbound/manager.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/handler.hpp"
#include "acppnode/app/proxyman/inbound/udp_handler.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/proxy/shadowsocks/validator.hpp"
#include "acppnode/proxy/anytls/validator.hpp"
#include "acppnode/proxy/trojan/validator.hpp"
#include "acppnode/proxy/vmess/validator.hpp"

namespace acpp::proxyman::inbound {

struct Manager::Impl {
    using HandlerMap = memory::ThreadLocalUnorderedMap<
        std::string,
        std::unique_ptr<Handler>,
        TransparentStringHash,
        TransparentStringEq>;

    explicit Impl(StatsShard& stats) noexcept
        : stats(stats) {}

    [[nodiscard]] ProtocolDeps Deps() noexcept {
        return ProtocolDeps{
            &vmess_validator,
            &trojan_validator,
            &ss_validator,
            &anytls_validator,
            &stats,
        };
    }

    StatsShard& stats;
    ::acpp::vmess::TimedUserValidator vmess_validator;
    ::acpp::trojan::Validator trojan_validator;
    ::acpp::ss::Validator ss_validator;
    ::acpp::anytls::Validator anytls_validator;
    HandlerMap handlers;
    memory::ThreadLocalVector<std::unique_ptr<Handler>> retired_handlers;
};

Manager::Manager(StatsShard& stats)
    : impl_(std::make_unique<Impl>(stats)) {}

Manager::~Manager() noexcept = default;

Handler* Manager::GetHandler(std::string_view tag) noexcept {
    auto it = impl_->handlers.find(tag);
    return it == impl_->handlers.end() ? nullptr : it->second.get();
}

const Handler* Manager::GetHandler(std::string_view tag) const noexcept {
    auto it = impl_->handlers.find(tag);
    return it == impl_->handlers.end() ? nullptr : it->second.get();
}

std::unique_ptr<::acpp::Inbound> Manager::NewHandler(
    std::string_view protocol,
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req) {
    return ::acpp::proxyman::inbound::NewHandler(
        protocol, impl_->Deps(), std::move(limiter), req);
}

std::unique_ptr<UdpHandler> Manager::NewUdpHandler(
    std::string_view protocol,
    ::acpp::ConnectionLimiterPtr limiter,
    const BuildRequest& req) {
    return ::acpp::proxyman::inbound::NewUdpHandler(
        protocol, impl_->Deps(), std::move(limiter), req);
}

Handler* Manager::AddHandler(std::unique_ptr<Handler> handler) noexcept {
    if (!handler) {
        return nullptr;
    }

    std::string tag(handler->Tag());
    if (impl_->handlers.contains(tag)) {
        return nullptr;
    }

    Handler* raw = handler.get();
    impl_->handlers.emplace(std::move(tag), std::move(handler));
    return raw;
}

void Manager::RemoveHandler(std::string_view tag) noexcept {
    auto it = impl_->handlers.find(tag);
    if (it == impl_->handlers.end()) {
        return;
    }

    impl_->retired_handlers.push_back(std::move(it->second));
    impl_->handlers.erase(it);
}

void Manager::DrainRetiredHandlers() {
    impl_->retired_handlers.clear();
    TryShrinkSequence(impl_->retired_handlers);
}

void Manager::ApplyUsers(std::string_view protocol, std::string_view tag, const UserSet& users) {
    UserStore::ApplyUsers(protocol, tag, users);
}

void Manager::AddUsers(std::string_view protocol, std::string_view tag, const UserSet& users) {
    UserStore::AddUsers(protocol, tag, users);
}

void Manager::RemoveUsers(std::string_view protocol, std::string_view tag, const UserSet& users) {
    UserStore::RemoveUsers(protocol, tag, users);
}

void Manager::ClearUsers(std::string_view protocol, std::string_view tag) {
    UserStore::ClearUsers(protocol, tag);
}

std::vector<::acpp::OnlineDevice>
Manager::GetOnlineDevices(std::string_view protocol, std::string_view tag) const {
    if (protocol == constants::protocol::kVmess) {
        return impl_->vmess_validator.GetOnlineDevices(tag);
    }
    if (protocol == constants::protocol::kTrojan) {
        return impl_->trojan_validator.GetOnlineDevices(tag);
    }
    if (protocol == constants::protocol::kShadowsocks) {
        return impl_->ss_validator.GetOnlineDevices(tag);
    }
    if (protocol == constants::protocol::kAnyTLS) {
        return impl_->anytls_validator.GetOnlineDevices(tag);
    }
    return {};
}

Manager::UserMemoryStats Manager::GetUserMemoryStats() const noexcept {
    const auto stats = UserStore::GetStats();
    return UserMemoryStats{
        stats.vmess_accounts,
        stats.trojan_users,
        stats.shadowsocks_users,
        stats.anytls_users,
    };
}

}  // namespace acpp::proxyman::inbound
