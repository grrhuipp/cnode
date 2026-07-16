#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "source_config.hpp"

#include <iostream>

namespace {

class DummyRuntime final : public acpp::proxyman::inbound::ProtocolRuntime {
public:
    void* Validator() noexcept override { return this; }

    std::vector<acpp::OnlineDevice>
    GetOnlineDevices(std::string_view) const override {
        return {};
    }
};

std::unique_ptr<acpp::proxyman::inbound::ProtocolRuntime>
CreateInboundRuntime() {
    return std::make_unique<DummyRuntime>();
}

std::unique_ptr<acpp::Inbound> CreateInboundHandler(
    const acpp::proxyman::inbound::ProtocolDeps&,
    acpp::ConnectionLimiterPtr,
    const acpp::proxyman::inbound::BuildRequest&) {
    return nullptr;
}

std::optional<acpp::proxyman::inbound::UserSet> BuildVmessUsers(
    const acpp::proxyman::inbound::BuildRequest&,
    std::span<const acpp::proxyman::inbound::RuntimeUser>) {
    return acpp::proxyman::inbound::UserSet{
        acpp::proxyman::inbound::PreparedVmessUsers{
            acpp::proxyman::inbound::PreparedVmessUser{.uuid = "alias-user"}}};
}

std::optional<acpp::proxyman::inbound::UserSet> BuildTrojanUsers(
    const acpp::proxyman::inbound::BuildRequest&,
    std::span<const acpp::proxyman::inbound::RuntimeUser>) {
    return acpp::proxyman::inbound::UserSet{
        acpp::proxyman::inbound::PreparedTrojanUsers{}};
}

std::optional<acpp::proxyman::outbound::PreparedOutboundConfig>
CreateOutboundConfig(
    const acpp::proxyman::outbound::OutboundSourceConfig&) {
    return acpp::proxyman::outbound::PreparedOutboundConfig{};
}

bool TestInboundRegistration() {
    acpp::proxyman::inbound::ProxyRegistration valid;
    valid.create_runtime = &CreateInboundRuntime;
    valid.create_tcp_handler = &CreateInboundHandler;

    if (acpp::proxyman::inbound::RegisterProxy("", valid)) return false;

    auto missing_runtime = valid;
    missing_runtime.create_runtime = nullptr;
    if (acpp::proxyman::inbound::RegisterProxy(
            "missing-runtime", missing_runtime)) {
        return false;
    }

    auto missing_handler = valid;
    missing_handler.create_tcp_handler = nullptr;
    if (acpp::proxyman::inbound::RegisterProxy(
            "missing-handler", missing_handler)) {
        return false;
    }

    auto missing_user_protocol = valid;
    missing_user_protocol.build_users = &BuildVmessUsers;
    if (acpp::proxyman::inbound::RegisterProxy(
            "missing-user-protocol", missing_user_protocol)) {
        return false;
    }

    auto orphan_user_protocol = valid;
    orphan_user_protocol.user_protocol =
        acpp::proxyman::inbound::UserProtocol::Vmess;
    if (acpp::proxyman::inbound::RegisterProxy(
            "orphan-user-protocol", orphan_user_protocol)) {
        return false;
    }

    if (!acpp::proxyman::inbound::RegisterProxy(
            "test-inbound", valid)) {
        return false;
    }
    if (acpp::proxyman::inbound::RegisterProxy(
            "test-inbound", valid)) {
        return false;
    }
    if (!acpp::proxyman::inbound::HasProxy("test-inbound")) return false;
    if (!acpp::proxyman::inbound::NewProtocolRuntime("test-inbound")) {
        return false;
    }

    auto typed_users = valid;
    typed_users.user_protocol =
        acpp::proxyman::inbound::UserProtocol::Vmess;
    typed_users.build_users = &BuildVmessUsers;
    if (!acpp::proxyman::inbound::RegisterProxy(
            "vmess-alias", typed_users)) {
        return false;
    }
    if (acpp::proxyman::inbound::RegisteredUserProtocol("vmess-alias") !=
        acpp::proxyman::inbound::UserProtocol::Vmess) {
        return false;
    }
    const acpp::proxyman::inbound::BuildRequest request;
    auto users = acpp::proxyman::inbound::BuildUsers("vmess-alias", request, {});
    if (!users || acpp::proxyman::inbound::UserProtocolOf(*users) !=
                      acpp::proxyman::inbound::UserProtocol::Vmess) {
        return false;
    }
    constexpr std::string_view kAliasTag = "alias-tag";
    acpp::proxyman::inbound::UserStore::ApplyUsers(kAliasTag, *users);
    acpp::proxyman::inbound::UserStore::ClearUsers(
        *acpp::proxyman::inbound::RegisteredUserProtocol("vmess-alias"),
        kAliasTag);
    if (acpp::proxyman::inbound::UserStore::SizeForProtocolTag(
            acpp::proxyman::inbound::UserProtocol::Vmess, kAliasTag) != 0) {
        return false;
    }

    auto mismatched_users = typed_users;
    mismatched_users.build_users = &BuildTrojanUsers;
    if (!acpp::proxyman::inbound::RegisterProxy(
            "mismatched-users", mismatched_users)) {
        return false;
    }
    return !acpp::proxyman::inbound::BuildUsers(
        "mismatched-users", request, {});
}

bool TestOutboundRegistration() {
    if (acpp::proxyman::outbound::RegisterProxy(
            "", &CreateOutboundConfig)) {
        return false;
    }
    if (acpp::proxyman::outbound::RegisterProxy(
            "missing-creator", nullptr)) {
        return false;
    }
    if (!acpp::proxyman::outbound::RegisterProxy(
            "test-outbound", &CreateOutboundConfig)) {
        return false;
    }
    if (acpp::proxyman::outbound::RegisterProxy(
            "test-outbound", &CreateOutboundConfig)) {
        return false;
    }
    return acpp::proxyman::outbound::HasProxy("test-outbound");
}

}  // namespace

int main() {
    if (!TestInboundRegistration()) {
        std::cerr << "inbound protocol registration accepted invalid state\n";
        return 1;
    }
    if (!TestOutboundRegistration()) {
        std::cerr << "outbound protocol registration accepted invalid state\n";
        return 1;
    }
    return 0;
}
