#include "acppnode/app/proxyman/inbound/factory.hpp"
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

    if (!acpp::proxyman::inbound::RegisterProxy(
            "test-inbound", valid)) {
        return false;
    }
    if (acpp::proxyman::inbound::RegisterProxy(
            "test-inbound", valid)) {
        return false;
    }
    if (!acpp::proxyman::inbound::HasProxy("test-inbound")) return false;
    return static_cast<bool>(
        acpp::proxyman::inbound::NewProtocolRuntime("test-inbound"));
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
