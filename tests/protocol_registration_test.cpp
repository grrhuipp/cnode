#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/udp_handler.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "source_config.hpp"

#include <concepts>
#include <iostream>
#include <stdexcept>

namespace acpp::app::dns {
class DNS {};
}  // namespace acpp::app::dns

namespace {

using OutboundCreator = acpp::proxyman::outbound::PreparedOutboundCreator;
static_assert(std::invocable<
    OutboundCreator&,
    std::string_view,
    acpp::net::io_context&,
    acpp::app::dns::DNS&,
    acpp::UDPSessionManager*,
    std::chrono::seconds>);
static_assert(!std::invocable<
    OutboundCreator&,
    acpp::net::io_context&,
    acpp::app::dns::DNS&,
    acpp::UDPSessionManager*,
    std::chrono::seconds>);

template <typename Exception, typename Function>
bool Throws(Function&& function) {
    try {
        function();
    } catch (const Exception&) {
        return true;
    } catch (...) {
        return false;
    }
    return false;
}

class DummyRuntime final : public acpp::proxyman::inbound::ProtocolRuntime {
public:
    void* Validator() noexcept override { return this; }

    std::vector<acpp::OnlineDevice>
    GetOnlineDevices(std::string_view) const override {
        return {};
    }
};

class DummyUdpHandler final : public acpp::proxyman::inbound::UdpHandler {
public:
    std::optional<acpp::proxyman::inbound::UdpDecodeResult> DecodeUdp(
        std::string_view,
        std::string_view,
        const uint8_t*,
        size_t) const override {
        return std::nullopt;
    }

    acpp::buf::MultiBuffer EncodeUdpResponse(
        acpp::UDPPacketView,
        const acpp::proxyman::inbound::UdpResponseContext&) const override {
        return {};
    }
};

class DummyOutbound final : public acpp::Outbound {
public:
    explicit DummyOutbound(std::string tag) : tag_(std::move(tag)) {}

    std::string_view Tag() const noexcept override { return tag_; }

    acpp::net::awaitable<acpp::OutboundProcessResult> Process(
        acpp::net::io_context&,
        const acpp::tcp::endpoint*,
        acpp::session::Context&,
        const acpp::TimeoutsConfig&,
        acpp::transport::Link,
        acpp::StatsShard&,
        const acpp::RelayConfig&,
        std::span<const uint8_t>,
        acpp::buf::MultiBuffer&,
        std::chrono::seconds,
        std::chrono::seconds) override {
        co_return acpp::RelayResult{};
    }

private:
    std::string tag_;
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

std::unique_ptr<acpp::proxyman::inbound::UdpHandler> FailUdpHandler(
    const acpp::proxyman::inbound::ProtocolDeps&,
    acpp::ConnectionLimiterPtr,
    const acpp::proxyman::inbound::BuildRequest&) {
    return nullptr;
}

std::unique_ptr<acpp::proxyman::inbound::UdpHandler> CreateUdpHandler(
    const acpp::proxyman::inbound::ProtocolDeps&,
    acpp::ConnectionLimiterPtr,
    const acpp::proxyman::inbound::BuildRequest&) {
    return std::make_unique<DummyUdpHandler>();
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

std::optional<acpp::proxyman::outbound::PreparedOutboundCreator>
CreateOutboundConfig(
    const acpp::proxyman::outbound::OutboundSourceConfig&) {
    return acpp::proxyman::outbound::PreparedOutboundCreator{
        [](std::string_view tag,
           acpp::net::io_context&,
           acpp::app::dns::DNS&,
           acpp::UDPSessionManager*,
           std::chrono::seconds) -> std::unique_ptr<acpp::Outbound> {
            return std::make_unique<DummyOutbound>(std::string(tag));
        }};
}

std::optional<acpp::proxyman::outbound::PreparedOutboundCreator>
CreateMismatchedOutboundConfig(
    const acpp::proxyman::outbound::OutboundSourceConfig&) {
    return acpp::proxyman::outbound::PreparedOutboundCreator{
        [](std::string_view,
           acpp::net::io_context&,
           acpp::app::dns::DNS&,
           acpp::UDPSessionManager*,
           std::chrono::seconds) -> std::unique_ptr<acpp::Outbound> {
            return std::make_unique<DummyOutbound>("wrong-tag");
        }};
}

std::optional<acpp::proxyman::outbound::PreparedOutboundCreator>
CreateNullOutboundConfig(
    const acpp::proxyman::outbound::OutboundSourceConfig&) {
    return acpp::proxyman::outbound::PreparedOutboundCreator{
        [](std::string_view,
           acpp::net::io_context&,
           acpp::app::dns::DNS&,
           acpp::UDPSessionManager*,
           std::chrono::seconds) -> std::unique_ptr<acpp::Outbound> {
            return nullptr;
        }};
}

std::optional<acpp::proxyman::outbound::PreparedOutboundCreator>
CreateEmptyOutboundConfig(
    const acpp::proxyman::outbound::OutboundSourceConfig&) {
    return acpp::proxyman::outbound::PreparedOutboundCreator{};
}

bool TestInboundRegistration() {
    acpp::proxyman::inbound::ProxyRegistration valid;
    valid.create_runtime = &CreateInboundRuntime;
    valid.create_tcp_handler = &CreateInboundHandler;

    if (!Throws<std::invalid_argument>([&] {
            acpp::proxyman::inbound::RegisterProxy("", valid);
        })) {
        return false;
    }

    auto missing_runtime = valid;
    missing_runtime.create_runtime = nullptr;
    if (!Throws<std::invalid_argument>([&] {
            acpp::proxyman::inbound::RegisterProxy(
                "missing-runtime", missing_runtime);
        })) {
        return false;
    }

    auto missing_handler = valid;
    missing_handler.create_tcp_handler = nullptr;
    if (!Throws<std::invalid_argument>([&] {
            acpp::proxyman::inbound::RegisterProxy(
                "missing-handler", missing_handler);
        })) {
        return false;
    }

    auto missing_user_protocol = valid;
    missing_user_protocol.build_users = &BuildVmessUsers;
    if (!Throws<std::invalid_argument>([&] {
            acpp::proxyman::inbound::RegisterProxy(
                "missing-user-protocol", missing_user_protocol);
        })) {
        return false;
    }

    auto orphan_user_protocol = valid;
    orphan_user_protocol.user_protocol =
        acpp::proxyman::inbound::UserProtocol::Vmess;
    if (!Throws<std::invalid_argument>([&] {
            acpp::proxyman::inbound::RegisterProxy(
                "orphan-user-protocol", orphan_user_protocol);
        })) {
        return false;
    }

    acpp::proxyman::inbound::RegisterProxy("test-inbound", valid);
    if (!Throws<std::logic_error>([&] {
            acpp::proxyman::inbound::RegisterProxy("test-inbound", valid);
        })) {
        return false;
    }
    if (!acpp::proxyman::inbound::HasProxy("test-inbound")) return false;
    if (!acpp::proxyman::inbound::NewProtocolRuntime("test-inbound")) {
        return false;
    }

    const acpp::proxyman::inbound::BuildRequest request;
    const acpp::proxyman::inbound::ProtocolDeps deps;
    auto unknown_udp = acpp::proxyman::inbound::NewUdpHandler(
        "unknown-udp", deps, nullptr, request);
    if (unknown_udp.status !=
            acpp::proxyman::inbound::UdpHandlerBuildStatus::Failed ||
        unknown_udp.handler) {
        return false;
    }

    auto unsupported_udp = acpp::proxyman::inbound::NewUdpHandler(
        "test-inbound", deps, nullptr, request);
    if (unsupported_udp.status !=
            acpp::proxyman::inbound::UdpHandlerBuildStatus::Unsupported ||
        unsupported_udp.handler) {
        return false;
    }

    auto failed_udp_registration = valid;
    failed_udp_registration.create_udp_handler = &FailUdpHandler;
    acpp::proxyman::inbound::RegisterProxy(
        "failed-udp", failed_udp_registration);
    auto failed_udp = acpp::proxyman::inbound::NewUdpHandler(
        "failed-udp", deps, nullptr, request);
    if (failed_udp.status !=
            acpp::proxyman::inbound::UdpHandlerBuildStatus::Failed ||
        failed_udp.handler) {
        return false;
    }

    auto ready_udp_registration = valid;
    ready_udp_registration.create_udp_handler = &CreateUdpHandler;
    acpp::proxyman::inbound::RegisterProxy(
        "ready-udp", ready_udp_registration);
    auto ready_udp = acpp::proxyman::inbound::NewUdpHandler(
        "ready-udp", deps, nullptr, request);
    if (ready_udp.status !=
            acpp::proxyman::inbound::UdpHandlerBuildStatus::Ready ||
        !ready_udp.handler) {
        return false;
    }

    auto typed_users = valid;
    typed_users.user_protocol =
        acpp::proxyman::inbound::UserProtocol::Vmess;
    typed_users.build_users = &BuildVmessUsers;
    acpp::proxyman::inbound::RegisterProxy("vmess-alias", typed_users);
    if (acpp::proxyman::inbound::RegisteredUserProtocol("vmess-alias") !=
        acpp::proxyman::inbound::UserProtocol::Vmess) {
        return false;
    }
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
    acpp::proxyman::inbound::RegisterProxy(
        "mismatched-users", mismatched_users);
    return !acpp::proxyman::inbound::BuildUsers(
        "mismatched-users", request, {});
}

bool TestOutboundRegistration() {
    if (!Throws<std::invalid_argument>([] {
            acpp::proxyman::outbound::RegisterProxy(
                "", &CreateOutboundConfig);
        })) {
        return false;
    }
    if (!Throws<std::invalid_argument>([] {
            acpp::proxyman::outbound::RegisterProxy(
                "missing-creator", nullptr);
        })) {
        return false;
    }
    acpp::proxyman::outbound::RegisterProxy(
        "test-outbound", &CreateOutboundConfig);
    if (!Throws<std::logic_error>([] {
            acpp::proxyman::outbound::RegisterProxy(
                "test-outbound", &CreateOutboundConfig);
        })) {
        return false;
    }
    if (!acpp::proxyman::outbound::HasProxy("test-outbound")) {
        return false;
    }

    acpp::proxyman::outbound::OutboundSourceConfig source;
    source.tag = "source-owned-tag";
    source.protocol = "test-outbound";
    auto prepared = acpp::proxyman::outbound::PrepareOutboundConfig(source);
    if (!prepared || prepared->tag != source.tag ||
        prepared->protocol != source.protocol || !prepared->create) {
        return false;
    }
    acpp::net::io_context io_context;
    acpp::app::dns::DNS dns;
    auto handler = acpp::proxyman::outbound::NewHandler(
        *prepared, io_context, dns, nullptr, std::chrono::seconds(1));
    if (!handler || handler->Tag() != source.tag) {
        return false;
    }

    acpp::proxyman::outbound::RegisterProxy(
        "mismatched-outbound", &CreateMismatchedOutboundConfig);
    source.protocol = "mismatched-outbound";
    prepared = acpp::proxyman::outbound::PrepareOutboundConfig(source);
    if (!prepared || !Throws<std::logic_error>([&] {
            (void)acpp::proxyman::outbound::NewHandler(
                *prepared, io_context, dns, nullptr,
                std::chrono::seconds(1));
        })) {
        return false;
    }

    acpp::proxyman::outbound::RegisterProxy(
        "null-outbound", &CreateNullOutboundConfig);
    source.protocol = "null-outbound";
    prepared = acpp::proxyman::outbound::PrepareOutboundConfig(source);
    if (!prepared || !Throws<std::logic_error>([&] {
            (void)acpp::proxyman::outbound::NewHandler(
                *prepared, io_context, dns, nullptr,
                std::chrono::seconds(1));
        })) {
        return false;
    }

    acpp::proxyman::outbound::PreparedOutboundConfig missing_creator;
    missing_creator.tag = "missing-runtime-creator";
    if (!Throws<std::logic_error>([&] {
            (void)acpp::proxyman::outbound::NewHandler(
                missing_creator, io_context, dns, nullptr,
                std::chrono::seconds(1));
        })) {
        return false;
    }

    acpp::proxyman::outbound::RegisterProxy(
        "empty-outbound", &CreateEmptyOutboundConfig);
    source.protocol = "empty-outbound";
    return !acpp::proxyman::outbound::PrepareOutboundConfig(source);
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
