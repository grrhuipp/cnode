#include "hysteria_settings.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "../inbound_admission.hpp"

#include <limits>

namespace {

constexpr uint64_t kBytesPerSecondPerMbps = 125000;

[[nodiscard]] uint64_t MbpsToBytesPerSecond(uint32_t mbps) noexcept {
    return static_cast<uint64_t>(mbps) * kBytesPerSecondPerMbps;
}

std::optional<std::shared_ptr<const acpp::proxyman::inbound::ProtocolSettings>>
PrepareSettings(acpp::proxy::hysteria::Version version,
                std::string_view,
                const acpp::StaticUserConfig& config) {
    auto settings = std::make_shared<acpp::proxy::hysteria::Settings>();
    settings->version = version;
    settings->upload_bytes_per_second =
        MbpsToBytesPerSecond(config.hysteria_up_mbps);
    settings->download_bytes_per_second =
        MbpsToBytesPerSecond(config.hysteria_down_mbps);
    return settings;
}

std::optional<acpp::proxyman::inbound::UserSet> BuildStaticUsers(
    std::string_view tag,
    const acpp::StaticUserConfig& config) {
    std::vector<acpp::proxyman::inbound::PreparedHysteriaUser> users;
    users.reserve(config.clients.size());
    for (const auto& client : config.clients) {
        const auto& credential = client.password.empty() ? client.id : client.password;
        if (credential.empty()) {
            LOG_WARN("Hysteria inbound '{}': static user credential is empty", tag);
            return std::nullopt;
        }
        acpp::proxyman::inbound::PreparedHysteriaUser user;
        user.credential_hash = acpp::proxy::hysteria::HashCredential(credential);
        user.profile.email = client.email.empty() ? std::string(tag) : client.email;
        users.push_back(std::move(user));
    }
    return acpp::proxyman::inbound::UserSet{std::move(users)};
}

std::optional<acpp::proxyman::inbound::UserSet> BuildRuntimeUsers(
    const acpp::proxyman::inbound::BuildRequest&,
    std::span<const acpp::proxyman::inbound::RuntimeUser> runtime_users) {
    std::vector<acpp::proxyman::inbound::PreparedHysteriaUser> users;
    users.reserve(runtime_users.size());
    for (const auto& runtime_user : runtime_users) {
        if (runtime_user.credential.empty()) return std::nullopt;
        acpp::proxyman::inbound::PreparedHysteriaUser user;
        user.credential_hash =
            acpp::proxy::hysteria::HashCredential(runtime_user.credential);
        user.profile.email = runtime_user.email;
        user.profile.user_id = runtime_user.user_id;
        user.profile.speed_limit = runtime_user.speed_limit;
        user.profile.device_limit = runtime_user.device_limit;
        users.push_back(std::move(user));
    }
    return acpp::proxyman::inbound::UserSet{std::move(users)};
}

acpp::proxyman::inbound::ProxyRegistration Registration() {
    acpp::proxyman::inbound::ProxyRegistration registration;
    registration.user_protocol =
        acpp::proxyman::inbound::UserProtocol::Hysteria;
    registration.datagram_transport =
        acpp::proxyman::inbound::DatagramTransport::Quic;
    registration.create_runtime = []() -> std::unique_ptr<
        acpp::proxyman::inbound::ProtocolRuntime> {
        return std::make_unique<acpp::proxy::UserOnlineProtocolRuntime>();
    };
    registration.build_static_users = &BuildStaticUsers;
    registration.build_users = &BuildRuntimeUsers;
    return registration;
}

const bool kHysteriaRegistered = [] {
    auto v1 = Registration();
    v1.prepare_settings = [](
        std::string_view tag, const acpp::StaticUserConfig& config)
        -> std::optional<std::shared_ptr<const
            acpp::proxyman::inbound::ProtocolSettings>> {
        return PrepareSettings(acpp::proxy::hysteria::Version::V1, tag, config);
    };
    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kHysteria, std::move(v1));

    auto v2 = Registration();
    v2.prepare_settings = [](
        std::string_view tag, const acpp::StaticUserConfig& config)
        -> std::optional<std::shared_ptr<const
            acpp::proxyman::inbound::ProtocolSettings>> {
        return PrepareSettings(acpp::proxy::hysteria::Version::V2, tag, config);
    };
    acpp::proxyman::inbound::RegisterProxy(
        acpp::constants::protocol::kHysteria2, std::move(v2));
    return true;
}();

}  // namespace
