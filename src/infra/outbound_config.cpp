#include "infra/config.hpp"
#include "infra/json.hpp"
#include "common/scoped_cleanse.hpp"
#include "proxy/anytls_padding.hpp"
#include "proxy/vless_config.hpp"
#include <limits>
#include <stdexcept>

namespace infra {
namespace {

const object& SingleObject(const value* value, std::string_view key) {
    if (!value || !value->is_array() || value->as_array().size() != 1 ||
        !value->as_array()[0].is_object()) {
        throw std::invalid_argument(std::string(key) + " must contain exactly one object");
    }
    return value->as_array()[0].as_object();
}

transport::OutboundServer Server(const object& source, uint16_t default_port) {
    const auto port = ReadJsonPort(source, "port");
    if (port.error != JsonPortError::None && port.error != JsonPortError::Missing) {
        throw std::invalid_argument("outbound server port must be an integer between 1 and 65535");
    }
    auto server = transport::MakeOutboundServer(JsonStringOr(source, "address", ""),
                                    port.Valid() ? port.value : default_port);
    if (!server) throw std::invalid_argument(std::string(server.error()));
    return std::move(*server);
}

std::string Password(const object& source) {
    auto password = JsonStringOr(source, "password", "");
    if (password.empty()) throw std::invalid_argument("outbound password is required");
    return password;
}

proxy::UotVersion ParseUotVersion(const infra::value& value) {
    const auto number = JsonUnsignedInteger(value);
    if (number == 1) return proxy::UotVersion::V1;
    if (number == 2) return proxy::UotVersion::V2;
    throw std::invalid_argument("UoT version must be 1 or 2");
}

std::optional<proxy::UotVersion> Uot(const object& source) {
    const auto* value = source.if_contains("uot");
    const auto* version = source.if_contains("uotVersion");
    if (!value) {
        if (version) throw std::invalid_argument("uotVersion requires uot");
        return std::nullopt;
    }
    if (value->is_bool()) {
        if (!value->as_bool()) {
            if (version) throw std::invalid_argument("disabled UoT cannot specify a version");
            return std::nullopt;
        }
        return version ? ParseUotVersion(*version) : proxy::UotVersion::V2;
    }
    if (!value->is_object()) throw std::invalid_argument("uot must be a boolean or object");
    if (version) throw std::invalid_argument("uot object cannot be combined with uotVersion");
    const auto& object = value->as_object();
    RequireJsonKeys(object, {"enabled", "version"}, "outbound.settings.uot");
    const bool enabled = JsonBoolOr(object, "enabled", true);
    version = object.if_contains("version");
    if (!enabled) {
        if (version) throw std::invalid_argument("disabled UoT cannot specify a version");
        return std::nullopt;
    }
    return version ? ParseUotVersion(*version) : proxy::UotVersion::V2;
}

std::chrono::seconds PositiveSeconds(const object& source, std::string_view key,
                                     std::chrono::seconds fallback) {
    const auto value = RequireJson(ParseJsonUint64(source, key));
    if (!value) return fallback;
    const auto maximum = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::duration::max()).count();
    if (*value == 0 || *value > static_cast<uint64_t>(maximum)) {
        throw std::invalid_argument(std::string(key) + " exceeds the positive steady clock range");
    }
    return std::chrono::seconds(static_cast<std::chrono::seconds::rep>(*value));
}

constexpr std::initializer_list<std::string_view> kSsFields{
    "address", "port", "password", "method", "uot", "uotVersion"};
constexpr std::initializer_list<std::string_view> kTrojanFields{
    "address", "port", "password", "serverName", "allowInsecure", "alpn"};
constexpr std::initializer_list<std::string_view> kVlessFields{
    "id", "encryption", "flow", "packetEncoding"};
constexpr std::initializer_list<std::string_view> kVmessFields{
    "id", "security", "alterId"};

}  // namespace

OutboundSettings ParseOutboundSettings(std::string_view protocol, const object& source) {
    if (protocol == common::kFreedom) {
        RequireJsonKeys(source, {"domainStrategy", "redirect"},
                        "outbound.settings");
        FreedomSettings result;
        const auto strategy = proxy::ParseDomainStrategy(
            JsonStringOr(source, "domainStrategy", "AsIs"));
        if (!strategy) throw std::invalid_argument("unsupported freedom domainStrategy");
        result.domain_strategy = *strategy;
        const auto redirect = JsonStringOr(source, "redirect", "");
        if (!redirect.empty()) {
            result.redirect = common::TargetAddress::Parse(redirect);
            if (!result.redirect || !result.redirect->IsValid()) {
                throw std::invalid_argument("freedom redirect must be a valid host:port");
            }
        }
        return result;
    }
    if (protocol == common::kBlackhole) {
        RequireJsonKeys(source, {"response"}, "outbound.settings");
        BlackholeSettings result;
        if (const auto* response = RequireJson(ParseJsonObject(source, "response"))) {
            RequireJsonKeys(*response, {"type"}, "outbound.settings.response");
            const auto type = common::LowerAscii(JsonStringOr(*response, "type", "none"));
            if (type != "none" && type != "http") {
                throw std::invalid_argument("blackhole response.type must be none or http");
            }
            result.http_response = type == "http";
        }
        return result;
    }
    if (protocol == common::kAnyTLS) {
        RequireJsonKeys(source, {"address", "port", "password", "idleSessionCheckInterval",
                                "idleSessionTimeout", "minIdleSession"}, "outbound.settings");
        AnyTlsSettings result;
        result.server = Server(source, 0);
        auto password = Password(source);
        common::ScopedCleanse cleanse{password};
        result.password_hash = proxy::HashAnyTlsPassword(password);
        result.idle_session_check_interval = PositiveSeconds(
            source, "idleSessionCheckInterval", result.idle_session_check_interval);
        result.idle_session_timeout = PositiveSeconds(source, "idleSessionTimeout", result.idle_session_timeout);
        result.min_idle_sessions = static_cast<size_t>(RequireJson(ParseJsonUint64(
            source, "minIdleSession", std::numeric_limits<size_t>::max())).value_or(0));
        return result;
    }
    if (protocol == common::kShadowsocks || protocol == common::kTrojan) {
        const bool shadowsocks = protocol == common::kShadowsocks;
        const object* server = &source;
        if (const auto* servers = source.if_contains("servers")) {
            RequireJsonKeys(source, {"servers"}, "outbound.settings");
            server = &SingleObject(servers, "servers");
        }
        RequireJsonKeys(*server, shadowsocks ? kSsFields : kTrojanFields, "outbound.settings.server");
        if (shadowsocks) {
            ShadowsocksSettings result;
            result.server = Server(*server, 8388);
            const auto cipher = proxy::ParseCipherMethod(JsonStringOr(*server, "method", "aes-256-gcm"));
            if (!cipher) throw std::invalid_argument("unsupported Shadowsocks method");
            result.cipher = *cipher;
            result.password = Password(*server);
            result.uot_version = Uot(*server);
            return result;
        }
        auto alpn = RequireJson(ParseJsonStringArray(*server, "alpn")).value_or(std::vector<std::string>{});
        if (!transport::IsValidTlsAlpn(alpn)) {
            throw std::invalid_argument("invalid Trojan ALPN policy");
        }
        return TrojanSettings{
            .server = Server(*server, 443),
            .password = Password(*server),
            .server_name = RequireJson(NormalizeTlsServerName(
                JsonStringOr(*server, "serverName", ""), "trojan serverName")),
            .allow_insecure = JsonBoolOr(*server, "allowInsecure", false),
            .alpn = std::move(alpn),
        };
    }
    if (protocol == common::kVless || protocol == common::kVmess) {
        const bool vless_protocol = protocol == common::kVless;
        const object* server = &source;
        const object* user = &source;
        const auto fields = vless_protocol ? kVlessFields : kVmessFields;
        if (const auto* vnext = source.if_contains("vnext")) {
            RequireJsonKeys(source, {"vnext"}, "outbound.settings");
            server = &SingleObject(vnext, "vnext");
            RequireJsonKeys(*server, {"address", "port", "users"}, "outbound.settings.vnext[0]");
            user = &SingleObject(server->if_contains("users"), "users");
            RequireJsonKeys(*user, fields, "outbound.settings.vnext[0].users[0]");
        } else {
            RequireJsonKeys(source, fields, "outbound.settings", {"address", "port"});
        }
        auto endpoint = Server(*server, 443);
        const auto id = JsonStringOr(*user, "id", "");
        if (vless_protocol) {
            VlessSettings result;
            result.server = std::move(endpoint);
            const auto uuid = proxy::ParseUuidBytes(id);
            if (!uuid) throw std::invalid_argument("VLESS id must be a UUID or a 1-30 byte custom id");
            result.id = *uuid;
            result.flow = proxy::NormalizeFlow(JsonStringOr(*user, "flow", ""));
            if (!result.flow.empty() && result.flow != "xtls-rprx-vision" &&
                result.flow != "xtls-rprx-vision-udp443") {
                throw std::invalid_argument("unsupported VLESS flow");
            }
            auto encryption = proxy::ParseVlessClientEncryption(JsonStringOr(*user, "encryption", ""));
            if (!encryption) throw std::invalid_argument(std::string(proxy::VlessEncryptionParseErrorMessage(encryption.error())));
            if (*encryption) result.encryption = std::make_shared<const proxy::VlessEncryptionConfig>(std::move(**encryption));
            const auto packet = JsonStringOr(*user, "packetEncoding", "xudp");
            if (common::EqualsAsciiCI(packet, "none")) result.packet_encoding = PacketEncoding::None;
            else if (common::EqualsAsciiCI(packet, "packetaddr")) result.packet_encoding = PacketEncoding::PacketAddr;
            else if (packet.empty() || common::EqualsAsciiCI(packet, "xudp")) result.packet_encoding = PacketEncoding::Xudp;
            else throw std::invalid_argument("packetEncoding must be none, packetaddr, or xudp");
            return result;
        }
        const auto uuid = common::ParseUuid(id);
        if (!uuid) throw std::invalid_argument("VMess id must be a UUID");
        const auto alter_id = RequireJson(ParseJsonUint64(*user, "alterId"));
        if (alter_id && *alter_id != 0) throw std::invalid_argument("VMess alterId must be zero");
        const auto security = common::LowerAscii(JsonStringOr(*user, "security", "auto"));
        proxy::VmessSecurity cipher;
        if (security.empty() || security == "auto" || security == "aes-128-gcm") cipher = proxy::VmessSecurity::AES_128_GCM;
        else if (security == "chacha20-poly1305") cipher = proxy::VmessSecurity::CHACHA20_POLY1305;
        else if (security == "none") cipher = proxy::VmessSecurity::NONE;
        else if (security == "zero") cipher = proxy::VmessSecurity::ZERO;
        else throw std::invalid_argument("unsupported VMess security");
        return VmessSettings{.server = std::move(endpoint), .id = *uuid, .security = cipher};
    }
    throw std::invalid_argument("unsupported outbound protocol");
}

}  // namespace infra
