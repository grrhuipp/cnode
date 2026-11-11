#include "infra/config.hpp"
#include "common/scoped_cleanse.hpp"
#include "proxy/anytls/anytls_codec.hpp"
#include "proxy/shadowsocks/shadowsocks_protocol.hpp"
#include "proxy/uot/uot.hpp"
#include "proxy/vless/vless_codec.hpp"
#include "proxy/vless/vless_encryption_config.hpp"
#include "proxy/vmess/vmess_crypto.hpp"

#include <limits>
#include <stdexcept>

namespace proxy::freedom::outbound {
std::optional<DomainStrategy> ParseDomainStrategy(std::string_view value) {
    if (common::EqualsAsciiCI(value, "asis")) return DomainStrategy::AsIs;
    if (common::EqualsAsciiCI(value, "useip")) return DomainStrategy::UseIP;
    if (common::EqualsAsciiCI(value, "useipv6v4")) return DomainStrategy::UseIPv6v4;
    if (common::EqualsAsciiCI(value, "useipv4")) return DomainStrategy::UseIPv4;
    if (common::EqualsAsciiCI(value, "useipv4v6")) return DomainStrategy::UseIPv4v6;
    if (common::EqualsAsciiCI(value, "useipv6")) return DomainStrategy::UseIPv6;
    if (common::EqualsAsciiCI(value, "forceip")) return DomainStrategy::ForceIP;
    if (common::EqualsAsciiCI(value, "forceipv6v4")) return DomainStrategy::ForceIPv6v4;
    if (common::EqualsAsciiCI(value, "forceipv6")) return DomainStrategy::ForceIPv6;
    if (common::EqualsAsciiCI(value, "forceipv4v6")) return DomainStrategy::ForceIPv4v6;
    if (common::EqualsAsciiCI(value, "forceipv4")) return DomainStrategy::ForceIPv4;
    return std::nullopt;
}
}  // namespace proxy::freedom::outbound

namespace infra {
namespace {

const json::object& SingleObject(const json::object& source, std::string_view key) {
    const auto* value = source.if_contains(key);
    if (!value || !value->is_array() || value->as_array().size() != 1 ||
        !value->as_array()[0].is_object()) {
        throw std::invalid_argument(std::string(key) + " must contain exactly one object");
    }
    return value->as_array()[0].as_object();
}

transport::internet::OutboundServer Server(const json::object& source, uint16_t default_port) {
    const auto port = ReadJsonPort(source, "port");
    if (port.error != JsonPortError::None && port.error != JsonPortError::Missing) {
        throw std::invalid_argument("outbound server port must be an integer between 1 and 65535");
    }
    auto server = transport::internet::MakeOutboundServer(JsonStringOr(source, "address", ""),
                                    port.Valid() ? port.value : default_port);
    if (!server) throw std::invalid_argument(std::string(server.error()));
    return std::move(*server);
}

std::string Password(const json::object& source) {
    auto password = JsonStringOr(source, "password", "");
    if (password.empty()) throw std::invalid_argument("outbound password is required");
    return password;
}

proxy::uot::Version UotVersion(const json::value& value) {
    const auto number = JsonUnsignedInteger(value);
    if (number == 1) return proxy::uot::Version::V1;
    if (number == 2) return proxy::uot::Version::V2;
    throw std::invalid_argument("UoT version must be 1 or 2");
}

std::optional<proxy::uot::Version> Uot(const json::object& source) {
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
        return version ? UotVersion(*version) : proxy::uot::Version::V2;
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
    return version ? UotVersion(*version) : proxy::uot::Version::V2;
}

std::chrono::seconds PositiveSeconds(const json::object& source, std::string_view key,
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

OutboundSettings ParseOutboundSettings(std::string_view protocol, const json::object& source) {
    if (protocol == constants::protocol::kFreedom) {
        RequireJsonKeys(source, {"domainStrategy", "redirect"},
                        "outbound.settings");
        FreedomSettings result;
        const auto strategy = proxy::freedom::outbound::ParseDomainStrategy(
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
    if (protocol == constants::protocol::kBlackhole) {
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
    if (protocol == constants::protocol::kAnyTLS) {
        RequireJsonKeys(source, {"address", "port", "password", "idleSessionCheckInterval",
                                "idleSessionTimeout", "minIdleSession"}, "outbound.settings");
        AnyTlsSettings result;
        result.server = Server(source, 0);
        auto password = Password(source);
        common::ScopedCleanse cleanse{password};
        result.password_hash = proxy::anytls::PasswordHash(password);
        result.idle_session_check_interval = PositiveSeconds(
            source, "idleSessionCheckInterval", result.idle_session_check_interval);
        result.idle_session_timeout = PositiveSeconds(source, "idleSessionTimeout", result.idle_session_timeout);
        result.min_idle_sessions = static_cast<size_t>(RequireJson(ParseJsonUint64(
            source, "minIdleSession", std::numeric_limits<size_t>::max())).value_or(0));
        return result;
    }
    if (protocol == constants::protocol::kShadowsocks || protocol == constants::protocol::kTrojan) {
        const bool shadowsocks = protocol == constants::protocol::kShadowsocks;
        const json::object* server = &source;
        if (source.contains("servers")) {
            RequireJsonKeys(source, {"servers"}, "outbound.settings");
            server = &SingleObject(source, "servers");
        }
        RequireJsonKeys(*server, shadowsocks ? kSsFields : kTrojanFields, "outbound.settings.server");
        if (shadowsocks) {
            ShadowsocksSettings result;
            result.server = Server(*server, 8388);
            const auto cipher = proxy::shadowsocks::ParseCipherMethod(JsonStringOr(*server, "method", "aes-256-gcm"));
            if (!cipher) throw std::invalid_argument("unsupported Shadowsocks method");
            result.cipher = *cipher;
            result.password = Password(*server);
            result.uot_version = Uot(*server);
            return result;
        }
        return TrojanSettings{
            .server = Server(*server, 443),
            .password = Password(*server),
            .server_name = JsonStringOr(*server, "serverName", ""),
            .allow_insecure = JsonBoolOr(*server, "allowInsecure", false),
            .alpn = RequireJson(ParseJsonStringArray(*server, "alpn")).value_or(std::vector<std::string>{}),
        };
    }
    if (protocol == constants::protocol::kVless || protocol == constants::protocol::kVmess) {
        const bool vless_protocol = protocol == constants::protocol::kVless;
        const json::object* server = &source;
        const json::object* user = &source;
        const auto fields = vless_protocol ? kVlessFields : kVmessFields;
        if (source.contains("vnext")) {
            RequireJsonKeys(source, {"vnext"}, "outbound.settings");
            server = &SingleObject(source, "vnext");
            RequireJsonKeys(*server, {"address", "port", "users"}, "outbound.settings.vnext[0]");
            user = &SingleObject(*server, "users");
            RequireJsonKeys(*user, fields, "outbound.settings.vnext[0].users[0]");
        } else {
            RequireJsonKeys(source, fields, "outbound.settings", {"address", "port"});
        }
        auto endpoint = Server(*server, 443);
        const auto id = JsonStringOr(*user, "id", "");
        if (vless_protocol) {
            VlessSettings result;
            result.server = std::move(endpoint);
            const auto uuid = proxy::vless::ParseUuidBytes(id);
            if (!uuid) throw std::invalid_argument("VLESS id must be a UUID or a 1-30 byte custom id");
            result.id = *uuid;
            result.flow = proxy::vless::NormalizeFlow(JsonStringOr(*user, "flow", ""));
            if (!result.flow.empty() && result.flow != "xtls-rprx-vision" &&
                result.flow != "xtls-rprx-vision-udp443") {
                throw std::invalid_argument("unsupported VLESS flow");
            }
            auto encryption = proxy::vless::ParseVlessClientEncryption(JsonStringOr(*user, "encryption", ""));
            if (!encryption) throw std::invalid_argument(std::string(proxy::vless::VlessEncryptionParseErrorMessage(encryption.error())));
            if (*encryption) result.encryption = std::make_shared<const proxy::vless::VlessEncryptionConfig>(std::move(**encryption));
            const auto packet = common::LowerAscii(JsonStringOr(*user, "packetEncoding", "xudp"));
            if (packet == "none") result.packet_encoding = PacketEncoding::None;
            else if (packet == "packetaddr") result.packet_encoding = PacketEncoding::PacketAddr;
            else if (packet == "xudp" || packet.empty()) result.packet_encoding = PacketEncoding::Xudp;
            else throw std::invalid_argument("packetEncoding must be none, packetaddr, or xudp");
            return result;
        }
        const auto uuid = common::ParseUuid(id);
        if (!uuid) throw std::invalid_argument("VMess id must be a UUID");
        const auto alter_id = RequireJson(ParseJsonUint64(*user, "alterId"));
        if (alter_id && *alter_id != 0) throw std::invalid_argument("VMess alterId must be zero");
        const auto security = common::LowerAscii(JsonStringOr(*user, "security", "auto"));
        proxy::vmess::Security cipher;
        if (security.empty() || security == "auto" || security == "aes-128-gcm") cipher = proxy::vmess::Security::AES_128_GCM;
        else if (security == "chacha20-poly1305") cipher = proxy::vmess::Security::CHACHA20_POLY1305;
        else if (security == "none") cipher = proxy::vmess::Security::NONE;
        else if (security == "zero") cipher = proxy::vmess::Security::ZERO;
        else throw std::invalid_argument("unsupported VMess security");
        return VmessSettings{.server = std::move(endpoint), .id = *uuid, .security = cipher};
    }
    throw std::invalid_argument("unsupported outbound protocol");
}

}  // namespace infra
