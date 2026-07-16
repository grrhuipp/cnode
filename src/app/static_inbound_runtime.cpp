#include "acppnode/app/static_inbound_runtime.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/config_types.hpp"

#include <stdexcept>
#include <utility>

namespace acpp {

namespace {

struct PreparedStaticInbound {
    StaticInboundRuntimeEntry entry;
    proxyman::inbound::UserSet users;
};

PreparedStaticInbound PrepareStaticInboundRuntimeEntry(
    const StaticInboundConfig& source) {
    StaticInboundRuntimeEntry entry;
    entry.protocol = source.protocol;
    entry.tag = source.tags.empty()
        ? naming::BuildProtocolPortTag(entry.protocol, source.port)
        : source.tags.front();
    entry.all_tags = source.tags.empty()
        ? std::vector<std::string>{entry.tag}
        : source.tags;
    entry.port = source.port;
    entry.listen = source.listen;
    entry.stream_settings = source.stream_settings;
    entry.sniffing = source.sniffing;
    entry.routing_enabled = source.routing_enabled;

    if (!proxyman::inbound::HasProxy(entry.protocol)) {
        throw std::invalid_argument(
            "static inbound '" + entry.tag + "' has unsupported protocol '" +
            entry.protocol + "'");
    }

    entry.build_request.tag = entry.tag;
    entry.build_request.protocol = entry.protocol;
    entry.build_request.cipher_method = source.static_users.method;
    entry.build_request.ss_identity_password = source.static_users.identity_password;
    entry.build_request.anytls_padding_scheme = source.static_users.padding_scheme;
    entry.build_request.vless_decryption = source.static_users.vless_decryption;

    auto users = proxyman::inbound::BuildStaticUsers(
        entry.protocol,
        entry.tag,
        source.static_users);
    if (!users) {
        throw std::invalid_argument(
            "static inbound '" + entry.tag + "' has invalid users or settings");
    }
    if (proxyman::inbound::UserSetEmpty(*users)) {
        throw std::invalid_argument(
            "static inbound '" + entry.tag + "' has no valid users");
    }

    return PreparedStaticInbound{
        .entry = std::move(entry),
        .users = std::move(*users),
    };
}

}  // namespace

std::vector<StaticInboundRuntimeEntry> BuildStaticInboundRuntimeEntries(
    const std::vector<StaticInboundConfig>& sources) {
    std::vector<PreparedStaticInbound> prepared;
    prepared.reserve(sources.size());
    for (const auto& source : sources) {
        prepared.push_back(PrepareStaticInboundRuntimeEntry(source));
    }

    std::vector<StaticInboundRuntimeEntry> entries;
    entries.reserve(prepared.size());
    for (auto& inbound : prepared) {
        proxyman::inbound::UserStore::ApplyUsers(inbound.entry.tag, inbound.users);
        entries.push_back(std::move(inbound.entry));
    }
    return entries;
}

}  // namespace acpp
