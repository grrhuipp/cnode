#include "acppnode/app/static_inbound_runtime.hpp"

#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"

namespace acpp {

std::optional<StaticInboundRuntimeEntry> BuildStaticInboundRuntimeEntry(
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
        LOG_WARN("Static inbound '{}': unsupported protocol '{}', skipped",
                 entry.tag,
                 entry.protocol);
        return std::nullopt;
    }

    entry.build_request.tag = entry.tag;
    entry.build_request.protocol = entry.protocol;
    entry.build_request.cipher_method = source.static_users.method;
    entry.build_request.ss_identity_password = source.static_users.identity_password;
    entry.build_request.anytls_padding_scheme = source.static_users.padding_scheme;

    auto users = proxyman::inbound::BuildStaticUsers(
        entry.protocol,
        entry.tag,
        source.static_users);
    if (!users) {
        LOG_WARN("Static inbound '{}': load users failed, skipped", entry.tag);
        return std::nullopt;
    }
    proxyman::inbound::UserStore::ApplyUsers(entry.protocol, entry.tag, *users);

    return entry;
}

std::vector<StaticInboundRuntimeEntry> BuildStaticInboundRuntimeEntries(
    const std::vector<StaticInboundConfig>& sources) {
    std::vector<StaticInboundRuntimeEntry> entries;
    entries.reserve(sources.size());

    for (const auto& source : sources) {
        auto entry = BuildStaticInboundRuntimeEntry(source);
        if (entry) {
            entries.push_back(std::move(*entry));
        }
    }

    return entries;
}

}  // namespace acpp
