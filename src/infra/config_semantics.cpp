#include "config_semantics.hpp"

#include "acppnode/common/asio_types.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/core/naming.hpp"

#include <array>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace acpp {

ConfigSemanticValidation ValidateOutboundRoutingSemantics(
    std::span<const proxyman::outbound::PreparedOutboundConfig> outbounds,
    std::span<const RouteRuleConfig> rules) {
    if (outbounds.empty()) {
        return {.error = ConfigSemanticError::NoOutbounds};
    }

    std::unordered_set<std::string_view> tags;
    tags.reserve(outbounds.size());
    for (size_t i = 0; i < outbounds.size(); ++i) {
        const std::string_view tag = outbounds[i].tag;
        if (tag.empty()) {
            return {
                .error = ConfigSemanticError::EmptyOutboundTag,
                .index = i,
            };
        }
        if (!tags.insert(tag).second) {
            return {
                .error = ConfigSemanticError::DuplicateOutboundTag,
                .index = i,
                .tag = tag,
            };
        }
    }

    for (size_t i = 0; i < rules.size(); ++i) {
        const std::string_view tag = rules[i].outbound_tag;
        if (tag.empty()) {
            return {
                .error = ConfigSemanticError::EmptyRouteOutboundTag,
                .index = i,
            };
        }
        if (!tags.contains(tag)) {
            return {
                .error = ConfigSemanticError::UnknownRouteOutboundTag,
                .index = i,
                .tag = tag,
            };
        }
    }

    return {};
}

StaticInboundSemanticValidation ValidateStaticInboundSemantics(
    std::span<const StaticInboundConfig> inbounds) {
    std::unordered_map<std::string, size_t> tags;
    std::unordered_map<std::string, size_t> endpoints;
    tags.reserve(inbounds.size());
    endpoints.reserve(inbounds.size() * 2);

    for (size_t i = 0; i < inbounds.size(); ++i) {
        const auto& inbound = inbounds[i];
        if (inbound.port == 0) {
            return {
                .error = StaticInboundSemanticError::InvalidPort,
                .index = i,
            };
        }

        std::string tag = inbound.tags.empty()
            ? naming::BuildProtocolPortTag(inbound.protocol, inbound.port)
            : inbound.tags.front();
        if (tag.empty()) {
            return {
                .error = StaticInboundSemanticError::EmptyTag,
                .index = i,
            };
        }
        if (const auto [it, inserted] = tags.emplace(tag, i); !inserted) {
            return {
                .error = StaticInboundSemanticError::DuplicateTag,
                .index = i,
                .conflicting_index = it->second,
                .detail = std::move(tag),
            };
        }

        std::array<net::ip::address, 2> addresses;
        size_t address_count = 0;
        if (inbound.listen.empty() ||
            inbound.listen == constants::network::kDualStackAuto) {
            addresses[address_count++] = net::ip::address_v4::any();
            addresses[address_count++] = net::ip::address_v6::any();
        } else {
            IoErrorCode ec;
            auto address = net::ip::make_address(inbound.listen, ec);
            if (ec) {
                return {
                    .error = StaticInboundSemanticError::InvalidListen,
                    .index = i,
                    .detail = inbound.listen,
                };
            }
            addresses[address_count++] = address;
        }

        for (size_t address_index = 0; address_index < address_count; ++address_index) {
            std::string endpoint = addresses[address_index].to_string();
            endpoint.push_back('|');
            endpoint.append(std::to_string(inbound.port));
            if (const auto [it, inserted] = endpoints.emplace(endpoint, i); !inserted) {
                return {
                    .error = StaticInboundSemanticError::DuplicateEndpoint,
                    .index = i,
                    .conflicting_index = it->second,
                    .detail = std::move(endpoint),
                };
            }
        }
    }

    return {};
}

}  // namespace acpp
