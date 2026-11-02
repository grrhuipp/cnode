#pragma once

#include "acppnode/infra/json.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"

#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace acpp::infra {

// Cold-path configuration normalization. A string preserves the existing
// binding semantics; an ordered array chooses only assigned local addresses.
[[nodiscard]] inline OutboundBind ParseOutboundBindConfig(
    const json::value& value, const json::value* strategy = nullptr) {
    if (value.is_string()) {
        if (strategy) {
            throw std::invalid_argument(
                "sendThroughStrategy requires an array sendThrough");
        }
        auto result = OutboundBind::Parse(value.as_string());
        if (!result) {
            throw std::invalid_argument(
                "sendThrough must be auto, wildcard, an IP address, or an array of IPs/CIDRs");
        }
        return std::move(*result);
    }
    if (!value.is_array()) {
        throw std::invalid_argument("sendThrough must be a string or an array of IPs/CIDRs");
    }

    auto policy = OutboundBind::ChoicePolicy::SourceHash;
    if (strategy) {
        if (!strategy->is_string()) {
            throw std::invalid_argument("sendThroughStrategy must be hash or random");
        }
        if (strategy->as_string() == "random") {
            policy = OutboundBind::ChoicePolicy::Random;
        } else if (strategy->as_string() != "hash") {
            throw std::invalid_argument("sendThroughStrategy must be hash or random");
        }
    }
    std::vector<std::string_view> entries;
    entries.reserve(value.as_array().size());
    for (const auto& entry : value.as_array()) {
        if (!entry.is_string()) {
            throw std::invalid_argument("sendThrough array must contain only IP/CIDR strings");
        }
        entries.push_back(entry.as_string());
    }
    auto result = OutboundBind::ParseCandidates(entries, policy);
    if (!result) {
        throw std::invalid_argument("sendThrough array contains an invalid IP/CIDR or is empty");
    }
    return std::move(*result);
}

}  // namespace acpp::infra
