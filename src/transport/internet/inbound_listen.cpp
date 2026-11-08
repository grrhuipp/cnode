#include "transport/internet/inbound_listen.hpp"

#include "common/ip_utils.hpp"
#include "common/ip_address.hpp"
#include "core/constants.hpp"
#include "transport/internet/http_headers.hpp"


InboundListen::InboundListen() noexcept {
    candidates_[0] = net::ip::address_v4::any();
    candidates_[1] = net::ip::address_v6::any();
}

bool InboundListen::Overlaps(const InboundListen& other) const noexcept {
    for (const auto& address : Candidates()) {
        for (const auto& candidate : other.Candidates()) {
            if (address.is_v4() == candidate.is_v4() &&
                (address == candidate || address.is_unspecified() || candidate.is_unspecified())) {
                return true;
            }
        }
    }
    return false;
}

bool InboundListen::operator==(const InboundListen& other) const noexcept {
    const auto addresses = Candidates();
    const auto candidates = other.Candidates();
    if (addresses.size() != candidates.size()) return false;
    for (size_t index = 0; index < addresses.size(); ++index) {
        if (addresses[index] != candidates[index]) return false;
    }
    return true;
}

std::optional<InboundListen> InboundListen::Parse(std::string_view value) {
    if (value.empty() || transport::internet::EqualsAsciiCI(value, constants::network::kDualStackAuto)) {
        return InboundListen{};
    }
    auto address = iputil::ParseLiteral(value);
    if (!address) {
        return std::nullopt;
    }

    InboundListen listen;
    listen.candidates_[0] = iputil::NormalizeAddress(*address);
    listen.candidate_count_ = 1;
    return listen;
}

