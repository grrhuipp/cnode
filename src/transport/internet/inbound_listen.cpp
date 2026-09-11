#include "acppnode/transport/internet/inbound_listen.hpp"

#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/ip_address.hpp"
#include "acppnode/core/constants.hpp"

namespace acpp {

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

std::optional<InboundListen> InboundListen::Parse(std::string_view value) {
    if (value.empty() || value == constants::network::kDualStackAuto) {
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

}  // namespace acpp
