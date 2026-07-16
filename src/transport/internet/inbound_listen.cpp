#include "acppnode/transport/internet/inbound_listen.hpp"

#include "acppnode/common/ip_utils.hpp"
#include "acppnode/core/constants.hpp"

namespace acpp {

InboundListen::InboundListen() noexcept {
    candidates_[0] = net::ip::address_v4::any();
    candidates_[1] = net::ip::address_v6::any();
}

std::optional<InboundListen> InboundListen::Parse(std::string_view value) {
    if (value.empty() || value == constants::network::kDualStackAuto) {
        return InboundListen{};
    }

    IoErrorCode error;
    auto address = net::ip::make_address(value, error);
    if (error) {
        return std::nullopt;
    }

    InboundListen listen;
    listen.candidates_[0] = iputil::NormalizeAddress(address);
    listen.candidate_count_ = 1;
    return listen;
}

}  // namespace acpp
