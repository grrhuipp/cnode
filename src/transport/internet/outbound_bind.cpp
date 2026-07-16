#include "acppnode/transport/internet/outbound_bind.hpp"

#include "acppnode/common/ip_utils.hpp"
#include "acppnode/core/constants.hpp"

namespace acpp {

OutboundBind OutboundBind::Auto() noexcept {
    OutboundBind bind;
    bind.mode_ = Mode::Auto;
    return bind;
}

std::optional<OutboundBind> OutboundBind::Parse(std::string_view value) {
    OutboundBind bind;
    if (value.empty()) {
        return bind;
    }
    if (value == constants::binding::kAuto) {
        return Auto();
    }

    IoErrorCode error;
    auto address = net::ip::make_address(value, error);
    if (error) {
        return std::nullopt;
    }
    address = iputil::NormalizeAddress(address);
    if (address.is_unspecified()) {
        return bind;
    }
    bind.mode_ = Mode::Explicit;
    bind.explicit_address_ = std::move(address);
    return bind;
}

}  // namespace acpp
