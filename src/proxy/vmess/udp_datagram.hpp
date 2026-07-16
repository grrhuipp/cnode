#pragma once

#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/target_address.hpp"

namespace acpp::vmess {

inline void ValidateFixedUdpDatagram(const buf::MultiBuffer& payload,
                                     const TargetAddress& fixed_target) {
    const auto datagram = buf::InspectUdpDatagram(payload);
    if (datagram.status == buf::UdpDatagramStatus::Empty) {
        return;
    }
    if (!datagram.Valid() || !datagram.target ||
        !datagram.target->IsValid()) {
        throw IoSystemError(
            io_error::invalid_argument,
            "VMess UDP datagram contains missing or mixed endpoints");
    }
    if (!datagram.target->SameEndpoint(fixed_target)) {
        throw IoSystemError(
            io_error::invalid_argument,
            "VMess UDP datagram target differs from the fixed session target");
    }
}

}  // namespace acpp::vmess
