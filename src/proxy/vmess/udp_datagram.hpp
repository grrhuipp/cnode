#pragma once

#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"
#include "common/target_address.hpp"
#include "transport/link.hpp"

namespace vmess {

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
    // VMess reserves an empty authenticated body for end-of-stream.
    if (datagram.payload_size == 0) {
        throw transport::LinkError(ErrorCode::NOT_SUPPORTED);
    }
}

}  // namespace vmess
