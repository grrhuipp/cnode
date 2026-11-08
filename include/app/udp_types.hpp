#pragma once

#include <cstdint>
#include <span>


struct TargetAddress;

// Native datagram response view. Borrowed bytes and target are valid only
// during encoding; a queued response must own its resulting payload.
struct UDPPacketView {
    const TargetAddress& target;
    std::span<const uint8_t> data;
};

