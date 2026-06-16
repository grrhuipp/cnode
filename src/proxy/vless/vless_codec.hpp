#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/target_address.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace acpp::vless {

inline constexpr uint8_t kVersion = 0x00;

enum class Command : uint8_t {
    TCP = 0x01,
    UDP = 0x02,
    MUX = 0x03,
};

struct RequestHeader {
    uint8_t version = kVersion;
    std::array<uint8_t, 16> uuid{};
    uint8_t addons_len = 0;
    Command command = Command::TCP;
    TargetAddress target;
};

class Codec {
public:
    static std::optional<RequestHeader> ParseRequestHeader(
        const uint8_t* data,
        size_t len,
        size_t& consumed);

    static size_t EncodeRequestHeaderTo(
        const std::array<uint8_t, 16>& uuid,
        Command command,
        const TargetAddress& target,
        uint8_t* output,
        size_t output_size);

    static size_t EncodeResponseHeaderTo(uint8_t* output,
                                         size_t output_size) noexcept;

    static std::optional<size_t> ParseResponseHeader(
        const uint8_t* data,
        size_t len,
        size_t& consumed) noexcept;

    static size_t EncodeUdpPacketTo(const uint8_t* payload,
                                    size_t payload_len,
                                    uint8_t* output,
                                    size_t output_size) noexcept;

    enum class UdpParseResult {
        SUCCESS,
        INCOMPLETE,
        INVALID,
    };

    struct UdpPacket {
        std::span<const uint8_t> payload;
    };

    struct UdpParseOutput {
        UdpParseResult result = UdpParseResult::INCOMPLETE;
        std::optional<UdpPacket> packet;
        size_t consumed = 0;
    };

    static UdpParseOutput ParseUdpPacket(const uint8_t* data,
                                         size_t len) noexcept;
};

}  // namespace acpp::vless
