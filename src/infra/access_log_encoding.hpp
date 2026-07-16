#pragma once

#include "acppnode/infra/access_log_reporter.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace acpp::accesslog::detail {

using Id128 = std::array<uint8_t, 16>;

struct SequencedEvent {
    uint64_t sequence = 0;
    Event event;
};

struct EncodedBatch {
    Id128 batch_id{};
    uint64_t first_sequence = 0;
    uint64_t last_sequence = 0;
    std::vector<uint8_t> protobuf;
};

[[nodiscard]] EncodedBatch EncodeBatch(
    std::span<const SequencedEvent> events,
    std::span<const Source> sources,
    std::string_view server_id,
    const Id128& boot_id);

[[nodiscard]] std::vector<uint8_t> CompressZstd(
    std::span<const uint8_t> input,
    int level = 3);

[[nodiscard]] std::string HexId(const Id128& id);

}  // namespace acpp::accesslog::detail
