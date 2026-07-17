#pragma once

#include <string_view>

namespace acpp::accesslog::detail {

[[nodiscard]] bool IsBatchAcknowledged(
    int status,
    std::string_view body,
    std::string_view expected_batch_id) noexcept;

}  // namespace acpp::accesslog::detail
