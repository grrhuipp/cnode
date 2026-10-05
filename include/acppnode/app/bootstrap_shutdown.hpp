#pragma once

#include "acppnode/common/asio_types.hpp"

namespace acpp {

// Wait on the runtime control executor so shutdown remains part of the joined
// application lifecycle. Cancellation stops the wait through Asio's associated
// cancellation slot.
[[nodiscard]] net::awaitable<int> WaitForShutdownSignal(
    net::any_io_executor executor);

}  // namespace acpp
