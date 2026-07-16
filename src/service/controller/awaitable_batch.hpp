#pragma once

#include "acppnode/common/asio_types.hpp"

#include <vector>

namespace acpp::controller {

// Starts every task on the same single-threaded control-plane executor and
// resumes only after all tasks finish. The first exception is rethrown after
// the remaining tasks have also completed.
net::awaitable<void> RunAwaitableBatch(
    net::any_io_executor executor,
    std::vector<net::awaitable<void>> tasks);

}  // namespace acpp::controller
