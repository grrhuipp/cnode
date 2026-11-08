#pragma once

#include "common/asio_types.hpp"

#include <vector>


// Starts every task on the supplied single-threaded executor and resumes only
// after all tasks finish. The first non-cancellation failure takes precedence
// over child cancellation. Caller cancellation is deferred until all started
// tasks finish; it cannot detach tasks that borrow the caller's state.
net::awaitable<void> RunAwaitableBatch(
    net::any_io_executor executor,
    std::vector<net::awaitable<void>> tasks);

