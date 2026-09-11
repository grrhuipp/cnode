#pragma once

#include "acppnode/common/asio_types.hpp"

#include <functional>

namespace acpp {

// A finite group on one executor. Spawn is only valid during start or from a
// running child. The group joins actual completion callbacks, including children
// added by another child. Cancellation and uncaught failure stop every child.
class AwaitableTaskGroup {
public:
    virtual void Spawn(net::awaitable<void> task) = 0;
    // Stop pending children on the group's executor; Run still joins them.
    virtual void Cancel() = 0;

protected:
    ~AwaitableTaskGroup() = default;
};

net::awaitable<void> RunAwaitableTaskGroup(
    net::any_io_executor executor,
    std::function<void(AwaitableTaskGroup&)> start);

}  // namespace acpp
