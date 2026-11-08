#pragma once

namespace session {
struct Context;
}  // namespace session

namespace features::policy {

// Worker-local request admission policy. Implementations may record policy
// hits, but Dispatcher only observes the allow/block result.
class RequestPolicy {
public:
    virtual ~RequestPolicy() noexcept = default;

    [[nodiscard]] virtual bool Blocked(
        const session::Context& ctx) = 0;
};

}  // namespace features::policy
