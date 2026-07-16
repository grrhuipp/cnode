#pragma once

#include "acppnode/app/relay_types.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/access_log_reporter.hpp"

namespace acpp::app {

// One guard may exist at the inbound boundary and another at Dispatcher. Only
// successfully completed logical proxy requests are submitted. The Context
// flag makes successful terminal submission idempotent.
class AccessLogSession final {
public:
    explicit AccessLogSession(session::Context& ctx) noexcept;
    ~AccessLogSession() noexcept;

    AccessLogSession(const AccessLogSession&) = delete;
    AccessLogSession& operator=(const AccessLogSession&) = delete;
    AccessLogSession(AccessLogSession&&) = delete;
    AccessLogSession& operator=(AccessLogSession&&) = delete;

    void Complete(const RelayResult& result) noexcept;
    void Cancel() noexcept;

private:
    session::Context* ctx_ = nullptr;
    accesslog::CloseSide close_side_ = accesslog::CloseSide::Unknown;
    uint64_t bytes_up_ = 0;
    uint64_t bytes_down_ = 0;
    bool completed_ = false;
    bool cancelled_ = false;
};

[[nodiscard]] accesslog::Event BuildAccessLogEvent(
    const session::Context& ctx,
    accesslog::CloseSide close_side,
    uint64_t bytes_up,
    uint64_t bytes_down);

}  // namespace acpp::app
