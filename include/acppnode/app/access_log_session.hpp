#pragma once

#include "acppnode/app/relay_types.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/access_log_reporter.hpp"

namespace acpp::app {

// One guard may exist at the inbound boundary and another at Dispatcher. The
// Context flag makes terminal submission idempotent; Dispatcher wins once a
// request reaches the canonical request chain, while the inbound guard covers
// pre-dispatch rejection and handshake failure.
class AccessLogSession final {
public:
    explicit AccessLogSession(session::Context& ctx) noexcept;
    ~AccessLogSession() noexcept;

    AccessLogSession(const AccessLogSession&) = delete;
    AccessLogSession& operator=(const AccessLogSession&) = delete;
    AccessLogSession(AccessLogSession&&) = delete;
    AccessLogSession& operator=(AccessLogSession&&) = delete;

    void Complete(const RelayResult& result) noexcept;
    void Reject(ErrorCode error) noexcept;
    void Fail(ErrorCode error) noexcept;
    void Cancel() noexcept;

private:
    session::Context* ctx_ = nullptr;
    accesslog::Result result_ = accesslog::Result::Failed;
    ErrorCode error_ = ErrorCode::INTERNAL;
    accesslog::CloseSide close_side_ = accesslog::CloseSide::Unknown;
    uint64_t bytes_up_ = 0;
    uint64_t bytes_down_ = 0;
    bool cancelled_ = false;
};

[[nodiscard]] accesslog::Event BuildAccessLogEvent(
    const session::Context& ctx,
    accesslog::Result result,
    ErrorCode error,
    accesslog::CloseSide close_side,
    uint64_t bytes_up,
    uint64_t bytes_down);

}  // namespace acpp::app
