#pragma once

#include "acppnode/app/relay_types.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/access_log_reporter.hpp"

namespace acpp::app {

// One guard may exist at the inbound boundary and another at Dispatcher. Each
// successful logical proxy request submits one terminal result. A failed,
// rejected or cancelled request is also submitted once both the authenticated
// user and its single target are known. The Context flag makes submission
// idempotent.
class AccessLogSession final {
public:
    explicit AccessLogSession(session::Context& ctx) noexcept;
    ~AccessLogSession() noexcept;

    AccessLogSession(const AccessLogSession&) = delete;
    AccessLogSession& operator=(const AccessLogSession&) = delete;
    AccessLogSession(AccessLogSession&&) = delete;
    AccessLogSession& operator=(AccessLogSession&&) = delete;

    void Complete(const RelayResult& result) noexcept;
    void Fail(ErrorCode error_code) noexcept;
    // Mux/control transports are containers rather than logical requests.
    void Suppress() noexcept;

private:
    session::Context* ctx_ = nullptr;
    accesslog::CloseSide close_side_ = accesslog::CloseSide::Unknown;
    uint64_t bytes_up_ = 0;
    uint64_t bytes_down_ = 0;
    ErrorCode error_code_ = ErrorCode::INTERNAL;
    bool terminal_ = false;
    bool suppressed_ = false;
};

[[nodiscard]] accesslog::Event BuildAccessLogEvent(
    const session::Context& ctx,
    accesslog::CloseSide close_side,
    uint64_t bytes_up,
    uint64_t bytes_down,
    ErrorCode error_code);

}  // namespace acpp::app
