#include "acppnode/app/access_log_session.hpp"

namespace acpp::app {

AccessLogSession::AccessLogSession(session::Context& ctx) noexcept
    : ctx_(&ctx) {}

AccessLogSession::~AccessLogSession() noexcept {
    if (!ctx_ || !completed_ || cancelled_ || ctx_->access_event_submitted ||
        ctx_->inbound.access_source_ref == 0) {
        return;
    }

    ctx_->access_event_submitted = true;
    try {
        (void)accesslog::Reporter::Instance().Submit(BuildAccessLogEvent(
            *ctx_, close_side_, bytes_up_, bytes_down_));
    } catch (...) {
        // Reporting is fail-open and must never unwind into the proxy path.
    }
}

void AccessLogSession::Complete(const RelayResult& result) noexcept {
    // Mux/control transports are not logical proxy requests. Their child
    // sessions are reported independently by Dispatcher::Dispatch.
    if (ctx_ && ctx_->content.network == Network::MUX) {
        Cancel();
        return;
    }
    if (result.error != ErrorCode::OK) {
        Cancel();
        return;
    }

    bytes_up_ = result.bytes_up;
    bytes_down_ = result.bytes_down;
    close_side_ = result.client_closed_first
        ? accesslog::CloseSide::Client
        : accesslog::CloseSide::Remote;
    completed_ = true;
}

void AccessLogSession::Cancel() noexcept {
    cancelled_ = true;
    if (ctx_) {
        ctx_->access_event_submitted = true;
    }
}

}  // namespace acpp::app
