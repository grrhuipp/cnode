#include "acppnode/app/access_log_session.hpp"

namespace acpp::app {

AccessLogSession::AccessLogSession(session::Context& ctx) noexcept
    : ctx_(&ctx) {}

AccessLogSession::~AccessLogSession() noexcept {
    if (!ctx_ || !terminal_ || suppressed_ || ctx_->access_event_submitted ||
        ctx_->inbound.access_source_ref == 0) {
        return;
    }

    try {
        if (accesslog::Reporter::Instance().Submit(BuildAccessLogEvent(
                *ctx_, close_side_, bytes_up_, bytes_down_, error_code_))) {
            ctx_->access_event_submitted = true;
        }
    } catch (...) {
        // Reporting is fail-open and must never unwind into the proxy path.
    }
}

void AccessLogSession::Complete(const RelayResult& result) noexcept {
    // Mux/control transports are not logical proxy requests. Their child
    // sessions are reported independently by Dispatcher::Dispatch.
    if (ctx_ && ctx_->content.network == Network::MUX) {
        Suppress();
        return;
    }

    bytes_up_ = result.bytes_up;
    bytes_down_ = result.bytes_down;
    error_code_ = result.error;
    if (result.close_side_known || result.error == ErrorCode::OK) {
        close_side_ = result.client_closed_first
            ? accesslog::CloseSide::Client
            : accesslog::CloseSide::Remote;
    } else if (result.error == ErrorCode::RELAY_CLIENT_CLOSED) {
        close_side_ = accesslog::CloseSide::Client;
    } else if (result.error == ErrorCode::RELAY_TARGET_CLOSED) {
        close_side_ = accesslog::CloseSide::Remote;
    }
    terminal_ = true;
}

void AccessLogSession::Fail(ErrorCode error_code) noexcept {
    RelayResult result;
    result.error = error_code == ErrorCode::OK
        ? ErrorCode::INTERNAL
        : error_code;
    if (ctx_) {
        result.bytes_up = ctx_->traffic.bytes_up;
        result.bytes_down = ctx_->traffic.bytes_down;
    }
    Complete(result);
}

void AccessLogSession::Suppress() noexcept {
    suppressed_ = true;
    if (ctx_) {
        ctx_->access_event_submitted = true;
    }
}

}  // namespace acpp::app
