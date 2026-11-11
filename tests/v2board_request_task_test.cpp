#include <gtest/gtest.h>

#include "api/v2board/request_task.hpp"
#include "api/api.hpp"
#include "app/dns/dns.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/steady_timer.hpp>
#include <asio/read_until.hpp>
#include <asio/streambuf.hpp>
#include <asio/write.hpp>
#include <algorithm>

#include <exception>
#include <stdexcept>
#include <string_view>

namespace {
namespace net = ::net;
using ::api::v2board::http::Response;
using ::api::v2board::http::RunRequest;
using namespace std::chrono_literals;


struct ExchangeState {
    bool started = false;
    bool released = false;
    bool aborted = false;
};

struct ExchangeLifetime {
    ExchangeState& state;
    explicit ExchangeLifetime(ExchangeState& value) : state(value) { state.started = true; }
    ~ExchangeLifetime() { state.released = true; }
};

enum class WaitResult { Throw, FailureValue, CompleteResponse };

net::awaitable<Response> WaitingExchange(ExchangeState& state, WaitResult result) {
    ExchangeLifetime lifetime(state);
    net::steady_timer gate(co_await net::this_coro::executor,
                          net::steady_timer::time_point::max());
    if (result == WaitResult::Throw) {
        co_await gate.async_wait(net::use_awaitable);
    } else {
        const auto [error] = co_await gate.async_wait(net::as_tuple(net::use_awaitable));
        state.aborted = error == net::error::operation_aborted;
    }
    // CompleteResponse models an already received response followed by a
    // cancelled TLS close_notify. FailureValue models a parser/DNS I/O error.
    co_return result == WaitResult::CompleteResponse
        ? Response{200, "acknowledged", "response-etag", false}
        : Response{-1, "read failed", {}, false};
}

net::awaitable<Response> ImmediateExchange(bool fail) {
    if (fail) throw std::runtime_error("original request failure");
    co_return Response{304, {}, "cached-etag", true};
}

class OrdinaryRequest : public testing::TestWithParam<bool> {};
TEST_P(OrdinaryRequest, DrainsDeadlineAndPreservesCompletionCategory) {
    const bool fail = GetParam();
    net::io_context io;
    bool completed = false;
    std::exception_ptr failure;
    Response response;
    net::co_spawn(io, RunRequest(ImmediateExchange(fail), 30s),
        [&](std::exception_ptr error, Response value) {
            completed = true;
            failure = error;
            response = std::move(value);
        });
    // A long request deadline must be cancelled and drained on early completion.
    io.run();
    ASSERT_TRUE(completed);
    ASSERT_FALSE(failure);
    if (fail) {
        EXPECT_EQ(response.status, -1);
    } else {
        EXPECT_EQ(response.status, 304);
        EXPECT_TRUE(response.not_modified);
        EXPECT_EQ(response.etag, "cached-etag");
    }
}
INSTANTIATE_TEST_SUITE_P(Outcomes, OrdinaryRequest, testing::Bool());

class RequestTimeout : public testing::TestWithParam<WaitResult> {};
TEST_P(RequestTimeout, JoinsExchangeBeforeReturningAndPreservesCompletedResponse) {
    const auto result = GetParam();
    net::io_context io;
    ExchangeState state;
    bool completed = false;
    bool released_before_completion = false;
    std::exception_ptr failure;
    Response response;
    net::co_spawn(io, RunRequest(WaitingExchange(state, result), 20ms),
        [&](std::exception_ptr error, Response value) {
            completed = true;
            released_before_completion = state.released;
            failure = error;
            response = std::move(value);
        });
    io.run();
    ASSERT_TRUE(completed);
    EXPECT_TRUE(state.started);
    EXPECT_TRUE(released_before_completion);
    ASSERT_FALSE(failure);
    if (result == WaitResult::CompleteResponse) {
        EXPECT_TRUE(state.aborted);
        EXPECT_EQ(response.status, 200);
        EXPECT_EQ(response.body, "acknowledged");
        EXPECT_EQ(response.etag, "response-etag");
    } else {
        EXPECT_EQ(response.status, -1);
    }
}
INSTANTIATE_TEST_SUITE_P(ExchangeOutcomes, RequestTimeout, testing::Values(
    WaitResult::Throw, WaitResult::FailureValue, WaitResult::CompleteResponse));

class RequestCancellation : public testing::TestWithParam<WaitResult> {};
TEST_P(RequestCancellation, JoinsExchangeAndPropagatesCallerCancellation) {
    const auto result = GetParam();
    net::io_context io;
    net::cancellation_signal cancellation;
    ExchangeState state;
    bool completed = false;
    bool released_before_completion = false;
    std::exception_ptr failure;
    net::co_spawn(io, RunRequest(WaitingExchange(state, result), 30s),
        net::bind_cancellation_slot(cancellation.slot(),
            [&](std::exception_ptr error, Response) {
                completed = true;
                released_before_completion = state.released;
                failure = error;
            }));
    io.poll();
    EXPECT_TRUE(state.started);
    EXPECT_FALSE(completed);
    cancellation.emit(net::cancellation_type::terminal);
    io.run();
    ASSERT_TRUE(completed);
    EXPECT_TRUE(released_before_completion);
    ASSERT_TRUE(failure);
    try {
        std::rethrow_exception(failure);
    } catch (const std::system_error& error) {
        EXPECT_EQ(error.code(), net::error::operation_aborted);
    }
    catch (...) {
        FAIL() << "caller cancellation must propagate a system error";
    }
}
INSTANTIATE_TEST_SUITE_P(ExchangeOutcomes, RequestCancellation,
    testing::Values(WaitResult::Throw, WaitResult::FailureValue));

// Exercise the public panel consumer over a real socket, not a private parser.
std::string PaddingHeaders(size_t bytes) {
    std::string out;
    while (bytes != 0) {
        size_t wire = std::min(bytes, size_t{64 * 1024 + 2});
        if (bytes > wire && bytes - wire < 4) wire -= 4;
        out += "X:";
        out.append(wire - 4, 'p');
        out += "\r\n";
        bytes -= wire;
    }
    return out;
}

class PanelHttpConsumer : public testing::TestWithParam<std::string_view> {};
TEST_P(PanelHttpConsumer, PreservesResponseBoundariesAndValidatorIdentity) {
    const auto mode = GetParam();
    net::io_context io;
    ::app::dns::Config dns_config;
    dns_config.servers = {{net::ip::address_v4::loopback(), 53}};
    ::app::dns::DNSWorker resolver(io, dns_config, 16);
    ::app::dns::DNS dns(resolver);
    tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
    ::api::Config config;
    config.Name = "http-consumer";
    config.Key = "panel-consumer-secret";
    config.NodeID = 1;
    config.NodeType = "vless";
    config.APIHost = "http://127.0.0.1:" + std::to_string(acceptor.local_endpoint().port());
    config.RequestTimeout = 2s;
    auto client = ::api::CreatePanelClient(io, std::move(config), dns);
    std::exception_ptr server_failure, client_failure;
    bool served = false, completed = false;
    UserListFetchResult result;
    auto serve = [&]() -> net::awaitable<void> {
        auto socket = co_await acceptor.async_accept(net::use_awaitable);
        net::streambuf request;
        co_await net::async_read_until(socket, request, "\r\n\r\n", net::use_awaitable);
        const auto bytes = request.data();
        const std::string text(static_cast<const char*>(bytes.data()), bytes.size());
        EXPECT_NE(text.find("If-None-Match: committed-users\r\n"), std::string::npos);
        EXPECT_TRUE(text.starts_with("GET /api/v1/server/UniProxy/user?"));
        const std::string body = R"({"users":[]})";
        std::string response = "HTTP/1.1 200 OK\r\nETag: \"candidate-users\"\r\n";
        const bool legal_boundary = mode.ends_with("-legal");
        if (mode.starts_with("head-")) {
            const std::string tail = "Content-Length: 12\r\n\r\n";
            if (mode.starts_with("head-line"))
                response += "X:" + std::string(64 * 1024 - 2 +
                    (legal_boundary ? 0 : 1), 'p') + "\r\n";
            else if (mode.starts_with("head-total"))
                response += PaddingHeaders(256 * 1024 +
                    (legal_boundary ? 0 : 1) - response.size() - tail.size());
            else
                response += PaddingHeaders(16 * 1024);
            response += tail + body;
        } else if (mode == "interim-large-legal") {
            response = "HTTP/1.1 103 Early Hints\r\n" + PaddingHeaders(16 * 1024) +
                "\r\n" + response + "Content-Length: 12\r\n\r\n" + body;
        } else if (mode == "interim-total-over") {
            const std::string interim = "HTTP/1.1 103 Early Hints\r\n";
            response = interim + PaddingHeaders(128 * 1024 - interim.size() - 2) +
                "\r\n" + response;
            response += PaddingHeaders(256 * 1024 + 1 - response.size() -
                std::string_view("Content-Length: 12\r\n\r\n").size());
            response += "Content-Length: 12\r\n\r\n" + body;
        } else if (mode.starts_with("chunk-line") || mode.starts_with("trailer-") ||
                   mode == "combined-budget-over") {
            if (mode == "combined-budget-over") response += PaddingHeaders(160 * 1024);
            response += "Transfer-Encoding: chunked\r\n\r\n";
            const size_t head_bytes = response.size();
            if (mode.starts_with("chunk-line"))
                response += "c;p=" + std::string(64 * 1024 - 4 +
                    (legal_boundary ? 0 : 1), 'p') + "\r\n";
            else
                response += "c\r\n";
            response += body + "\r\n0\r\n";
            if (mode.starts_with("trailer-line"))
                response += "X:" + std::string(64 * 1024 - 2 +
                    (legal_boundary ? 0 : 1), 'p') + "\r\n";
            else if (mode == "trailer-many-legal")
                for (size_t i = 0; i < 256; ++i) response += "X:p\r\n";
            else if (mode.starts_with("trailer-total"))
                response += PaddingHeaders(256 * 1024 - head_bytes - 2 +
                    (legal_boundary ? 0 : 1));
            else if (mode == "combined-budget-over")
                response += PaddingHeaders(110 * 1024);
            response += "\r\n";
        } else if (mode == "chunked" || mode == "bad-trailer" || mode == "chunk-residual") {
            response += "Transfer-Encoding: chunked\r\n\r\nc;source=panel\r\n" + body +
                "\r\n0\r\n" + (mode == "bad-trailer" ? "bad trailer\r\n" : "X-Panel: complete\r\n") + "\r\n";
            if (mode == "chunk-residual") response += "not-body";
        } else if (mode == "not-modified") {
            response = "HTTP/1.1 103 Early Hints\r\nLink: </panel>\r\n\r\n"
                       "HTTP/1.1 304 Not Modified\r\nContent-Length: 67108865\r\n\r\n";
        } else if (mode == "oversized") {
            response += "Content-Length: 67108865\r\n\r\n";
        } else if (mode == "oversized-chunk") {
            response += "Transfer-Encoding: chunked\r\n\r\n4000001\r\n";
        } else if (mode == "ambiguous") {
            response += "Transfer-Encoding: chunked\r\nContent-Length: 12\r\n\r\n"
                        "c\r\n" + body + "\r\n0\r\n\r\n";
        } else if (mode == "close-delimited") {
            response += "Connection: close\r\n\r\n" + body;
        } else {
            response += "Content-Length: " + std::to_string(mode == "truncated" ? 100 : body.size()) +
                "\r\n\r\n" + body;
            if (mode == "fixed-residual") response += "not-body";
        }
        served = true;
        const auto [write_error, written] = co_await net::async_write(
            socket, net::buffer(response), net::as_tuple(net::use_awaitable));
        (void)written;
        if (legal_boundary || mode == "fixed" || mode == "chunked" || mode == "close-delimited")
            EXPECT_FALSE(write_error);
    };
    net::co_spawn(io, serve(), [&](std::exception_ptr failure) { server_failure = failure; });
    net::co_spawn(io, client->GetUserList("committed-users"),
        [&](std::exception_ptr failure, UserListFetchResult value) {
            client_failure = failure;
            result = std::move(value);
            completed = true;
        });
    io.run();
    io.restart();
    net::co_spawn(io, resolver.AsyncJoin(), [&](std::exception_ptr failure) {
        if (failure) client_failure = failure;
    });
    io.run();
    ASSERT_FALSE(server_failure);
    ASSERT_FALSE(client_failure);
    ASSERT_TRUE(served);
    ASSERT_TRUE(completed);
    if (mode == "not-modified") {
        EXPECT_TRUE(result.Ok());
        EXPECT_TRUE(result.not_modified);
    } else if (mode == "fixed" || mode == "chunked" || mode == "close-delimited" ||
               mode.ends_with("-legal")) {
        EXPECT_TRUE(result.Ok());
        EXPECT_FALSE(result.not_modified);
        EXPECT_TRUE(result.users.empty());
        EXPECT_EQ(result.etag, "candidate-users");
    } else {
        EXPECT_FALSE(result.Ok());
        EXPECT_FALSE(result.not_modified);
        EXPECT_TRUE(result.etag.empty());
        if (mode == "oversized" || mode == "oversized-chunk")
            EXPECT_NE(result.error_msg.find("HTTP body too large"), std::string::npos);
    }
}
INSTANTIATE_TEST_SUITE_P(RealHttp, PanelHttpConsumer, testing::Values(
    "fixed", "chunked", "close-delimited", "not-modified", "oversized",
    "ambiguous", "truncated", "bad-trailer", "fixed-residual", "chunk-residual", "oversized-chunk",
    "head-large-legal", "head-line-legal", "head-line-over", "head-total-legal", "head-total-over",
    "interim-large-legal", "interim-total-over", "chunk-line-legal", "chunk-line-over",
    "trailer-line-legal", "trailer-line-over", "trailer-many-legal",
    "trailer-total-legal", "trailer-total-over", "combined-budget-over"));
}  // namespace

