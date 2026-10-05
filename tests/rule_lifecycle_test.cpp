#include "acppnode/common/rule.hpp"

#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/strand.hpp>
#include <asio/use_future.hpp>

#include <regex>
#include <string>

namespace {

acpp::net::awaitable<int> Run(acpp::net::any_io_executor owner) {
    acpp::rule::Manager manager(owner);
    const std::string tag = "panel/vmess/443";

    co_await manager.UpdateRule(tag, {
        acpp::rule::DetectRule{
            .ID = 7,
            .Pattern = std::regex("blocked\\.example"),
        },
    });

    acpp::features::policy::RequestPolicy& policy = manager;
    if (!co_await policy.Blocked(
            tag, 42, "node/user/42", "blocked.example")) co_return 1;

    const auto results = co_await manager.GetDetectResult(tag);
    if (results.size() != 1 || results.front().UID != 42 ||
        results.front().RuleID != 7) co_return 2;

    co_await manager.UpdateRule(tag, {});
    if (co_await policy.Blocked(
            tag, 42, "node/user/42", "blocked.example")) co_return 3;
    if (!(co_await manager.GetDetectResult(tag)).empty()) co_return 4;
    co_return 0;
}

}  // namespace

int main() {
    acpp::net::io_context io;
    auto result = acpp::net::co_spawn(
        io, Run(acpp::net::make_strand(io)), acpp::net::use_future);
    io.run();
    return result.get();
}
