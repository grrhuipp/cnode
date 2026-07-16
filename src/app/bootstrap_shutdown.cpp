#include "acppnode/app/bootstrap_shutdown.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/infra/log.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/post.hpp>
#include <asio/signal_set.hpp>
#include <asio/use_awaitable.hpp>

#include <csignal>
#include <exception>
#include <memory>

namespace acpp {
namespace {

net::awaitable<void> ShutdownWorkers(const RuntimeContext& ctx) {
    for (const auto& worker : ctx.workers) {
        try {
            co_await net::co_spawn(
                worker->GetExecutor(),
                worker->ShutdownTask(),
                net::use_awaitable);
        } catch (const std::exception& e) {
            LOG_ERROR("Worker[{}]: shutdown failed: {}", worker->Id(), e.what());
        } catch (...) {
            LOG_ERROR("Worker[{}]: shutdown failed with unknown exception", worker->Id());
        }
    }

    ctx.work_guards.clear();
    for (const auto& io_ctx : ctx.io_contexts) {
        io_ctx->stop();
    }
    net::post(ctx.main_ctx, [&ctx] {
        ctx.main_ctx.stop();
    });
}

}  // namespace

std::unique_ptr<net::signal_set> InstallShutdownHandler(
    const RuntimeContext& ctx,
    RuntimeState& state) {
    auto signals = std::make_unique<net::signal_set>(ctx.main_ctx);
    signals->add(SIGINT);
    signals->add(SIGTERM);
#ifdef _WIN32
    signals->add(SIGBREAK);
#endif

    signals->async_wait([&state, &ctx](
                            const IoErrorCode& ec, int signo) {
        if (ec) {
            return;
        }
        LOG_CONSOLE("shutdown signal={} status=stopping", signo);
        state.running = false;

        ctx.controller.Stop();

        net::co_spawn(
            ctx.main_ctx.get_executor(),
            ShutdownWorkers(ctx),
            net::detached);
    });

    return signals;
}

}  // namespace acpp
