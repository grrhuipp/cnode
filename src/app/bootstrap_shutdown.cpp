#include "acppnode/app/bootstrap_shutdown.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/infra/log.hpp"

#include <asio/signal_set.hpp>

#include <csignal>
#include <memory>

namespace acpp {

std::unique_ptr<net::signal_set> InstallShutdownHandler(
    const RuntimeContext& ctx,
    RuntimeState& state) {
    auto signals = std::make_unique<net::signal_set>(ctx.main_ctx, SIGINT, SIGTERM);

    signals->async_wait([&state, &ctx](
                            const IoErrorCode&, int signo) {
        LOG_CONSOLE("shutdown signal={} status=stopping", signo);
        state.running = false;

        ctx.controller.Stop();

        auto tags = std::make_shared<std::vector<std::string>>();
        for (const auto& tag : ctx.controller.RegisteredTags()) {
            tags->push_back(tag);
        }
        for (const auto& tag : ctx.inbound_startup.tags) {
            tags->push_back(tag);
        }

        struct ShutdownJoin {
            const RuntimeContext* ctx = nullptr;
            size_t remaining = 0;
        };
        auto join = std::make_shared<ShutdownJoin>();
        join->ctx = &ctx;
        join->remaining = ctx.workers.size();

        if (join->remaining == 0) {
            ctx.work_guards.clear();
            ctx.main_ctx.stop();
            return;
        }

        for (const auto& worker : ctx.workers) {
            worker->ShutdownListenersAsync(*tags, [join] {
                net::post(join->ctx->main_ctx, [join] {
                    if (join->remaining == 0) {
                        return;
                    }
                    --join->remaining;
                    if (join->remaining != 0) {
                        return;
                    }

                    join->ctx->work_guards.clear();
                    for (const auto& io_ctx : join->ctx->io_contexts) {
                        io_ctx->stop();
                    }

                    join->ctx->main_ctx.stop();
                });
            });
        }
    });

    return signals;
}

}  // namespace acpp
