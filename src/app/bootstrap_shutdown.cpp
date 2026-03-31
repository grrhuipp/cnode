#include "acppnode/app/bootstrap_shutdown.hpp"
#include "acppnode/app/panel_sync.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/infra/log.hpp"

#include <boost/asio/signal_set.hpp>

#include <csignal>

namespace acpp {

std::shared_ptr<net::signal_set> InstallShutdownHandler(
    const RuntimeContext& ctx,
    std::atomic<bool>& running) {
    auto signals = std::make_shared<net::signal_set>(ctx.main_ctx, SIGINT, SIGTERM);

    signals->async_wait([&running, &ctx](
                            const boost::system::error_code&, int signo) {
        LOG_CONSOLE("Received signal {}, shutting down...", signo);
        running = false;

        ctx.sync_manager.Stop();

        for (const auto& tag : ctx.sync_manager.RegisteredTags()) {
            for (const auto& worker : ctx.workers) {
                worker->RemoveListenerAsync(tag);
            }
        }
        for (const auto& tag : ctx.static_inbound_tags) {
            for (const auto& worker : ctx.workers) {
                worker->RemoveListenerAsync(tag);
            }
        }

        ctx.work_guards.clear();
        for (const auto& io_ctx : ctx.io_contexts) {
            io_ctx->stop();
        }

        ctx.main_ctx.stop();
    });

    return signals;
}

}  // namespace acpp
