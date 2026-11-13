// 执行器投递微基准：向单个 Worker 的原生 io_context 投递 10000 个任务并运行至排空，
// 输出总墙钟耗时；协调器构造与停机收束不计入计时。

#include <gtest/gtest.h>

#include "app/group_coordinator.hpp"

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <iostream>

namespace {

TEST(ExecutorBenchmark, NativeIoContextDispatch) {
    net::io_context worker;
    auto coordinator = std::make_shared<app::GroupCoordinator>(worker, 64);
    coordinator->RegisterWorker();

    constexpr std::size_t kIterations = 10000;
    std::size_t completed = 0;
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < kIterations; ++i) {
        net::post(worker, [&] { ++completed; });
    }
    worker.run();
    const auto elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - start).count();

    EXPECT_EQ(completed, kIterations);
    coordinator->CloseAdmission();
    net::co_spawn(
        worker,
        [coordinator]() -> net::awaitable<void> {
            co_await coordinator->AsyncJoin();
            coordinator->ReleaseServices();
            co_await coordinator->Finalize();
        },
        [](std::exception_ptr) {});
    worker.restart();
    worker.run();
    std::cout << "EXECUTOR_BENCHMARK iterations=" << kIterations
              << " seconds=" << elapsed << '\n';
}

}  // namespace
