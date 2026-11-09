#include <gtest/gtest.h>

#include "app/session_group_executor.hpp"

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <iostream>

namespace {

TEST(ExecutorBenchmark, NativeIoContextDispatch) {
    net::io_context worker;
    auto coordinator = std::make_shared<GroupCoordinator>(worker, 64);
    coordinator->RegisterWorker(0, worker, worker.get_executor());

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
