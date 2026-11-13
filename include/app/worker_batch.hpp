#pragma once

#include "common/asio_types.hpp"
#include "common/awaitable_batch.hpp"
#include "common/error.hpp"

#include <cstddef>
#include <type_traits>
#include <utility>
#include <vector>

// 控制面逐 Worker 批量投递的唯一入口。`stopping` 由控制面执行器独占写入，
// 调用方保证它的寿命覆盖整个批量操作；停机请求之后不再开始新的 Worker 变更。

namespace app {

inline void ThrowIfStopping(const bool& stopping) {
    if (stopping) throw IoSystemError(net::error::operation_aborted);
}

template <typename Operation>
struct AwaitableValue;

template <typename T>
struct AwaitableValue<net::awaitable<T>> {
    using type = T;
};

// 每个 Worker 一次投递：工厂返回的 awaitable（PostCall / PostTask）惰性启动，
// 先检查 stopping 再进入 Worker 邮箱；未启动的投递随帧丢弃，不占用邮箱槽位。
template <typename WorkerRange, typename OperationFactory>
using OperationValue = typename AwaitableValue<std::invoke_result_t<
    OperationFactory&, decltype(*std::declval<WorkerRange&>()[size_t{}]), size_t>>::type;

template <typename T>
using BatchResult = std::conditional_t<std::is_void_v<T>, void, std::vector<T>>;

inline net::awaitable<void> AwaitUnlessStopping(
    const bool* stopping, net::awaitable<void> operation) {
    ThrowIfStopping(*stopping);
    co_await std::move(operation);
}

template <typename T>
net::awaitable<void> AwaitUnlessStopping(
    const bool* stopping, net::awaitable<T> operation, T* result) {
    ThrowIfStopping(*stopping);
    *result = co_await std::move(operation);
}

// 对每个 Worker 并发投递 `make_operation(worker, index)`，并在全部已启动的子任务
// 结束后才返回（首个非取消失败优先上报）。非 void 结果按 Worker 下标收集，
// 结果在 `executor` 上写入，不跨线程共享。
template <typename WorkerRange, typename OperationFactory,
          typename T = OperationValue<WorkerRange, OperationFactory>>
[[nodiscard]] net::awaitable<BatchResult<T>> PostToEachWorker(
    net::any_io_executor executor,
    WorkerRange& workers,
    const bool& stopping,
    OperationFactory make_operation) {
    ThrowIfStopping(stopping);
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers.size());
    if constexpr (std::is_void_v<T>) {
        for (size_t i = 0; i < workers.size(); ++i) {
            tasks.push_back(AwaitUnlessStopping(
                &stopping, make_operation(*workers[i], i)));
        }
        co_await common::RunAwaitableBatch(std::move(executor), std::move(tasks));
    } else {
        std::vector<T> results(workers.size());
        for (size_t i = 0; i < workers.size(); ++i) {
            tasks.push_back(AwaitUnlessStopping(
                &stopping, make_operation(*workers[i], i), &results[i]));
        }
        co_await common::RunAwaitableBatch(std::move(executor), std::move(tasks));
        co_return results;
    }
}

// 按 Worker 下标逐个投递，前一个结束后才开始下一个。只用于顺序本身是契约的
// 操作：监听安装决定 SO_REUSEPORT 组内的 socket 下标，QUIC 的 CBPF 以
// worker_id 作为该下标投递，因此入站必须按 Worker 顺序安装。
template <typename WorkerRange, typename OperationFactory,
          typename T = OperationValue<WorkerRange, OperationFactory>>
[[nodiscard]] net::awaitable<BatchResult<T>> PostToEachWorkerInOrder(
    WorkerRange& workers,
    const bool& stopping,
    OperationFactory make_operation) {
    if constexpr (std::is_void_v<T>) {
        for (size_t index = 0; index < workers.size(); ++index) {
            ThrowIfStopping(stopping);
            co_await make_operation(*workers[index], index);
        }
    } else {
        std::vector<T> results(workers.size());
        for (size_t index = 0; index < workers.size(); ++index) {
            ThrowIfStopping(stopping);
            results[index] = co_await make_operation(*workers[index], index);
        }
        co_return results;
    }
}

}  // namespace app
