#pragma once

#include <cstddef>
#include <optional>

namespace app {

struct ProcessDescriptors {
    std::optional<size_t> open;
    std::optional<size_t> soft_limit;
    bool soft_limit_unlimited = false;
};

// 仅供控制线程诊断；不可得的计数保持 unknown，而不是 0。
// 结果不含本次采样临时打开的目录描述符。实现位于 bootstrap.cpp。
[[nodiscard]] ProcessDescriptors ReadProcessDescriptors() noexcept;

struct DescriptorLimitRaise {
    // 调整前后的 RLIMIT_NOFILE 软上限；RLIM_INFINITY 原样保留。
    unsigned long long previous_soft = 0;
    unsigned long long current_soft = 0;
    unsigned long long hard = 0;
    int error = 0; // getrlimit/setrlimit 的 errno；0 表示成功或无需调整。
};

// 启动期、Worker 创建前调用一次：把 NOFILE 软上限提到硬上限（与 Go 运行时
// 自 1.19 起的行为一致）。硬上限本身即边界；失败只返回 errno，不阻断启动。
[[nodiscard]] DescriptorLimitRaise RaiseDescriptorSoftLimit() noexcept;

}  // namespace app
