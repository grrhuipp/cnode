#pragma once

#include <cstddef>
#include <optional>

struct ProcessDescriptors {
    std::optional<size_t> open;
    std::optional<size_t> soft_limit;
    bool soft_limit_unlimited = false;
};

// 仅供控制线程诊断；不可得的计数保持 unknown，而不是 0。
// 结果不含本次采样临时打开的目录描述符。实现位于 bootstrap.cpp。
[[nodiscard]] ProcessDescriptors ReadProcessDescriptors() noexcept;
