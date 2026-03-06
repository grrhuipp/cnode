#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace acpp {

using steady_clock = std::chrono::steady_clock;
using time_point = steady_clock::time_point;
using namespace std::chrono_literals;

// 获取当前时间戳（微秒，Unix 纪元）
inline int64_t NowMicros() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

// 获取当前时间戳（毫秒，Unix 纪元）
inline int64_t NowMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

// 格式化字节数
std::string FormatBytes(uint64_t bytes);

// 格式化时间戳
std::string FormatTimestamp(int64_t timestamp_us);

// 生成唯一连接 ID
uint64_t GenerateConnId();

}  // namespace acpp
