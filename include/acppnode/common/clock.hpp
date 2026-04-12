#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
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

// 使用系统本地时区转换时间，避免依赖 chrono tzdb 在静态环境中漂移。
inline std::tm LocalTime(std::time_t timestamp) noexcept {
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &timestamp);
#else
    localtime_r(&timestamp, &tm);
#endif
    return tm;
}

inline std::string FormatLocalTime(
    std::chrono::system_clock::time_point tp,
    const char* format) {
    const auto timestamp = std::chrono::system_clock::to_time_t(tp);
    const std::tm tm = LocalTime(timestamp);

    char buffer[64]{};
    const size_t written = std::strftime(buffer, sizeof(buffer), format, &tm);
    return written > 0 ? std::string(buffer, written) : std::string{};
}

// 格式化字节数
std::string FormatBytes(uint64_t bytes);

// 格式化时间戳
std::string FormatTimestamp(int64_t timestamp_us);

// 生成唯一连接 ID
uint64_t GenerateConnId();

}  // namespace acpp
