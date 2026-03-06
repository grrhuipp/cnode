#pragma once

#include <chrono>
#include <cstdint>
#include <algorithm>

namespace acpp {

// 令牌桶限速器，用于 TCP/UDP relay 的流量控制
// rate 单位为 bytes/s，0 表示不限速
class TokenBucket {
public:
    explicit TokenBucket(uint64_t rate)
        : rate_(rate)
        , tokens_(rate > 0 ? rate : 0)
        , last_time_(std::chrono::steady_clock::now()) {}

    // 消费 bytes 个令牌，返回需要等待的时间
    std::chrono::milliseconds Consume(size_t bytes) {
        if (rate_ == 0) {
            return std::chrono::milliseconds(0);
        }

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_time_).count();

        if (elapsed > 0) {
            uint64_t new_tokens = (rate_ * elapsed) / 1000;
            tokens_ = std::min(tokens_ + new_tokens, rate_ * 2);
            last_time_ = now;
        }

        if (tokens_ >= bytes) {
            tokens_ -= bytes;
            return std::chrono::milliseconds(0);
        }

        uint64_t needed = bytes - tokens_;
        uint64_t wait_ms = (needed * 1000) / rate_;
        tokens_ = 0;
        return std::chrono::milliseconds(wait_ms + 1);
    }

private:
    uint64_t rate_;
    uint64_t tokens_;
    std::chrono::steady_clock::time_point last_time_;
};

}  // namespace acpp
