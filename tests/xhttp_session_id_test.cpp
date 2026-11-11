#include <gtest/gtest.h>

#include "transport/internet/xhttp_client.hpp"

#include <set>
#include <string>

// 会话 ID 必须是 16 字节随机数的 32 位小写 hex：服务端把它当路径段与会话键使用，
// 可预测或重复的 ID 会让他人会话被注入上行请求。
TEST(XHttpSessionId, IsRandomLowercaseHex) {
    constexpr int kSamples = 256;
    std::set<std::string> seen;
    for (int i = 0; i < kSamples; ++i) {
        const transport::internet::XHttpSessionId id = transport::internet::GenerateXHttpSessionId();
        ASSERT_EQ(id.size(), 32u);
        for (const char ch : id) {
            ASSERT_TRUE((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) << ch;
        }
        ASSERT_TRUE(seen.emplace(id.data(), id.size()).second);
    }
}
