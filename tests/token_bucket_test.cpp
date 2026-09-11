#include "acppnode/app/token_bucket.hpp"

#include <cstdio>
#include <limits>
#include <iostream>
#include <optional>
#include <string_view>
#include <thread>

using namespace std::chrono_literals;

namespace {
using Clock = acpp::TokenBucket::Clock;
Clock::time_point At(int64_t millis) {
    return Clock::time_point{std::chrono::milliseconds{millis}};
}
}

int main(int argc, char** argv) {
    // The independent Python integer oracle exercises the same production
    // class through a narrow test-only command stream.
    if (argc == 2 && std::string_view(argv[1]) == "--trace") {
        std::optional<acpp::TokenBucket> bucket;
        char command;
        uint64_t value;
        int64_t now;
        while (std::cin >> command >> value >> now) {
            if (command == 'R') bucket.emplace(value, At(now));
            else if (command == 'C' && bucket) std::cout << bucket->Consume(value, At(now)).count() << '\n';
            else return 2;
        }
        return 0;
    }
    bool passed = true;
    acpp::TokenBucket bucket(1000);
    const auto first = bucket.Consume(2000);
    std::this_thread::sleep_for(first);
    const auto second = bucket.Consume(1000);
    std::printf("first=%lldms second=%lldms\n", static_cast<long long>(first.count()),
                static_cast<long long>(second.count()));
    passed &= second >= 850ms && second <= 1000ms;

    const acpp::TokenBucket::Clock::time_point epoch{};
    acpp::TokenBucket slow(1, epoch);
    const auto huge = slow.Consume(std::numeric_limits<size_t>::max(), epoch);
    std::printf("maximum consumption wait=%lldms\n", static_cast<long long>(huge.count()));
    passed &= huge == std::chrono::milliseconds::max();

    acpp::TokenBucket continuous(1000, At(0));
    passed &= continuous.Consume(2000, At(0)) == 1000ms;
    passed &= continuous.Consume(1000, At(1000)) == 1000ms;
    passed &= continuous.Consume(1000, At(2000)) == 1000ms;
    acpp::TokenBucket reserved(1000, At(0));
    passed &= reserved.Consume(2000, At(0)) == 1000ms;
    passed &= reserved.Consume(1000, At(0)) == 2000ms;
    passed &= reserved.Consume(1000, At(2000)) == 1000ms;
    acpp::TokenBucket idle(1000, At(0));
    passed &= idle.Consume(1000, At(0)) == 0ms;
    passed &= idle.Consume(2000, At(10000)) == 0ms;
    passed &= idle.Consume(1000, At(10000)) == 1000ms;
    acpp::TokenBucket fractional(3, At(0));
    passed &= fractional.Consume(3, At(0)) == 0ms;
    passed &= fractional.Consume(1, At(333)) == 1ms;
    passed &= fractional.Consume(1, At(334)) == 333ms;
    passed &= fractional.Consume(1, At(667)) == 333ms;
    acpp::TokenBucket unlimited(0, At(0));
    passed &= unlimited.Consume(std::numeric_limits<size_t>::max(), At(0)) == 0ms;
    acpp::TokenBucket extreme(std::numeric_limits<uint64_t>::max(), At(0));
    passed &= extreme.Consume(std::numeric_limits<size_t>::max(), At(0)) == 0ms;
    passed &= extreme.Consume(std::numeric_limits<size_t>::max(), At(1)) == 999ms;
    acpp::TokenBucket saturated(uint64_t{1} << 63, At(0));
    passed &= saturated.Consume(uint64_t{1} << 63, At(0)) == 0ms;
    passed &= saturated.Consume(std::numeric_limits<size_t>::max(), At(2000)) == 0ms;
    passed &= saturated.Consume(1, At(2000)) == 1ms;
    std::printf("deterministic reservation, fractional and saturation checks: %s\n", passed ? "PASS" : "FAIL");
    return passed ? 0 : 1;
}
