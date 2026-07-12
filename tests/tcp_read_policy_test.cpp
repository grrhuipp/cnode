#include "tcp_read_policy.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>
#include <thread>

namespace {

namespace policy = acpp::transport::internet::tcp_read_policy;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

}  // namespace

int main() {
    Check(policy::ActiveStreamCount() == 0, "initial active stream count is not zero");
    Check(policy::MaxReadBufferCount() == 4, "normal readv cap is not four");

    for (uint32_t i = 0; i + 1 < policy::kPressureActiveStreamThreshold; ++i) {
        policy::RegisterActiveStream();
    }
    Check(policy::MaxReadBufferCount() == 4,
          "readv pressure cap activated before threshold");

    policy::RegisterActiveStream();
    Check(policy::ActiveStreamCount() == policy::kPressureActiveStreamThreshold,
          "active stream threshold count mismatch");
    Check(policy::MaxReadBufferCount() == 2,
          "high-pressure readv cap is not two");

    bool child_is_worker_local = false;
    std::thread child([&child_is_worker_local] {
        child_is_worker_local = policy::ActiveStreamCount() == 0 &&
            policy::MaxReadBufferCount() == 4;
    });
    child.join();
    Check(child_is_worker_local, "active stream pressure leaked across Worker threads");

    for (uint32_t i = 0; i < policy::kPressureActiveStreamThreshold; ++i) {
        policy::UnregisterActiveStream();
    }
    Check(policy::ActiveStreamCount() == 0, "active stream count did not return to zero");
    Check(policy::MaxReadBufferCount() == 4,
          "readv cap did not recover after pressure dropped");

    policy::UnregisterActiveStream();
    Check(policy::ActiveStreamCount() == 0, "active stream count underflowed");

    std::cout << "tcp_read_policy_test: ok\n";
    return 0;
}
