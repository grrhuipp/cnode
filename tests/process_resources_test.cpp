#include <gtest/gtest.h>

#include "common/process_resources.hpp"

#include <cstdio>
#include <type_traits>

#include <fcntl.h>
#include <unistd.h>


TEST(ProcessResources, Contract) {
    const auto before = ::ReadProcessDescriptors();
    const int resource = ::open("/dev/null", O_RDONLY);
    ASSERT_FALSE((resource < 0));
    const auto during = ::ReadProcessDescriptors();
    ::close(resource);
    const auto after = ::ReadProcessDescriptors();
    ASSERT_FALSE((!before.open || !during.open || !after.open ||
        *during.open != *before.open + 1 || *after.open != *before.open));
    rlimit limits{};
    if (::getrlimit(RLIMIT_NOFILE, &limits) == 0) {
        if (limits.rlim_cur == RLIM_INFINITY) {
            ASSERT_FALSE((!before.soft_limit_unlimited || before.soft_limit));
        } else ASSERT_FALSE((before.soft_limit_unlimited || !before.soft_limit ||
                   *before.soft_limit != static_cast<size_t>(limits.rlim_cur)));
    }
    std::printf("process descriptor sampling: open=%zu\n", before.open.value_or(0));
}
