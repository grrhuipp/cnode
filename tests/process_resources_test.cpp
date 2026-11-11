#include <gtest/gtest.h>

#include "app/process_descriptors.hpp"

#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>

TEST(ProcessResources, DescriptorCountTracksOpenAndClose) {
    const auto before = ::app::ReadProcessDescriptors();
    const int descriptor = ::open("/dev/null", O_RDONLY);
    ASSERT_GE(descriptor, 0);
    const auto during = ::app::ReadProcessDescriptors();
    const int closed = ::close(descriptor);
    const auto after = ::app::ReadProcessDescriptors();
    EXPECT_EQ(closed, 0);
    ASSERT_TRUE(before.open);
    ASSERT_TRUE(during.open);
    ASSERT_TRUE(after.open);
    EXPECT_EQ(*during.open, *before.open + 1);
    EXPECT_EQ(*after.open, *before.open);
}

TEST(ProcessResources, ReportsOperatingSystemSoftLimit) {
    rlimit limits{};
    ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &limits), 0);
    const auto sample = ::app::ReadProcessDescriptors();
    if (limits.rlim_cur == RLIM_INFINITY) {
        EXPECT_TRUE(sample.soft_limit_unlimited);
        EXPECT_FALSE(sample.soft_limit);
    } else {
        EXPECT_FALSE(sample.soft_limit_unlimited);
        ASSERT_TRUE(sample.soft_limit);
        EXPECT_EQ(*sample.soft_limit, static_cast<size_t>(limits.rlim_cur));
    }
}
