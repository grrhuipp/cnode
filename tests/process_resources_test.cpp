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

TEST(ProcessResources, RaisesSoftLimitToHardLimit) {
    rlimit original{};
    ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &original), 0);
    if (original.rlim_max == RLIM_INFINITY || original.rlim_max <= 64)
        GTEST_SKIP() << "hard limit leaves no room for a lower soft limit";
    rlimit lowered = original;
    lowered.rlim_cur = 64;
    ASSERT_EQ(::setrlimit(RLIMIT_NOFILE, &lowered), 0);

    const auto raised = ::app::RaiseDescriptorSoftLimit();
    rlimit after{};
    ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &after), 0);
    const auto sample = ::app::ReadProcessDescriptors();
    (void)::setrlimit(RLIMIT_NOFILE, &original);

    EXPECT_EQ(raised.error, 0);
    EXPECT_EQ(raised.previous_soft, 64u);
    EXPECT_EQ(raised.current_soft, original.rlim_max);
    EXPECT_EQ(raised.hard, original.rlim_max);
    EXPECT_EQ(after.rlim_cur, original.rlim_max);
    EXPECT_EQ(sample.soft_limit, static_cast<size_t>(original.rlim_max));
}
