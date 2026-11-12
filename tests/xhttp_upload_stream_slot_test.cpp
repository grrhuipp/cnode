#include <gtest/gtest.h>

#include "allocation_hook.hpp"
#include "transport/internet/xhttp_session.hpp"

#include <cstdlib>
#include <memory>

namespace {
thread_local bool reject_next_new = false;

void RejectArmedNew(std::size_t) {
    if (!reject_next_new) return;
    reject_next_new = false;
    throw std::bad_alloc();
}

class TestStream final {
public:
    explicit TestStream(size_t& destructions) : destructions_(destructions) {}
    ~TestStream() noexcept { ++destructions_; }

    void Close() { open_ = false; }
    bool IsOpen() const { return open_; }

private:
    size_t& destructions_;
    bool open_ = true;
};

}  // namespace

constinit allocation_hook::Hooks allocation_hook::hooks{.before_new = RejectArmedNew};

TEST(XhttpUploadStreamSlot, RejectsSecondOwnerAndRetainsInFlightSnapshotUntilReleased) {
    size_t first_destructions = 0;
    size_t rejected_destructions = 0;
    ::transport::internet::detail::BasicXHttpUploadStreamSlot<TestStream> slot;
    ASSERT_TRUE(slot.Attach(std::make_unique<TestStream>(first_destructions)));
    auto in_flight = slot.Snapshot();
    const bool attached_again = slot.Attach(std::make_unique<TestStream>(rejected_destructions));
    ASSERT_TRUE(in_flight);
    EXPECT_FALSE(attached_again);
    EXPECT_EQ(rejected_destructions, 1u);
    auto detached = slot.Take();
    EXPECT_TRUE(slot.Empty());
    ASSERT_TRUE(detached);
    EXPECT_EQ(first_destructions, 0u);
    detached->Close();
    detached.reset();
    EXPECT_EQ(first_destructions, 0u);
    EXPECT_FALSE(in_flight->IsOpen());
    in_flight.reset();
    EXPECT_EQ(first_destructions, 1u);
}

TEST(XhttpUploadStreamSlot, AllocationFailurePreservesCallerOwnershipAndAllowsRetry) {
    size_t destructions = 0;
    ::transport::internet::detail::BasicXHttpUploadStreamSlot<TestStream> slot;
    auto retained = std::make_unique<TestStream>(destructions);
    bool allocation_failed = false;
    {
        struct RestoreAllocationFault {
            ~RestoreAllocationFault() { reject_next_new = false; }
        } restore_fault;
        reject_next_new = true;
        try {
            (void)slot.Attach(std::move(retained));
        } catch (const std::bad_alloc&) {
            allocation_failed = true;
        }
    }
    EXPECT_TRUE(allocation_failed);
    EXPECT_TRUE(retained);
    EXPECT_TRUE(slot.Empty());
    EXPECT_EQ(destructions, 0u);
    EXPECT_TRUE(slot.Attach(std::move(retained)));
    EXPECT_FALSE(retained);
    auto recovered = slot.Take();
    recovered.reset();
    EXPECT_EQ(destructions, 1u);
}
