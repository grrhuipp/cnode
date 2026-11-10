#include <gtest/gtest.h>

#include "xhttp_session.hpp"

#include <cstdlib>
#include <memory>

namespace {

class TestStream final {
public:
    TestStream(::memory::worker_memory& pool, size_t& destructions)
        : pool_(pool), destructions_(destructions) {}
    ~TestStream() noexcept { ++destructions_; }

    ::memory::worker_memory& Pool() const noexcept { return pool_; }
    void Close() { open_ = false; }
    bool IsOpen() const { return open_; }

private:
    ::memory::worker_memory& pool_;
    size_t& destructions_;
    bool open_ = true;
};

}  // namespace

TEST(XhttpUploadStreamSlot, Contract) {
    ::memory::worker_memory pool;
    ::detail::BasicXHttpUploadStreamSlot<TestStream> slot;
    size_t first_destructions = 0;
    size_t rejected_destructions = 0;
    ASSERT_FALSE((!slot.Attach(std::make_unique<TestStream>(pool, first_destructions))));
    auto in_flight = slot.Snapshot();
    // A rejected temporary remains owned by the call expression.
    const bool attached_again = slot.Attach(
        std::make_unique<TestStream>(pool, rejected_destructions));
    ASSERT_FALSE((!in_flight || attached_again || rejected_destructions != 1));

    auto detached = slot.Take();
    ASSERT_FALSE((!slot.Empty() || !detached || first_destructions != 0));
    detached->Close();
    detached.reset();
    ASSERT_FALSE((first_destructions != 0 || in_flight->IsOpen()));
    in_flight.reset();
    ASSERT_FALSE((first_destructions != 1));
    size_t allocation_failure_destructions = 0;
    auto retained = std::make_unique<TestStream>(pool, allocation_failure_destructions);
    // The control block comes from the stream's pool.
    ::memory::reject_next_pmr_allocation = true;
    bool allocation_failed = false;
    try {
        (void)slot.Attach(std::move(retained));
    } catch (const std::bad_alloc&) {
        allocation_failed = true;
    }
    const bool fault_consumed = !::memory::reject_next_pmr_allocation;
    ::memory::reject_next_pmr_allocation = false;
    ASSERT_FALSE((!allocation_failed || !fault_consumed || !retained || !slot.Empty() ||
        allocation_failure_destructions != 0));
    ASSERT_FALSE((!slot.Attach(std::move(retained)) || retained));
    auto recovered = slot.Take();
    recovered.reset();
    ASSERT_FALSE((allocation_failure_destructions != 1));
    { ASSERT_EQ((EXIT_SUCCESS), 0); return; }
}
