#include <gtest/gtest.h>

#include "transport/internet/xhttp_session.hpp"

#include <cstdlib>
#include <memory>

namespace {

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

TEST(XhttpUploadStreamSlot, Contract) {
    ::detail::BasicXHttpUploadStreamSlot<TestStream> slot;
    size_t first_destructions = 0;
    size_t rejected_destructions = 0;
    ASSERT_FALSE((!slot.Attach(std::make_unique<TestStream>(first_destructions))));
    auto in_flight = slot.Snapshot();
    // A rejected temporary remains owned by the call expression.
    const bool attached_again = slot.Attach(
        std::make_unique<TestStream>(rejected_destructions));
    ASSERT_FALSE((!in_flight || attached_again || rejected_destructions != 1));

    auto detached = slot.Take();
    ASSERT_FALSE((!slot.Empty() || !detached || first_destructions != 0));
    detached->Close();
    detached.reset();
    ASSERT_FALSE((first_destructions != 0 || in_flight->IsOpen()));
    in_flight.reset();
    ASSERT_FALSE((first_destructions != 1));
    size_t allocation_failure_destructions = 0;
    auto retained = std::make_unique<TestStream>(allocation_failure_destructions);
    // The control block uses the process resource.
    ::memory::reject_next_process_allocation = true;
    bool allocation_failed = false;
    try {
        (void)slot.Attach(std::move(retained));
    } catch (const std::bad_alloc&) {
        allocation_failed = true;
    }
    const bool fault_consumed = !::memory::reject_next_process_allocation;
    ::memory::reject_next_process_allocation = false;
    ASSERT_FALSE((!allocation_failed || !fault_consumed || !retained || !slot.Empty() ||
        allocation_failure_destructions != 0));
    ASSERT_FALSE((!slot.Attach(std::move(retained)) || retained));
    auto recovered = slot.Take();
    recovered.reset();
    ASSERT_FALSE((allocation_failure_destructions != 1));
    { ASSERT_EQ((EXIT_SUCCESS), 0); return; }
}
