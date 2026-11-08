#include <gtest/gtest.h>

#include "xhttp_upload_stream_slot.hpp"

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
    auto* previous_resource = std::pmr::set_default_resource(std::pmr::null_memory_resource());
    bool allocation_failed = false;
    try {
        (void)slot.Attach(std::move(retained));
    } catch (const std::bad_alloc&) {
        allocation_failed = true;
    }
    std::pmr::set_default_resource(previous_resource);
    ASSERT_FALSE((!allocation_failed || !retained || !slot.Empty() ||
        allocation_failure_destructions != 0));
    ASSERT_FALSE((!slot.Attach(std::move(retained)) || retained));
    auto recovered = slot.Take();
    recovered.reset();
    ASSERT_FALSE((allocation_failure_destructions != 1));
    { ASSERT_EQ((EXIT_SUCCESS), 0); return; }
}
