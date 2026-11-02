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

int main() {
    acpp::detail::BasicXHttpUploadStreamSlot<TestStream> slot;
    size_t first_destructions = 0;
    size_t rejected_destructions = 0;
    if (!slot.Attach(std::make_unique<TestStream>(first_destructions))) {
        return 1;
    }
    auto in_flight = slot.Snapshot();
    // A rejected temporary remains owned by the call expression.
    const bool attached_again = slot.Attach(
        std::make_unique<TestStream>(rejected_destructions));
    if (!in_flight || attached_again || rejected_destructions != 1) {
        return 2;
    }

    auto detached = slot.Take();
    if (!slot.Empty() || !detached || first_destructions != 0) {
        return 3;
    }
    detached->Close();
    detached.reset();
    if (first_destructions != 0 || in_flight->IsOpen()) {
        return 4;
    }
    in_flight.reset();
    if (first_destructions != 1) {
        return 5;
    }
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
    if (!allocation_failed || !retained || !slot.Empty() ||
        allocation_failure_destructions != 0) return 6;
    if (!slot.Attach(std::move(retained)) || retained) return 7;
    auto recovered = slot.Take();
    recovered.reset();
    if (allocation_failure_destructions != 1) return 8;
    return EXIT_SUCCESS;
}
