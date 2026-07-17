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
    if (!in_flight || slot.Attach(
            std::make_unique<TestStream>(rejected_destructions)) ||
        rejected_destructions != 1) {
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
    return EXIT_SUCCESS;
}
