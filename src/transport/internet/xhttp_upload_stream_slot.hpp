#pragma once

#include "acppnode/transport/async_stream.hpp"

#include <memory>
#include <utility>

namespace acpp::detail {

// Worker-local single-upload owner. Readers take a shared snapshot across
// co_await so Close can cancel and detach the stream without destroying an
// object that still has an asynchronous member function in flight.
template <typename Stream>
class BasicXHttpUploadStreamSlot final {
public:
    [[nodiscard]] bool Attach(std::unique_ptr<Stream> stream) {
        if (!stream || current_) {
            return false;
        }
        current_ = std::shared_ptr<Stream>(std::move(stream));
        return true;
    }

    [[nodiscard]] std::shared_ptr<Stream> Snapshot() const noexcept {
        return current_;
    }

    [[nodiscard]] bool ReleaseIfCurrent(
        const std::shared_ptr<Stream>& expected) noexcept {
        if (current_ != expected) {
            return false;
        }
        current_.reset();
        return true;
    }

    [[nodiscard]] std::shared_ptr<Stream> Take() noexcept {
        return std::exchange(current_, {});
    }

    [[nodiscard]] bool Empty() const noexcept { return !current_; }

private:
    std::shared_ptr<Stream> current_;
};

using XHttpUploadStreamSlot = BasicXHttpUploadStreamSlot<AsyncStream>;

}  // namespace acpp::detail
