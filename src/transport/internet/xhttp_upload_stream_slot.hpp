#pragma once

#include "transport/async_stream.hpp"
#include "common/allocator.hpp"

#include <memory>
#include <utility>

namespace detail {

// Worker-local single-upload owner. Readers take a shared snapshot across
// co_await so Close can cancel and detach the stream without destroying an
// object that still has an asynchronous member function in flight.
template <typename Stream>
class BasicXHttpUploadStreamSlot final {
public:
    [[nodiscard]] bool Attach(std::unique_ptr<Stream>&& stream) {
        if (!stream || current_) {
            return false;
        }
        // Commit the unique owner only after the PMR control block exists.
        struct DeleteAfterCommit {
            bool committed = false;
            void operator()(Stream* value) const noexcept {
                if (committed) delete value;
            }
        };
        std::shared_ptr<Stream> shared(stream.get(), DeleteAfterCommit{},
                                      memory::ThreadLocalAllocator<Stream>{});
        std::get_deleter<DeleteAfterCommit>(shared)->committed = true;
        (void)stream.release();
        current_ = std::move(shared);
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

}  // namespace detail
