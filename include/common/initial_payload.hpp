#pragma once

#include "common/buf/multi_buffer.hpp"

#include <utility>

// The upstream bytes a protocol already decoded before dispatch. They cross
// Dispatch by value exactly once and become the relay's first upload batch;
// the owned buffers are transferred, never copied or staged inline.
class InitialPayload {
public:
    InitialPayload() noexcept = default;
    explicit InitialPayload(buf::MultiBuffer data) noexcept : data_(std::move(data)) {
        data_.ReleaseIfIdle();
    }

    InitialPayload(const InitialPayload&) = delete;
    InitialPayload& operator=(const InitialPayload&) = delete;
    InitialPayload(InitialPayload&&) noexcept = default;
    InitialPayload& operator=(InitialPayload&&) noexcept = default;

    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }

    [[nodiscard]] buf::MultiBuffer MoveToMultiBuffer() && noexcept { return std::move(data_); }

private:
    buf::MultiBuffer data_;
};
