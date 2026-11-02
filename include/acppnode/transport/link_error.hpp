#pragma once

#include "acppnode/common/error.hpp"

#include <exception>

namespace acpp::transport {

// Logical I/O failures retain their application code across reader/writer
// boundaries. They are not fabricated operating-system socket errors.
class LinkError final : public std::exception {
public:
    explicit LinkError(ErrorCode code) noexcept : code_(code) {}
    [[nodiscard]] ErrorCode code() const noexcept { return code_; }
    const char* what() const noexcept override { return ErrorCodeToString(code_).data(); }

private:
    ErrorCode code_;
};

}  // namespace acpp::transport
