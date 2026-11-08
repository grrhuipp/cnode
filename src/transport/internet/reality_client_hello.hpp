#pragma once

#include "common/allocator.hpp"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>


// RFC 8446 sections 4.1.2 and 5.1: handshake messages may span records.
// Retain the original wire image for fallback/replay, but authenticate the
// concatenated handshake, never record headers. Append only received bytes;
// neither record nor handshake lengths cause speculative allocation.
class RealityClientHelloReader {
public:
    enum class Status { Reading, Complete, Invalid };
    // Maximum ClientHello body from its uint8/uint16 vector length fields.
    static constexpr size_t kMaxHelloSize = 4 + 2 + 32 + 1 + 32 + 2 + 65534 + 1 + 255 + 2 + 65535;

    [[nodiscard]] Status State() const noexcept { return status_; }
    [[nodiscard]] size_t ReadSize() const noexcept {
        if (status_ != Status::Reading) return 0;
        return header_size_ < header_.size()
            ? header_.size() - header_size_
            : std::min<size_t>(remaining_, 1024);
    }
    void Append(std::span<const uint8_t> bytes) {
        if (bytes.empty() || bytes.size() > ReadSize()) {
            status_ = Status::Invalid;
            return;
        }
        wire_.insert(wire_.end(), bytes.begin(), bytes.end());
        if (header_size_ < header_.size()) {
            std::copy(bytes.begin(), bytes.end(), header_.begin() + header_size_);
            header_size_ += bytes.size();
            if ((header_size_ >= 1 && header_[0] != 22) ||
                (header_size_ >= 2 && header_[1] != 3)) {
                status_ = Status::Invalid;
                return;
            }
            if (header_size_ != header_.size()) return;
            remaining_ = (size_t{header_[3]} << 8) | header_[4];
            if (remaining_ == 0 || remaining_ > 16384) {
                status_ = Status::Invalid;
            }
            return;
        }
        remaining_ -= bytes.size();
        if (hello_.size() < 4) {
            const size_t header_bytes = std::min(bytes.size(), 4 - hello_.size());
            hello_.insert(hello_.end(), bytes.begin(), bytes.begin() + header_bytes);
            bytes = bytes.subspan(header_bytes);
            if (hello_[0] != 1) {
                status_ = Status::Invalid;
                return;
            }
            if (hello_.size() == 4) {
                hello_size_ = 4 + (size_t{hello_[1]} << 16) + (size_t{hello_[2]} << 8) + hello_[3];
                if (hello_size_ < 4 + 2 + 32 + 1 + 32 + 2 + 2 + 1 + 1 + 2 || hello_size_ > kMaxHelloSize) {
                    status_ = Status::Invalid;
                    return;
                }
            }
        }
        if (hello_size_) {
            if (bytes.size() + remaining_ > hello_size_ - hello_.size()) {
                status_ = Status::Invalid;
                return;
            }
            hello_.insert(hello_.end(), bytes.begin(), bytes.end());
        }
        if (remaining_ == 0) {
            if (hello_size_ && hello_.size() == hello_size_) status_ = Status::Complete;
            else header_size_ = 0;
        }
    }
    [[nodiscard]] std::span<const uint8_t> Hello() const noexcept { return hello_; }
    [[nodiscard]] memory::ByteVector TakeWire() noexcept { return std::move(wire_); }
private:
    std::array<uint8_t, 5> header_{};
    size_t header_size_ = 0;
    size_t remaining_ = 0;
    size_t hello_size_ = 0;
    Status status_ = Status::Reading;
    memory::ByteVector wire_;
    memory::ByteVector hello_;
};

