#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/transport/link.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>

namespace acpp::vless {

class VlessBufferedReader final : public transport::MultiBufferReader {
public:
    explicit VlessBufferedReader(transport::MultiBufferReader& src) noexcept
        : src_(src) {}

    net::awaitable<bool> ReadExact(uint8_t* data,
                                   size_t len,
                                   bool eof_ok_at_start = false) {
        size_t done = 0;
        while (done < len) {
            if (pending_offset_ < pending_.size()) {
                const size_t n = std::min(
                    len - done,
                    pending_.size() - pending_offset_);
                std::memcpy(data + done, pending_.data() + pending_offset_, n);
                pending_offset_ += n;
                done += n;
                CompactPending();
                continue;
            }

            buf::MultiBuffer mb = co_await src_.ReadMultiBuffer();
            if (mb.empty()) {
                co_return done == 0 && eof_ok_at_start ? false : done == len;
            }
            AppendToPending(std::move(mb));
        }
        co_return true;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (pending_offset_ < pending_.size()) {
            buf::MultiBuffer out;
            if (!buf::AppendSpanToMultiBuffer(
                    std::span<const uint8_t>(
                        pending_.data() + pending_offset_,
                        pending_.size() - pending_offset_),
                    out)) {
                throw IoSystemError(io_error::fault,
                                    "VLESS pending buffer allocation failed");
            }
            pending_.clear();
            pending_offset_ = 0;
            co_return out;
        }
        co_return co_await src_.ReadMultiBuffer();
    }

private:
    transport::MultiBufferReader& src_;
    memory::ByteVector pending_;
    size_t pending_offset_ = 0;

    void AppendToPending(buf::MultiBuffer mb) {
        for (buf::Buffer* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto bytes = buffer->Bytes();
            pending_.insert(pending_.end(), bytes.begin(), bytes.end());
        }
        mb.clear();
    }

    void CompactPending() {
        if (pending_offset_ == 0) {
            return;
        }
        if (pending_offset_ >= pending_.size()) {
            pending_.clear();
            pending_offset_ = 0;
            return;
        }
        if (pending_offset_ >= buf::Buffer::kSize &&
            pending_offset_ >= pending_.size() - pending_offset_) {
            pending_.erase(
                pending_.begin(),
                pending_.begin() + static_cast<std::ptrdiff_t>(pending_offset_));
            pending_offset_ = 0;
        }
    }
};

inline net::awaitable<void> WriteVlessBytes(
    transport::MultiBufferWriter& writer,
    std::span<const uint8_t> data) {
    buf::MultiBuffer mb;
    if (!buf::AppendSpanToMultiBuffer(data, mb)) {
        throw IoSystemError(io_error::fault,
                            "VLESS write buffer allocation failed");
    }
    co_await writer.WriteMultiBuffer(std::move(mb));
}

}  // namespace acpp::vless
