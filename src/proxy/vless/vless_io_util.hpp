#pragma once

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
            buf::Buffer* head = PendingHead();
            if (head) {
                const size_t n = std::min(
                    len - done,
                    static_cast<size_t>(head->Len()));
                std::memcpy(data + done, head->Bytes().data(), n);
                head->Advance(static_cast<uint32_t>(n));
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
        CompactPending();
        if (!pending_.empty()) {
            co_return std::move(pending_);
        }
        co_return co_await src_.ReadMultiBuffer();
    }

private:
    transport::MultiBufferReader& src_;
    buf::MultiBuffer pending_;

    void AppendToPending(buf::MultiBuffer mb) {
        for (buf::Buffer*& buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            pending_.push_back(buffer);
            buffer = nullptr;
        }
        mb.clear();
    }

    buf::Buffer* PendingHead() noexcept {
        CompactPending();
        if (pending_.empty()) {
            return nullptr;
        }
        return *pending_.begin();
    }

    void CompactPending() {
        size_t drained = 0;
        for (buf::Buffer* buffer : pending_) {
            if (buffer && !buffer->IsEmpty()) {
                break;
            }
            ++drained;
        }
        if (drained > 0) {
            pending_.drop_front(drained);
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
