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
            if (buf::HasData(pending_)) {
                const size_t n = pending_.ConsumePrefixTo(
                    std::span<uint8_t>(data + done, len - done));
                done += n;
                if (n > 0) {
                    continue;
                }
            }

            buf::MultiBuffer mb = co_await src_.ReadMultiBuffer();
            if (!buf::HasData(mb)) {
                co_return done == 0 && eof_ok_at_start ? false : done == len;
            }
            AppendToPending(std::move(mb));
        }
        co_return true;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (buf::HasData(pending_)) {
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
            pending_.push_back(mb.ReleaseSlot(buffer));
        }
        mb.clear();
    }
};

inline net::awaitable<void> WriteVlessBytes(
    transport::MultiBufferWriter& writer,
    std::span<const uint8_t> data) {
    net::const_buffer buffer{data.data(), data.size()};
    co_await writer.WriteBuffers(std::span<const net::const_buffer>{&buffer, 1});
}

}  // namespace acpp::vless
