#pragma once

#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"
#include "transport/link.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>

namespace vless {

class VlessBufferedReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return src_.ReadEofAction(); }
    [[nodiscard]] bool EnableRawRead() noexcept override { return src_.EnableRawRead(); }

    explicit VlessBufferedReader(transport::MultiBufferReader& src) noexcept
        : src_(src) {}

    net::awaitable<bool> ReadExact(uint8_t* data,
                                   size_t len,
                                   bool eof_ok_at_start = false,
                                   size_t* progress = nullptr) {
        size_t local_done = 0;
        size_t& done = progress ? *progress : local_done;
        while (done < len) {
            if (pending_.byte_size() != 0) {
                const size_t n = pending_.ConsumePrefixTo(
                    std::span<uint8_t>(data + done, len - done));
                if (pending_.empty()) {
                    pending_.ReleaseIfIdle();
                }
                done += n;
                if (n > 0) {
                    continue;
                }
            }

            buf::MultiBuffer mb = co_await src_.ReadMultiBuffer();
            const bool received = mb.byte_size() != 0;
            if (received) mb.MoveTo(pending_);
            // Retain concurrently received bytes before observing cancellation.
            if ((co_await net::this_coro::cancellation_state).cancelled() !=
                net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            if (!received) {
                co_return done == 0 && eof_ok_at_start ? false : done == len;
            }
        }
        co_return true;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (pending_.byte_size() != 0) {
            co_return std::move(pending_);
        }
        co_return co_await src_.ReadMultiBuffer();
    }

private:
    transport::MultiBufferReader& src_;
    buf::MultiBuffer pending_;
};

inline net::awaitable<void> WriteVlessBytes(
    transport::MultiBufferWriter& writer,
    std::span<const uint8_t> data) {
    net::const_buffer buffer{data.data(), data.size()};
    co_await writer.WriteBuffers(std::span<const net::const_buffer>{&buffer, 1});
}

}  // namespace vless
