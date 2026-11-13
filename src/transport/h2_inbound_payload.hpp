#pragma once

#include "transport/h2_frame.hpp"
namespace transport {

// 两端只提供帧队列与会话预算操作；codec 分派、Hunk 解码和读取语义只有此一份。
struct H2InboundPayload final {
    H2PayloadCodec codec;
    GrpcHunkDecoder decoder;

    template <class Source>
    bool Ready(Source& source) noexcept {
        return codec == H2PayloadCodec::RawData
            ? source.RawReady() : !decoder.Payload().empty();
    }

    template <class Source>
    net::awaitable<bool> Ensure(Source& source) {
        if (codec == H2PayloadCodec::RawData)
            co_return co_await source.WaitForDataFrame();
        while (decoder.Payload().empty()) {
            if (!co_await source.WaitForDataFrame()) {
                if (!decoder.AtMessageBoundary()) {
                    source.HunkFailure();
                    throw IoSystemError(io_error::connection_reset, "truncated gRPC message");
                }
                co_return false;
            }
            const auto bytes = source.HunkInput();
            const auto consumed = decoder.Feed(bytes);
            if (!consumed) {
                source.HunkFailure();
                throw IoSystemError(io_error::connection_reset, consumed.error().data());
            }
            source.ConsumeHunkInput(bytes.size(), *consumed);
        }
        co_return true;
    }

    template <class Source>
    size_t Consume(Source& source, net::mutable_buffer buffer) noexcept {
        if (codec == H2PayloadCodec::RawData) return source.ConsumeRaw(buffer);
        const auto bytes = decoder.Payload();
        const size_t size = std::min(buffer.size(), bytes.size());
        std::memcpy(buffer.data(), bytes.data(), size);
        decoder.Consume(size);
        if (decoder.Payload().empty()) source.ReleaseHunkStorage();
        return size;
    }

    template <class Source>
    net::awaitable<size_t> Read(Source& source, net::mutable_buffer buffer) {
        if (buffer.size() == 0 || (!Ready(source) && !co_await Ensure(source))) co_return 0;
        co_return Consume(source, buffer);
    }

    template <class Source>
    net::awaitable<common::MultiBuffer> ReadMultiBuffer(Source& source) {
        if (!Ready(source) && !co_await Ensure(source)) co_return common::MultiBuffer{};
        if (codec == H2PayloadCodec::RawData) {
            co_return source.ConsumeRawMultiBuffer();
        }
        common::BufferGuard buffer{common::Buffer::New()};
        if (!buffer) throw std::bad_alloc();
        const size_t size = Consume(source,
            net::buffer(buffer->Tail().data(), buffer->Available()));
        if (size == 0) co_return common::MultiBuffer{};
        buffer->Produce(size);
        co_return common::MultiBuffer{std::move(buffer)};
    }
};

}  // namespace transport
