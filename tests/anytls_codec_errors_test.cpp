#include "anytls_codec.hpp"
#include "padding.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link_error.hpp"

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace {
using namespace acpp;
std::array<void*, 128> allocations{};
size_t live = 0;
bool tracking = false;
static_assert(alignof(buf::Buffer) <= alignof(std::max_align_t));
}
void* operator new(std::size_t size) {
    if (auto* result = std::malloc(size ? size : 1)) {
        if (tracking && size == sizeof(buf::Buffer)) {
            if (live == allocations.size()) std::abort();
            allocations[live++] = result;
        }
        return result;
    }
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept {
    for (size_t i = 0; i < live; ++i) {
        if (allocations[i] == value) { allocations[i] = allocations[--live]; break; }
    }
    std::free(value);
}
void operator delete(void* value, std::size_t) noexcept { ::operator delete(value); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void operator delete(void* value, const std::nothrow_t&) noexcept { ::operator delete(value); }

namespace {
enum class Fault { None, Memory, Link, Cancelled, Timeout, Reset, Unexpected, NonStandard };
constexpr std::array names{"none", "memory", "link", "cancelled", "timeout", "reset", "unexpected", "non-standard"};

[[noreturn]] void Raise(Fault fault) {
    switch (fault) {
        case Fault::Memory: throw std::bad_alloc();
        case Fault::Link: throw transport::LinkError(ErrorCode::BLOCKED);
        case Fault::Cancelled: throw IoSystemError(io_error::operation_aborted);
        case Fault::Timeout: throw IoSystemError(io_error::timed_out);
        case Fault::Reset: throw IoSystemError(io_error::connection_reset);
        case Fault::Unexpected: throw std::runtime_error("codec-test-original-exception");
        case Fault::NonStandard: throw 42;
        default: std::abort();
    }
}

class Stream final : public AsyncStream {
public:
    Fault fault = Fault::None;
    size_t threshold = 0;
    size_t transferred = 0;
    size_t failures = 0;
    bool closed = false;
    net::awaitable<void> Fail() {
        if (threshold != 0) co_await net::post(net::use_awaitable);
        ++failures;
        Raise(fault);
    }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (fault != Fault::None && transferred >= threshold) co_await Fail();
        const size_t count = fault == Fault::None ? buffer.size() : std::min(buffer.size(), threshold - transferred);
        std::memset(buffer.data(), 0, count);
        transferred += count;
        co_return count;
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (fault != Fault::None) {
            const size_t count = std::min(buffer.size(), threshold - std::min(threshold, transferred));
            transferred += count;
            if (count < buffer.size()) co_await Fail();
        } else transferred += buffer.size();
        co_return buffer.size();
    }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override { co_return buf::MultiBuffer{}; }
    void ShutdownWrite() override {}
    void Cancel() noexcept override { NotifyCancellation(); }
    void Close() override { closed = true; }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return !closed; }
};

buf::MultiBuffer Payload(size_t count) {
    buf::MultiBuffer result;
    for (size_t i = 0; i < count; ++i) {
        buf::BufferGuard block{buf::Buffer::New()};
        if (!block) throw std::bad_alloc();
        block->Tail()[0] = uint8_t(i);
        block->Produce(1);
        result.push_back(std::move(block));
    }
    return result;
}

template<class T> ErrorCode Result(const std::expected<T, ErrorCode>& value) {
    return value ? ErrorCode::OK : value.error();
}

net::awaitable<ErrorCode> Invoke(Stream& stream, int operation) {
    const anytls::PaddingScheme no_padding;
    const auto padding = *anytls::ParsePaddingScheme("stop=2\n1=64-65\n");
    const std::array<uint8_t, 9> bytes{1, 2, 3, 4, 5, 6, 7, 8, 9};
    std::array<net::const_buffer, 9> buffers;
    for (size_t i = 0; i < buffers.size(); ++i) buffers[i] = net::buffer(bytes.data() + i, 1);
    switch (operation) {
        case 0: co_return Result(co_await anytls::ReadFrameHeader(stream));
        case 1: co_return Result(co_await anytls::ReadFrameText(stream, 19));
        case 2: co_return Result(co_await anytls::DiscardFramePayload(stream, 9000));
        case 3: co_return Result(co_await anytls::ReadFramePayload(stream, 9000));
        case 4: co_return Result(co_await anytls::WriteAll(stream, bytes));
        case 5: co_return Result(co_await anytls::WriteFrame(stream, 2, 1, bytes));
        case 6: {
            auto body = Payload(1);
            co_return Result(co_await anytls::WriteFrameBody(stream, 2, 1, **body.begin()));
        }
        case 7: co_return Result(co_await anytls::WriteMultiBufferAsFrameBatch(stream, 2, 1, Payload(1)));
        case 8: co_return Result(co_await anytls::WriteMultiBufferAsFrameBatch(stream, 2, 1, Payload(9)));
        case 9: co_return Result(co_await anytls::WriteMultiBufferAsFramesWithPadding(stream, padding, 1, 2, 1, Payload(9)));
        case 10: co_return Result(co_await anytls::WriteBuffersAsFramesWithPadding(stream, no_padding, 0, 2, 1, std::span(buffers).first(1)));
        case 11: co_return Result(co_await anytls::WriteBuffersAsFramesWithPadding(stream, no_padding, 0, 2, 1, buffers));
        case 12: co_return Result(co_await anytls::WriteBuffersAsFramesWithPadding(stream, padding, 1, 2, 1, buffers));
        case 13: co_return Result(co_await anytls::WritePacketWithPadding(stream, padding, 1, memory::ByteVector(bytes.begin(), bytes.end())));
        case 14: co_return Result(co_await anytls::WritePacketWithPadding(stream, no_padding, 0, memory::ByteVector(bytes.begin(), bytes.end())));
        case 16: {
            const auto large = *anytls::ParsePaddingScheme("stop=2\n1=65535-65535,65535-65535\n");
            co_return Result(co_await anytls::WritePacketWithPadding(stream, large, 1,
                memory::ByteVector(bytes.begin(), bytes.end())));
        }
        case 17: {
            const auto split = *anytls::ParsePaddingScheme("stop=2\n1=1-1,7-7,8-8\n");
            co_return Result(co_await anytls::WritePacketWithPadding(stream, split, 1,
                memory::ByteVector(bytes.begin(), bytes.end())));
        }
        default: co_return Result(co_await anytls::WriteMultiBufferAsFramesWithPadding(stream, no_padding, 0, 2, 1, Payload(9)));
    }
}

bool RunDeferredBatch() {
    net::io_context io;
    Stream stream;
    if (live != 0) std::abort();
    tracking = true;
    auto pending = anytls::WriteMultiBufferAsFrameBatch(stream, 2, 1, Payload(1));
    const bool idle_before_await = stream.transferred == 0;
    bool returned = false;
    ErrorCode code = ErrorCode::INTERNAL;
    net::co_spawn(io, std::move(pending), [&](std::exception_ptr error, std::expected<void, ErrorCode> result) {
        returned = error == nullptr;
        code = Result(result);
    });
    const bool idle_before_run = stream.transferred == 0;
    io.run();
    const bool passed = idle_before_await && idle_before_run && returned &&
        code == ErrorCode::OK && stream.transferred == anytls::kFrameHeaderSize + 1 && live == 0;
    tracking = false;
    if (!passed) std::printf("deferred batch: FAIL (idle=%d/%d returned=%s code=%s transferred=%zu live=%zu)\n",
        idle_before_await, idle_before_run, returned ? "true" : "false",
        ErrorCodeToString(code).data(), stream.transferred, live);
    return passed;
}

bool Run(int operation, Fault fault, size_t threshold) {
    net::io_context io;
    Stream stream;
    stream.fault = fault;
    stream.threshold = threshold;
    if (live != 0) std::abort();
    tracking = true;
    bool returned = false;
    ErrorCode code = ErrorCode::INTERNAL;
    Fault observed = Fault::None;
    net::co_spawn(io, Invoke(stream, operation), [&](std::exception_ptr error, ErrorCode result) {
        returned = true;
        code = result;
        if (!error) return;
        try { std::rethrow_exception(error); }
        catch (const std::bad_alloc&) { observed = Fault::Memory; }
        catch (const transport::LinkError& e) { if (e.code() == ErrorCode::BLOCKED) observed = Fault::Link; }
        catch (const std::runtime_error& e) {
            if (std::string_view(e.what()) == "codec-test-original-exception") observed = Fault::Unexpected;
        }
        catch (int value) { if (value == 42) observed = Fault::NonStandard; }
        catch (...) {}
    });
    io.run();
    const ErrorCode expected = fault == Fault::Cancelled ? ErrorCode::CANCELLED
        : fault == Fault::Timeout ? ErrorCode::TIMEOUT : fault == Fault::Reset ? ErrorCode::SOCKET_CLOSED : ErrorCode::OK;
    const bool exceptional = fault == Fault::Memory || fault == Fault::Link || fault == Fault::Unexpected || fault == Fault::NonStandard;
    bool passed = returned && !stream.closed && (exceptional ? observed == fault : observed == Fault::None && code == expected);
    passed &= fault == Fault::None || (stream.failures == 1 && stream.transferred == threshold);
    passed &= live == 0;
    tracking = false;
    if (!passed) std::printf("op=%d fault=%s after=%zu returned=%s observed=%s live=%zu: FAIL\n",
        operation, names[int(fault)], threshold, ErrorCodeToString(code).data(), names[int(observed)], live);
    return passed;
}
}

int main() {
    size_t passed = 0, total = 0;
    passed += RunDeferredBatch(); ++total;
    for (int operation = 0; operation < 18; ++operation) {
        passed += Run(operation, Fault::None, 0); ++total;
        for (int fault = 1; fault < 8; ++fault) {
            for (size_t threshold : {size_t(0), size_t(3)}) {
                passed += Run(operation, Fault(fault), threshold); ++total;
            }
        }
    }
    for (int fault = 1; fault < 8; ++fault) {
        passed += Run(16, Fault(fault), 65536); ++total;
    }
    std::printf("codec cases=%zu passed=%zu failed=%zu released=%d\n", total, passed, total - passed, live == 0);
    return passed == total ? 0 : 1;
}
