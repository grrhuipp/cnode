#include "vless_encryption_io.hpp"

#include "acppnode/common/error.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <future>
#include <iostream>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace acpp;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

std::vector<uint8_t> Flatten(const buf::MultiBuffer& payload) {
    std::vector<uint8_t> out;
    out.reserve(payload.byte_size());
    for (const buf::Buffer* buffer : payload) {
        if (buffer && !buffer->IsEmpty()) {
            const auto bytes = buffer->Bytes();
            out.insert(out.end(), bytes.begin(), bytes.end());
        }
    }
    return out;
}

class CaptureWriter final : public transport::MultiBufferWriter {
public:
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override {
        for (const buf::Buffer* buffer : payload) {
            if (buffer && !buffer->IsEmpty()) {
                const auto data = buffer->Bytes();
                bytes.insert(bytes.end(), data.begin(), data.end());
            }
        }
        co_return;
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        for (const auto& buffer : buffers) {
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            bytes.insert(bytes.end(), data, data + buffer.size());
        }
        co_return;
    }

    std::vector<uint8_t> bytes;
};

class InterruptedReader final : public transport::MultiBufferReader {
public:
    InterruptedReader(const std::vector<uint8_t>& bytes,
                      std::vector<size_t> cutpoints,
                      net::cancellation_signal& signal,
                      bool empty_on_cancel)
        : bytes_(bytes), cutpoints_(std::move(cutpoints)), signal_(signal),
          empty_on_cancel_(empty_on_cancel) {}

    transport::CancellationSource& Cancellation() noexcept override {
        return cancellation_;
    }

    size_t Interruptions() const noexcept { return cutpoint_index_; }
    size_t Offset() const noexcept { return offset_; }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (cutpoint_index_ < cutpoints_.size() &&
            offset_ == cutpoints_[cutpoint_index_]) {
            ++cutpoint_index_;
            const auto executor = co_await net::this_coro::executor;
            net::steady_timer pending(executor);
            pending.expires_at(net::steady_timer::time_point::max());
            // The post runs only after async_wait has installed its cancellation
            // handler. No elapsed-time deadline controls this interruption.
            net::post(executor, [this] {
                signal_.emit(net::cancellation_type::terminal);
            });
            IoErrorCode error;
            co_await pending.async_wait(
                net::redirect_error(net::use_awaitable, error));
            Check(error == io_error::operation_aborted,
                  "controlled read was not cancelled by Asio");
            if (empty_on_cancel_) {
                // TcpStream may report cancellation as an empty MultiBuffer.
                co_return buf::MultiBuffer{};
            }
            throw IoSystemError(error);
        }

        if (offset_ == bytes_.size()) {
            co_return buf::MultiBuffer{};
        }
        const size_t end = cutpoint_index_ < cutpoints_.size()
            ? cutpoints_[cutpoint_index_] : bytes_.size();
        Check(end > offset_ && end <= bytes_.size(),
              "invalid encrypted stream interruption boundary");
        buf::MultiBuffer out;
        Check(buf::AppendSpanToMultiBuffer(
                  std::span<const uint8_t>(bytes_.data() + offset_, end - offset_),
                  out),
              "failed to allocate encrypted input fragment");
        offset_ = end;
        co_return out;
    }

private:
    transport::CancellationSource cancellation_;
    const std::vector<uint8_t>& bytes_;
    std::vector<size_t> cutpoints_;
    net::cancellation_signal& signal_;
    bool empty_on_cancel_;
    size_t offset_ = 0;
    size_t cutpoint_index_ = 0;
};

std::optional<vless::VlessEncryptionHeaderXor> MakeHeaderXor(
    bool enabled,
    std::span<const uint8_t> key,
    const std::array<uint8_t, vless::kVlessEncryptionCtrIvSize>& context) {
    if (!enabled) {
        return std::nullopt;
    }
    auto result = vless::VlessEncryptionHeaderXor::Create(key, context);
    Check(result.has_value(), "failed to create encryption header XOR state");
    return result;
}

void RunResumeCase(vless::VlessEncryptionAeadCipher cipher,
                   bool header_xor,
                   bool empty_on_cancel,
                   bool lazy_context) {
    net::io_context io;
    net::cancellation_signal signal;
    const auto exercise = [&]() -> net::awaitable<void> {
        std::array<uint8_t, vless::kVlessEncryptionCtrIvSize> context{};
        vless::VlessEncryptionUnitedKey key;
        for (size_t i = 0; i < context.size(); ++i) {
            context[i] = static_cast<uint8_t>(0x31 + i * 7);
        }
        for (size_t i = 0; i < key.bytes.size(); ++i) {
            key.bytes[i] = static_cast<uint8_t>(0xa7 ^ (i * 13));
        }
        const auto create_aead = [&] {
            auto aead = vless::VlessEncryptionAead::Create(context, key.bytes, cipher);
            Check(aead.has_value(), "failed to create VLESS encryption AEAD");
            return std::move(*aead);
        };

        std::array<std::vector<uint8_t>, 4> plaintext;
        constexpr std::array<size_t, 4> sizes{37, 4097, 73, 129};
        CaptureWriter capture;
        if (lazy_context) {
            capture.bytes.insert(capture.bytes.end(), context.begin(), context.end());
        }
        std::optional<vless::VlessEncryptionWriter> writer;
        writer.emplace(capture, create_aead(), key,
                       MakeHeaderXor(header_xor, key.bytes, context));
        std::array<size_t, 5> boundaries{};
        for (size_t record = 0; record < plaintext.size(); ++record) {
            auto& data = plaintext[record];
            data.resize(sizes[record]);
            for (size_t i = 0; i < data.size(); ++i) {
                data[i] = static_cast<uint8_t>(i * 29 + record * 53);
            }
            boundaries[record] = capture.bytes.size();
            const net::const_buffer buffer(data.data(), data.size());
            co_await writer->WriteBuffers(
                std::span<const net::const_buffer>(&buffer, 1));
            Check(capture.bytes.size() - boundaries[record] ==
                      vless::kVlessEncryptionRecordHeaderSize + data.size() +
                          vless::kVlessEncryptionTagSize,
                  "writer did not produce one encrypted record per plaintext");
        }
        boundaries.back() = capture.bytes.size();

        std::vector<size_t> cutpoints;
        if (lazy_context) {
            cutpoints = {0, 1, context.size() - 1};
        }
        const size_t second = boundaries[1];
        const size_t body = second + vless::kVlessEncryptionRecordHeaderSize;
        // Record zero succeeds first. Repeated cancellation then covers an
        // untouched header, partial header, complete header, partial body and
        // partial authentication tag, all on the same reader and record.
        cutpoints.insert(cutpoints.end(), {
            second, second, second + 1, body - 1, body,
            body + 1, body + plaintext[1].size() / 2,
            boundaries[2] - 1,
        });
        InterruptedReader source(capture.bytes, cutpoints, signal, empty_on_cancel);
        std::optional<vless::VlessEncryptionReader> reader;
        if (lazy_context) {
            reader.emplace(source,
                           vless::VlessEncryptionDeferredRead{
                               .cipher = cipher,
                               .header_xor = header_xor,
                           },
                           key, std::nullopt);
        } else {
            reader.emplace(source, create_aead(), key,
                           MakeHeaderXor(header_xor, key.bytes, context));
        }

        size_t decoded = 0;
        size_t cancelled = 0;
        while (decoded < plaintext.size()) {
            bool interrupted = false;
            try {
                auto output = co_await reader->ReadMultiBuffer();
                Check(Flatten(output) == plaintext[decoded],
                      "resumed encryption reader lost or changed plaintext");
                ++decoded;
            } catch (const IoSystemError& error) {
                if (error.code() != io_error::operation_aborted) {
                    throw;
                }
                interrupted = true;
            }
            if (interrupted) {
                Check(cancelled < cutpoints.size() &&
                          source.Interruptions() == cancelled + 1 &&
                          source.Offset() == cutpoints[cancelled],
                      "cancellation did not occur at the requested byte boundary");
                Check(decoded == (source.Offset() < boundaries[0] ? 0u : 1u),
                      "cancellation occurred before the preceding record decoded");
                const auto state = co_await net::this_coro::cancellation_state;
                Check(state.cancelled() != net::cancellation_type::none,
                      "read interruption lost its coroutine cancellation state");
                ++cancelled;
                co_await net::this_coro::reset_cancellation_state();
            }
        }
        Check(cancelled == cutpoints.size(),
              "encrypted reader did not exercise every cancellation cutpoint");
        Check(source.Offset() == capture.bytes.size(),
              "encrypted reader left wire bytes unconsumed");
        Check((co_await reader->ReadMultiBuffer()).byte_size() == 0,
              "real encrypted stream EOF returned plaintext");
        Check((co_await reader->ReadMultiBuffer()).byte_size() == 0,
              "repeated encrypted stream EOF returned plaintext");
    };
    auto future = net::co_spawn(io, exercise(),
        net::bind_cancellation_slot(signal.slot(), net::use_future));
    io.run();
    try {
        future.get();
    } catch (const std::exception& error) {
        std::cerr << "cipher=" << static_cast<int>(cipher)
                  << " xor=" << header_xor
                  << " empty-on-cancel=" << empty_on_cancel
                  << " lazy-context=" << lazy_context << '\n';
        Fail(error.what());
    }
}

}  // namespace

int main() {
    for (const auto cipher : {vless::VlessEncryptionAeadCipher::Aes256Gcm,
                              vless::VlessEncryptionAeadCipher::Chacha20Poly1305}) {
        for (const bool header_xor : {false, true}) {
            for (const bool empty_on_cancel : {false, true}) {
                for (const bool lazy_context : {false, true}) {
                    RunResumeCase(cipher, header_xor, empty_on_cancel, lazy_context);
                }
            }
        }
    }
    return 0;
}
