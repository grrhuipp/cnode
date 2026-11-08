#include <stdexcept>
#include <gtest/gtest.h>

#include "vless_encryption_crypto.hpp"
#include "vless_encryption_handshake.hpp"
#include "vless_encryption_io.hpp"

#include "common/error.hpp"

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
#include <type_traits>
#include <utility>
#include <vector>

namespace {
static_assert(!std::is_copy_constructible_v<vless::VlessEncryptionTicketRejection>);
static_assert(!std::is_copy_assignable_v<vless::VlessEncryptionTicketRejection>);
static_assert(!std::is_move_constructible_v<vless::VlessEncryptionTicketRejection>);
static_assert(!std::is_move_assignable_v<vless::VlessEncryptionTicketRejection>);
static_assert(!std::is_copy_constructible_v<vless::VlessEncryptionWriter>);
static_assert(!std::is_copy_assignable_v<vless::VlessEncryptionWriter>);
static_assert(!std::is_move_constructible_v<vless::VlessEncryptionWriter>);
static_assert(!std::is_move_assignable_v<vless::VlessEncryptionWriter>);



[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
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
        vless::VlessEncryptionTicketRejection rejection;
        std::optional<vless::VlessEncryptionReader> reader;
        if (lazy_context) {
            reader.emplace(source,
                           vless::VlessEncryptionDeferredRead{
                               .cipher = cipher,
                               .header_xor = header_xor,
                               .ticket_rejection = &rejection,
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
                Check(!rejection.rejected,
                      "cancelled deferred read invalidated a reusable ticket");
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
        reader->RejectDeferredTicket();
        Check(!rejection.rejected,
              "authenticated response or later EOF invalidated the ticket");
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

void RunDeferredRejectionCase(vless::VlessEncryptionAeadCipher cipher,
                              bool header_xor,
                              unsigned boundary) {
    net::io_context io;
    net::cancellation_signal signal;
    const auto exercise = [&]() -> net::awaitable<void> {
        std::array<uint8_t, vless::kVlessEncryptionCtrIvSize> context{};
        vless::VlessEncryptionUnitedKey key;
        auto aead = vless::VlessEncryptionAead::Create(context, key.bytes, cipher);
        Check(aead.has_value(), "failed to create deferred response AEAD");
        CaptureWriter capture;
        capture.bytes.insert(capture.bytes.end(), context.begin(), context.end());
        vless::VlessEncryptionWriter writer(
            capture, std::move(*aead), key,
            MakeHeaderXor(header_xor, key.bytes, context));
        constexpr std::string_view payload = "authenticated-ticket-response";
        const net::const_buffer buffer(payload.data(), payload.size());
        co_await writer.WriteBuffers(std::span<const net::const_buffer>(&buffer, 1));
        switch (boundary) {
            case 0: capture.bytes.clear(); break;
            case 1: capture.bytes.resize(context.size() - 1); break;
            case 2: capture.bytes.resize(context.size()); break;
            case 3: capture.bytes.resize(context.size() + 1); break;
            case 4: capture.bytes.pop_back(); break;
            case 5: capture.bytes.back() ^= 1; break;
            case 6: break;
        }
        InterruptedReader source(capture.bytes, {}, signal, false);
        vless::VlessEncryptionTicketRejection rejection;
        vless::VlessEncryptionReader reader(
            source,
            vless::VlessEncryptionDeferredRead{
                .cipher = cipher,
                .header_xor = header_xor,
                .ticket_rejection = &rejection,
            },
            key, std::nullopt);
        bool failed = false;
        try {
            auto result = co_await reader.ReadMultiBuffer();
            if (boundary == 6) {
                const auto bytes = Flatten(result);
                Check(std::string_view(reinterpret_cast<const char*>(bytes.data()),
                                       bytes.size()) == payload,
                      "deferred authenticated response changed payload");
            } else {
                Check(boundary == 2 && result.empty(),
                      "incomplete deferred response produced plaintext");
            }
        } catch (const IoSystemError& error) {
            Check(error.code() != io_error::operation_aborted,
                  "deferred rejection unexpectedly reported cancellation");
            failed = true;
        }
        Check(failed == (boundary != 2 && boundary != 6),
              "deferred response failure category changed");
        Check(rejection.rejected == (boundary != 6),
              "ticket rejection did not match first-response authentication");
        reader.RejectDeferredTicket();
        Check(rejection.rejected == (boundary != 6),
              "late failure invalidated an authenticated ticket");
    };
    auto future = net::co_spawn(io, exercise(), net::use_future);
    io.run();
    future.get();
}

enum class WriteFault { PartialFailure, SuspendedCancellation, Closed };

class InterruptedWriter final : public transport::MultiBufferWriter {
public:
    InterruptedWriter(WriteFault fault, net::cancellation_signal& signal)
        : fault_(fault), signal_(signal) {}

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override {
        const auto bytes = Flatten(payload);
        const net::const_buffer buffer(bytes.data(), bytes.size());
        co_await WriteBuffers(std::span<const net::const_buffer>(&buffer, 1));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (!armed_) {
            co_await capture.WriteBuffers(buffers);
            co_return;
        }
        armed_ = false;
        if (fault_ == WriteFault::Closed) {
            throw transport::WriteClosed();
        }
        // Publish an incomplete record before reporting an unknown write result.
        const net::const_buffer prefix(
            buffers.front().data(), vless::kVlessEncryptionRecordHeaderSize + 3);
        co_await capture.WriteBuffers(
            std::span<const net::const_buffer>(&prefix, 1));
        if (fault_ == WriteFault::PartialFailure) {
            throw IoSystemError(io_error::connection_refused,
                                "controlled partial encrypted write");
        }
        const auto executor = co_await net::this_coro::executor;
        net::steady_timer pending(executor);
        pending.expires_at(net::steady_timer::time_point::max());
        net::post(executor, [this] {
            signal_.emit(net::cancellation_type::terminal);
        });
        IoErrorCode error;
        co_await pending.async_wait(
            net::redirect_error(net::use_awaitable, error));
        Check(error == io_error::operation_aborted,
              "controlled encrypted write was not cancelled");
        throw IoSystemError(error);
    }

    CaptureWriter capture;

private:
    WriteFault fault_;
    net::cancellation_signal& signal_;
    bool armed_ = true;
};

void RunWriterFailureCase(vless::VlessEncryptionAeadCipher cipher,
                          bool header_xor, WriteFault fault) {
    net::io_context io;
    net::cancellation_signal signal;
    const auto exercise = [&]() -> net::awaitable<void> {
        const std::array<uint8_t, vless::kVlessEncryptionCtrIvSize> context{};
        const vless::VlessEncryptionUnitedKey key;
        auto aead = vless::VlessEncryptionAead::Create(context, key.bytes, cipher);
        Check(aead.has_value(), "failed to create faulting writer AEAD");
        InterruptedWriter destination(fault, signal);
        vless::VlessEncryptionWriter writer(
            destination, std::move(*aead), key,
            MakeHeaderXor(header_xor, key.bytes, context));
        constexpr std::string_view payload = "encrypted-write-lifecycle";
        const net::const_buffer buffer(payload.data(), payload.size());
        bool original_error = false;
        try {
            co_await writer.WriteBuffers(
                std::span<const net::const_buffer>(&buffer, 1));
        } catch (const transport::WriteClosed&) {
            original_error = fault == WriteFault::Closed;
        } catch (const IoSystemError& error) {
            original_error = error.code() ==
                (fault == WriteFault::PartialFailure
                     ? io_error::connection_refused : io_error::operation_aborted);
        }
        Check(original_error, "encrypted write did not preserve its original error");
        co_await net::this_coro::reset_cancellation_state();
        const auto published = destination.capture.bytes;
        bool rejected = false;
        try {
            co_await writer.WriteBuffers(
                std::span<const net::const_buffer>(&buffer, 1));
        } catch (const transport::WriteClosed&) {
            rejected = fault == WriteFault::Closed;
        } catch (const IoSystemError& error) {
            rejected = fault != WriteFault::Closed &&
                       error.code() == io_error::connection_reset;
        }
        Check(destination.capture.bytes == published,
              "terminal encrypted writer published another record");
        Check(rejected, "terminal encrypted writer accepted another write");
    };
    auto future = net::co_spawn(io, exercise(),
        net::bind_cancellation_slot(signal.slot(), net::use_future));
    io.run();
    future.get();
}

void RunWriterShutdownCase(vless::VlessEncryptionAeadCipher cipher,
                           bool header_xor) {
    net::io_context io;
    const auto exercise = [&]() -> net::awaitable<void> {
        const std::array<uint8_t, vless::kVlessEncryptionCtrIvSize> context{};
        const vless::VlessEncryptionUnitedKey key;
        auto aead = vless::VlessEncryptionAead::Create(context, key.bytes, cipher);
        Check(aead.has_value(), "failed to create shutdown writer AEAD");
        CaptureWriter destination;
        vless::VlessEncryptionWriter writer(
            destination, std::move(*aead), key,
            MakeHeaderXor(header_xor, key.bytes, context));
        constexpr std::string_view payload = "before-write-shutdown";
        const net::const_buffer buffer(payload.data(), payload.size());
        co_await writer.WriteBuffers(
            std::span<const net::const_buffer>(&buffer, 1));
        co_await writer.AsyncShutdownWrite();
        co_await writer.AsyncShutdownWrite();
        const auto published = destination.bytes;
        bool rejected = false;
        try {
            co_await writer.WriteBuffers(
                std::span<const net::const_buffer>(&buffer, 1));
        } catch (const transport::WriteClosed&) {
            rejected = true;
        }
        Check(destination.bytes == published,
              "finished encrypted writer published another record");
        Check(rejected, "finished encrypted writer accepted another write");
    };
    auto future = net::co_spawn(io, exercise(), net::use_future);
    io.run();
    future.get();
}

void RunWriterPrecancelCase(vless::VlessEncryptionAeadCipher cipher,
                            bool header_xor) {
    net::io_context io;
    net::cancellation_signal signal;
    const auto exercise = [&]() -> net::awaitable<void> {
        const std::array<uint8_t, vless::kVlessEncryptionCtrIvSize> context{};
        const vless::VlessEncryptionUnitedKey key;
        auto aead = vless::VlessEncryptionAead::Create(context, key.bytes, cipher);
        auto read_aead = vless::VlessEncryptionAead::Create(context, key.bytes, cipher);
        Check(aead.has_value() && read_aead.has_value(),
              "failed to create pre-cancel writer AEAD");
        CaptureWriter destination;
        vless::VlessEncryptionWriter writer(
            destination, std::move(*aead), key,
            MakeHeaderXor(header_xor, key.bytes, context));
        constexpr std::string_view payload = "recoverable-before-record-start";
        const net::const_buffer buffer(payload.data(), payload.size());
        co_await net::this_coro::throw_if_cancelled(false);
        signal.emit(net::cancellation_type::terminal);
        bool cancelled = false;
        try {
            co_await writer.WriteBuffers(
                std::span<const net::const_buffer>(&buffer, 1));
        } catch (const IoSystemError& error) {
            cancelled = error.code() == io_error::operation_aborted;
        }
        Check(destination.bytes.empty(),
              "pre-cancelled encrypted writer published a record");
        Check(cancelled, "pre-cancelled encrypted write did not report cancellation");
        co_await net::this_coro::reset_cancellation_state();
        co_await writer.WriteBuffers(
            std::span<const net::const_buffer>(&buffer, 1));
        InterruptedReader source(destination.bytes, {}, signal, false);
        vless::VlessEncryptionReader reader(
            source, std::move(*read_aead), key,
            MakeHeaderXor(header_xor, key.bytes, context));
        const auto decoded = Flatten(co_await reader.ReadMultiBuffer());
        Check(std::string_view(reinterpret_cast<const char*>(decoded.data()),
                               decoded.size()) == payload,
              "pre-cancelled writer could not resume a consumable stream");
        Check((co_await reader.ReadMultiBuffer()).empty(),
              "pre-cancelled writer emitted extra plaintext");
    };
    auto future = net::co_spawn(io, exercise(),
        net::bind_cancellation_slot(signal.slot(), net::use_future));
    io.run();
    future.get();
}

}  // namespace

TEST(VlessEncryptionIo, Contract) {
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
}

TEST(VlessEncryptionIo, DeferredTicketAuthenticationAndCloseBoundaries) {
    for (const auto cipher : {vless::VlessEncryptionAeadCipher::Aes256Gcm,
                              vless::VlessEncryptionAeadCipher::Chacha20Poly1305}) {
        for (const bool header_xor : {false, true}) {
            for (unsigned boundary = 0; boundary != 7; ++boundary) {
                SCOPED_TRACE(testing::Message() << "cipher=" << static_cast<int>(cipher)
                    << " xor=" << header_xor << " boundary=" << boundary);
                RunDeferredRejectionCase(cipher, header_xor, boundary);
            }
        }
    }
}

TEST(VlessEncryptionIo, WriterPartialFailureIsTerminal) {
    for (const auto cipher : {vless::VlessEncryptionAeadCipher::Aes256Gcm,
                              vless::VlessEncryptionAeadCipher::Chacha20Poly1305}) {
        for (const bool header_xor : {false, true}) {
            RunWriterFailureCase(cipher, header_xor, WriteFault::PartialFailure);
        }
    }
}

TEST(VlessEncryptionIo, WriterSuspendedCancellationIsTerminal) {
    for (const auto cipher : {vless::VlessEncryptionAeadCipher::Aes256Gcm,
                              vless::VlessEncryptionAeadCipher::Chacha20Poly1305}) {
        for (const bool header_xor : {false, true}) {
            RunWriterFailureCase(cipher, header_xor, WriteFault::SuspendedCancellation);
        }
    }
}

TEST(VlessEncryptionIo, WriterClosedRejectionIsTerminal) {
    RunWriterFailureCase(vless::VlessEncryptionAeadCipher::Aes256Gcm,
                         true, WriteFault::Closed);
}

TEST(VlessEncryptionIo, WriterShutdownIsTerminal) {
    for (const auto cipher : {vless::VlessEncryptionAeadCipher::Aes256Gcm,
                              vless::VlessEncryptionAeadCipher::Chacha20Poly1305}) {
        for (const bool header_xor : {false, true}) {
            RunWriterShutdownCase(cipher, header_xor);
        }
    }
}

TEST(VlessEncryptionIo, WriterPrecancelDoesNotAdvanceRecord) {
    for (const auto cipher : {vless::VlessEncryptionAeadCipher::Aes256Gcm,
                              vless::VlessEncryptionAeadCipher::Chacha20Poly1305}) {
        for (const bool header_xor : {false, true}) {
            RunWriterPrecancelCase(cipher, header_xor);
        }
    }
}

TEST(VlessEncryptionCrypto, MlKemSeedPreservesBothHalves) {
    vless::VlessSecretBytes<vless::kVlessMlKem768SeedSize> seed;
    for (size_t i = 0; i < seed.bytes.size(); ++i) {
        seed.bytes[i] = static_cast<uint8_t>(i);
    }
    auto key = vless::CreateVlessMlKem768PrivateKeyFromSeed(seed.bytes);
    ASSERT_TRUE(key);
    EXPECT_EQ(EVP_PKEY_id(key.get()), EVP_PKEY_ML_KEM_768);
    vless::VlessSecretBytes<vless::kVlessMlKem768SeedSize> exported;
    size_t exported_size = exported.bytes.size();
    ASSERT_EQ(EVP_PKEY_get_private_seed(
                  key.get(), exported.bytes.data(), &exported_size), 1);
    EXPECT_EQ(exported_size, 64u);
    EXPECT_EQ(exported.bytes, seed.bytes);

    const auto public_key = vless::DeriveVlessMlKem768PublicKey(key.get());
    ASSERT_TRUE(public_key);
    auto changed_seed = seed;
    changed_seed.bytes.back() ^= 1;  // z only affects implicit rejection.
    auto changed_z = vless::CreateVlessMlKem768PrivateKeyFromSeed(changed_seed.bytes);
    ASSERT_TRUE(changed_z);
    EXPECT_EQ(vless::DeriveVlessMlKem768PublicKey(changed_z.get()), public_key);
    changed_seed = seed;
    changed_seed.bytes.front() ^= 1;  // d determines the public key.
    auto changed_d = vless::CreateVlessMlKem768PrivateKeyFromSeed(changed_seed.bytes);
    ASSERT_TRUE(changed_d);
    EXPECT_NE(vless::DeriveVlessMlKem768PublicKey(changed_d.get()), public_key);

    std::array<uint8_t, vless::kVlessMlKem768CiphertextSize> invalid{};
    vless::VlessSecretBytes<vless::kVlessMlKem768SharedSecretSize> rejected, repeated, other_z;
    ASSERT_TRUE(vless::DecapsulateVlessMlKem768(key.get(), invalid, rejected.bytes));
    ASSERT_TRUE(vless::DecapsulateVlessMlKem768(key.get(), invalid, repeated.bytes));
    ASSERT_TRUE(vless::DecapsulateVlessMlKem768(changed_z.get(), invalid, other_z.bytes));
    EXPECT_EQ(rejected.bytes, repeated.bytes);
    EXPECT_NE(rejected.bytes, other_z.bytes);
}

TEST(VlessEncryptionCrypto, MlKemNativeAndEncodedPublicKeysInteroperate) {
    auto key = vless::GenerateVlessMlKem768PrivateKey();
    ASSERT_TRUE(key);
    const auto public_key = vless::DeriveVlessMlKem768PublicKey(key.get());
    ASSERT_TRUE(public_key);
    EXPECT_EQ(public_key->size(), 1184u);
    auto peer = vless::CreateVlessMlKem768PublicKey(*public_key);
    ASSERT_TRUE(peer);
    EXPECT_EQ(vless::DeriveVlessMlKem768PublicKey(peer.get()), public_key);

    for (const bool encoded : {false, true}) {
        const auto encapsulated = encoded
            ? vless::EncapsulateVlessMlKem768(*public_key)
            : vless::EncapsulateVlessMlKem768(peer.get());
        ASSERT_TRUE(encapsulated);
        EXPECT_EQ(encapsulated->ciphertext.size(), 1088u);
        EXPECT_EQ(encapsulated->shared_secret.bytes.size(), 32u);
        vless::VlessSecretBytes<vless::kVlessMlKem768SharedSecretSize> shared;
        ASSERT_TRUE(vless::DecapsulateVlessMlKem768(
            key.get(), encapsulated->ciphertext, shared.bytes));
        EXPECT_EQ(shared.bytes, encapsulated->shared_secret.bytes);
        EXPECT_FALSE(vless::DecapsulateVlessMlKem768(
            peer.get(), encapsulated->ciphertext, shared.bytes));
        EXPECT_FALSE(vless::DecapsulateVlessMlKem768(
            key.get(), std::span(encapsulated->ciphertext).first(1087), shared.bytes));
        EXPECT_FALSE(vless::DecapsulateVlessMlKem768(
            nullptr, encapsulated->ciphertext, shared.bytes));
    }
}

TEST(VlessEncryptionCrypto, MlKemRejectsInvalidKeyMaterial) {
    std::array<uint8_t, vless::kVlessMlKem768SeedSize + 1> seed{};
    EXPECT_FALSE(vless::CreateVlessMlKem768PrivateKeyFromSeed(seed));
    EXPECT_FALSE(vless::CreateVlessMlKem768PrivateKeyFromSeed(
        std::span(seed).first(63)));
    std::array<uint8_t, vless::kVlessMlKem768PublicKeySize> invalid{};
    invalid.fill(0xff);  // Encoded coefficients must be reduced modulo q.
    EXPECT_FALSE(vless::CreateVlessMlKem768PublicKey(invalid));
    EXPECT_FALSE(vless::EncapsulateVlessMlKem768(invalid));
    EXPECT_FALSE(vless::CreateVlessMlKem768PublicKey(std::span(invalid).first(1183)));
    EXPECT_FALSE(vless::EncapsulateVlessMlKem768(std::span(invalid).first(1183)));
    EXPECT_FALSE(vless::EncapsulateVlessMlKem768(nullptr));
    EXPECT_FALSE(vless::DeriveVlessMlKem768PublicKey(nullptr));
}

TEST(VlessEncryptionCrypto, MlKemHandshakePreservesPfsAndTickets) {
    vless::VlessSecretBytes<vless::kVlessMlKem768SeedSize> seed;
    auto key = vless::CreateVlessMlKem768PrivateKeyFromSeed(seed.bytes);
    ASSERT_TRUE(key);
    const auto public_key = vless::DeriveVlessMlKem768PublicKey(key.get());
    ASSERT_TRUE(public_key);
    auto peer = vless::CreateVlessMlKem768PublicKey(*public_key);
    ASSERT_TRUE(peer);
    vless::VlessEncryptionConfig client;
    client.client_keys.push_back({
        .public_key = {public_key->begin(), public_key->end()},
        .mlkem_key = std::move(peer),
    });
    vless::VlessEncryptionConfig server;
    server.role = vless::VlessEncryptionRole::Server;
    server.seconds_from = server.seconds_to = 120;
    server.server_keys.emplace_back(
        std::vector<uint8_t>(seed.bytes.begin(), seed.bytes.end()),
        std::vector<uint8_t>(public_key->begin(), public_key->end()), std::move(key));

    for (const auto cipher : {vless::VlessEncryptionAeadCipher::Aes256Gcm,
                              vless::VlessEncryptionAeadCipher::Chacha20Poly1305}) {
        auto nfs = vless::BuildVlessEncryptionClientNfsHello(client);
        ASSERT_TRUE(nfs);
        auto opened_nfs = vless::OpenVlessEncryptionClientNfsHello(server, nfs->bytes);
        ASSERT_TRUE(opened_nfs);
        ASSERT_EQ(opened_nfs->nfs_key.bytes, nfs->nfs_key.bytes);
        auto nfs_aead = vless::VlessEncryptionAead::Create(
            nfs->iv, nfs->nfs_key.bytes, cipher);
        ASSERT_TRUE(nfs_aead);
        auto hello = vless::BuildVlessEncryptionClientPfsHello(*nfs_aead);
        ASSERT_TRUE(hello);
        EXPECT_EQ(hello->public_key.size(), 1216u);
        auto response = vless::BuildVlessEncryptionServerPfsResponse(
            server, nfs->iv, opened_nfs->nfs_key, hello->public_key, cipher);
        ASSERT_TRUE(response);
        ASSERT_EQ(response->encrypted_public_key.size(), 1136u);
        const auto encrypted_public =
            std::span<const uint8_t, vless::kVlessEncryptionEncryptedServerPfsPublicSize>(
                response->encrypted_public_key.data(), response->encrypted_public_key.size());
        auto opened = vless::OpenVlessEncryptionServerPfsResponse(
            *hello, nfs->iv, nfs->nfs_key, encrypted_public,
            response->encrypted_ticket, cipher);
        ASSERT_TRUE(opened);
        EXPECT_EQ(opened->pfs_key.bytes, response->pfs_key.bytes);
        EXPECT_EQ(opened->united_key.bytes, response->united_key.bytes);
        EXPECT_EQ(opened->ticket, response->ticket);
        EXPECT_EQ(opened->ticket_seconds, 120);
        auto zero_rtt = vless::BuildVlessEncryptionClientZeroRttRequest(
            nfs->iv, nfs->nfs_key, opened->pfs_key, opened->ticket, cipher);
        ASSERT_TRUE(zero_rtt);
        EXPECT_EQ(zero_rtt->bytes.size(), 50u);
        EXPECT_EQ(zero_rtt->united_key.bytes, opened->united_key.bytes);

        response->encrypted_ticket.back() ^= 1;
        EXPECT_FALSE(vless::OpenVlessEncryptionServerPfsResponse(
            *hello, nfs->iv, nfs->nfs_key, encrypted_public,
            response->encrypted_ticket, cipher));
    }
}

TEST(VlessEncryptionCrypto, AeadMovesPreserveNonceAndTransferOwnership) {
    const std::array<uint8_t, vless::kVlessEncryptionIvSize> context{};
    const vless::VlessEncryptionUnitedKey key;
    const std::array<uint8_t, 4> plaintext{1, 2, 3, 4};
    std::array<uint8_t, plaintext.size() + vless::kVlessEncryptionTagSize> ciphertext{};
    std::array<uint8_t, plaintext.size()> opened{};
    for (const auto cipher : {vless::VlessEncryptionAeadCipher::Aes256Gcm,
                              vless::VlessEncryptionAeadCipher::Chacha20Poly1305}) {
        auto source = vless::VlessEncryptionAead::Create(context, key.bytes, cipher);
        auto reader = vless::VlessEncryptionAead::Create(context, key.bytes, cipher);
        ASSERT_TRUE(source);
        ASSERT_TRUE(reader);
        ASSERT_EQ(source->Seal(plaintext, {}, ciphertext), ciphertext.size());
        ASSERT_EQ(reader->Open(ciphertext, {}, opened), plaintext.size());
        EXPECT_EQ(opened, plaintext);
        const auto nonce = source->Nonce();

        vless::VlessEncryptionAead moved(std::move(*source));
        EXPECT_EQ(moved.Nonce(), nonce);
        EXPECT_EQ(moved.Cipher(), cipher);
        EXPECT_FALSE(source->Seal(plaintext, {}, ciphertext));
        EXPECT_FALSE(source->Open(ciphertext, {}, opened));
        ASSERT_EQ(moved.Seal(plaintext, {}, ciphertext), ciphertext.size());
        ASSERT_EQ(reader->Open(ciphertext, {}, opened), plaintext.size());
        EXPECT_EQ(opened, plaintext);

        vless::VlessEncryptionUnitedKey replaced_key;
        replaced_key.bytes.fill(0xff);
        auto assigned = vless::VlessEncryptionAead::Create(
            context, replaced_key.bytes, cipher);
        ASSERT_TRUE(assigned);
        const auto next_nonce = moved.Nonce();
        *assigned = std::move(moved);
        EXPECT_EQ(assigned->Nonce(), next_nonce);
        EXPECT_EQ(assigned->Cipher(), cipher);
        EXPECT_FALSE(moved.Seal(plaintext, {}, ciphertext));
        EXPECT_FALSE(moved.Open(ciphertext, {}, opened));
        ASSERT_EQ(assigned->Seal(plaintext, {}, ciphertext), ciphertext.size());
        ASSERT_EQ(reader->Open(ciphertext, {}, opened), plaintext.size());
        EXPECT_EQ(opened, plaintext);
    }
}
