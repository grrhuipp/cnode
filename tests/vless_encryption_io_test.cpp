#include <stdexcept>
#include <gtest/gtest.h>

#include "proxy/vless/vless_encryption.hpp"
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
#include <exception>
#include <future>
#include <optional>
#include <span>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace {

std::vector<uint8_t> Flatten(const common::MultiBuffer& payload) {
    const auto bytes = payload.FrontSpan();
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

class CaptureWriter final : public transport::MultiBufferWriter {
public:
    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer payload) override {
        const auto data = payload.FrontSpan();
        bytes.insert(bytes.end(), data.begin(), data.end());
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

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
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
            EXPECT_EQ(error, io_error::operation_aborted) << "controlled read was not cancelled by Asio";
            if (empty_on_cancel_) {
                // TcpStream may report cancellation as an empty MultiBuffer.
                co_return common::MultiBuffer{};
            }
            throw IoSystemError(error);
        }

        if (offset_ == bytes_.size()) {
            co_return common::MultiBuffer{};
        }
        const size_t end = cutpoint_index_ < cutpoints_.size()
            ? cutpoints_[cutpoint_index_] : bytes_.size();
        if (end <= offset_ || end > bytes_.size()) {
            throw std::runtime_error("invalid encrypted stream interruption boundary");
        }
        common::MultiBuffer out;
        if (!out.AppendSpan(
                std::span<const uint8_t>(bytes_.data() + offset_, end - offset_))) {
            throw std::bad_alloc();
        }
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

std::optional<proxy::VlessEncryptionHeaderXor> MakeHeaderXor(
    bool enabled,
    std::span<const uint8_t> key,
    const std::array<uint8_t, proxy::kVlessEncryptionCtrIvSize>& context) {
    if (!enabled) {
        return std::nullopt;
    }
    auto result = proxy::VlessEncryptionHeaderXor::Create(key, context);
    if (!result) throw std::runtime_error("header XOR fixture unavailable");
    return result;
}

void ResumeInterruptedRecords(proxy::VlessEncryptionAeadCipher cipher,
                   bool header_xor,
                   bool empty_on_cancel,
                   bool lazy_context) {
    net::io_context io;
    net::cancellation_signal signal;
    const auto exercise = [&]() -> net::awaitable<void> {
        std::array<uint8_t, proxy::kVlessEncryptionCtrIvSize> context{};
        proxy::VlessEncryptionUnitedKey key;
        for (size_t i = 0; i < context.size(); ++i) {
            context[i] = static_cast<uint8_t>(0x31 + i * 7);
        }
        for (size_t i = 0; i < key.bytes.size(); ++i) {
            key.bytes[i] = static_cast<uint8_t>(0xa7 ^ (i * 13));
        }
        const auto create_aead = [&] {
            auto aead = proxy::VlessEncryptionAead::Create(context, key.bytes, cipher);
            if (!aead) throw std::runtime_error("AEAD fixture unavailable");
            return std::move(*aead);
        };

        std::array<std::vector<uint8_t>, 4> plaintext;
        constexpr std::array<size_t, 4> sizes{37, 4097, 73, 129};
        CaptureWriter capture;
        if (lazy_context) {
            capture.bytes.insert(capture.bytes.end(), context.begin(), context.end());
        }
        std::optional<proxy::VlessEncryptionWriter> writer;
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
            EXPECT_EQ(capture.bytes.size() - boundaries[record], proxy::kVlessEncryptionRecordHeaderSize + data.size() +
                proxy::kVlessEncryptionTagSize) << "writer did not produce one encrypted record per plaintext";
        }
        boundaries.back() = capture.bytes.size();

        std::vector<size_t> cutpoints;
        if (lazy_context) {
            cutpoints = {0, 1, context.size() - 1};
        }
        const size_t second = boundaries[1];
        const size_t body = second + proxy::kVlessEncryptionRecordHeaderSize;
        // Record zero succeeds first. Repeated cancellation then covers an
        // untouched header, partial header, complete header, partial body and
        // partial authentication tag, all on the same reader and record.
        cutpoints.insert(cutpoints.end(), {
            second, second, second + 1, body - 1, body,
            body + 1, body + plaintext[1].size() / 2,
            boundaries[2] - 1,
        });
        InterruptedReader source(capture.bytes, cutpoints, signal, empty_on_cancel);
        proxy::VlessEncryptionTicketRejection rejection;
        std::optional<proxy::VlessEncryptionReader> reader;
        if (lazy_context) {
            reader.emplace(source,
                           proxy::VlessEncryptionDeferredRead{
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
                EXPECT_EQ(Flatten(output), plaintext[decoded]) << "resumed encryption reader lost or changed plaintext";
                ++decoded;
            } catch (const IoSystemError& error) {
                if (error.code() != io_error::operation_aborted) {
                    throw;
                }
                interrupted = true;
            }
            if (interrupted) {
                EXPECT_FALSE(rejection.rejected) << "cancelled deferred read invalidated a reusable ticket";
                EXPECT_TRUE((cancelled < cutpoints.size() &&
                          source.Interruptions() == cancelled + 1 &&
                          source.Offset() == cutpoints[cancelled])) << "cancellation did not occur at the requested byte boundary";
                EXPECT_EQ(decoded, (source.Offset() < boundaries[0] ? 0u : 1u)) << "cancellation occurred before the preceding record decoded";
                const auto state = co_await net::this_coro::cancellation_state;
                EXPECT_NE(state.cancelled(), net::cancellation_type::none) << "read interruption lost its coroutine cancellation state";
                ++cancelled;
                co_await net::this_coro::reset_cancellation_state();
            }
        }
        EXPECT_EQ(cancelled, cutpoints.size()) << "encrypted reader did not exercise every cancellation cutpoint";
        EXPECT_EQ(source.Offset(), capture.bytes.size()) << "encrypted reader left wire bytes unconsumed";
        EXPECT_EQ((co_await reader->ReadMultiBuffer()).byte_size(), 0) << "real encrypted stream EOF returned plaintext";
        EXPECT_EQ((co_await reader->ReadMultiBuffer()).byte_size(), 0) << "repeated encrypted stream EOF returned plaintext";
        reader->RejectDeferredTicket();
        EXPECT_FALSE(rejection.rejected) << "authenticated response or later EOF invalidated the ticket";
    };
    auto future = net::co_spawn(io, exercise(),
        net::bind_cancellation_slot(signal.slot(), net::use_future));
    io.run();
    future.get();
}

void AuthenticateDeferredResponse(proxy::VlessEncryptionAeadCipher cipher,
                              bool header_xor,
                              unsigned boundary) {
    net::io_context io;
    net::cancellation_signal signal;
    const auto exercise = [&]() -> net::awaitable<void> {
        std::array<uint8_t, proxy::kVlessEncryptionCtrIvSize> context{};
        proxy::VlessEncryptionUnitedKey key;
        auto aead = proxy::VlessEncryptionAead::Create(context, key.bytes, cipher);
        if (!aead) throw std::runtime_error("AEAD fixture unavailable");
        CaptureWriter capture;
        capture.bytes.insert(capture.bytes.end(), context.begin(), context.end());
        proxy::VlessEncryptionWriter writer(
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
        proxy::VlessEncryptionTicketRejection rejection;
        proxy::VlessEncryptionReader reader(
            source,
            proxy::VlessEncryptionDeferredRead{
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
                EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(bytes.data()),
                                       bytes.size()), payload) << "deferred authenticated response changed payload";
            } else {
                EXPECT_TRUE((boundary == 2 && result.empty())) << "incomplete deferred response produced plaintext";
            }
        } catch (const IoSystemError& error) {
            EXPECT_NE(error.code(), io_error::operation_aborted) << "deferred rejection unexpectedly reported cancellation";
            failed = true;
        }
        EXPECT_EQ(failed, (boundary != 2 && boundary != 6)) << "deferred response failure category changed";
        EXPECT_EQ(rejection.rejected, (boundary != 6)) << "ticket rejection did not match first-response authentication";
        reader.RejectDeferredTicket();
        EXPECT_EQ(rejection.rejected, (boundary != 6)) << "late failure invalidated an authenticated ticket";
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

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer payload) override {
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
            buffers.front().data(), proxy::kVlessEncryptionRecordHeaderSize + 3);
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
        EXPECT_EQ(error, io_error::operation_aborted) << "controlled encrypted write was not cancelled";
        throw IoSystemError(error);
    }

    CaptureWriter capture;

private:
    WriteFault fault_;
    net::cancellation_signal& signal_;
    bool armed_ = true;
};

void RejectWritesAfterFailure(proxy::VlessEncryptionAeadCipher cipher,
                          bool header_xor, WriteFault fault) {
    net::io_context io;
    net::cancellation_signal signal;
    const auto exercise = [&]() -> net::awaitable<void> {
        const std::array<uint8_t, proxy::kVlessEncryptionCtrIvSize> context{};
        const proxy::VlessEncryptionUnitedKey key;
        auto aead = proxy::VlessEncryptionAead::Create(context, key.bytes, cipher);
        if (!aead) throw std::runtime_error("AEAD fixture unavailable");
        InterruptedWriter destination(fault, signal);
        proxy::VlessEncryptionWriter writer(
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
        EXPECT_TRUE((original_error)) << "encrypted write did not preserve its original error";
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
        EXPECT_EQ(destination.capture.bytes, published) << "terminal encrypted writer published another record";
        EXPECT_TRUE((rejected)) << "terminal encrypted writer accepted another write";
    };
    auto future = net::co_spawn(io, exercise(),
        net::bind_cancellation_slot(signal.slot(), net::use_future));
    io.run();
    future.get();
}

void RejectWritesAfterShutdown(proxy::VlessEncryptionAeadCipher cipher,
                           bool header_xor) {
    net::io_context io;
    const auto exercise = [&]() -> net::awaitable<void> {
        const std::array<uint8_t, proxy::kVlessEncryptionCtrIvSize> context{};
        const proxy::VlessEncryptionUnitedKey key;
        auto aead = proxy::VlessEncryptionAead::Create(context, key.bytes, cipher);
        if (!aead) throw std::runtime_error("AEAD fixture unavailable");
        CaptureWriter destination;
        proxy::VlessEncryptionWriter writer(
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
        EXPECT_EQ(destination.bytes, published) << "finished encrypted writer published another record";
        EXPECT_TRUE((rejected)) << "finished encrypted writer accepted another write";
    };
    auto future = net::co_spawn(io, exercise(), net::use_future);
    io.run();
    future.get();
}

void ResumePrecancelledWriter(proxy::VlessEncryptionAeadCipher cipher,
                            bool header_xor) {
    net::io_context io;
    net::cancellation_signal signal;
    const auto exercise = [&]() -> net::awaitable<void> {
        const std::array<uint8_t, proxy::kVlessEncryptionCtrIvSize> context{};
        const proxy::VlessEncryptionUnitedKey key;
        auto aead = proxy::VlessEncryptionAead::Create(context, key.bytes, cipher);
        auto read_aead = proxy::VlessEncryptionAead::Create(context, key.bytes, cipher);
        if (!aead || !read_aead) throw std::runtime_error("AEAD fixture unavailable");
        CaptureWriter destination;
        proxy::VlessEncryptionWriter writer(
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
        EXPECT_TRUE((destination.bytes.empty())) << "pre-cancelled encrypted writer published a record";
        EXPECT_TRUE((cancelled)) << "pre-cancelled encrypted write did not report cancellation";
        co_await net::this_coro::reset_cancellation_state();
        co_await writer.WriteBuffers(
            std::span<const net::const_buffer>(&buffer, 1));
        InterruptedReader source(destination.bytes, {}, signal, false);
        proxy::VlessEncryptionReader reader(
            source, std::move(*read_aead), key,
            MakeHeaderXor(header_xor, key.bytes, context));
        const auto decoded = Flatten(co_await reader.ReadMultiBuffer());
        EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(decoded.data()),
                               decoded.size()), payload) << "pre-cancelled writer could not resume a consumable stream";
        EXPECT_TRUE(((co_await reader.ReadMultiBuffer()).empty())) << "pre-cancelled writer emitted extra plaintext";
    };
    auto future = net::co_spawn(io, exercise(),
        net::bind_cancellation_slot(signal.slot(), net::use_future));
    io.run();
    future.get();
}

}  // namespace

namespace {
using Cipher = proxy::VlessEncryptionAeadCipher;
const auto ciphers = testing::Values(Cipher::Aes256Gcm, Cipher::Chacha20Poly1305);

class InterruptedEncryptedRead
    : public testing::TestWithParam<std::tuple<Cipher, bool, bool, bool>> {};
TEST_P(InterruptedEncryptedRead, CancellationResumesWithoutLosingRecordsOrRejectingTicket) {
    const auto [cipher, header_xor, empty_on_cancel, lazy_context] = GetParam();
    ResumeInterruptedRecords(cipher, header_xor, empty_on_cancel, lazy_context);
}
INSTANTIATE_TEST_SUITE_P(Modes, InterruptedEncryptedRead,
    testing::Combine(ciphers, testing::Bool(), testing::Bool(), testing::Bool()));

class DeferredEncryptedResponse
    : public testing::TestWithParam<std::tuple<Cipher, bool, unsigned>> {};
TEST_P(DeferredEncryptedResponse, RejectsTicketUnlessFirstResponseAuthenticates) {
    const auto [cipher, header_xor, boundary] = GetParam();
    AuthenticateDeferredResponse(cipher, header_xor, boundary);
}
INSTANTIATE_TEST_SUITE_P(Boundaries, DeferredEncryptedResponse,
    testing::Combine(ciphers, testing::Bool(), testing::Values(0u, 1u, 2u, 3u, 4u, 5u, 6u)));

class FailedEncryptedWrite
    : public testing::TestWithParam<std::tuple<Cipher, bool, WriteFault>> {};
TEST_P(FailedEncryptedWrite, PreservesOriginalErrorAndRejectsFurtherPublication) {
    const auto [cipher, header_xor, fault] = GetParam();
    RejectWritesAfterFailure(cipher, header_xor, fault);
}
INSTANTIATE_TEST_SUITE_P(Faults, FailedEncryptedWrite,
    testing::Combine(ciphers, testing::Bool(), testing::Values(
        WriteFault::PartialFailure, WriteFault::SuspendedCancellation, WriteFault::Closed)));

class EncryptedWriter : public testing::TestWithParam<std::tuple<Cipher, bool>> {};
TEST_P(EncryptedWriter, ShutdownPreventsFurtherPublication) {
    const auto [cipher, header_xor] = GetParam();
    RejectWritesAfterShutdown(cipher, header_xor);
}
TEST_P(EncryptedWriter, PrecancelDoesNotAdvanceRecordAndCanResume) {
    const auto [cipher, header_xor] = GetParam();
    ResumePrecancelledWriter(cipher, header_xor);
}
INSTANTIATE_TEST_SUITE_P(Modes, EncryptedWriter, testing::Combine(ciphers, testing::Bool()));
}  // namespace

TEST(VlessEncryptionCrypto, MlKemSeedPreservesBothHalves) {
    proxy::VlessSecretBytes<proxy::kVlessMlKem768SeedSize> seed;
    for (size_t i = 0; i < seed.bytes.size(); ++i) {
        seed.bytes[i] = static_cast<uint8_t>(i);
    }
    auto key = proxy::CreateVlessMlKem768PrivateKeyFromSeed(seed.bytes);
    ASSERT_TRUE(key);
    EXPECT_EQ(EVP_PKEY_id(key.get()), EVP_PKEY_ML_KEM_768);
    proxy::VlessSecretBytes<proxy::kVlessMlKem768SeedSize> exported;
    size_t exported_size = exported.bytes.size();
    ASSERT_EQ(EVP_PKEY_get_private_seed(
                  key.get(), exported.bytes.data(), &exported_size), 1);
    EXPECT_EQ(exported_size, 64u);
    EXPECT_EQ(exported.bytes, seed.bytes);

    const auto public_key = proxy::DeriveVlessMlKem768PublicKey(key.get());
    ASSERT_TRUE(public_key);
    auto changed_seed = seed;
    changed_seed.bytes.back() ^= 1;  // z only affects implicit rejection.
    auto changed_z = proxy::CreateVlessMlKem768PrivateKeyFromSeed(changed_seed.bytes);
    ASSERT_TRUE(changed_z);
    EXPECT_EQ(proxy::DeriveVlessMlKem768PublicKey(changed_z.get()), public_key);
    changed_seed = seed;
    changed_seed.bytes.front() ^= 1;  // d determines the public key.
    auto changed_d = proxy::CreateVlessMlKem768PrivateKeyFromSeed(changed_seed.bytes);
    ASSERT_TRUE(changed_d);
    EXPECT_NE(proxy::DeriveVlessMlKem768PublicKey(changed_d.get()), public_key);

    std::array<uint8_t, proxy::kVlessMlKem768CiphertextSize> invalid{};
    proxy::VlessSecretBytes<proxy::kVlessMlKem768SharedSecretSize> rejected, repeated, other_z;
    ASSERT_TRUE(proxy::DecapsulateVlessMlKem768(key.get(), invalid, rejected.bytes));
    ASSERT_TRUE(proxy::DecapsulateVlessMlKem768(key.get(), invalid, repeated.bytes));
    ASSERT_TRUE(proxy::DecapsulateVlessMlKem768(changed_z.get(), invalid, other_z.bytes));
    EXPECT_EQ(rejected.bytes, repeated.bytes);
    EXPECT_NE(rejected.bytes, other_z.bytes);
}

namespace {
class MlKemPublicKeyEncoding : public testing::TestWithParam<bool> {};
TEST_P(MlKemPublicKeyEncoding, EncapsulationInteroperatesAndRejectsInvalidDecapsulationInputs) {
    auto key = proxy::GenerateVlessMlKem768PrivateKey();
    ASSERT_TRUE(key);
    const auto public_key = proxy::DeriveVlessMlKem768PublicKey(key.get());
    ASSERT_TRUE(public_key);
    EXPECT_EQ(public_key->size(), 1184u);
    auto peer = proxy::CreateVlessMlKem768PublicKey(*public_key);
    ASSERT_TRUE(peer);
    EXPECT_EQ(proxy::DeriveVlessMlKem768PublicKey(peer.get()), public_key);

    {
        const bool encoded = GetParam();
        const auto encapsulated = encoded
            ? proxy::EncapsulateVlessMlKem768(*public_key)
            : proxy::EncapsulateVlessMlKem768(peer.get());
        ASSERT_TRUE(encapsulated);
        EXPECT_EQ(encapsulated->ciphertext.size(), 1088u);
        EXPECT_EQ(encapsulated->shared_secret.bytes.size(), 32u);
        proxy::VlessSecretBytes<proxy::kVlessMlKem768SharedSecretSize> shared;
        ASSERT_TRUE(proxy::DecapsulateVlessMlKem768(
            key.get(), encapsulated->ciphertext, shared.bytes));
        EXPECT_EQ(shared.bytes, encapsulated->shared_secret.bytes);
        EXPECT_FALSE(proxy::DecapsulateVlessMlKem768(
            peer.get(), encapsulated->ciphertext, shared.bytes));
        EXPECT_FALSE(proxy::DecapsulateVlessMlKem768(
            key.get(), std::span(encapsulated->ciphertext).first(1087), shared.bytes));
        EXPECT_FALSE(proxy::DecapsulateVlessMlKem768(
            nullptr, encapsulated->ciphertext, shared.bytes));
    }
}
INSTANTIATE_TEST_SUITE_P(Forms, MlKemPublicKeyEncoding, testing::Bool());
}

TEST(VlessEncryptionCrypto, MlKemRejectsInvalidKeyMaterial) {
    std::array<uint8_t, proxy::kVlessMlKem768SeedSize + 1> seed{};
    EXPECT_FALSE(proxy::CreateVlessMlKem768PrivateKeyFromSeed(seed));
    EXPECT_FALSE(proxy::CreateVlessMlKem768PrivateKeyFromSeed(
        std::span(seed).first(63)));
    std::array<uint8_t, proxy::kVlessMlKem768PublicKeySize> invalid{};
    invalid.fill(0xff);  // Encoded coefficients must be reduced modulo q.
    EXPECT_FALSE(proxy::CreateVlessMlKem768PublicKey(invalid));
    EXPECT_FALSE(proxy::EncapsulateVlessMlKem768(invalid));
    EXPECT_FALSE(proxy::CreateVlessMlKem768PublicKey(std::span(invalid).first(1183)));
    EXPECT_FALSE(proxy::EncapsulateVlessMlKem768(std::span(invalid).first(1183)));
    EXPECT_FALSE(proxy::EncapsulateVlessMlKem768(nullptr));
    EXPECT_FALSE(proxy::DeriveVlessMlKem768PublicKey(nullptr));
}

namespace {
class MlKemHandshakeCipher : public testing::TestWithParam<Cipher> {};
TEST_P(MlKemHandshakeCipher, PreservesPfsAndTicketsAndRejectsTamperedTicket) {
    proxy::VlessSecretBytes<proxy::kVlessMlKem768SeedSize> seed;
    auto key = proxy::CreateVlessMlKem768PrivateKeyFromSeed(seed.bytes);
    ASSERT_TRUE(key);
    const auto public_key = proxy::DeriveVlessMlKem768PublicKey(key.get());
    ASSERT_TRUE(public_key);
    auto peer = proxy::CreateVlessMlKem768PublicKey(*public_key);
    ASSERT_TRUE(peer);
    proxy::VlessEncryptionConfig client;
    client.client_keys.push_back({
        .public_key = {public_key->begin(), public_key->end()},
        .mlkem_key = std::move(peer),
    });
    proxy::VlessEncryptionConfig server;
    server.role = proxy::VlessEncryptionRole::Server;
    server.seconds_from = server.seconds_to = 120;
    server.server_keys.emplace_back(
        std::vector<uint8_t>(seed.bytes.begin(), seed.bytes.end()),
        std::vector<uint8_t>(public_key->begin(), public_key->end()), std::move(key));

    {
        const auto cipher = GetParam();
        auto nfs = proxy::BuildVlessEncryptionClientNfsHello(client);
        ASSERT_TRUE(nfs);
        auto opened_nfs = proxy::OpenVlessEncryptionClientNfsHello(server, nfs->bytes);
        ASSERT_TRUE(opened_nfs);
        ASSERT_EQ(opened_nfs->nfs_key.bytes, nfs->nfs_key.bytes);
        auto nfs_aead = proxy::VlessEncryptionAead::Create(
            nfs->iv, nfs->nfs_key.bytes, cipher);
        ASSERT_TRUE(nfs_aead);
        auto hello = proxy::BuildVlessEncryptionClientPfsHello(*nfs_aead);
        ASSERT_TRUE(hello);
        EXPECT_EQ(hello->public_key.size(), 1216u);
        auto response = proxy::BuildVlessEncryptionServerPfsResponse(
            server, nfs->iv, opened_nfs->nfs_key, hello->public_key, cipher);
        ASSERT_TRUE(response);
        ASSERT_EQ(response->encrypted_public_key.size(), 1136u);
        const auto encrypted_public =
            std::span<const uint8_t, proxy::kVlessEncryptionEncryptedServerPfsPublicSize>(
                response->encrypted_public_key.data(), response->encrypted_public_key.size());
        auto opened = proxy::OpenVlessEncryptionServerPfsResponse(
            *hello, nfs->iv, nfs->nfs_key, encrypted_public,
            response->encrypted_ticket, cipher);
        ASSERT_TRUE(opened);
        EXPECT_EQ(opened->pfs_key.bytes, response->pfs_key.bytes);
        EXPECT_EQ(opened->united_key.bytes, response->united_key.bytes);
        EXPECT_EQ(opened->ticket, response->ticket);
        EXPECT_EQ(opened->ticket_seconds, 120);
        auto zero_rtt = proxy::BuildVlessEncryptionClientZeroRttRequest(
            nfs->iv, nfs->nfs_key, opened->pfs_key, opened->ticket, cipher);
        ASSERT_TRUE(zero_rtt);
        EXPECT_EQ(zero_rtt->bytes.size(), 50u);
        EXPECT_EQ(zero_rtt->united_key.bytes, opened->united_key.bytes);

        response->encrypted_ticket.back() ^= 1;
        EXPECT_FALSE(proxy::OpenVlessEncryptionServerPfsResponse(
            *hello, nfs->iv, nfs->nfs_key, encrypted_public,
            response->encrypted_ticket, cipher));
    }
}
INSTANTIATE_TEST_SUITE_P(Ciphers, MlKemHandshakeCipher, ciphers);
}

namespace {
class TransferredAead : public testing::TestWithParam<std::tuple<Cipher, bool>> {};
TEST_P(TransferredAead, ContinuesRecordSequenceWithoutLeavingTwoUsableOwners) {
    const auto [cipher, assignment] = GetParam();
    const std::array<uint8_t, proxy::kVlessEncryptionIvSize> context{};
    const proxy::VlessEncryptionUnitedKey key;
    const std::array<uint8_t, 4> plaintext{1, 2, 3, 4};
    std::array<uint8_t, plaintext.size() + proxy::kVlessEncryptionTagSize> ciphertext{};
    std::array<uint8_t, plaintext.size()> opened{};
    auto source = proxy::VlessEncryptionAead::Create(context, key.bytes, cipher);
    auto reader = proxy::VlessEncryptionAead::Create(context, key.bytes, cipher);
    ASSERT_TRUE(source);
    ASSERT_TRUE(reader);
    ASSERT_EQ(source->Seal(plaintext, {}, ciphertext), ciphertext.size());
    ASSERT_EQ(reader->Open(ciphertext, {}, opened), plaintext.size());
    EXPECT_EQ(opened, plaintext);

    std::optional<proxy::VlessEncryptionAead> destination;
    if (assignment) {
        proxy::VlessEncryptionUnitedKey replaced_key;
        replaced_key.bytes.fill(0xff);
        destination = proxy::VlessEncryptionAead::Create(context, replaced_key.bytes, cipher);
        ASSERT_TRUE(destination);
        *destination = std::move(*source);
    } else {
        destination.emplace(std::move(*source));
    }
    // Ownership transfer must not leave a second writer able to reuse a nonce.
    EXPECT_FALSE(source->Seal(plaintext, {}, ciphertext));
    EXPECT_FALSE(source->Open(ciphertext, {}, opened));
    ASSERT_EQ(destination->Seal(plaintext, {}, ciphertext), ciphertext.size());
    ASSERT_EQ(reader->Open(ciphertext, {}, opened), plaintext.size());
    EXPECT_EQ(opened, plaintext);
}
INSTANTIATE_TEST_SUITE_P(Transfers, TransferredAead, testing::Combine(ciphers, testing::Bool()));
}  // namespace
