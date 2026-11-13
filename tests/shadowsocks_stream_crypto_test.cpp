#include <stdexcept>
#include <gtest/gtest.h>

#include "proxy/shadowsocks/shadowsocks_protocol.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <tuple>
#include <vector>

namespace {
bool fail_cipher_context = false;
}
#if defined(CNODE_WRAP_MALLOC)
extern "C" void* __real_malloc(size_t);
extern "C" void* __wrap_malloc(size_t size) {
    return __real_malloc(size);
}
extern "C" EVP_AEAD_CTX* __real_EVP_AEAD_CTX_new(const EVP_AEAD*, const uint8_t*, size_t, size_t);
extern "C" EVP_AEAD_CTX* __wrap_EVP_AEAD_CTX_new(
    const EVP_AEAD* cipher, const uint8_t* key, size_t key_size, size_t tag_size) {
    return fail_cipher_context ? nullptr : __real_EVP_AEAD_CTX_new(cipher, key, key_size, tag_size);
}
#endif

namespace {



TEST(ShadowsocksStreamCrypto, AesBlockMatchesFips197AndSupportsOverlap) {
    // FIPS 197 的 AES-128/AES-256 单块已知答案。
    const std::array<uint8_t, 16> plain{
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const std::array<std::array<uint8_t, 16>, 2> expected{{
        {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a},
        {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89}}};
    std::array<uint8_t, 34> keys{};
    for (size_t i = 0; i < 32; ++i) keys[i + 1] = static_cast<uint8_t>(i);
    for (size_t index = 0; index < 2; ++index) {
        const auto key = std::span<const uint8_t>(keys).subspan(1, index ? 32 : 16);
        for (int round = 0; round < 64; ++round) {
            std::array<uint8_t, 18> guarded;
            guarded.fill(0xa5);
            auto output = std::span<uint8_t>(guarded).subspan<1, 16>();
            EXPECT_TRUE((proxy::AesBlocksCrypt<16>(key, plain, output, true))) << "AES block encrypt failed";
            EXPECT_TRUE((std::equal(output.begin(), output.end(), expected[index].begin()))) << "AES known answer mismatch";
            EXPECT_TRUE((proxy::AesBlocksCrypt<16>(key, output, output, false))) << "AES in-place decrypt failed";
            EXPECT_TRUE((std::equal(output.begin(), output.end(), plain.begin()))) << "AES plaintext mismatch";
            EXPECT_TRUE((proxy::AesBlocksCrypt<16>(key, output, output, true))) << "AES in-place encrypt failed";
            EXPECT_TRUE((std::equal(output.begin(), output.end(), expected[index].begin()))) << "AES in-place ciphertext mismatch";
            EXPECT_TRUE((guarded.front() == 0xa5 && guarded.back() == 0xa5)) << "AES wrote outside output block";
        }
        std::array<uint8_t, 17> overlap{};
        std::copy(plain.begin(), plain.end(), overlap.begin());
        auto first = std::span<uint8_t>(overlap).first<16>();
        auto shifted = std::span<uint8_t>(overlap).subspan<1, 16>();
        EXPECT_TRUE((proxy::AesBlocksCrypt<16>(key, first, shifted, true))) << "AES overlapping encrypt failed";
        EXPECT_TRUE((std::equal(shifted.begin(), shifted.end(), expected[index].begin()))) << "AES overlapping ciphertext mismatch";
        EXPECT_TRUE((proxy::AesBlocksCrypt<16>(key, shifted, first, false))) << "AES overlapping decrypt failed";
        EXPECT_TRUE((std::equal(first.begin(), first.end(), plain.begin()))) << "AES overlapping plaintext mismatch";
    }
    for (size_t size : {size_t(0),size_t(1),size_t(15),size_t(17),size_t(24),size_t(31),size_t(33)}) {
        auto output = plain;
        for (bool encrypt : {false, true}) {
            EXPECT_FALSE((proxy::AesBlocksCrypt<16>(std::span<const uint8_t>(keys).first(size), plain, output, encrypt))) << "AES accepted unsupported key size";
            EXPECT_EQ((output), (plain)) << "AES invalid key modified output";
        }
    }
}

TEST(ShadowsocksStreamCrypto, SubkeyMatchesIndependentHmacSha1Vectors) {
    // info="ss-subkey" 的独立 HMAC-SHA1 Extract+Expand 已知答案。
    const std::array<std::array<uint8_t, 32>, 2> expected{{
        {0xf0,0xa4,0xbe,0x5d,0x42,0x09,0xa6,0x16,0x8b,0x93,0x6a,0x2b,0xa4,0x4c,0xa3,0x40},
        {0x7d,0xc1,0x97,0xfc,0xef,0x2d,0xc7,0xe6,0x61,0x03,0x27,0x35,0x76,0x75,0xfc,0x6a,
         0x83,0x16,0x98,0x33,0x5a,0x9b,0x23,0xd1,0x24,0x22,0xa6,0xb2,0x06,0x77,0x91,0xa6}}};
    std::array<uint8_t, 32> key{}, salt{}, warm{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i);
        salt[i] = static_cast<uint8_t>(0xa0 + i);
    }
    EXPECT_TRUE((proxy::DeriveSsSubkey(key.data(), 32, salt.data(), 32, warm.data()))) << "HKDF warmup failed";
    for (size_t index = 0; index < expected.size(); ++index) {
        const size_t size = index ? 32 : 16;
        for (int round = 0; round < 64; ++round) {
            std::array<uint8_t, 34> guarded;
            guarded.fill(0xa5);
            EXPECT_TRUE((proxy::DeriveSsSubkey(key.data(), size, salt.data(), size, guarded.data() + 1))) << "HKDF derivation failed";
            EXPECT_TRUE((std::equal(expected[index].begin(), expected[index].begin() + size,
                             guarded.begin() + 1))) << "HKDF known answer mismatch";
            EXPECT_TRUE((guarded.front() == 0xa5 && guarded[size + 1] == 0xa5)) << "HKDF wrote outside output";
            auto in_place = key;
            EXPECT_TRUE((proxy::DeriveSsSubkey(in_place.data(), size, salt.data(), size, in_place.data()))) << "HKDF in-place derivation failed";
            EXPECT_TRUE((std::equal(expected[index].begin(), expected[index].begin() + size,
                             in_place.begin()))) << "HKDF in-place result mismatch";
        }
    }
    const size_t oversized = static_cast<size_t>(std::numeric_limits<int>::max()) + 1;
    auto output = warm;
    EXPECT_FALSE((proxy::DeriveSsSubkey(nullptr, 32, salt.data(), 32, output.data()))) << "HKDF accepted null key";
    EXPECT_FALSE((proxy::DeriveSsSubkey(key.data(), 32, nullptr, 32, output.data()))) << "HKDF accepted null salt";
    EXPECT_FALSE((proxy::DeriveSsSubkey(key.data(), 32, salt.data(), 32, nullptr))) << "HKDF accepted null output";
    EXPECT_FALSE((proxy::DeriveSsSubkey(key.data(), oversized, salt.data(), 32, output.data()))) << "HKDF accepted oversized key";
    EXPECT_FALSE((proxy::DeriveSsSubkey(key.data(), 32, salt.data(), oversized, output.data()))) << "HKDF accepted oversized salt";
    EXPECT_EQ((output), (warm)) << "invalid HKDF input modified output";
}

std::vector<uint8_t> Flatten(const common::MultiBuffer& mb) {
    std::vector<uint8_t> out;
    out.reserve(mb.byte_size());
    for (const common::Buffer* buffer : mb) {
        EXPECT_TRUE((buffer != nullptr)) << "decoded MultiBuffer contains a null slot";
        if (!buffer) throw std::runtime_error("missing decoded buffer");
        EXPECT_TRUE((buffer->start <= buffer->end && buffer->end <= buffer->capacity)) << "decoded Buffer cursor escaped the payload capacity";
        const auto bytes = buffer->Bytes();
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

void TestLargeRecord(size_t payload_size, proxy::SsCipherType cipher_type) {
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    std::array<uint8_t, 12> nonce{};
    for (size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<uint8_t>(i * 11 + 1);
    }

    std::vector<uint8_t> plaintext(payload_size);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>((i * 131 + i / 17) & 0xff);
    }

    proxy::SsAeadCipher cipher(
        cipher_type,
        key.data(),
        key.size());
    std::vector<uint8_t> ciphertext(
        payload_size + proxy::SsAeadCipher::kTagSize);
    EXPECT_TRUE((cipher.Encrypt(
              nonce.data(),
              plaintext.data(),
              plaintext.size(),
              ciphertext.data()))) << "large Shadowsocks record encryption failed";

    proxy::SsAeadCipher decryptor(cipher_type, key.data(), key.size());
    common::MultiBuffer encrypted;
    EXPECT_TRUE((common::AppendSpanToMultiBuffer(ciphertext, encrypted))) << "encrypted fixture allocation failed";
    common::MultiBuffer decoded;
    EXPECT_TRUE((proxy::DecryptStreamPayload(
              decryptor, nonce, std::move(encrypted), decoded))) << "large Shadowsocks record decrypt failed";

    EXPECT_EQ((decoded.byte_size()), (payload_size)) << "large Shadowsocks record decoded byte count mismatch";
    EXPECT_EQ((Flatten(decoded)), (plaintext)) << "large Shadowsocks record plaintext mismatch";
}

void TestInvalidTagDoesNotPublishPartialPlaintext() {
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce{};
    std::vector<uint8_t> plaintext(common::Buffer::kSize + 257, 0x5a);
    std::vector<uint8_t> ciphertext(
        plaintext.size() + proxy::SsAeadCipher::kTagSize);

    proxy::SsAeadCipher cipher(
        proxy::SsCipherType::AES_256_GCM,
        key.data(),
        key.size());
    EXPECT_TRUE((cipher.Encrypt(
              nonce.data(),
              plaintext.data(),
              plaintext.size(),
              ciphertext.data()))) << "invalid-tag fixture encryption failed";
    ciphertext.back() ^= 0x80;

    proxy::SsAeadCipher decryptor(proxy::SsCipherType::AES_256_GCM, key.data(), key.size());
    common::MultiBuffer encrypted;
    EXPECT_TRUE((common::AppendSpanToMultiBuffer(ciphertext, encrypted))) << "encrypted fixture allocation failed";
    common::MultiBuffer decoded;
    EXPECT_FALSE((proxy::DecryptStreamPayload(
               decryptor, nonce, std::move(encrypted), decoded))) << "invalid Shadowsocks record tag was accepted";
    EXPECT_TRUE((decoded.empty() && decoded.byte_size() == 0)) << "unauthenticated plaintext escaped into the output";
}

class WireReader final : public transport::MultiBufferReader {
public:
    explicit WireReader(const std::vector<uint8_t>& wire,
                        size_t fragment = SIZE_MAX)
        : wire_(wire), fragment_(fragment) {}

    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        if (cut_ < cuts.size() && offset_ == cuts[cut_]) {
            ++cut_;
            const auto executor = co_await net::this_coro::executor;
            net::steady_timer wait(executor);
            wait.expires_at(net::steady_timer::time_point::max());
            net::post(executor, [this] { signal->emit(net::cancellation_type::terminal); });
            IoErrorCode error;
            co_await wait.async_wait(net::redirect_error(net::use_awaitable, error));
            EXPECT_EQ((error), (io_error::operation_aborted)) << "wire interruption did not cancel an actual wait";
            if (empty_on_cancel) co_return common::MultiBuffer{};
            throw IoSystemError(error);
        }
        if (offset_ == wire_.size()) {
            if (fail_at_eof) throw transport::LinkError(common::ErrorCode::BLOCKED);
            co_return common::MultiBuffer{};
        }
        size_t count = std::min(fragment_, wire_.size() - offset_);
        if (cut_ < cuts.size()) count = std::min(count, cuts[cut_] - offset_);
        EXPECT_TRUE((count != 0)) << "invalid encrypted wire cutpoint";
        common::MultiBuffer raw;
        EXPECT_TRUE((common::AppendSpanToMultiBuffer({wire_.data() + offset_, count}, raw))) << "wire input allocation failed";
        offset_ += count;
#ifdef CNODE_TEST_ALLOCATOR
        if (fail_payload_allocation) {
            fail_payload_allocation = false;
            common::reject_next_process_allocation = true;
        }
#endif
        co_return raw;
    }

    std::vector<size_t> cuts;
    net::cancellation_signal* signal = nullptr;
    bool empty_on_cancel = false;
    bool fail_at_eof = false;
    bool fail_payload_allocation = false;

private:
    transport::CancellationSource cancellation_;
    const std::vector<uint8_t>& wire_;
    size_t fragment_;
    size_t offset_ = 0;
    size_t cut_ = 0;
};

constexpr std::array<uint8_t, 32> kRecordKey{
    1, 4, 7, 10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43, 46,
    49, 52, 55, 58, 61, 64, 67, 70, 73, 76, 79, 82, 85, 88, 91, 94};

size_t RecordKeySize(proxy::SsCipherType type) {
    return proxy::BaseCipherType(type) == proxy::SsCipherType::AES_128_GCM ? 16 : 32;
}

void AppendRecord(proxy::SsAeadCipher& cipher, uint64_t& counter,
                  std::span<const uint8_t> plaintext, std::vector<uint8_t>& wire) {
    const size_t start = wire.size();
    wire.resize(start + 2 + 32 + plaintext.size());
    const std::array<uint8_t, 2> length{
        static_cast<uint8_t>(plaintext.size() >> 8), static_cast<uint8_t>(plaintext.size())};
    auto nonce = proxy::MakeNonce(counter++);
    EXPECT_TRUE((cipher.Encrypt(nonce.data(), length.data(), length.size(), wire.data() + start))) << "real record length encryption failed";
    nonce = proxy::MakeNonce(counter++);
    EXPECT_TRUE((cipher.Encrypt(nonce.data(), plaintext.data(), plaintext.size(), wire.data() + start + 18))) << "real record payload encryption failed";
}

void TestReaderResume(proxy::SsCipherType type, uint64_t initial_nonce, bool empty_on_cancel,
                      size_t fragment = 137) {
    proxy::SsAeadCipher encoder(type, kRecordKey.data(), RecordKeySize(type));
    uint64_t nonce = initial_nonce;
    std::vector<uint8_t> wire;
    const std::vector<uint8_t> first{0x01, 0x02, 0x03};
    const size_t max_payload = proxy::Is2022Cipher(type) ? proxy::kSs2022MaxChunkPayload : proxy::kMaxChunkPayload;
    std::vector<uint8_t> second(max_payload);
    AppendRecord(encoder, nonce, first, wire);
    const size_t boundary = wire.size();
    AppendRecord(encoder, nonce, {}, wire); // Empty authenticated data is not EOF.
    const size_t data = wire.size();
    AppendRecord(encoder, nonce, second, wire);
    net::io_context io;
    net::cancellation_signal signal;
    WireReader source(wire, fragment);
    source.signal = &signal;
    source.empty_on_cancel = empty_on_cancel;
    source.cuts = {boundary, boundary, boundary + 1, boundary + 17, boundary + 18,
                   data + 1, data + 17, data + 18, data + 19, data + 4100, wire.size() - 1};
    proxy::BodyReader reader(
        proxy::SsAeadCipher(type, kRecordKey.data(), RecordKeySize(type)),
        initial_nonce, source, max_payload);
    const auto exercise = [&]() -> net::awaitable<void> {
        EXPECT_EQ((Flatten(co_await reader.ReadMultiBuffer())), (first)) << "first real record changed";
        size_t cancelled = 0;
        for (;;) {
            bool interrupted = false;
            try {
                EXPECT_EQ((Flatten(co_await reader.ReadMultiBuffer())), (second)) << "cancelled record resumed with wrong plaintext or nonce";
            } catch (const IoSystemError& error) {
                if (error.code() != io_error::operation_aborted) throw;
                interrupted = true;
            }
            if (!interrupted) break;
            ++cancelled;
            co_await net::this_coro::reset_cancellation_state();
        }
        EXPECT_EQ((cancelled), (source.cuts.size())) << "reader missed a real record cancellation boundary";
        EXPECT_EQ(((co_await reader.ReadMultiBuffer()).byte_size()), (0)) << "clean record boundary was not EOF";
        EXPECT_EQ(((co_await reader.ReadMultiBuffer()).byte_size()), (0)) << "repeated record EOF returned data";
    };
    auto done = net::co_spawn(io, exercise(),
        net::bind_cancellation_slot(signal.slot(), net::use_future));
    io.run();
    done.get();
}

void CheckReaderFailure(const std::vector<uint8_t>& wire, proxy::SsCipherType type,
                        uint64_t nonce, common::ErrorCode expected, bool preceding_record,
                        bool source_fault = false) {
    net::io_context io;
    WireReader source(wire);
    source.fail_at_eof = source_fault;
    proxy::BodyReader reader(
        proxy::SsAeadCipher(type, kRecordKey.data(), RecordKeySize(type)),
        nonce, source);
    const auto exercise = [&]() -> net::awaitable<void> {
        if (preceding_record)
            EXPECT_EQ((Flatten(co_await reader.ReadMultiBuffer())), (std::vector<uint8_t>({7, 8, 9}))) << "valid record preceding corruption was lost";
        for (int retry = 0; retry < 2; ++retry) {
            bool failed = false;
            try { (void)co_await reader.ReadMultiBuffer(); }
            catch (const transport::LinkError& error) { failed = error.code() == expected; }
            EXPECT_TRUE((failed)) << "record failure was replaced by EOF, another error, or nonce recovery";
        }
    };
    auto done = net::co_spawn(io, exercise(), net::use_future);
    io.run();
    done.get();
}

class ShadowsocksReaderFailure : public testing::TestWithParam<
    std::tuple<proxy::SsCipherType, uint64_t>> {};

TEST_P(ShadowsocksReaderFailure, AuthenticationFailureRetiresReader) {
    const auto [type, initial_nonce] = GetParam();
    proxy::SsAeadCipher encoder(type, kRecordKey.data(), RecordKeySize(type));
    uint64_t nonce = initial_nonce;
    std::vector<uint8_t> wire;
    const std::array<uint8_t, 3> plain{7, 8, 9};
    AppendRecord(encoder, nonce, plain, wire);
    const size_t next = wire.size();
    AppendRecord(encoder, nonce, plain, wire);
    for (const size_t tamper : {next, next + 17, wire.size() - 1}) {
        auto corrupted = wire;
        corrupted[tamper] ^= 0x80;
        CheckReaderFailure(corrupted, type, initial_nonce, common::ErrorCode::PROTOCOL_AUTH_FAILED, true);
    }
}

TEST_P(ShadowsocksReaderFailure, TruncatedEofRetiresReader) {
    const auto [type, initial_nonce] = GetParam();
    proxy::SsAeadCipher encoder(type, kRecordKey.data(), RecordKeySize(type));
    uint64_t nonce = initial_nonce;
    std::vector<uint8_t> wire;
    const std::array<uint8_t, 3> plain{7, 8, 9};
    AppendRecord(encoder, nonce, plain, wire);
    const size_t next = wire.size();
    AppendRecord(encoder, nonce, plain, wire);
    for (const size_t size : {next + 1, next + 17, next + 18, next + 19, wire.size() - 1}) {
        const std::vector<uint8_t> truncated(wire.begin(), wire.begin() + size);
        CheckReaderFailure(truncated, type, initial_nonce, common::ErrorCode::PROTOCOL_DECODE_FAILED, true);
    }
}

TEST_P(ShadowsocksReaderFailure, SourceFailureRetiresReader) {
    const auto [type, initial_nonce] = GetParam();
    proxy::SsAeadCipher encoder(type, kRecordKey.data(), RecordKeySize(type));
    uint64_t nonce = initial_nonce;
    std::vector<uint8_t> wire;
    const std::array<uint8_t, 3> plain{7, 8, 9};
    AppendRecord(encoder, nonce, plain, wire);
    const size_t next = wire.size();
    AppendRecord(encoder, nonce, plain, wire);
    std::vector<uint8_t> interrupted(wire.begin(), wire.begin() + next + 1);
    CheckReaderFailure(interrupted, type, initial_nonce, common::ErrorCode::BLOCKED, true, true);
}

TEST_P(ShadowsocksReaderFailure, OversizedAuthenticatedLengthIsRejectedBeforePayload) {
    const auto [type, initial_nonce] = GetParam();
    proxy::SsAeadCipher encoder(type, kRecordKey.data(), RecordKeySize(type));
    std::array<uint8_t, 18> invalid_length{};
    const std::array<uint8_t, 2> oversized{0x40, 0x00};
    const auto first_nonce = proxy::MakeNonce(initial_nonce);
    EXPECT_TRUE((encoder.Encrypt(first_nonce.data(), oversized.data(), 2, invalid_length.data()))) << "oversized authenticated length fixture failed";
    CheckReaderFailure({invalid_length.begin(), invalid_length.end()}, type, initial_nonce,
                       common::ErrorCode::PROTOCOL_DECODE_FAILED, false);
}

TEST(ShadowsocksStreamCrypto, ResetKeyAllowsIndependentAuthenticationTrials) {
    const std::array<uint8_t, 12> nonce{};
    const std::array<uint8_t, 3> plain{17, 31, 91};
    std::array<uint8_t, 19> ciphertext{};
    proxy::SsAeadCipher encoder(proxy::SsCipherType::AES_256_GCM, kRecordKey.data(), 32);
    EXPECT_TRUE((encoder.Encrypt(nonce.data(), plain.data(), plain.size(), ciphertext.data()))) << "trial fixture encryption failed";
    std::array<uint8_t, 32> wrong{};
    proxy::SsAeadCipher trials(proxy::SsCipherType::AES_256_GCM, wrong.data(), 32);
    std::array<uint8_t, 3> decoded{};
    EXPECT_FALSE((trials.Decrypt(nonce.data(), ciphertext.data(), ciphertext.size(), decoded.data()))) << "wrong trial key authenticated";
    for (size_t i = 0; i < 8; ++i) {
        EXPECT_TRUE((trials.ResetKey(kRecordKey.data(), 32) &&
              trials.Decrypt(nonce.data(), ciphertext.data(), ciphertext.size(), decoded.data()) &&
              decoded == plain)) << "reused authentication context failed with correct key";
        EXPECT_TRUE((trials.ResetKey(wrong.data(), 32) &&
              !trials.Decrypt(nonce.data(), ciphertext.data(), ciphertext.size(), decoded.data()))) << "reused authentication context accepted wrong key";
    }
}
#ifdef CNODE_WRAP_MALLOC
TEST(ShadowsocksStreamCrypto, ContextAllocationFailureRejectsConstruction) {
    struct FaultReset {
        ~FaultReset() { fail_cipher_context = false; }
    } reset;
    fail_cipher_context = true;
    bool failed = false;
    try {
        proxy::SsAeadCipher unavailable(proxy::SsCipherType::AES_256_GCM, kRecordKey.data(), 32);
    } catch (const std::bad_alloc&) { failed = true; }
    fail_cipher_context = false;
    EXPECT_TRUE((failed)) << "EVP allocation failure created usable SS state";
}
#endif
#ifdef CNODE_TEST_ALLOCATOR
TEST(ShadowsocksStreamCrypto, PayloadAllocationFailureRetiresReaderWithoutPlaintext) {
    proxy::SsAeadCipher encoder(proxy::SsCipherType::AES_256_GCM, kRecordKey.data(), 32);
    std::vector<uint8_t> wire;
    uint64_t counter = 0;
    const std::vector<uint8_t> large_plain(common::Buffer::kSize + 1, 0x5a);
    AppendRecord(encoder, counter, large_plain, wire);
    net::io_context io;
    WireReader source(wire);
    source.fail_payload_allocation = true;
    proxy::BodyReader reader(
        proxy::SsAeadCipher(proxy::SsCipherType::AES_256_GCM, kRecordKey.data(), 32), 0, source);
    const auto exercise = [&]() -> net::awaitable<void> {
        for (int retry = 0; retry < 2; ++retry) {
            bool failed = false;
            try { (void)co_await reader.ReadMultiBuffer(); }
            catch (const std::bad_alloc&) { failed = true; }
            catch (...) {
                common::reject_next_process_allocation = false;
                throw;
            }
            common::reject_next_process_allocation = false;
            EXPECT_TRUE((failed)) << "payload OOM exposed plaintext or masqueraded as EOF";
        }
    };
    auto done = net::co_spawn(io, exercise(), net::use_future);
    io.run();
    done.get();
}
#endif

}  // namespace

class ShadowsocksLargeRecord : public testing::TestWithParam<std::tuple<size_t, proxy::SsCipherType>> {};

TEST_P(ShadowsocksLargeRecord, AuthenticatesCompletePayloadAcrossBufferBoundary) {
    const auto [size, cipher] = GetParam();
    TestLargeRecord(size, cipher);
}

INSTANTIATE_TEST_SUITE_P(WireBoundaries, ShadowsocksLargeRecord, testing::Values(
    std::tuple{common::Buffer::kSize, proxy::SsCipherType::AES_256_GCM},
    std::tuple{common::Buffer::kSize + size_t{1}, proxy::SsCipherType::AES_256_GCM},
    std::tuple{size_t{proxy::kMaxChunkPayload}, proxy::SsCipherType::AES_256_GCM},
    std::tuple{size_t{proxy::kSs2022MaxChunkPayload}, proxy::SsCipherType::AES_256_GCM_2022}));

TEST(ShadowsocksStreamCrypto, InvalidTagDoesNotPublishPartialPlaintext) {
    TestInvalidTagDoesNotPublishPartialPlaintext();
}

class ShadowsocksReaderResume : public testing::TestWithParam<
    std::tuple<proxy::SsCipherType, uint64_t, bool>> {};

TEST_P(ShadowsocksReaderResume, CancellationRetainsRecordAndNonceProgress) {
    const auto [cipher, nonce, empty_cancel] = GetParam();
    TestReaderResume(cipher, nonce, empty_cancel);
}

INSTANTIATE_TEST_SUITE_P(Classic, ShadowsocksReaderResume, testing::Combine(
    testing::Values(proxy::SsCipherType::AES_128_GCM, proxy::SsCipherType::AES_256_GCM,
                    proxy::SsCipherType::CHACHA20_POLY1305),
    testing::Values(uint64_t{0}, uint64_t{2}), testing::Bool()));
INSTANTIATE_TEST_SUITE_P(Ss2022, ShadowsocksReaderResume, testing::Combine(
    testing::Values(proxy::SsCipherType::AES_128_GCM_2022, proxy::SsCipherType::AES_256_GCM_2022,
                    proxy::SsCipherType::CHACHA20_POLY1305_2022),
    testing::Values(uint64_t{1}, uint64_t{2}), testing::Bool()));

TEST(ShadowsocksStreamCrypto, OneByteFragmentsResumeWithoutNonceDrift) {
    TestReaderResume(proxy::SsCipherType::AES_256_GCM, 2, false, 1);
}

INSTANTIATE_TEST_SUITE_P(Classic, ShadowsocksReaderFailure, testing::Combine(
    testing::Values(proxy::SsCipherType::AES_128_GCM, proxy::SsCipherType::AES_256_GCM,
                    proxy::SsCipherType::CHACHA20_POLY1305),
    testing::Values(uint64_t{0}, uint64_t{2})));

TEST(ShadowsocksStreamCrypto, AesBlocksMatchIndependentVectors) {
    // NIST SP 800-38A F.1.1/F.1.5 的前两块，独立验证批处理而非自生成回环。
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    const std::array<uint8_t, 32> plain{
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    const std::array<std::array<uint8_t, 32>, 2> keys{{
        {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c},
        {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
         0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}}};
    const std::array<std::array<uint8_t, 32>, 2> expected{{
        {0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97,
         0xf5,0xd3,0xd5,0x85,0x03,0xb9,0x69,0x9d,0xe7,0x85,0x89,0x5a,0x96,0xfd,0xba,0xaf},
        {0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8,
         0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70}}};
    for (size_t index = 0; index < keys.size(); ++index) {
        const auto key = std::span<const uint8_t>(keys[index]).first(index ? 32 : 16);
        std::array<uint8_t, 66> guarded;
        guarded.fill(0xa5);
        auto input = std::span<uint8_t>(guarded).subspan<1, 32>();
        auto output = std::span<uint8_t>(guarded).subspan<33, 32>();
        std::copy(plain.begin(), plain.end(), input.begin());
        ASSERT_TRUE(proxy::AesBlocksCrypt<32>(key, input, output, true));
        EXPECT_TRUE(std::equal(output.begin(), output.end(), expected[index].begin()));
        ASSERT_TRUE(proxy::AesBlocksCrypt<32>(key, output, output, false));
        EXPECT_TRUE(std::equal(output.begin(), output.end(), plain.begin()));
        ASSERT_TRUE(proxy::AesBlocksCrypt<32>(key, output, output, true));
        EXPECT_TRUE(std::equal(output.begin(), output.end(), expected[index].begin()));
        EXPECT_TRUE(std::equal(input.begin(), input.end(), plain.begin()));
        EXPECT_EQ(guarded.front(), 0xa5);
        EXPECT_EQ(guarded.back(), 0xa5);
    }
}

TEST(ShadowsocksStreamCrypto, AesBlocksRejectPartialOverlapWithoutMutation) {
    const std::array<uint8_t, 16> key{};
    std::array<uint8_t, 64> output;
    output.fill(0xa5);
    const auto original = output;
    for (bool encrypt : {false, true}) {
        EXPECT_FALSE(proxy::AesBlocksCrypt<32>(key, std::span(output).first<32>(),
            std::span(output).subspan<1, 32>(), encrypt));
        EXPECT_EQ(output, original);
        EXPECT_FALSE(proxy::AesBlocksCrypt<32>(key, std::span(output).subspan<1, 32>(),
            std::span(output).first<32>(), encrypt));
        EXPECT_EQ(output, original);
    }
}
