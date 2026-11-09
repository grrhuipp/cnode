#include <stdexcept>
#include <gtest/gtest.h>

#include "stream_crypto.hpp"
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
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>
#include <vector>

namespace {
thread_local volatile size_t system_allocations = 0;
bool fail_cipher_context = false;
}
#if defined(CNODE_WRAP_MALLOC)
extern "C" void* __real_malloc(size_t);
extern "C" void* __wrap_malloc(size_t size) {
    system_allocations = system_allocations + 1;
    return __real_malloc(size);
}
extern "C" EVP_AEAD_CTX* __real_EVP_AEAD_CTX_new(const EVP_AEAD*, const uint8_t*, size_t, size_t);
extern "C" EVP_AEAD_CTX* __wrap_EVP_AEAD_CTX_new(
    const EVP_AEAD* cipher, const uint8_t* key, size_t key_size, size_t tag_size) {
    return fail_cipher_context ? nullptr : __real_EVP_AEAD_CTX_new(cipher, key, key_size, tag_size);
}
#endif

namespace {


[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

void TestAesBlock() {
    // FIPS 197 single-block AES-128/AES-256 known-answer vectors.
    const std::array<uint8_t, 16> plain{
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const std::array<std::array<uint8_t, 16>, 2> expected{{
        {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a},
        {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89}}};
    std::array<uint8_t, 34> keys{};
    for (size_t i = 0; i < 32; ++i) keys[i + 1] = static_cast<uint8_t>(i);
#if defined(CNODE_WRAP_MALLOC)
    const auto cold = system_allocations;
    auto* ctx = EVP_CIPHER_CTX_new();
    Check(ctx != nullptr && system_allocations > cold, "malloc instrumentation is inactive");
    EVP_CIPHER_CTX_free(ctx);
#endif
    const auto before = system_allocations;
    for (size_t index = 0; index < 2; ++index) {
        const auto key = std::span<const uint8_t>(keys).subspan(1, index ? 32 : 16);
        for (int round = 0; round < 64; ++round) {
            std::array<uint8_t, 18> guarded;
            guarded.fill(0xa5);
            auto output = std::span<uint8_t>(guarded).subspan<1, 16>();
            Check(ss::AesBlocksCrypt<16>(key, plain, output, true), "AES block encrypt failed");
            Check(std::equal(output.begin(), output.end(), expected[index].begin()), "AES known answer mismatch");
            Check(ss::AesBlocksCrypt<16>(key, output, output, false), "AES in-place decrypt failed");
            Check(std::equal(output.begin(), output.end(), plain.begin()), "AES plaintext mismatch");
            Check(ss::AesBlocksCrypt<16>(key, output, output, true), "AES in-place encrypt failed");
            Check(std::equal(output.begin(), output.end(), expected[index].begin()), "AES in-place ciphertext mismatch");
            Check(guarded.front() == 0xa5 && guarded.back() == 0xa5, "AES wrote outside output block");
        }
        std::array<uint8_t, 17> overlap{};
        std::copy(plain.begin(), plain.end(), overlap.begin());
        auto first = std::span<uint8_t>(overlap).first<16>();
        auto shifted = std::span<uint8_t>(overlap).subspan<1, 16>();
        Check(ss::AesBlocksCrypt<16>(key, first, shifted, true), "AES overlapping encrypt failed");
        Check(std::equal(shifted.begin(), shifted.end(), expected[index].begin()),
              "AES overlapping ciphertext mismatch");
        Check(ss::AesBlocksCrypt<16>(key, shifted, first, false), "AES overlapping decrypt failed");
        Check(std::equal(first.begin(), first.end(), plain.begin()), "AES overlapping plaintext mismatch");
    }
#if defined(CNODE_WRAP_MALLOC)
    Check(system_allocations == before, "AES block operation allocated heap memory");
#else
    (void)before;
#endif
    for (size_t size : {size_t(0),size_t(1),size_t(15),size_t(17),size_t(24),size_t(31),size_t(33)}) {
        auto output = plain;
        for (bool encrypt : {false, true}) {
            Check(!ss::AesBlocksCrypt<16>(std::span<const uint8_t>(keys).first(size), plain, output, encrypt),
                  "AES accepted unsupported key size");
            Check(output == plain, "AES invalid key modified output");
        }
    }
}

void TestDeriveSubkey() {
    // Independent HMAC-SHA1 Extract+Expand answers for info="ss-subkey".
    const std::array<std::array<uint8_t, 32>, 2> expected{{
        {0xf0,0xa4,0xbe,0x5d,0x42,0x09,0xa6,0x16,0x8b,0x93,0x6a,0x2b,0xa4,0x4c,0xa3,0x40},
        {0x7d,0xc1,0x97,0xfc,0xef,0x2d,0xc7,0xe6,0x61,0x03,0x27,0x35,0x76,0x75,0xfc,0x6a,
         0x83,0x16,0x98,0x33,0x5a,0x9b,0x23,0xd1,0x24,0x22,0xa6,0xb2,0x06,0x77,0x91,0xa6}}};
    std::array<uint8_t, 32> key{}, salt{}, warm{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i);
        salt[i] = static_cast<uint8_t>(0xa0 + i);
    }
    Check(ss::DeriveSubkey(key.data(), 32, salt.data(), 32, warm.data()),
          "HKDF warmup failed");
    const auto before = system_allocations;
    for (size_t index = 0; index < expected.size(); ++index) {
        const size_t size = index ? 32 : 16;
        for (int round = 0; round < 64; ++round) {
            std::array<uint8_t, 34> guarded;
            guarded.fill(0xa5);
            Check(ss::DeriveSubkey(key.data(), size, salt.data(), size, guarded.data() + 1),
                  "HKDF derivation failed");
            Check(std::equal(expected[index].begin(), expected[index].begin() + size,
                             guarded.begin() + 1), "HKDF known answer mismatch");
            Check(guarded.front() == 0xa5 && guarded[size + 1] == 0xa5,
                  "HKDF wrote outside output");
            auto in_place = key;
            Check(ss::DeriveSubkey(in_place.data(), size, salt.data(), size, in_place.data()),
                  "HKDF in-place derivation failed");
            Check(std::equal(expected[index].begin(), expected[index].begin() + size,
                             in_place.begin()), "HKDF in-place result mismatch");
        }
    }
#if defined(CNODE_WRAP_MALLOC)
    Check(system_allocations == before, "HKDF derivation allocated heap memory");
#else
    (void)before;
#endif
    const size_t oversized = static_cast<size_t>(std::numeric_limits<int>::max()) + 1;
    auto output = warm;
    Check(!ss::DeriveSubkey(nullptr, 32, salt.data(), 32, output.data()), "HKDF accepted null key");
    Check(!ss::DeriveSubkey(key.data(), 32, nullptr, 32, output.data()), "HKDF accepted null salt");
    Check(!ss::DeriveSubkey(key.data(), 32, salt.data(), 32, nullptr), "HKDF accepted null output");
    Check(!ss::DeriveSubkey(key.data(), oversized, salt.data(), 32, output.data()), "HKDF accepted oversized key");
    Check(!ss::DeriveSubkey(key.data(), 32, salt.data(), oversized, output.data()), "HKDF accepted oversized salt");
    Check(output == warm, "invalid HKDF input modified output");
}

std::vector<uint8_t> Flatten(const buf::MultiBuffer& mb) {
    std::vector<uint8_t> out;
    out.reserve(mb.byte_size());
    for (const buf::Buffer* buffer : mb) {
        Check(buffer != nullptr, "decoded MultiBuffer contains a null slot");
        Check(buffer->start <= buffer->end && buffer->end <= buf::Buffer::kSize,
              "decoded Buffer cursor escaped the 8KB payload");
        const auto bytes = buffer->Bytes();
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

void TestLargeRecord(size_t payload_size, ss::SsCipherType cipher_type) {
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

    ss::SsAeadCipher cipher(
        cipher_type,
        key.data(),
        key.size(), proxy::AeadDirection::Encrypt);
    std::vector<uint8_t> ciphertext(
        payload_size + ss::SsAeadCipher::kTagSize);
    Check(cipher.Encrypt(
              nonce.data(),
              plaintext.data(),
              plaintext.size(),
              ciphertext.data()),
          "large Shadowsocks record encryption failed");

    ss::SsAeadCipher decryptor(cipher_type, key.data(), key.size(), proxy::AeadDirection::Decrypt);
    buf::MultiBuffer encrypted;
    Check(buf::AppendSpanToMultiBuffer(ciphertext, encrypted),
          "encrypted fixture allocation failed");
    buf::MultiBuffer decoded;
    Check(ss::detail::DecryptStreamPayload(
              decryptor, nonce, std::move(encrypted), decoded),
          "large Shadowsocks record decrypt failed");

    Check(decoded.byte_size() == payload_size,
          "large Shadowsocks record decoded byte count mismatch");
    Check(Flatten(decoded) == plaintext,
          "large Shadowsocks record plaintext mismatch");
}

void TestInvalidTagDoesNotPublishPartialPlaintext() {
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce{};
    std::vector<uint8_t> plaintext(buf::Buffer::kSize + 257, 0x5a);
    std::vector<uint8_t> ciphertext(
        plaintext.size() + ss::SsAeadCipher::kTagSize);

    ss::SsAeadCipher cipher(
        ss::SsCipherType::AES_256_GCM,
        key.data(),
        key.size(), proxy::AeadDirection::Encrypt);
    Check(cipher.Encrypt(
              nonce.data(),
              plaintext.data(),
              plaintext.size(),
              ciphertext.data()),
          "invalid-tag fixture encryption failed");
    ciphertext.back() ^= 0x80;

    ss::SsAeadCipher decryptor(ss::SsCipherType::AES_256_GCM, key.data(), key.size(),
                               proxy::AeadDirection::Decrypt);
    buf::MultiBuffer encrypted;
    Check(buf::AppendSpanToMultiBuffer(ciphertext, encrypted),
          "encrypted fixture allocation failed");
    buf::MultiBuffer decoded;
    Check(!ss::detail::DecryptStreamPayload(
               decryptor, nonce, std::move(encrypted), decoded),
          "invalid Shadowsocks record tag was accepted");
    Check(decoded.empty() && decoded.byte_size() == 0,
          "unauthenticated plaintext escaped into the output");
}

class WireReader final : public transport::MultiBufferReader {
public:
    explicit WireReader(const std::vector<uint8_t>& wire, size_t fragment = SIZE_MAX)
        : wire_(wire), fragment_(fragment) {}

    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (cut_ < cuts.size() && offset_ == cuts[cut_]) {
            ++cut_;
            const auto executor = co_await net::this_coro::executor;
            net::steady_timer wait(executor);
            wait.expires_at(net::steady_timer::time_point::max());
            net::post(executor, [this] { signal->emit(net::cancellation_type::terminal); });
            IoErrorCode error;
            co_await wait.async_wait(net::redirect_error(net::use_awaitable, error));
            Check(error == io_error::operation_aborted, "wire interruption did not cancel an actual wait");
            if (empty_on_cancel) co_return buf::MultiBuffer{};
            throw IoSystemError(error);
        }
        if (offset_ == wire_.size()) {
            if (fail_at_eof) throw transport::LinkError(ErrorCode::BLOCKED);
            co_return buf::MultiBuffer{};
        }
        size_t count = std::min(fragment_, wire_.size() - offset_);
        if (cut_ < cuts.size()) count = std::min(count, cuts[cut_] - offset_);
        Check(count != 0, "invalid encrypted wire cutpoint");
        buf::MultiBuffer raw;
        Check(buf::AppendSpanToMultiBuffer({wire_.data() + offset_, count}, raw),
              "wire input allocation failed");
        offset_ += count;
#ifdef CNODE_TEST_ALLOCATOR_FAULT
        if (fail_payload_allocation) {
            fail_payload_allocation = false;
            memory::reject_next_pmr_allocation = true;
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

size_t RecordKeySize(ss::SsCipherType type) {
    return ss::BaseCipherType(type) == ss::SsCipherType::AES_128_GCM ? 16 : 32;
}

void AppendRecord(ss::SsAeadCipher& cipher, uint64_t& counter,
                  std::span<const uint8_t> plaintext, std::vector<uint8_t>& wire) {
    const size_t start = wire.size();
    wire.resize(start + 2 + 32 + plaintext.size());
    const std::array<uint8_t, 2> length{
        static_cast<uint8_t>(plaintext.size() >> 8), static_cast<uint8_t>(plaintext.size())};
    auto nonce = ss::detail::MakeNonce(counter++);
    Check(cipher.Encrypt(nonce.data(), length.data(), length.size(), wire.data() + start),
          "real record length encryption failed");
    nonce = ss::detail::MakeNonce(counter++);
    Check(cipher.Encrypt(nonce.data(), plaintext.data(), plaintext.size(), wire.data() + start + 18),
          "real record payload encryption failed");
}

void TestReaderResume(ss::SsCipherType type, uint64_t initial_nonce, bool empty_on_cancel,
                      size_t fragment = 137) {
    ss::SsAeadCipher encoder(type, kRecordKey.data(), RecordKeySize(type), proxy::AeadDirection::Encrypt);
    uint64_t nonce = initial_nonce;
    std::vector<uint8_t> wire;
    const std::vector<uint8_t> first{0x01, 0x02, 0x03};
    const size_t max_payload = ss::Is2022Cipher(type) ? ss::kSs2022MaxChunkPayload : ss::kMaxChunkPayload;
    std::vector<uint8_t> second(max_payload);
    for (size_t i = 0; i < second.size(); ++i) second[i] = static_cast<uint8_t>(i * 11);
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
    ss::detail::BodyReader reader(
        ss::SsAeadCipher(type, kRecordKey.data(), RecordKeySize(type), proxy::AeadDirection::Decrypt),
        initial_nonce, source, max_payload);
    const auto exercise = [&]() -> net::awaitable<void> {
        Check(Flatten(co_await reader.ReadMultiBuffer()) == first, "first real record changed");
        size_t cancelled = 0;
        for (;;) {
            bool interrupted = false;
            try {
                Check(Flatten(co_await reader.ReadMultiBuffer()) == second,
                      "cancelled record resumed with wrong plaintext or nonce");
            } catch (const IoSystemError& error) {
                if (error.code() != io_error::operation_aborted) throw;
                interrupted = true;
            }
            if (!interrupted) break;
            ++cancelled;
            co_await net::this_coro::reset_cancellation_state();
        }
        Check(cancelled == source.cuts.size(), "reader missed a real record cancellation boundary");
        Check((co_await reader.ReadMultiBuffer()).byte_size() == 0, "clean record boundary was not EOF");
        Check((co_await reader.ReadMultiBuffer()).byte_size() == 0, "repeated record EOF returned data");
    };
    auto done = net::co_spawn(io, exercise(),
        net::bind_cancellation_slot(signal.slot(), net::use_future));
    io.run();
    done.get();
}

void CheckReaderFailure(const std::vector<uint8_t>& wire, ss::SsCipherType type,
                        uint64_t nonce, ErrorCode expected, bool preceding_record,
                        bool source_fault = false) {
    net::io_context io;
    WireReader source(wire);
    source.fail_at_eof = source_fault;
    ss::detail::BodyReader reader(
        ss::SsAeadCipher(type, kRecordKey.data(), RecordKeySize(type), proxy::AeadDirection::Decrypt),
        nonce, source);
    const auto exercise = [&]() -> net::awaitable<void> {
        if (preceding_record)
            Check(Flatten(co_await reader.ReadMultiBuffer()) == std::vector<uint8_t>({7, 8, 9}),
                  "valid record preceding corruption was lost");
        for (int retry = 0; retry < 2; ++retry) {
            bool failed = false;
            try { (void)co_await reader.ReadMultiBuffer(); }
            catch (const transport::LinkError& error) { failed = error.code() == expected; }
            Check(failed, "record failure was replaced by EOF, another error, or nonce recovery");
        }
    };
    auto done = net::co_spawn(io, exercise(), net::use_future);
    io.run();
    done.get();
}

void TestReaderFailures(ss::SsCipherType type, uint64_t initial_nonce) {
    ss::SsAeadCipher encoder(type, kRecordKey.data(), RecordKeySize(type), proxy::AeadDirection::Encrypt);
    uint64_t nonce = initial_nonce;
    std::vector<uint8_t> wire;
    const std::array<uint8_t, 3> plain{7, 8, 9};
    AppendRecord(encoder, nonce, plain, wire);
    const size_t next = wire.size();
    AppendRecord(encoder, nonce, plain, wire);
    for (const size_t tamper : {next, next + 17, wire.size() - 1}) {
        auto corrupted = wire;
        corrupted[tamper] ^= 0x80;
        CheckReaderFailure(corrupted, type, initial_nonce, ErrorCode::PROTOCOL_AUTH_FAILED, true);
    }
    for (const size_t size : {next + 1, next + 17, next + 18, next + 19, wire.size() - 1}) {
        const std::vector<uint8_t> truncated(wire.begin(), wire.begin() + size);
        CheckReaderFailure(truncated, type, initial_nonce, ErrorCode::PROTOCOL_DECODE_FAILED, true);
    }
    std::vector<uint8_t> interrupted(wire.begin(), wire.begin() + next + 1);
    CheckReaderFailure(interrupted, type, initial_nonce, ErrorCode::BLOCKED, true, true);
    // Authenticated length outside the classic wire limit must fail before
    // waiting for (or allocating) the claimed payload.
    std::array<uint8_t, 18> invalid_length{};
    const std::array<uint8_t, 2> oversized{0x40, 0x00};
    const auto first_nonce = ss::detail::MakeNonce(initial_nonce);
    Check(encoder.Encrypt(first_nonce.data(), oversized.data(), 2, invalid_length.data()),
          "oversized authenticated length fixture failed");
    CheckReaderFailure({invalid_length.begin(), invalid_length.end()}, type, initial_nonce,
                       ErrorCode::PROTOCOL_DECODE_FAILED, false);
}

void TestContextLifetime() {
    const std::array<uint8_t, 12> nonce{};
    const std::array<uint8_t, 3> plain{17, 31, 91};
    std::array<uint8_t, 19> ciphertext{};
    ss::SsAeadCipher encoder(ss::SsCipherType::AES_256_GCM, kRecordKey.data(), 32,
                              proxy::AeadDirection::Encrypt);
    Check(encoder.Encrypt(nonce.data(), plain.data(), plain.size(), ciphertext.data()),
          "trial fixture encryption failed");
    std::array<uint8_t, 32> wrong{};
    ss::SsAeadCipher trials(ss::SsCipherType::AES_256_GCM, wrong.data(), 32,
                             proxy::AeadDirection::Decrypt);
    std::array<uint8_t, 3> decoded{};
    Check(!trials.Decrypt(nonce.data(), ciphertext.data(), ciphertext.size(), decoded.data()),
          "wrong trial key authenticated");
    for (size_t i = 0; i < 8; ++i) {
        Check(trials.ResetKey(kRecordKey.data(), 32) &&
              trials.Decrypt(nonce.data(), ciphertext.data(), ciphertext.size(), decoded.data()) &&
              decoded == plain, "reused authentication context failed with correct key");
        Check(trials.ResetKey(wrong.data(), 32) &&
              !trials.Decrypt(nonce.data(), ciphertext.data(), ciphertext.size(), decoded.data()),
              "reused authentication context accepted wrong key");
    }
#ifdef CNODE_WRAP_MALLOC
    fail_cipher_context = true;
    bool failed = false;
    try {
        ss::SsAeadCipher unavailable(ss::SsCipherType::AES_256_GCM, kRecordKey.data(), 32,
                                     proxy::AeadDirection::Decrypt);
    } catch (const std::bad_alloc&) { failed = true; }
    fail_cipher_context = false;
    Check(failed, "EVP allocation failure created usable SS state");
#endif
#ifdef CNODE_TEST_ALLOCATOR_FAULT
    std::vector<uint8_t> wire;
    uint64_t counter = 0;
    const std::vector<uint8_t> large_plain(buf::Buffer::kSize + 1, 0x5a);
    AppendRecord(encoder, counter, large_plain, wire);
    net::io_context io;
    WireReader source(wire);
    source.fail_payload_allocation = true;
    ss::detail::BodyReader reader(
        ss::SsAeadCipher(ss::SsCipherType::AES_256_GCM, kRecordKey.data(), 32,
                         proxy::AeadDirection::Decrypt), 0, source);
    const auto exercise = [&]() -> net::awaitable<void> {
        for (int retry = 0; retry < 2; ++retry) {
            bool failed = false;
            try { (void)co_await reader.ReadMultiBuffer(); }
            catch (const std::bad_alloc&) { failed = true; }
            Check(failed, "payload OOM exposed plaintext or masqueraded as EOF");
        }
    };
    auto done = net::co_spawn(io, exercise(), net::use_future);
    io.run();
    done.get();
#endif
}

}  // namespace

TEST(ShadowsocksStreamCrypto, Contract) {
    TestAesBlock();
    TestDeriveSubkey();
    TestLargeRecord(buf::Buffer::kSize, ss::SsCipherType::AES_256_GCM);
    TestLargeRecord(buf::Buffer::kSize + 1, ss::SsCipherType::AES_256_GCM);
    TestLargeRecord(ss::kMaxChunkPayload, ss::SsCipherType::AES_256_GCM);
    for (size_t i = 0; i < 16; ++i) {
        TestLargeRecord(
            ss::kSs2022MaxChunkPayload,
            ss::SsCipherType::AES_256_GCM_2022);
    }
    TestInvalidTagDoesNotPublishPartialPlaintext();
    TestContextLifetime();
    for (const auto cipher : {ss::SsCipherType::AES_128_GCM, ss::SsCipherType::AES_256_GCM,
                               ss::SsCipherType::CHACHA20_POLY1305}) {
        for (const uint64_t nonce : {uint64_t{0}, uint64_t{2}}) {
            for (const bool empty_cancel : {false, true}) TestReaderResume(cipher, nonce, empty_cancel);
            TestReaderFailures(cipher, nonce);
        }
    }
    for (const auto cipher : {ss::SsCipherType::AES_128_GCM_2022, ss::SsCipherType::AES_256_GCM_2022,
                               ss::SsCipherType::CHACHA20_POLY1305_2022}) {
        for (const uint64_t nonce : {uint64_t{1}, uint64_t{2}})
            for (const bool empty_cancel : {false, true}) TestReaderResume(cipher, nonce, empty_cancel);
    }
    TestReaderResume(ss::SsCipherType::AES_256_GCM, 2, false, 1);
    std::cout << "shadowsocks_stream_crypto_test: ok\n";
}

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
        ASSERT_TRUE(ss::AesBlocksCrypt<32>(key, input, output, true));
        EXPECT_TRUE(std::equal(output.begin(), output.end(), expected[index].begin()));
        ASSERT_TRUE(ss::AesBlocksCrypt<32>(key, output, output, false));
        EXPECT_TRUE(std::equal(output.begin(), output.end(), plain.begin()));
        ASSERT_TRUE(ss::AesBlocksCrypt<32>(key, output, output, true));
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
        EXPECT_FALSE(ss::AesBlocksCrypt<32>(key, std::span(output).first<32>(),
            std::span(output).subspan<1, 32>(), encrypt));
        EXPECT_EQ(output, original);
        EXPECT_FALSE(ss::AesBlocksCrypt<32>(key, std::span(output).subspan<1, 32>(),
            std::span(output).first<32>(), encrypt));
        EXPECT_EQ(output, original);
    }
}
