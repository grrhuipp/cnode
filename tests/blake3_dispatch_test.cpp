extern "C" {
#include "blake3_impl.h"
}

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

bool CheckCompression() {
    std::array<uint8_t, 64> block{};
    for (size_t i = 0; i < block.size(); ++i) block[i] = static_cast<uint8_t>(i * 3);
    for (uint8_t length : {0, 1, 31, 63, 64}) {
        for (uint8_t flags : std::array<uint8_t, 6>{0, CHUNK_START | CHUNK_END, ROOT,
                             KEYED_HASH | ROOT, DERIVE_KEY_CONTEXT | ROOT,
                             DERIVE_KEY_MATERIAL | ROOT}) {
            for (uint64_t counter : {uint64_t{0}, uint64_t{1}, uint64_t{0xffffffff},
                                     uint64_t{0x100000001}}) {
                std::array<uint32_t, 8> expected{}, actual{};
                std::copy_n(IV, 8, expected.begin());
                actual = expected;
                blake3_compress_in_place_portable(expected.data(), block.data(), length, counter, flags);
                blake3_compress_in_place(actual.data(), block.data(), length, counter, flags);
                if (expected != actual) return false;
                std::array<uint8_t, 64> expected_xof{}, actual_xof{};
                blake3_compress_xof_portable(IV, block.data(), length, counter, flags, expected_xof.data());
                blake3_compress_xof(IV, block.data(), length, counter, flags, actual_xof.data());
                if (expected_xof != actual_xof) return false;
                std::array<uint8_t, 17 * 64> xof{};
                blake3_xof_many(IV, block.data(), length, counter, flags, xof.data(), 17);
                for (size_t i = 0; i < 17; ++i) {
                    blake3_compress_xof_portable(IV, block.data(), length, counter + i,
                                               flags, expected_xof.data());
                    if (!std::equal(expected_xof.begin(), expected_xof.end(), xof.begin() + i * 64))
                        return false;
                }
            }
        }
    }
    return true;
}

bool CheckHashMany() {
    std::array<std::array<uint8_t, 1024>, 17> input{};
    std::array<const uint8_t*, 17> pointers{};
    for (size_t n = 0; n < input.size(); ++n) {
        for (size_t i = 0; i < input[n].size(); ++i)
            input[n][i] = static_cast<uint8_t>((i + n * 17) % 251);
        pointers[n] = input[n].data();
    }
    for (size_t count : {1, 2, 3, 4, 7, 8, 15, 16, 17}) {
        for (size_t blocks : {1, 16}) {
            for (bool increment : {false, true}) {
                std::array<uint8_t, 17 * 32> expected{}, actual{};
                blake3_hash_many_portable(pointers.data(), count, blocks, IV, 0xffffffff,
                                         increment, KEYED_HASH, CHUNK_START, CHUNK_END, expected.data());
                blake3_hash_many(pointers.data(), count, blocks, IV, 0xffffffff,
                                increment, KEYED_HASH, CHUNK_START, CHUNK_END, actual.data());
                if (expected != actual) return false;
            }
        }
    }
    // Official empty-input digest: also test the public hasher entry point.
    constexpr std::array<uint8_t, 32> empty_hash{
        0xaf,0x13,0x49,0xb9,0xf5,0xf9,0xa1,0xa6,0xa0,0x40,0x4d,0xea,0x36,0xdc,0xc9,0x49,
        0x9b,0xcb,0x25,0xc9,0xad,0xc1,0x12,0xb7,0xcc,0x9a,0x93,0xca,0xe4,0x1f,0x32,0x62};
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    std::array<uint8_t, 32> digest{};
    blake3_hasher_finalize(&hasher, digest.data(), digest.size());
    return digest == empty_hash;
}

void Benchmark() {
    std::array<uint8_t, 64> block{}, output{};
    constexpr size_t rounds = 1000000;
    auto run = [&](auto compress) {
        const auto start = std::chrono::steady_clock::now();
        for (size_t i = 0; i < rounds; ++i)
            compress(IV, block.data(), 64, i, ROOT, output.data());
        return std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count();
    };
    const auto portable = run(blake3_compress_xof_portable);
    const auto dispatched = run(blake3_compress_xof);
    std::printf("compression x%zu: portable=%.2fms dispatched=%.2fms ratio=%.2fx checksum=%u\n",
                rounds, portable, dispatched, portable / dispatched, unsigned(output[0]));
}

} // namespace

int main(int argc, char** argv) {
#ifdef CNODE_EXPECT_PORTABLE
    if (blake3_simd_degree() != 1) return 1;
#endif
    if (!CheckCompression() || !CheckHashMany()) {
        std::fprintf(stderr, "BLAKE3 dispatch differs from portable reference\n");
        return 1;
    }
    std::printf("BLAKE3 runtime dispatch matches portable; SIMD degree=%zu\n", blake3_simd_degree());
    if (argc == 2 && std::strcmp(argv[1], "--benchmark") == 0) Benchmark();
    return 0;
}
