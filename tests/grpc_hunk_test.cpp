#include "grpc_hunk.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string_view>
#include <vector>

namespace {
using namespace acpp::transport::internet;
bool measuring = false;
size_t largest = 0, allocated = 0, denied = 0, live_large = 0, peak_large = 0, checks = 0;
size_t allocation_limit = kMaxGrpcHunkMessageSize;
struct Allocation { void* pointer = nullptr; size_t size = 0; };
std::array<Allocation, 64> tracked;

void Check(bool condition, const char* message) {
    ++checks;
    if (!condition) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}

void Forget(void* pointer) noexcept {
    for (auto& item : tracked) if (item.pointer == pointer && pointer) {
        live_large -= item.size;
        item = {};
        break;
    }
}
}  // namespace

void* operator new(size_t size) {
    if (measuring) {
        largest = std::max(largest, size);
        allocated += size;
        if (size > allocation_limit) { ++denied; throw std::bad_alloc(); }
    }
    void* pointer = std::malloc(size ? size : 1);
    if (!pointer) throw std::bad_alloc();
    if (measuring && size > 4096) {
        for (auto& item : tracked) if (!item.pointer) {
            item = {pointer, size}; live_large += size;
            peak_large = std::max(peak_large, live_large);
            return pointer;
        }
        std::abort();
    }
    return pointer;
}
void operator delete(void* pointer) noexcept { Forget(pointer); std::free(pointer); }
void operator delete(void* pointer, size_t) noexcept { ::operator delete(pointer); }
void* operator new(size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void operator delete(void* pointer, const std::nothrow_t&) noexcept { ::operator delete(pointer); }

namespace {
using Bytes = std::vector<uint8_t>;

std::array<uint8_t, 5> Prefix(uint32_t size) {
    return {0, uint8_t(size >> 24), uint8_t(size >> 16), uint8_t(size >> 8), uint8_t(size)};
}
void Varint(Bytes& bytes, uint32_t value) {
    do { bytes.push_back(uint8_t(value & 127) | (value >= 128 ? 128 : 0)); value >>= 7; } while (value);
}
Bytes Frame(const Bytes& message) {
    const auto prefix = Prefix(static_cast<uint32_t>(message.size()));
    Bytes bytes(prefix.begin(), prefix.end());
    bytes.insert(bytes.end(), message.begin(), message.end());
    return bytes;
}
void Case(const Bytes& bytes, std::string_view expected, bool valid) {
    for (size_t fragment : {size_t{1}, size_t{2}, size_t{5}, size_t{13}, size_t{8192}}) {
        GrpcHunkDecoder decoder;
        Bytes decoded;
        bool accepted = true;
        size_t offset = 0;
        while (offset < bytes.size()) {
            const auto result = decoder.Feed(std::span<const uint8_t>(bytes).subspan(
                offset, std::min(fragment, bytes.size() - offset)));
            if (!result) { accepted = false; break; }
            Check(*result > 0, "decoder made no progress");
            offset += *result;
            const auto payload = decoder.Payload();
            decoded.insert(decoded.end(), payload.begin(), payload.end());
            if (!payload.empty()) decoder.Consume(payload.size());
        }
        accepted &= decoder.AtMessageBoundary();
        Check(accepted == valid, "unexpected Hunk acceptance");
        if (valid) Check(std::string_view(reinterpret_cast<const char*>(decoded.data()), decoded.size()) == expected,
                         "incorrect Hunk data or message boundary");
        else Check(decoded.empty(), "invalid message exposed data before full validation");
    }
}
}  // namespace

int main() {
    for (uint32_t size : {1024u, 4194304u, 4194305u, UINT32_MAX}) {
        GrpcHunkDecoder decoder;
        largest = allocated = denied = 0; allocation_limit = 1024 * 1024; measuring = true;
        const auto result = decoder.Feed(Prefix(size));
        measuring = false;
        Check(bool(result) == (size <= kMaxGrpcHunkMessageSize), "message limit not checked at prefix");
        Check(largest == 0 && allocated == 0 && denied == 0, "prefix alone allocated message storage");
        std::printf("hunk-prefix declared=%u largest=%zu denied=%zu accepted=%d: PASS\n", size, largest, denied, bool(result));
    }
    {
        GrpcHunkDecoder partial;
        Check(bool(partial.Feed(Prefix(static_cast<uint32_t>(kMaxGrpcHunkMessageSize)))), "partial message header rejected");
        largest = allocated = denied = 0; measuring = true;
        const std::array<uint8_t, 2> bytes{0x0a, 0xff};
        Check(bool(partial.Feed(bytes)) && partial.Payload().empty() && !partial.AtMessageBoundary(),
              "partial body was treated as a complete message");
        Check(largest <= 4096 && denied == 0, "partial body allocated its advertised length");
        partial.Clear();
        measuring = false;
        std::printf("hunk-partial received=2 declared=4194304 largest=%zu: PASS\n", largest);
    }
    Case(Frame({0x0a, 3, 'a', 'b', 'c'}), "abc", true);
    Case(Frame({}), "", true);
    Case(Frame({0x0a, 0}), "", true);
    Case(Frame({0x0a, 3, 'o', 'l', 'd', 0x0a, 3, 'n', 'e', 'w'}), "new", true);
    Case(Frame({0x0a, 3, 'o', 'l', 'd', 0x0a, 0}), "", true);
    Case(Frame({0x10, 0x96, 1, 0x1a, 1, 'x', 0x0a, 1, 'a', 0x25, 0, 0, 0, 0}), "a", true);
    Case(Frame({0x13, 0x1b, 0x20, 1, 0x1c, 0x14, 0x0a, 1, 'g'}), "g", true);
    Case(Frame({0x08, 0, 0x0a, 1, 'a'}), "a", true);
    Case(Frame({0}), "", false);
    Case(Frame({0x0a, 1, 'a', 0}), "", false);
    Case(Frame({0x0a, 1, 'a', 0x1a, 4, 0}), "", false);
    Case(Frame({0x0a, 2, 'a'}), "", false);
    Case(Frame({0x0a, 0x80}), "", false);
    Case(Frame({0x13, 0x1c}), "", false);
    Case(Frame({0x14}), "", false);
    Case(Frame({0x16}), "", false);
    Case(Frame({0x17}), "", false);
    Case(Frame({0x19, 0, 0}), "", false);
    Case(Frame({0x80, 0x80, 0x80, 0x80, 0x10, 0}), "", false);
    Bytes max_varint{0x10}; max_varint.insert(max_varint.end(), 9, 0xff); max_varint.push_back(1);
    Case(Frame(max_varint), "", true);
    max_varint.back() = 2; Case(Frame(max_varint), "", false);
    Bytes groups(100, 0x13); groups.insert(groups.end(), 100, 0x14); Case(Frame(groups), "", true);
    groups.insert(groups.begin(), 0x13); groups.push_back(0x14); Case(Frame(groups), "", false);
    auto compressed = Frame({}); compressed[0] = 1; Case(compressed, "", false);
    Bytes combined = Frame({});
    for (const auto body : {Bytes{0x0a, 1, 'a'}, Bytes{0x0a, 0}, Bytes{0x0a, 1, 'b'}}) {
        const auto next = Frame(body); combined.insert(combined.end(), next.begin(), next.end());
    }
    Case(combined, "ab", true);
    const auto complete = Frame({0x0a, 3, 'a', 'b', 'c'});
    for (size_t size = 1; size < complete.size(); ++size) {
        Case(Bytes(complete.begin(), complete.begin() + size), "", false);
    }

    Bytes large{0x0a}; Varint(large, static_cast<uint32_t>(kMaxGrpcHunkMessageSize - 5));
    large.resize(kMaxGrpcHunkMessageSize, 0x5a);
    GrpcHunkDecoder decoder;
    Check(bool(decoder.Feed(Prefix(static_cast<uint32_t>(large.size())))), "maximum header rejected");
    largest = allocated = denied = peak_large = 0; allocation_limit = kMaxGrpcHunkMessageSize; measuring = true;
    for (size_t offset = 0; offset < large.size();) {
        const auto result = decoder.Feed(std::span<const uint8_t>(large).subspan(offset, std::min(size_t{16384}, large.size() - offset)));
        Check(bool(result) && *result > 0, "maximum message rejected");
        offset += *result;
        if (offset != large.size()) Check(decoder.Payload().empty(), "incomplete message exposed payload");
    }
    const auto payload = decoder.Payload();
    Check(payload.size() == kMaxGrpcHunkMessageSize - 5 &&
          std::all_of(payload.begin(), payload.end(), [](uint8_t value) { return value == 0x5a; }), "maximum payload changed");
    Check(denied == 0 && largest <= kMaxGrpcHunkMessageSize && live_large <= kMaxGrpcHunkMessageSize &&
          peak_large <= 2 * kMaxGrpcHunkMessageSize,
          "message storage exceeded its budget");
    decoder.Consume(payload.size());
    Check(live_large == 0, "consumed message retained large storage");
    measuring = false;
    std::printf("hunk-codec checks=%zu largest=%zu total=%zu peak=%zu live=%zu: PASS\n", checks, largest, allocated, peak_large, live_large);
}
