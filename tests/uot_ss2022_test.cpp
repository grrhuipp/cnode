#include "uot.hpp"

#include "shadowsocks_protocol.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <future>
#include <iostream>
#include <span>
#include <string>
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

std::vector<uint8_t> Flatten(const buf::MultiBuffer& mb) {
    std::vector<uint8_t> out;
    out.reserve(buf::TotalLen(mb));
    for (const buf::Buffer* buffer : mb) {
        if (!buffer || buffer->IsEmpty()) {
            continue;
        }
        const auto bytes = buffer->Bytes();
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

buf::MultiBuffer MakePacket(std::string_view payload, const TargetAddress& target) {
    buf::MultiBuffer packet;
    Check(buf::AppendSpanToMultiBuffer(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(payload.data()), payload.size()),
        packet), "packet allocation failed");
    for (buf::Buffer* buffer : packet) {
        if (buffer) {
            buffer->SetUDP(target);
        }
    }
    return packet;
}

class CaptureWriter final : public transport::MultiBufferWriter {
public:
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        for (const buf::Buffer* buffer : mb) {
            if (!buffer || buffer->IsEmpty()) {
                continue;
            }
            const auto span = buffer->Bytes();
            bytes.insert(bytes.end(), span.begin(), span.end());
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

class FragmentReader final : public transport::MultiBufferReader {
public:
    FragmentReader(std::vector<uint8_t> bytes, std::vector<size_t> fragments)
        : bytes_(std::move(bytes)), fragments_(std::move(fragments)) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (offset_ >= bytes_.size()) {
            co_return buf::MultiBuffer{};
        }
        const size_t requested = fragment_index_ < fragments_.size()
            ? fragments_[fragment_index_++]
            : bytes_.size() - offset_;
        const size_t size = std::min(requested, bytes_.size() - offset_);
        buf::MultiBuffer out;
        if (!buf::AppendSpanToMultiBuffer(
                std::span<const uint8_t>(bytes_.data() + offset_, size), out)) {
            Fail("reader allocation failed");
        }
        offset_ += size;
        co_return out;
    }

private:
    std::vector<uint8_t> bytes_;
    std::vector<size_t> fragments_;
    size_t offset_ = 0;
    size_t fragment_index_ = 0;
};

template <typename Factory>
void Run(Factory&& factory) {
    net::io_context io_context;
    auto future = net::co_spawn(
        io_context,
        std::forward<Factory>(factory)(),
        net::use_future);
    io_context.run();
    future.get();
}

void TestV2BoardSs2022Keys() {
    const auto cipher = ss::ParseCipherMethod("2022-blake3-aes-256-gcm");
    Check(cipher.has_value(), "SS2022 cipher was not parsed");

    constexpr std::string_view uuid = "01234567-89ab-cdef-0123-456789abcdef";
    constexpr std::string_view prefix = "01234567-89ab-cdef-0123-456789ab";
    constexpr std::string_view user_psk =
        "MDEyMzQ1NjctODlhYi1jZGVmLTAxMjMtNDU2Nzg5YWI=";
    constexpr std::string_view server_psk =
        "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";

    const auto uuid_key = ss::Build2022UserKeyFromUuid(uuid, *cipher);
    Check(uuid_key.size == 32, "UUID-derived user key length mismatch");
    Check(std::memcmp(uuid_key.data(), prefix.data(), prefix.size()) == 0,
          "UUID-derived user key bytes mismatch");

    const auto decoded_user = ss::Decode2022Psk(user_psk, cipher->key_size);
    Check(decoded_user.size == uuid_key.size &&
          std::memcmp(decoded_user.data(), uuid_key.data(), uuid_key.size) == 0,
          "subscription user PSK does not match runtime UUID key");

    const auto decoded_server = ss::Decode2022Psk(server_psk, cipher->key_size);
    Check(decoded_server.size == 32, "server identity PSK length mismatch");
    Check(ss::Decode2022Psk(
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYw", cipher->key_size).empty(),
        "oversized SS2022 PSK was accepted");
}

void TestMagicAndRequestCodec() {
    Check(proxy::uot::VersionFromMagicAddress(
        TargetAddress(proxy::uot::kMagicAddress, 0)) == proxy::uot::Version::V2,
        "UoT v2 magic was not recognized");
    Check(proxy::uot::VersionFromMagicAddress(
        TargetAddress(proxy::uot::kV1MagicAddress, 0)) ==
            proxy::uot::Version::V1,
        "UoT v1 magic was not recognized");
    Check(!proxy::uot::VersionFromMagicAddress(
        TargetAddress("prefix.sp.v2.udp-over-tcp.arpa", 0)),
        "non-exact UoT magic was accepted");

    const TargetAddress target("dns.example", 53);
    const auto request = proxy::uot::EncodeRequest(false, target);
    Check(request.has_value(), "UoT request encode failed");
    const auto bytes = request->span();
    Check(bytes.size() == 1 + 1 + 1 + 11 + 2, "UoT request size mismatch");
    Check(bytes[0] == 0 && bytes[1] == 3 && bytes[2] == 11,
          "UoT v2 request header mismatch");
    Check(bytes[bytes.size() - 2] == 0 && bytes.back() == 53,
          "UoT request port mismatch");
}

void TestConnectPacketRoundTrip() {
    const TargetAddress target("1.1.1.1", 53);
    CaptureWriter capture;
    proxy::uot::PacketWriter writer(capture, true, target);
    Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket("alpha", target));
        co_await writer.WriteMultiBuffer(MakePacket("beta-payload", target));
    });

    FragmentReader source(capture.bytes, {1, 1, 2, 3, 1, 4, 2});
    proxy::uot::PacketReader reader(source, true, target);
    Run([&]() -> net::awaitable<void> {
        auto first = co_await reader.ReadMultiBuffer();
        auto second = co_await reader.ReadMultiBuffer();
        Check(Flatten(first) == std::vector<uint8_t>({'a','l','p','h','a'}),
              "connect packet one mismatch");
        Check(Flatten(second) == std::vector<uint8_t>(
            {'b','e','t','a','-','p','a','y','l','o','a','d'}),
              "connect packet two mismatch");
        Check(first.begin()[0]->HasUDP() && first.begin()[0]->UDP().port == 53,
              "connect packet target missing");
    });
}

void TestLargeConnectPacketRoundTrip() {
    const TargetAddress target("1.1.1.1", 53);
    const std::string large_payload(buf::Buffer::kSize + 257, '\x6d');

    CaptureWriter capture;
    proxy::uot::PacketWriter writer(capture, true, target);
    Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket(large_payload, target));
    });

    Check(capture.bytes.size() == large_payload.size() + 2,
          "large UoT datagram was split into multiple frames");
    const size_t wire_length =
        (static_cast<size_t>(capture.bytes[0]) << 8) | capture.bytes[1];
    Check(wire_length == large_payload.size(),
          "large UoT frame length did not cover the complete datagram");

    FragmentReader source(
        capture.bytes, {1, 2, 4096, 17, 2048, 3, 1024});
    proxy::uot::PacketReader reader(source, true, target);
    Run([&]() -> net::awaitable<void> {
        auto decoded = co_await reader.ReadMultiBuffer();
        Check(Flatten(decoded) == std::vector<uint8_t>(
            large_payload.begin(), large_payload.end()),
            "large UoT datagram round-trip mismatch");
        Check(decoded.size() > 1,
              "large UoT datagram did not exercise multi-buffer storage");
    });
}

void TestNonConnectRequestAndPackets() {
    const TargetAddress initial("dns.example", 53);
    const TargetAddress second("8.8.8.8", 5353);

    const auto request = proxy::uot::EncodeRequest(false, initial);
    Check(request.has_value(), "non-connect request encode failed");

    CaptureWriter capture;
    capture.bytes.insert(
        capture.bytes.end(), request->span().begin(), request->span().end());
    proxy::uot::PacketWriter writer(capture, false, initial);
    Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket("one", initial));
        co_await writer.WriteMultiBuffer(MakePacket("two-two", second));
    });

    FragmentReader source(capture.bytes, {1, 2, 1, 3, 2, 5, 1, 4});
    buf::MultiBuffer pending;
    Run([&]() -> net::awaitable<void> {
        auto decoded_request = co_await proxy::uot::ReadRequest(source, pending);
        Check(decoded_request.has_value(), "fragmented UoT request decode failed");
        Check(!decoded_request->is_connect &&
              decoded_request->destination.host == "dns.example" &&
              decoded_request->destination.port == 53,
              "fragmented UoT request target mismatch");

        proxy::uot::PacketReader reader(
            source, false, decoded_request->destination, std::move(pending));
        auto first = co_await reader.ReadMultiBuffer();
        auto next = co_await reader.ReadMultiBuffer();
        Check(Flatten(first) == std::vector<uint8_t>({'o','n','e'}),
              "non-connect packet one mismatch");
        Check(Flatten(next) == std::vector<uint8_t>({'t','w','o','-','t','w','o'}),
              "non-connect packet two mismatch");
        Check(first.begin()[0]->UDP().host == "dns.example" &&
              first.begin()[0]->UDP().port == 53,
              "non-connect domain target mismatch");
        Check(next.begin()[0]->UDP().resolved_addr.has_value() &&
              next.begin()[0]->UDP().port == 5353,
              "non-connect IP target mismatch");
    });
}

}  // namespace

int main() {
    TestV2BoardSs2022Keys();
    TestMagicAndRequestCodec();
    TestConnectPacketRoundTrip();
    TestLargeConnectPacketRoundTrip();
    TestNonConnectRequestAndPackets();
    std::cout << "uot_ss2022_test: ok\n";
    return 0;
}
