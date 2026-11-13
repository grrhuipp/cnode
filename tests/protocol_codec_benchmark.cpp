// 全协议编解码与流/数据报加解密微基准：覆盖 VMess、VLESS、Trojan、Shadowsocks（AEAD 与 2022）、
// AnyTLS、Hysteria（v1 与 v2）、UDP-over-TCP（UoT）及 Mux.Cool 的核心编解码与帧/块加解密路径。
// 每项预热 128 轮、测量 2048 轮（可用 CNODE_BENCH_ITERATIONS 覆盖），使用全局 mimalloc 并统计
// 测量区间内的 C++ new / mi_malloc_aligned 分配次数、每操作 CPU/墙钟耗时及吞吐。

#include <gtest/gtest.h>

#include "benchmark_memory.hpp"
#include "common/allocator.hpp"
#include "common/multi_buffer.hpp"
#include "common/mux_codec.hpp"
#include "common/target_address.hpp"
#include "proxy/anytls/anytls_codec.hpp"
#include "proxy/shadowsocks/shadowsocks_protocol.hpp"
#include "proxy/trojan/trojan_codec.hpp"
#include "proxy/uot/uot.hpp"
#include "proxy/vless/vless_codec.hpp"
#include "proxy/vmess/body.hpp"
#include "proxy/vmess/vmess_crypto.hpp"
#include "transport/async_stream.hpp"
#include "transport/hysteria_wire.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using benchmark::AllocationCountScope;
using benchmark::AllocationCounts;
using benchmark::ReadProcessMemory;
using benchmark::ResidentBytes;

void Require(bool condition, const char* message = "protocol codec benchmark check failed") {
    if (!condition) throw std::runtime_error(message);
}

uint64_t CpuNanoseconds() {
    timespec ts{};
    Require(::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) == 0, "cannot read process CPU clock");
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

size_t ConfiguredIterations(size_t fallback = 2048) {
    if (const char* env = std::getenv("CNODE_BENCH_ITERATIONS")) {
        return std::max<size_t>(1, static_cast<size_t>(std::stoull(env)));
    }
    return fallback;
}

class MemoryLoopStream final : public transport::AsyncStream {
public:
    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        const size_t n = pending_.ConsumePrefixTo(
            {static_cast<uint8_t*>(buffer.data()), buffer.size()});
        co_return n;
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        const auto span = std::span(
            static_cast<const uint8_t*>(buffer.data()), buffer.size());
        Require(pending_.AppendSpan(span));
        co_return buffer.size();
    }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        co_return std::move(pending_);
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        pending_.AppendAndCoalesce(std::move(mb));
        co_return;
    }

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        for (const auto& buf : buffers) {
            const auto span = std::span(
                static_cast<const uint8_t*>(buf.data()), buf.size());
            Require(pending_.AppendSpan(span));
        }
        co_return;
    }

    void ShutdownWrite() override {}
    void Close() override { pending_.clear(); }
    void Cancel() noexcept override {}
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return true; }

    common::MultiBuffer& Pending() noexcept { return pending_; }

private:
    common::MultiBuffer pending_;
    transport::CancellationSource cancellation_;
};

template <typename StepFn>
void RunBenchCase(std::string_view protocol,
                  std::string_view operation,
                  size_t payload_bytes,
                  size_t iterations,
                  StepFn&& step) {
    constexpr size_t kWarmup = 128;
    for (size_t i = 0; i < kWarmup; ++i) {
        step();
    }
    common::CollectThreadHeap();
    const size_t rss_before = ResidentBytes();
    AllocationCounts allocations{};
    const auto wall_start = std::chrono::steady_clock::now();
    const uint64_t cpu_start = CpuNanoseconds();
    {
        AllocationCountScope scope(allocations);
        for (size_t i = 0; i < iterations; ++i) {
            step();
        }
    }
    const uint64_t cpu_ns = CpuNanoseconds() - cpu_start;
    const double wall_ns = std::chrono::duration<double, std::nano>(
        std::chrono::steady_clock::now() - wall_start).count();
    const auto memory = ReadProcessMemory();
    const double total_mib =
        static_cast<double>(payload_bytes) * static_cast<double>(iterations) / (1024.0 * 1024.0);
    const double throughput_mib_s = wall_ns > 0.0 ? (total_mib / (wall_ns / 1e9)) : 0.0;
    std::printf(
        "PROTOCOL_CODEC_BENCH protocol=%.*s op=%.*s bytes=%zu iterations=%zu "
        "wall_ns_per_op=%.1f cpu_ns_per_op=%.1f mib_per_s=%.1f "
        "cpp_allocs=%llu aligned_allocs=%llu rss_before=%zu anon_rss=%zu peak_rss=%zu\n",
        static_cast<int>(protocol.size()), protocol.data(),
        static_cast<int>(operation.size()), operation.data(),
        payload_bytes, iterations,
        wall_ns / static_cast<double>(iterations),
        static_cast<double>(cpu_ns) / static_cast<double>(iterations),
        throughput_mib_s,
        static_cast<unsigned long long>(allocations.cpp_calls),
        static_cast<unsigned long long>(allocations.aligned_calls),
        rss_before, memory.anonymous_resident_bytes, memory.peak_resident_bytes);
}

TEST(ProtocolCodecBenchmark, VmessStreamAndHeaderCodec) {
    const size_t iterations = ConfiguredIterations();
    net::io_context io;
    const common::TargetAddress target("127.0.0.1", 443);
    std::vector<uint8_t> plain(8192, 0x5a);

    for (const auto [name, sec] : {
             std::pair{"aes-128-gcm", proxy::VmessSecurity::AES_128_GCM},
             std::pair{"chacha20-poly1305", proxy::VmessSecurity::CHACHA20_POLY1305},
             std::pair{"none", proxy::VmessSecurity::NONE}}) {
        proxy::BodyKey req_key{};
        req_key.key.fill(0x11);
        req_key.iv.fill(0x22);
        const proxy::BodyOptions options{
            .security = sec,
            .options = proxy::VmessOption::CHUNK_STREAM | proxy::VmessOption::CHUNK_MASKING,
            .command = proxy::VmessCommand::TCP,
        };
        proxy::BodyEncoder encoder(options, req_key, req_key);
        proxy::BodyDecoder decoder(options, req_key, req_key);
        MemoryLoopStream loop;
        const net::const_buffer slice(plain.data(), plain.size());

        RunBenchCase("vmess", std::string("stream_") + name, plain.size(), iterations, [&] {
            encoder.Encode(std::span(&slice, 1), loop.Pending());
            auto future = net::co_spawn(io, decoder.Read(loop), net::use_future);
            io.restart();
            io.run();
            auto decoded = future.get();
            Require(decoded.byte_size() == plain.size(), "VMess decoded size mismatch");
        });
    }
}

TEST(ProtocolCodecBenchmark, VlessHeaderAndUdpFraming) {
    const size_t iterations = ConfiguredIterations();
    std::array<uint8_t, 16> uuid{};
    uuid.fill(0x42);
    const common::TargetAddress target("127.0.0.1", 8443);
    std::array<uint8_t, proxy::kVlessMaxRequestHeaderSize> wire{};

    RunBenchCase("vless", "request_header_codec", 26, iterations, [&] {
        const size_t len = proxy::EncodeRequestHeaderTo(
            uuid, proxy::VlessCommand::TCP, target, wire.data(), wire.size());
        Require(len > 0, "VLESS header encode failed");
        const auto decoded = proxy::DecodeVlessRequestHeader({wire.data(), len});
        Require(decoded.status == proxy::VlessRequestDecodeStatus::Complete &&
                decoded.consumed == len, "VLESS header decode failed");
    });

    net::io_context io;
    MemoryLoopStream loop;
    proxy::VlessUdpFramer framer(false);
    std::vector<uint8_t> datagram(1200, 0x37);

    RunBenchCase("vless", "udp_framing_1200b", datagram.size(), iterations, [&] {
        common::MultiBuffer pkt;
        Require(pkt.AppendSpan(datagram));
        Require(common::SetUdpTarget(pkt, target));
        auto write_fut = net::co_spawn(
            io, proxy::WriteVlessUdpDatagram(loop, std::move(pkt), false), net::use_future);
        io.restart();
        io.run();
        write_fut.get();

        framer.Feed(std::move(loop.Pending()));
        proxy::VlessFramedUdpPacket out;
        Require(framer.Next(out) && out.payload.byte_size() == datagram.size(),
                "VLESS UDP framer output mismatch");
    });
}

TEST(ProtocolCodecBenchmark, TrojanHeaderAndUdpFraming) {
    const size_t iterations = ConfiguredIterations();
    const auto hash = proxy::HashTrojanPassword("benchmark-secret");
    const common::TargetAddress target("127.0.0.1", 443);
    std::array<uint8_t, 256> wire{};

    RunBenchCase("trojan", "request_header_codec", 68, iterations, [&] {
        const size_t len = proxy::EncodeRequestTo(
            hash, proxy::TrojanCommand::CONNECT, target, wire.data(), wire.size());
        Require(len > 0, "Trojan header encode failed");
        const auto decoded = proxy::DecodeTrojanRequest({wire.data(), len});
        Require(decoded.status == proxy::TrojanRequestDecodeStatus::Complete &&
                decoded.consumed == len, "Trojan header decode failed");
    });

    net::io_context io;
    MemoryLoopStream loop;
    proxy::TrojanUdpFramer framer;
    std::vector<uint8_t> datagram(1200, 0x6b);
    const net::const_buffer slice(datagram.data(), datagram.size());

    RunBenchCase("trojan", "udp_framing_1200b", datagram.size(), iterations, [&] {
        auto write_fut = net::co_spawn(
            io, proxy::WriteTrojanUdpDatagram(loop, target, std::span(&slice, 1)), net::use_future);
        io.restart();
        io.run();
        write_fut.get();

        framer.Feed(std::move(loop.Pending()));
        proxy::TrojanFramedUdpPacket out;
        Require(framer.Next(out) && out.payload.byte_size() == datagram.size(),
                "Trojan UDP framer output mismatch");
    });
}

TEST(ProtocolCodecBenchmark, ShadowsocksAeadAnd2022Crypto) {
    const size_t iterations = ConfiguredIterations();
    std::vector<uint8_t> plain(8192, 0x9c);
    std::vector<uint8_t> cipher_buf(8192 + 16);
    std::vector<uint8_t> out_buf(8192);
    std::array<uint8_t, 32> key{};
    key.fill(0x55);
    std::array<uint8_t, 12> nonce{};

    for (const auto [name, type, key_len] : {
             std::tuple{"aes-128-gcm", proxy::SsCipherType::AES_128_GCM, size_t{16}},
             std::tuple{"aes-256-gcm", proxy::SsCipherType::AES_256_GCM, size_t{32}},
             std::tuple{"chacha20-ietf-poly1305", proxy::SsCipherType::CHACHA20_POLY1305, size_t{32}}}) {
        proxy::SsAeadCipher enc(type, key.data(), key_len);
        proxy::SsAeadCipher dec(type, key.data(), key_len);
        RunBenchCase("shadowsocks", std::string("aead_8k_") + name, plain.size(), iterations, [&] {
            ++nonce[0];
            Require(enc.Encrypt(nonce.data(), plain.data(), plain.size(), cipher_buf.data()),
                    "SS AEAD encrypt failed");
            Require(dec.Decrypt(nonce.data(), cipher_buf.data(), cipher_buf.size(), out_buf.data()),
                    "SS AEAD decrypt failed");
        });
    }
}

TEST(ProtocolCodecBenchmark, AnyTlsFrameBatchAndPadding) {
    const size_t iterations = ConfiguredIterations();
    net::io_context io;
    MemoryLoopStream loop;
    const auto scheme = proxy::DefaultAnyTlsPaddingScheme();
    std::vector<uint8_t> payload(8192, 0x4d);
    const net::const_buffer slice(payload.data(), payload.size());

    RunBenchCase("anytls", "frame_batch_8k", payload.size(), iterations, [&] {
        auto write_fut = net::co_spawn(
            io,
            proxy::WriteAnyTlsBuffersAsFramesWithPadding(
                loop, *scheme, 4, proxy::kCmdPSH, 1,
                std::span(&slice, 1)),
            net::use_future);
        io.restart();
        io.run();
        Require(write_fut.get().has_value(), "AnyTLS frame write failed");

        auto hdr_fut = net::co_spawn(io, proxy::ReadAnyTlsFrameHeader(loop), net::use_future);
        io.restart();
        io.run();
        const auto hdr = hdr_fut.get();
        Require(hdr.has_value() && hdr->length == payload.size(), "AnyTLS frame header mismatch");

        auto body_fut = net::co_spawn(io, proxy::ReadFramePayload(loop, hdr->length), net::use_future);
        io.restart();
        io.run();
        const auto body = body_fut.get();
        Require(body.has_value() && body->byte_size() == payload.size(), "AnyTLS frame payload mismatch");
    });
}

TEST(ProtocolCodecBenchmark, HysteriaV1AndV2WireCodec) {
    const size_t iterations = ConfiguredIterations();
    std::vector<uint8_t> udp_payload(1200, 0x71);
    const transport::HysteriaUdpMessage message{
        .session_id = 42,
        .packet_id = 9,
        .fragment_id = 0,
        .fragment_count = 1,
        .target = common::TargetAddress("127.0.0.1", 5353),
        .payload = udp_payload,
    };

    for (const auto [name, ver] : {
             std::pair{"v1_udp_1200b", transport::HysteriaVersion::V1},
             std::pair{"v2_udp_1200b", transport::HysteriaVersion::V2}}) {
        RunBenchCase("hysteria", name, udp_payload.size(), iterations, [&] {
            auto encoded = transport::EncodeUdpMessage(ver, message);
            Require(encoded.has_value(), "Hysteria UDP encode failed");
            auto decoded = transport::ParseUdpMessage(ver, *encoded);
            Require(decoded.has_value() && decoded->payload.size() == udp_payload.size(),
                    "Hysteria UDP decode failed");
        });
    }
}

TEST(ProtocolCodecBenchmark, UotAndMuxCoolFraming) {
    const size_t iterations = ConfiguredIterations();
    net::io_context io;
    MemoryLoopStream loop;
    const common::TargetAddress target("127.0.0.1", 53);
    proxy::UotPacketWriter uot_writer(loop, false, target);
    proxy::UotPacketReader uot_reader(loop, false, target);
    std::vector<uint8_t> datagram(1200, 0x2e);

    RunBenchCase("uot", "datagram_framing_1200b", datagram.size(), iterations, [&] {
        common::MultiBuffer mb;
        Require(mb.AppendSpan(datagram));
        Require(common::SetUdpTarget(mb, target));
        auto write_fut = net::co_spawn(io, uot_writer.WriteMultiBuffer(std::move(mb)), net::use_future);
        io.restart();
        io.run();
        write_fut.get();

        auto read_fut = net::co_spawn(io, uot_reader.ReadMultiBuffer(), net::use_future);
        io.restart();
        io.run();
        auto decoded = read_fut.get();
        Require(decoded.byte_size() == datagram.size(), "UoT decoded size mismatch");
    });

    std::array<uint8_t, common::kMaxFrameHeaderBytes> mux_hdr{};
    RunBenchCase("mux", "frame_header_codec_1200b", datagram.size(), iterations, [&] {
        const size_t hdr_len = common::EncodeNewHeaderTo(
            mux_hdr, 7, common::NetworkType::TCP, target, datagram.size(), true);
        Require(hdr_len > 0, "Mux header encode failed");
        common::MultiBuffer frame;
        Require(frame.AppendSpan({mux_hdr.data(), hdr_len}));
        Require(frame.AppendSpan(datagram));
        const auto decoded = common::DecodeFrame(frame);
        Require(decoded.has_value() && decoded->frame_size == hdr_len + datagram.size(),
                "Mux frame decode failed");
    });
}

}  // namespace
