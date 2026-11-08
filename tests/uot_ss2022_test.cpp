#include <stdexcept>
#include <gtest/gtest.h>

#include "uot.hpp"

#include "shadowsocks_protocol.hpp"
#include "common/address_codec.hpp"

#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <future>
#include <iostream>
#include <memory_resource>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

std::vector<uint8_t> Flatten(const buf::MultiBuffer& mb) {
    std::vector<uint8_t> out;
    out.reserve(mb.byte_size());
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
    Check(buf::SetUdpTarget(packet, target), "packet target allocation failed");
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
    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }

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
    transport::CancellationSource cancellation_;

    std::vector<uint8_t> bytes_;
    std::vector<size_t> fragments_;
    size_t offset_ = 0;
    size_t fragment_index_ = 0;
};

class FramedEndpointDouble final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    explicit FramedEndpointDouble(std::vector<uint8_t> input = {},
                                  std::vector<size_t> fragments = {})
        : reader_(std::move(input), std::move(fragments)) {}

    transport::CancellationSource& Cancellation() noexcept override {
        return reader_.Cancellation();
    }

    void Cancel() noexcept { ++cancel_calls; }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        ++read_calls;
        co_return co_await reader_.ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer) override {
        co_return;
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        ++write_calls;
        descriptor_address = buffers.data();
        descriptors.assign(buffers.begin(), buffers.end());
        std::vector<uint8_t> before;
        for (const auto& buffer : buffers) {
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            before.insert(before.end(), data, data + buffer.size());
        }
        if (suspend_write) {
            auto executor = co_await net::this_coro::executor;
            net::steady_timer timer(executor);
            timer.expires_after(std::chrono::milliseconds(1));
            co_await timer.async_wait(net::use_awaitable);
            resumed = true;
            Check(buffers.data() == descriptor_address &&
                  std::equal(buffers.begin(), buffers.end(), descriptors.begin(),
                      [](const net::const_buffer& left, const net::const_buffer& right) {
                          return left.data() == right.data() && left.size() == right.size();
                      }), "UoT write buffer descriptors changed across suspension");
            std::vector<uint8_t> after;
            for (const auto& buffer : buffers) {
                const auto* data = static_cast<const uint8_t*>(buffer.data());
                after.insert(after.end(), data, data + buffer.size());
            }
            Check(after == before, "UoT write buffer bytes changed across suspension");
        }
        if (throw_on_write) {
            throw std::runtime_error("synthetic write failure");
        }
        bytes.insert(bytes.end(), before.begin(), before.end());
    }

    FragmentReader reader_;
    std::vector<uint8_t> bytes;
    std::vector<net::const_buffer> descriptors;
    const net::const_buffer* descriptor_address = nullptr;
    size_t read_calls = 0;
    size_t write_calls = 0;
    size_t cancel_calls = 0;
    bool suspend_write = false;
    bool resumed = false;
    bool throw_on_write = false;
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

TEST(UotSs2022, V2BoardSs2022Keys) {
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

TEST(UotSs2022, MagicAndRequestCodec) {
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

TEST(UotSs2022, ConnectPacketRoundTrip) {
    const TargetAddress target("1.1.1.1", 53);
    CaptureWriter capture;
    proxy::uot::PacketWriter writer(capture, true, target);
    ::Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket("alpha", target));
        co_await writer.WriteMultiBuffer(MakePacket("beta-payload", target));
    });

    FragmentReader source(capture.bytes, {1, 1, 2, 3, 1, 4, 2});
    proxy::uot::PacketReader reader(source, true, target);
    ::Run([&]() -> net::awaitable<void> {
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

TEST(UotSs2022, LargeConnectPacketRoundTrip) {
    const TargetAddress target("1.1.1.1", 53);
    const std::string large_payload(buf::Buffer::kSize + 257, '\x6d');

    CaptureWriter capture;
    proxy::uot::PacketWriter writer(capture, true, target);
    ::Run([&]() -> net::awaitable<void> {
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
    ::Run([&]() -> net::awaitable<void> {
        auto decoded = co_await reader.ReadMultiBuffer();
        Check(Flatten(decoded) == std::vector<uint8_t>(
            large_payload.begin(), large_payload.end()),
            "large UoT datagram round-trip mismatch");
        Check(decoded.size() > 1,
              "large UoT datagram did not exercise multi-buffer storage");
    });
}

TEST(UotSs2022, EmptyDatagramsPreserveSequenceAndTargets) {
    const TargetAddress first("1.1.1.1", 53);
    const TargetAddress second("8.8.8.8", 5353);
    for (const bool connect : {false, true}) {
        CaptureWriter capture;
        proxy::uot::PacketWriter writer(capture, connect, first);
        const auto& last = connect ? first : second;
        ::Run([&]() -> net::awaitable<void> {
            co_await writer.WriteMultiBuffer({});
            Check(capture.bytes.empty(), "no UDP message wrote an empty frame");
            co_await writer.WriteMultiBuffer(MakePacket("", first));
            co_await writer.WriteMultiBuffer(MakePacket("data", first));
            if (connect) {
                co_await writer.WriteBuffers(std::span<const net::const_buffer>{});
            } else {
                co_await writer.WriteMultiBuffer(MakePacket("", last));
            }
        });
        Check(capture.bytes.size() == (connect ? 10 : 31),
              "UoT empty datagrams did not write complete protocol headers");
        FragmentReader source(capture.bytes, {1, 1, 1, 1, 1, 1, 1, 1});
        proxy::uot::PacketReader reader(source, connect, first);
        ::Run([&]() -> net::awaitable<void> {
            const std::array<size_t, 3> sizes{0, 4, 0};
            for (size_t index = 0; index < sizes.size(); ++index) {
                const size_t size = sizes[index];
                auto packet = co_await reader.ReadMultiBuffer();
                const auto datagram = buf::InspectUdpDatagram(packet);
                Check(datagram.Valid() && datagram.payload_size == size &&
                          datagram.target->SameEndpoint(index == 2 ? last : first),
                      "UoT empty/data sequence became EOF or lost a target");
                if (size != 0) Check(Flatten(packet) == std::vector<uint8_t>({'d','a','t','a'}),
                                     "UoT UDP data changed");
            }
            Check((co_await reader.ReadMultiBuffer()).empty(),
                  "UoT TCP EOF became an empty datagram");
        });
    }
}

TEST(UotSs2022, V1FirstEmptyDatagramSurvivesPreparation) {
    const TargetAddress target("dns.example", 53);
    CaptureWriter capture;
    proxy::uot::PacketWriter writer(capture, false, target);
    ::Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket("", target));
        co_await writer.WriteMultiBuffer(MakePacket("next", target));
    });
    FragmentReader source(capture.bytes, {1, 2, 3, 1});
    ::Run([&]() -> net::awaitable<void> {
        auto prepared = co_await proxy::uot::ReadUotRequestHeader(
            proxy::uot::Version::V1, source);
        Check(prepared.has_value() && prepared->destination.SameEndpoint(target),
              "UoT v1 first empty UDP message was mistaken for EOF");
        proxy::uot::PacketReader reader(source, std::move(*prepared));
        auto empty = co_await reader.ReadMultiBuffer();
        const auto datagram = buf::InspectUdpDatagram(empty);
        Check(datagram.Valid() && datagram.payload_size == 0 &&
                  datagram.target->SameEndpoint(target),
              "UoT prepared first empty datagram was lost");
        Check(Flatten(co_await reader.ReadMultiBuffer()) ==
                  std::vector<uint8_t>({'n','e','x','t'}),
              "UoT first empty datagram damaged the following payload");
        Check((co_await reader.ReadMultiBuffer()).empty(), "UoT v1 EOF changed");
    });
}

TEST(UotSs2022, FramedEndpointWriteAndRead) {
    const TargetAddress target("1.1.1.1", 53);
    FramedEndpointDouble underlying;
    underlying.suspend_write = true;
    proxy::uot::FramedEndpoint endpoint(underlying, true, target);
    auto pending_write = endpoint.WriteMultiBuffer(MakePacket("framed", target));
    Check(underlying.write_calls == 0 && underlying.bytes.empty(),
          "UoT framed write started before its awaitable was awaited");
    ::Run([&]() -> net::awaitable<void> {
        co_await std::move(pending_write);
    });
    Check(underlying.write_calls == 1 && underlying.resumed,
          "UoT underlying WriteBuffers did not suspend and resume");
    Check(underlying.bytes == std::vector<uint8_t>({0, 6, 'f', 'r', 'a', 'm', 'e', 'd'}),
          "UoT framed endpoint wrote incorrect frame header or payload");

    const std::array<uint8_t, 4> borrowed_payload{'n', 'e', 'x', 't'};
    const std::array<net::const_buffer, 1> borrowed_buffers{net::buffer(borrowed_payload)};
    underlying.resumed = false;
    auto pending_buffers = endpoint.WriteBuffers(borrowed_buffers);
    Check(underlying.write_calls == 1,
          "UoT framed WriteBuffers started before its awaitable was awaited");
    ::Run([&]() -> net::awaitable<void> {
        co_await std::move(pending_buffers);
    });
    Check(underlying.write_calls == 2 && underlying.resumed &&
          underlying.bytes == std::vector<uint8_t>(
              {0, 6, 'f', 'r', 'a', 'm', 'e', 'd', 0, 4, 'n', 'e', 'x', 't'}),
          "UoT framed WriteBuffers did not preserve the borrowed payload across suspension");
    endpoint.Cancel();
    Check(underlying.cancel_calls == 1, "UoT framed endpoint did not forward cancellation");

    FramedEndpointDouble encoded(underlying.bytes, {1, 1, 2, 1, 3});
    proxy::uot::FramedEndpoint read_endpoint(encoded, true, target);
    auto pending_read = read_endpoint.ReadMultiBuffer();
    Check(encoded.read_calls == 0,
          "UoT framed read started before its awaitable was awaited");
    ::Run([&]() -> net::awaitable<void> {
        auto packet = co_await std::move(pending_read);
        Check(Flatten(packet) == std::vector<uint8_t>({'f','r','a','m','e','d'}),
              "UoT framed endpoint failed to read a fragmented frame");
        auto next = co_await read_endpoint.ReadMultiBuffer();
        Check(Flatten(next) == std::vector<uint8_t>({'n','e','x','t'}),
              "UoT framed WriteBuffers payload failed to round-trip");
    });
}

TEST(UotSs2022, FramedEndpointWriteException) {
    const TargetAddress target("1.1.1.1", 53);
    FramedEndpointDouble underlying;
    underlying.throw_on_write = true;
    proxy::uot::FramedEndpoint endpoint(underlying, true, target);
    bool propagated = false;
    try {
        ::Run([&]() -> net::awaitable<void> {
            co_await endpoint.WriteMultiBuffer(MakePacket("failure", target));
        });
    } catch (const std::runtime_error& error) {
        propagated = std::string_view(error.what()) == "synthetic write failure";
    }
    Check(propagated, "UoT framed endpoint swallowed the underlying write exception");
}

TEST(UotSs2022, NonConnectRequestAndPackets) {
    const TargetAddress initial("dns.example", 53);
    const TargetAddress second("8.8.8.8", 5353);

    const auto request = proxy::uot::EncodeRequest(false, initial);
    Check(request.has_value(), "non-connect request encode failed");

    CaptureWriter capture;
    capture.bytes.insert(
        capture.bytes.end(), request->span().begin(), request->span().end());
    proxy::uot::PacketWriter writer(capture, false, initial);
    ::Run([&]() -> net::awaitable<void> {
        co_await writer.WriteMultiBuffer(MakePacket("one", initial));
        co_await writer.WriteMultiBuffer(MakePacket("two-two", second));
    });

    FragmentReader source(capture.bytes, {1, 2, 1, 3, 2, 5, 1, 4});
    buf::MultiBuffer pending;
    ::Run([&]() -> net::awaitable<void> {
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

// Exercise the public wire codec independently of each protocol's handshake.
TEST(UotSs2022, SharedAddressCodec) {
    const std::array targets{
        TargetAddress("192.0.2.1", 0x1234),
        TargetAddress("2001:db8::1", 0x1234),
        TargetAddress("example.com", 0x1234)};
    const std::array formats{AddressWireFormat::Socks5,
        AddressWireFormat::PortFirst, AddressWireFormat::Uot};
    for (const auto format : formats) {
        for (const auto& target : targets) {
            std::array<uint8_t, kMaxEncodedAddressSize> encoded{};
            const size_t size = EncodeAddressTo(
                target, encoded.data(), encoded.size(), format);
            Check(size == AddressEncodedSize(target) && size != 0,
                  "shared address size mismatch");
            const size_t type_pos = format == AddressWireFormat::PortFirst ? 2 : 0;
            const uint8_t expected_type = target.IsDomain()
                ? (format == AddressWireFormat::Socks5 ? 3 : 2)
                : target.IsIPv4() ? (format == AddressWireFormat::Uot ? 0 : 1)
                : format == AddressWireFormat::Socks5 ? 4
                : format == AddressWireFormat::PortFirst ? 3 : 1;
            Check(encoded[type_pos] == expected_type,
                  "shared address changed wire type semantics");
            const size_t port_pos = format == AddressWireFormat::PortFirst ? 0 : size - 2;
            Check(encoded[port_pos] == 0x12 && encoded[port_pos + 1] == 0x34,
                  "shared address changed port byte order");
            const auto* body = encoded.data() + type_pos + 1;
            if (target.IsIPv4()) {
                const std::array<uint8_t, 4> expected{192, 0, 2, 1};
                Check(std::equal(expected.begin(), expected.end(), body),
                      "shared address changed IPv4 wire bytes");
            } else if (target.IsIPv6()) {
                const std::array<uint8_t, 16> expected{
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
                Check(std::equal(expected.begin(), expected.end(), body),
                      "shared address changed IPv6 wire bytes");
            } else {
                Check(body[0] == 11 && std::memcmp(body + 1, "example.com", 11) == 0,
                      "shared address changed domain wire bytes");
            }
            Check(EncodeAddressTo(target, encoded.data(), size - 1, format) == 0,
                  "shared address overwrote insufficient output");
            for (size_t split = 0; split <= size; ++split) {
                const auto parsed = DecodeAddress(
                    std::span<const uint8_t>(encoded.data(), split), format);
                Check(parsed.status == (split == size ? AddressDecodeStatus::Complete
                                                      : AddressDecodeStatus::Incomplete),
                      "shared address confused split input with invalid input");
                Check(split == size
                    ? parsed.consumed == size && parsed.target.SameEndpoint(target)
                    : parsed.consumed == 0 && parsed.required > split,
                    "shared address lost consumed/required boundary");
                std::vector<uint8_t> input{0xaa};
                input.insert(input.end(), encoded.begin(), encoded.begin() + size);
                input.push_back(0xbb);
                FragmentReader source(input, {1, split ? split : 1, 1});
                buf::MultiBuffer pending;
                ::Run([&]() -> net::awaitable<void> {
                    auto decoded = co_await ReadAddress(source, pending, format, 1);
                    Check(decoded && decoded->consumed == size &&
                          decoded->target.SameEndpoint(target),
                          "incremental shared address failed a split");
                    Check(pending.byte_size() >= size + 1,
                          "incremental address consumed caller-owned prefix");
                    pending.DropPrefixBytes(size + 1);
                    if (pending.byte_size() == 0) {
                        auto remaining = co_await source.ReadMultiBuffer();
                        remaining.MoveTo(pending, true);
                    }
                    Check(Flatten(pending) == std::vector<uint8_t>{0xbb},
                          "incremental address lost the following frame byte");
                });
                if (split == size) continue;
                FragmentReader truncated(
                    std::vector<uint8_t>(encoded.begin(), encoded.begin() + split), {1, 2});
                buf::MultiBuffer incomplete;
                ::Run([&]() -> net::awaitable<void> {
                    auto decoded = co_await ReadAddress(truncated, incomplete, format);
                    Check(!decoded && decoded.error() == ErrorCode::PROTOCOL_DECODE_FAILED,
                          "incremental address accepted truncated EOF");
                });
            }
            encoded[type_pos] = 0xff;
            Check(DecodeAddress(std::span<const uint8_t>(encoded.data(), size), format).status ==
                      AddressDecodeStatus::Invalid,
                  "shared address accepted an unknown type");
        }
        std::array<uint8_t, kMaxBaseEncodedAddressSize> domain{};
        const size_t type_pos = format == AddressWireFormat::PortFirst ? 2 : 0;
        domain[type_pos] = format == AddressWireFormat::Socks5 ? 3 : 2;
        domain[type_pos + 1] = 0;
        Check(DecodeAddress(domain, format, {.require_non_empty_domain = true}).status ==
                  AddressDecodeStatus::Invalid,
              "shared address accepted a forbidden empty domain");
        domain[type_pos + 1] = 255;
        Check(DecodeAddress(std::span<const uint8_t>(domain.data(), domain.size() - 1),
                            format).status == AddressDecodeStatus::Incomplete &&
              DecodeAddress(domain, format).consumed == domain.size(),
              "shared address failed its maximum wire-domain boundary");

        const std::array<ForwardedMetadataView, 3> metadata_cases{
            ForwardedMetadataView{
                .user_id = 424242,
                .user_email = "alice@example.com",
                .client_ip = net::ip::make_address("203.0.113.99"),
            },
            ForwardedMetadataView{
                .user_id = 0,
                .user_email = "only-email@example.com",
                .client_ip = std::nullopt,
            },
            ForwardedMetadataView{
                .user_id = 7,
                .user_email = {},
                .client_ip = net::ip::make_address("2001:db8::abcd"),
            },
        };
        for (const auto& target : targets) {
            for (const auto& meta : metadata_cases) {
                std::array<uint8_t, kMaxEncodedAddressSize> encoded{};
                const size_t size = EncodeAddressTo(
                    target, encoded.data(), encoded.size(), format, meta);
                Check(size == AddressEncodedSize(target, meta) &&
                      size > AddressEncodedSize(target),
                      "extended address size mismatch");
                for (size_t split = 0; split <= size; ++split) {
                    const auto parsed = DecodeAddress(
                        std::span<const uint8_t>(encoded.data(), split), format);
                    Check(parsed.status == (split == size ? AddressDecodeStatus::Complete
                                                          : AddressDecodeStatus::Incomplete),
                          "extended address split status mismatch");
                    if (split == size) {
                        Check(parsed.consumed == size &&
                              parsed.target.SameEndpoint(target) &&
                              parsed.forwarded.has_value() &&
                              parsed.forwarded->user_id == meta.user_id &&
                              parsed.forwarded->user_email == meta.user_email &&
                              parsed.forwarded->client_ip == meta.client_ip,
                              "extended address roundtrip metadata mismatch");
                    }
                }
                const auto disallowed = DecodeAddress(
                    std::span<const uint8_t>(encoded.data(), size),
                    format, {.allow_metadata = false});
                Check(disallowed.status == AddressDecodeStatus::Invalid &&
                      !disallowed.target.IsValid() &&
                      disallowed.target.host.empty() &&
                      !disallowed.forwarded.has_value(),
                      "disallowed metadata was accepted or polluted target");
                auto malformed = encoded;
                malformed[size - 1] = 0;
                if ((meta.user_email.empty() && meta.inbound_tag.empty())) {
                    malformed[AddressEncodedSize(target) + 1] = 0xFF;
                } else {
                    malformed[AddressEncodedSize(target) + 1] |= 0x80;
                }
                const auto rejected_meta = DecodeAddress(
                    std::span<const uint8_t>(malformed.data(), size), format);
                Check(rejected_meta.status == AddressDecodeStatus::Invalid &&
                      !rejected_meta.target.IsValid() &&
                      rejected_meta.target.host.empty() &&
                      !rejected_meta.forwarded.has_value(),
                      "invalid metadata polluted DecodeAddress result.target");
            }
        }
    }
}

TEST(UotSs2022, PacketEofBoundaries) {
    const TargetAddress target("192.0.2.1", 53);
    for (bool connect : {false, true}) {
        CaptureWriter capture;
        proxy::uot::PacketWriter writer(capture, connect, target);
        ::Run([&]() -> net::awaitable<void> {
            co_await writer.WriteMultiBuffer(MakePacket("end", target));
        });
        for (size_t length = 0; length <= capture.bytes.size(); ++length) {
            FragmentReader source(std::vector<uint8_t>(
                capture.bytes.begin(), capture.bytes.begin() + length), {1, 1, 2});
            proxy::uot::PacketReader reader(source, connect, target);
            bool failed = false;
            try {
                ::Run([&]() -> net::awaitable<void> {
                    auto packet = co_await reader.ReadMultiBuffer();
                    Check(length == 0 ? packet.byte_size() == 0
                        : Flatten(packet) == std::vector<uint8_t>({'e','n','d'}),
                        "UoT boundary EOF lost a complete packet");
                    auto eof = co_await reader.ReadMultiBuffer();
                    Check(eof.byte_size() == 0, "UoT boundary EOF returned data");
                });
            } catch (const IoSystemError&) {
                failed = true;
            }
            Check(failed == (length != 0 && length != capture.bytes.size()),
                  "UoT confused truncated framing with normal EOF");
        }
    }
}

TEST(UotSs2022, NonConnectIpPacketDoesNotDependOnUnusedRequestDomainStorage) {
    class AllocationGate final : public std::pmr::memory_resource {
    public:
        explicit AllocationGate(std::pmr::memory_resource* upstream) : upstream_(upstream) {}
        bool reject = false;
        size_t live_bytes = 0;
    private:
        void* do_allocate(size_t bytes, size_t alignment) override {
            if (reject) throw std::bad_alloc();
            auto* result = upstream_->allocate(bytes, alignment);
            live_bytes += bytes;
            return result;
        }
        void do_deallocate(void* pointer, size_t bytes, size_t alignment) override {
            live_bytes -= bytes;
            upstream_->deallocate(pointer, bytes, alignment);
        }
        bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
            return this == &other;
        }
        std::pmr::memory_resource* upstream_;
    };
    struct ResourceScope {
        std::pmr::memory_resource* previous;
        explicit ResourceScope(std::pmr::memory_resource* resource)
            : previous(std::pmr::set_default_resource(resource)) {}
        ~ResourceScope() { std::pmr::set_default_resource(previous); }
    };
    struct RejectAllocations {
        AllocationGate& resource;
        explicit RejectAllocations(AllocationGate& value) : resource(value) { resource.reject = true; }
        ~RejectAllocations() { resource.reject = false; }
    };
    memory::ConfigureProcessAllocator();
    AllocationGate resource(std::pmr::get_default_resource());
    ResourceScope scope(&resource);
    const std::string domain = std::string(63, 'a') + "." +
        std::string(63, 'b') + "." + std::string(61, 'c');
    const std::array<uint8_t, 12> wire{0, 192, 0, 2, 7, 0x14, 0xe9, 0, 3, 'u', 'd', 'p'};
    for (const bool prepared_constructor : {false, true}) {
        SCOPED_TRACE(prepared_constructor);
        {
            buf::MultiBuffer pending;
            ASSERT_TRUE(buf::AppendSpanToMultiBuffer(wire, pending));
            FragmentReader source({}, {});
            std::optional<proxy::uot::PacketReader> reader;
            TargetAddress unused(domain, 53);
            if (prepared_constructor) {
                proxy::uot::PreparedRequest prepared;
                prepared.destination = std::move(unused);
                prepared.pending = std::move(pending);
                reader.emplace(source, std::move(prepared));
            } else {
                reader.emplace(source, false, std::move(unused), std::move(pending));
            }
            EXPECT_EQ(resource.live_bytes, 0) << "non-connect request target must not remain resident";
            ASSERT_NO_THROW(::Run([&]() -> net::awaitable<void> {
                buf::MultiBuffer packet;
                {
                    RejectAllocations pressure(resource);
                    packet = co_await reader->ReadMultiBuffer();
                }
                const auto datagram = buf::InspectUdpDatagram(packet);
                Check(datagram.Valid() &&
                      datagram.target->SameEndpoint(TargetAddress("192.0.2.7", 5353)) &&
                      Flatten(packet) == std::vector<uint8_t>({'u', 'd', 'p'}),
                      "complete non-connect IP packet must survive unrelated allocation pressure");
            }));
        }
        EXPECT_EQ(resource.live_bytes, 0);
    }
}

}  // namespace

