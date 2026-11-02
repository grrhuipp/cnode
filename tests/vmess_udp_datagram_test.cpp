#include "udp_datagram.hpp"
#include "acppnode/common/buf/contiguous_buffer_view.hpp"
#include "encoding/server.hpp"
#include "vmess_cipher.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <chrono>
#include <exception>
#include <iostream>
#include <string_view>

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

buf::BufferGuard MakeBuffer(size_t size,
                        const TargetAddress* target,
                        uint8_t value = 0x6d) {
    buf::BufferGuard buffer{buf::Buffer::New()};
    Check(buffer && size <= buffer->Available(),
          "failed to allocate VMess UDP test buffer");
    std::fill_n(buffer->Tail().data(), size, value);
    buffer->Produce(static_cast<uint32_t>(size));
    if (target) {
        buffer->SetUDP(*target);
    }
    return buffer;
}

template <typename Factory>
void CheckRejected(Factory&& factory, std::string_view message) {
    bool rejected = false;
    try {
        factory();
    } catch (const IoSystemError&) {
        rejected = true;
    }
    Check(rejected, message);
}

vmess::VMessRequest MakeRequest(vmess::Security security, uint8_t options,
                                vmess::Command command) {
    vmess::VMessRequest request;
    request.security = security;
    request.options = options;
    request.command = command;
    request.target = TargetAddress("127.0.0.1", 5353);
    for (size_t i = 0; i < request.body_key.size(); ++i) {
        request.body_key[i] = static_cast<uint8_t>(0x31 + i);
        request.body_iv[i] = static_cast<uint8_t>(0x71 + i);
    }
    return request;
}

// Request framing uses the production ciphers and mask stream. In particular,
// later records depend on every earlier length/body nonce and padding mask.
class RequestEncoder {
public:
    explicit RequestEncoder(const vmess::VMessRequest& request)
        : cipher_(request.security, request.body_key.data(), request.body_iv.data())
        , padding_((request.options & vmess::Option::GLOBAL_PADDING) != 0) {
        if ((request.options & vmess::Option::AUTHENTICATED_LENGTH) != 0) {
            const std::array<std::string_view, 1> path{"auth_len"};
            auto key = vmess::KDF16(request.body_key.data(), request.body_key.size(), path);
            length_cipher_.emplace(request.security, key.data(), request.body_iv.data());
        }
        if ((request.options & vmess::Option::CHUNK_MASKING) != 0) {
            mask_.emplace(request.body_iv.data());
        }
    }

    size_t HeaderSize() const {
        return length_cipher_ ? length_cipher_->Overhead() + 2 : 2;
    }

    memory::ByteVector Encode(std::span<const uint8_t> payload) {
        const size_t padding = padding_ && mask_ ? mask_->NextMask() % 64 : 0;
        const size_t body_size = payload.size() + cipher_.Overhead();
        const size_t total_size = body_size + padding;
        memory::ByteVector wire(HeaderSize() + total_size);
        Check(cipher_.Encrypt(payload.data(), payload.size(), wire.data() + HeaderSize()) ==
                  static_cast<ssize_t>(body_size),
              "VMess test request encryption failed");
        if (length_cipher_) {
            const auto plain_size = static_cast<uint16_t>(total_size - length_cipher_->Overhead());
            const std::array<uint8_t, 2> length{
                static_cast<uint8_t>(plain_size >> 8), static_cast<uint8_t>(plain_size)};
            Check(length_cipher_->Encrypt(length.data(), length.size(), wire.data()) ==
                      static_cast<ssize_t>(HeaderSize()),
                  "VMess test authenticated length encryption failed");
        } else {
            auto length = static_cast<uint16_t>(total_size);
            if (mask_) {
                length ^= mask_->NextMask();
            }
            wire[0] = static_cast<uint8_t>(length >> 8);
            wire[1] = static_cast<uint8_t>(length);
        }
        std::fill(wire.begin() + HeaderSize() + body_size, wire.end(), 0xa7);
        return wire;
    }

private:
    vmess::VMessCipher cipher_;
    std::optional<vmess::VMessCipher> length_cipher_;
    std::optional<vmess::ShakeMask> mask_;
    bool padding_;
};

struct Connection {
    net::io_context io;
    tcp::acceptor acceptor{io, {net::ip::address_v4::loopback(), 0}};
    tcp::socket peer{io};
    TcpStream stream{Connect()};

    tcp::socket Connect() {
        tcp::socket socket(io);
        socket.connect(acceptor.local_endpoint());
        acceptor.accept(peer);
        return socket;
    }
};

net::awaitable<buf::MultiBuffer> ReadBody(transport::MultiBufferReader& reader,
                                         bool automatic_cancel = true) {
    co_await net::this_coro::throw_if_cancelled(automatic_cancel);
    co_return co_await reader.ReadMultiBuffer();
}

void CancelBlockedRead(Connection& connection, transport::MultiBufferReader& reader,
                       bool automatic_cancel) {
    net::cancellation_signal cancellation;
    bool completed = false;
    std::exception_ptr failure;
    connection.io.restart();
    net::co_spawn(connection.io, ReadBody(reader, automatic_cancel),
        net::bind_cancellation_slot(cancellation.slot(),
            [&](std::exception_ptr error, buf::MultiBuffer result) {
                Check(result.empty(), "cancelled VMess read returned partial plaintext");
                failure = error;
                completed = true;
            }));
    // All prefix bytes are already in the production stream's pending data.
    // Drain ready work: the only remaining read is a real socket wait, with no
    // peer data and no elapsed-time assumption about when cancellation occurs.
    connection.io.poll();
    Check(!completed, "VMess read did not wait for the incomplete record");
    cancellation.emit(net::cancellation_type::terminal);
    connection.io.run_for(std::chrono::seconds(1));
    Check(completed && failure, "VMess cancellation became EOF or did not finish");
    bool aborted = false;
    try {
        std::rethrow_exception(failure);
    } catch (const IoSystemError& error) {
        aborted = error.code() == io_error::operation_aborted;
    }
    Check(aborted, "VMess cancellation returned the wrong error");
    Check(connection.stream.IsOpen() && connection.peer.is_open(),
          "VMess cancellation permanently closed the transport");
}

buf::MultiBuffer ReadReady(Connection& connection, transport::MultiBufferReader& reader) {
    bool completed = false;
    std::exception_ptr failure;
    buf::MultiBuffer result;
    connection.io.restart();
    net::co_spawn(connection.io, reader.ReadMultiBuffer(),
        [&](std::exception_ptr error, buf::MultiBuffer value) {
            failure = error;
            result = std::move(value);
            completed = true;
        });
    connection.io.run_for(std::chrono::seconds(1));
    Check(completed, "resumed VMess read stalled");
    if (failure) {
        std::rethrow_exception(failure);
    }
    return result;
}

void CheckPayload(const buf::MultiBuffer& result, std::span<const uint8_t> expected,
                  const vmess::VMessRequest& request) {
    const buf::ContiguousBufferView actual(result);
    Check(actual.Bytes().size() == expected.size() &&
              std::equal(actual.Bytes().begin(), actual.Bytes().end(), expected.begin()),
          "resumed VMess record lost, duplicated, or corrupted payload bytes");
    if (request.command == vmess::Command::UDP) {
        vmess::ValidateFixedUdpDatagram(result, request.target);
    }
}

memory::ByteVector MakePayload(size_t size, uint8_t seed) {
    memory::ByteVector payload(size);
    for (size_t i = 0; i < size; ++i) {
        payload[i] = static_cast<uint8_t>(seed + i * 17);
    }
    return payload;
}

void TestCancellationResume(vmess::Security security, uint8_t options,
                            vmess::Command command, size_t payload_size) {
    auto request = MakeRequest(security, options, command);
    RequestEncoder encoder(request);
    const auto payload = MakePayload(payload_size, 0x23);
    const auto later_payload = MakePayload(257, 0x89);
    const auto wire = encoder.Encode(payload);
    const auto later_wire = encoder.Encode(later_payload);
    const auto eof_wire = encoder.Encode({});
    const size_t request_prefix = payload_size > buf::Buffer::kSize ? 1 : 0;
    request.SetPendingData(std::span<const uint8_t>(wire).first(request_prefix));
    Connection connection;
    vmess::TimedUserValidator validator;
    vmess::encoding::ServerSession session(validator, "cancellation-test");
    session.SetRequest(request);
    auto reader = session.DecodeRequestBody(connection.stream);

    size_t supplied = request_prefix;
    const std::array<size_t, 5> cuts{
        request_prefix, 1, encoder.HeaderSize(), encoder.HeaderSize() + 7, wire.size() - 1};
    for (size_t i = 0; i < cuts.size(); ++i) {
        connection.stream.PrependReadData(
            std::span<const uint8_t>(wire).subspan(supplied, cuts[i] - supplied));
        supplied = cuts[i];
        CancelBlockedRead(connection, *reader, (i % 2) == 0);
    }

    connection.stream.PrependReadData(std::span<const uint8_t>(wire).subspan(supplied));
    CheckPayload(ReadReady(connection, *reader), payload, request);
    connection.stream.PrependReadData(later_wire);
    CheckPayload(ReadReady(connection, *reader), later_payload, request);

    // The EOF marker is itself a framed record and must also survive a partial
    // read without re-consuming its authenticated length or padding mask.
    connection.stream.PrependReadData(
        std::span<const uint8_t>(eof_wire).first(eof_wire.size() - 1));
    CancelBlockedRead(connection, *reader, false);
    connection.stream.PrependReadData(std::span<const uint8_t>(eof_wire).last(1));
    Check(ReadReady(connection, *reader).empty(), "VMess EOF marker did not finish the reader");
    Check(ReadReady(connection, *reader).empty(), "VMess EOF marker was not permanent");
}

void TestBatchCancellation(vmess::Security security, uint8_t options) {
    auto request = MakeRequest(security, options, vmess::Command::TCP);
    RequestEncoder encoder(request);
    auto expected = MakePayload(113, 0x12);
    const auto second_payload = MakePayload(157, 0x83);
    const auto first_wire = encoder.Encode(expected);
    const auto second_wire = encoder.Encode(second_payload);
    const auto third_payload = MakePayload(81, 0x29);
    const auto third_wire = encoder.Encode(third_payload);
    expected.insert(expected.end(), second_payload.begin(), second_payload.end());

    Connection connection;
    vmess::TimedUserValidator validator;
    vmess::encoding::ServerSession session(validator, "batch-cancellation-test");
    session.SetRequest(request);
    auto reader = session.DecodeRequestBody(connection.stream);
    memory::ByteVector prefix(first_wire.begin(), first_wire.end());
    const size_t cut = encoder.HeaderSize() + 5;
    prefix.insert(prefix.end(), second_wire.begin(), second_wire.begin() + cut);
    connection.stream.PrependReadData(prefix);
    CancelBlockedRead(connection, *reader, false);
    connection.stream.PrependReadData(std::span<const uint8_t>(second_wire).subspan(cut));
    CheckPayload(ReadReady(connection, *reader), expected, request);
    connection.stream.PrependReadData(third_wire);
    CheckPayload(ReadReady(connection, *reader), third_payload, request);
}

void TestTransportEOF(vmess::Security security, uint8_t options, size_t prefix_size) {
    auto request = MakeRequest(security, options, vmess::Command::UDP);
    RequestEncoder encoder(request);
    const auto payload = MakePayload(113, 0x57);
    const auto wire = encoder.Encode(payload);
    // Also cover bytes coalesced with the request header, not only transport
    // pending data. Cancellation must preserve progress from either source.
    request.SetPendingData(std::span<const uint8_t>(wire).first(prefix_size));
    Connection connection;
    vmess::TimedUserValidator validator;
    vmess::encoding::ServerSession session(validator, "transport-eof-test");
    session.SetRequest(request);
    auto reader = session.DecodeRequestBody(connection.stream);
    CancelBlockedRead(connection, *reader, false);
    connection.peer.shutdown(tcp::socket::shutdown_send);
    Check(ReadReady(connection, *reader).empty(), "real VMess TCP EOF became a cancellation error");
    Check(ReadReady(connection, *reader).empty(), "real VMess TCP EOF was not permanent");
}

void TestAuthenticationFailure(vmess::Security security, uint8_t options,
                               bool corrupt_length) {
    auto request = MakeRequest(security, options, vmess::Command::UDP);
    RequestEncoder encoder(request);
    const auto payload = MakePayload(113, 0x47);
    auto wire = encoder.Encode(payload);
    const size_t corrupt_offset = corrupt_length
        ? encoder.HeaderSize() - 1
        : encoder.HeaderSize() + payload.size();
    wire[corrupt_offset] ^= 0x80;
    Connection connection;
    vmess::TimedUserValidator validator;
    vmess::encoding::ServerSession session(validator, "authentication-failure-test");
    session.SetRequest(request);
    auto reader = session.DecodeRequestBody(connection.stream);
    connection.stream.PrependReadData(std::span<const uint8_t>(wire).first(1));
    CancelBlockedRead(connection, *reader, false);
    connection.stream.PrependReadData(std::span<const uint8_t>(wire).subspan(1));
    bool reset = false;
    try {
        static_cast<void>(ReadReady(connection, *reader));
    } catch (const IoSystemError& error) {
        reset = error.code() == io_error::connection_reset;
    }
    Check(reset, "resumed VMess read suppressed an authentication failure");
    Check(ReadReady(connection, *reader).empty(), "VMess authentication failure was not permanent");
}

void TestEncryptedCancellation() {
    const std::array<vmess::Security, 2> securities{
        vmess::Security::AES_128_GCM, vmess::Security::CHACHA20_POLY1305};
    const std::array<uint8_t, 3> options{
        vmess::Option::CHUNK_STREAM,
        vmess::Option::CHUNK_STREAM | vmess::Option::CHUNK_MASKING | vmess::Option::GLOBAL_PADDING,
        vmess::Option::CHUNK_STREAM | vmess::Option::CHUNK_MASKING |
            vmess::Option::GLOBAL_PADDING | vmess::Option::AUTHENTICATED_LENGTH};
    for (const auto security : securities) {
        for (const auto option : options) {
            for (const auto command : {vmess::Command::UDP, vmess::Command::TCP}) {
                TestCancellationResume(security, option, command, 113);
                TestCancellationResume(security, option, command, buf::Buffer::kSize + 37);
            }
            TestBatchCancellation(security, option);
            TestAuthenticationFailure(security, option, false);
            if ((option & vmess::Option::AUTHENTICATED_LENGTH) != 0) {
                TestAuthenticationFailure(security, option, true);
            }
            for (const size_t prefix_size : {size_t{0}, size_t{1}, size_t{23}}) {
                TestTransportEOF(security, option, prefix_size);
            }
        }
    }
}

}  // namespace

int main() {
    const TargetAddress target("1.1.1.1", 53);
    const TargetAddress other("8.8.8.8", 53);

    buf::MultiBuffer valid;
    valid.push_back(MakeBuffer(buf::Buffer::kSize, &target, 0x11));
    valid.push_back(MakeBuffer(257, &target, 0x22));
    vmess::ValidateFixedUdpDatagram(valid, target);
    const buf::ContiguousBufferView contiguous(valid);
    Check(contiguous.Bytes().size() == buf::Buffer::kSize + 257 &&
          std::all_of(
              contiguous.Bytes().begin(),
              contiguous.Bytes().begin() + buf::Buffer::kSize,
              [](uint8_t value) { return value == 0x11; }) &&
          std::all_of(
              contiguous.Bytes().begin() + buf::Buffer::kSize,
              contiguous.Bytes().end(),
              [](uint8_t value) { return value == 0x22; }),
          "VMess multi-buffer UDP datagram was not coalesced exactly once");

    const std::array<uint8_t, 32> first{};
    const std::array<uint8_t, 48> second{};
    const std::array<net::const_buffer, 2> scatter{
        net::buffer(first),
        net::buffer(second),
    };
    const buf::ContiguousBufferView scatter_packet(scatter);
    Check(scatter_packet.Bytes().size() == first.size() + second.size(),
          "VMess scatter UDP datagram was split into multiple payloads");

    buf::MultiBuffer mixed;
    mixed.push_back(MakeBuffer(4096, &target));
    mixed.push_back(MakeBuffer(1024, &other));
    CheckRejected(
        [&] { vmess::ValidateFixedUdpDatagram(mixed, target); },
        "mixed VMess UDP endpoint was partially accepted");

    buf::MultiBuffer missing;
    missing.push_back(MakeBuffer(4096, &target));
    missing.push_back(MakeBuffer(1024, nullptr));
    CheckRejected(
        [&] { vmess::ValidateFixedUdpDatagram(missing, target); },
        "missing VMess UDP endpoint was partially accepted");

    buf::MultiBuffer wrong{MakeBuffer(4096, &other)};
    CheckRejected(
        [&] { vmess::ValidateFixedUdpDatagram(wrong, target); },
        "wrong fixed VMess UDP endpoint was accepted");

    TestEncryptedCancellation();

    return 0;
}
