#include <stdexcept>
#include <gtest/gtest.h>

#include "udp_datagram.hpp"
#include "common/buf/contiguous_buffer_view.hpp"
#include "encoding/server.hpp"
#include "vmess_cipher.hpp"
#include "encoding/body.hpp"
#include "vmess_crypto.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "app/proxyman/inbound/prepared_config.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>
#include <asio/read.hpp>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <chrono>
#include <exception>
#include <iostream>
#include <string_view>

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
        : cipher_(request.security, request.body_key.data(), request.body_iv.data(),
                  proxy::AeadDirection::Encrypt)
        , padding_((request.options & vmess::Option::GLOBAL_PADDING) != 0) {
        if ((request.options & vmess::Option::AUTHENTICATED_LENGTH) != 0) {
            const std::array<std::string_view, 1> path{"auth_len"};
            auto key = vmess::KDF16(request.body_key.data(), request.body_key.size(), path);
            length_cipher_.emplace(request.security, key.data(), request.body_iv.data(),
                                   proxy::AeadDirection::Encrypt);
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

// Response framing as Xray-core decodes it (DecodeResponseBody): payload
// cipher and mask use the response key/IV, the authenticated length always
// uses the request body key and the request body IV.
class ResponseDecoder {
public:
    explicit ResponseDecoder(const vmess::VMessRequest& request)
        : key_(Sha256(request.body_key))
        , iv_(Sha256(request.body_iv))
        , cipher_(request.security, key_.data(), iv_.data(), proxy::AeadDirection::Decrypt)
        , padding_((request.options & vmess::Option::GLOBAL_PADDING) != 0) {
        if ((request.options & vmess::Option::AUTHENTICATED_LENGTH) != 0) {
            const std::array<std::string_view, 1> path{"auth_len"};
            length_key_ = vmess::KDF16(request.body_key.data(), request.body_key.size(), path);
            length_cipher_.emplace(request.security, length_key_.data(), request.body_iv.data(),
                                   proxy::AeadDirection::Decrypt);
        }
        if ((request.options & vmess::Option::CHUNK_MASKING) != 0) {
            mask_.emplace(iv_.data());
        }
    }

    memory::ByteVector Decode(std::span<const uint8_t> wire, size_t& offset) {
        const size_t padding = padding_ && mask_ ? mask_->NextMask() % 64 : 0;
        const size_t header_size = length_cipher_ ? length_cipher_->Overhead() + 2 : 2;
        Check(wire.size() - offset >= header_size, "VMess response chunk header truncated");
        size_t total_size = 0;
        if (length_cipher_) {
            std::array<uint8_t, 2> length{};
            Check(length_cipher_->Decrypt(wire.data() + offset, header_size, length.data()) ==
                      static_cast<ssize_t>(length.size()),
                  "VMess response authenticated length does not decrypt with the request IV");
            total_size = ((size_t{length[0]} << 8) | length[1]) + length_cipher_->Overhead();
        } else {
            auto length = static_cast<uint16_t>((wire[offset] << 8) | wire[offset + 1]);
            if (mask_) {
                length ^= mask_->NextMask();
            }
            total_size = length;
        }
        offset += header_size;
        Check(total_size >= padding + cipher_.Overhead() && wire.size() - offset >= total_size,
              "VMess response chunk body truncated");
        const size_t sealed_size = total_size - padding;
        memory::ByteVector payload(sealed_size - cipher_.Overhead());
        Check(cipher_.Decrypt(wire.data() + offset, sealed_size, payload.data()) ==
                  static_cast<ssize_t>(payload.size()),
              "VMess response chunk payload failed authentication");
        offset += total_size;
        return payload;
    }

private:
    static std::array<uint8_t, SHA256_DIGEST_LENGTH> Sha256(const std::array<uint8_t, 16>& value) {
        std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
        SHA256(value.data(), value.size(), digest.data());
        return digest;
    }

    std::array<uint8_t, SHA256_DIGEST_LENGTH> key_;
    std::array<uint8_t, SHA256_DIGEST_LENGTH> iv_;
    std::array<uint8_t, 16> length_key_{};
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
    Connection connection;
    connection.stream.PrependReadData(std::span<const uint8_t>(wire).first(request_prefix));
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
    Connection connection;
    connection.stream.PrependReadData(std::span<const uint8_t>(wire).first(prefix_size));
    vmess::TimedUserValidator validator;
    vmess::encoding::ServerSession session(validator, "transport-eof-test");
    session.SetRequest(request);
    auto reader = session.DecodeRequestBody(connection.stream);
    CancelBlockedRead(connection, *reader, false);
    connection.peer.shutdown(tcp::socket::shutdown_send);
    if (prefix_size == 0) {
        Check(ReadReady(connection, *reader).empty(),
              "real VMess TCP EOF became a cancellation error");
    } else {
        // EOF inside a record is truncation, never a clean end of body.
        bool reset = false;
        try {
            static_cast<void>(ReadReady(connection, *reader));
        } catch (const IoSystemError& error) {
            reset = error.code() == io_error::connection_reset;
        }
        Check(reset, "truncated VMess record ended as a clean EOF");
    }
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
    // Corrupted EOF chunk authentication tag must be rejected as connection_reset.
    {
        Connection eof_connection;
        vmess::TimedUserValidator eof_validator;
        vmess::encoding::ServerSession eof_session(eof_validator, "eof-auth-failure-test");
        eof_session.SetRequest(request);
        auto eof_reader = eof_session.DecodeRequestBody(eof_connection.stream);
        auto eof_wire = encoder.Encode({});
        eof_wire[encoder.HeaderSize()] ^= 0x80;
        eof_connection.stream.PrependReadData(eof_wire);
        bool eof_reset = false;
        try {
            static_cast<void>(ReadReady(eof_connection, *eof_reader));
        } catch (const IoSystemError& error) {
            eof_reset = error.code() == io_error::connection_reset;
        }
        Check(eof_reset, "corrupted VMess EOF chunk authentication tag was accepted");
    }
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

void WriteReady(Connection& connection, transport::MultiBufferWriter& writer,
                buf::MultiBuffer payload) {
    bool completed = false;
    std::exception_ptr failure;
    connection.io.restart();
    net::co_spawn(connection.io, writer.WriteMultiBuffer(std::move(payload)),
        [&](std::exception_ptr error) {
            failure = error;
            completed = true;
        });
    connection.io.run_for(std::chrono::seconds(1));
    Check(completed && !failure, "VMess response write failed");
}

// A server response with AUTHENTICATED_LENGTH must decode with Xray-core's
// nonce choice; the production client decoder cannot prove this alone.
void TestResponseAuthenticatedLength(vmess::Security security) {
    constexpr size_t kResponseHeaderSize = 38;
    const uint8_t options = vmess::Option::CHUNK_STREAM | vmess::Option::CHUNK_MASKING |
        vmess::Option::GLOBAL_PADDING | vmess::Option::AUTHENTICATED_LENGTH;
    const auto request = MakeRequest(security, options, vmess::Command::TCP);
    Connection connection;
    vmess::TimedUserValidator validator;
    vmess::encoding::ServerSession session(validator, "response-length-test");
    session.SetRequest(request);
    auto writer = session.EncodeResponseBodyWithHeader(connection.stream);
    Check(writer != nullptr, "VMess response writer was not created");

    const std::array<std::pair<size_t, uint8_t>, 2> chunks{{{113, 0x5a}, {257, 0x3c}}};
    for (const auto& [size, value] : chunks) {
        buf::MultiBuffer payload;
        payload.push_back(MakeBuffer(size, nullptr, value));
        WriteReady(connection, *writer, std::move(payload));
    }

    memory::ByteVector wire;
    connection.peer.non_blocking(true);
    for (;;) {
        std::array<uint8_t, 4096> block{};
        IoErrorCode ec;
        const size_t n = connection.peer.read_some(net::buffer(block), ec);
        if (ec) break;
        wire.insert(wire.end(), block.begin(), block.begin() + n);
    }
    Check(wire.size() > kResponseHeaderSize, "VMess response was not written");

    ResponseDecoder decoder(request);
    size_t offset = kResponseHeaderSize;
    for (const auto& [size, value] : chunks) {
        const auto payload = decoder.Decode(wire, offset);
        Check(payload.size() == size &&
                  std::all_of(payload.begin(), payload.end(),
                              [value](uint8_t byte) { return byte == value; }),
              "VMess response chunk payload changed");
    }
    Check(offset == wire.size(), "VMess response carried unexpected trailing bytes");
}

void TestAuthenticatedHeaderFailure() {
    using namespace proxyman::inbound;
    constexpr auto tag = "vmess-header-classification";
    PreparedVmessUser user;
    user.uuid = "11111111-1111-4111-8111-111111111111";
    user.auth_key.fill(0x19);
    user.cmd_key.fill(0x27);
    user.profile.user_id = 73;
    user.profile.email = "header@example.test";
    auto snapshot = UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{user}});
    auto view = UserStore::PrepareWorkerView(snapshot);
    UserStore::CommitSnapshot(std::move(snapshot));
    UserStore::InstallWorkerView(std::move(view));
    vmess::TimedUserValidator validator;

    for (int fault = 0; fault != 3; ++fault) {
        std::array<uint8_t, 49> plain{};
        plain[0] = 1;
        plain[35] = static_cast<uint8_t>(vmess::Security::NONE);
        plain[37] = static_cast<uint8_t>(vmess::Command::UDP);
        plain[38] = 0;
        plain[39] = 53;
        plain[40] = 1;
        plain[41] = 1; plain[42] = 1; plain[43] = 1; plain[44] = 1;
        const uint32_t checksum = vmess::FNV1a32(plain.data(), 45) ^ (fault == 1 ? 1u : 0u);
        for (size_t i = 0; i != 4; ++i) {
            plain[45 + i] = static_cast<uint8_t>(checksum >> (24 - i * 8));
        }
        std::array<uint8_t, 42 + 49 + 16> wire{};
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        vmess::GenerateAuthID(vmess::ExpandAuthIDEncryptKey(user.auth_key), now, wire.data());
        const std::span<const uint8_t, 16> auth_id(wire.data(), 16);
        const std::span<const uint8_t, 8> nonce(wire.data() + 34, 8);
        const auto length_key = vmess::RequestHeaderLengthKey(user.cmd_key, auth_id, nonce);
        const auto payload_key = vmess::RequestHeaderPayloadKey(user.cmd_key, auth_id, nonce);
        const std::array<uint8_t, 2> length{0, static_cast<uint8_t>(plain.size())};
        Check(vmess::AES128GCMEncrypt(length_key.key.data(), length_key.nonce.data(),
                  auth_id.data(), auth_id.size(), length.data(), length.size(),
                  wire.data() + 16, wire.data() + 18), "failed to seal header length");
        Check(vmess::AES128GCMEncrypt(payload_key.key.data(), payload_key.nonce.data(),
                  auth_id.data(), auth_id.size(), plain.data(), plain.size(),
                  wire.data() + 42, wire.data() + 42 + plain.size()), "failed to seal header");
        if (fault == 2) wire.back() ^= 1;
        vmess::encoding::ServerSession session(validator, tag);
        auto [request, consumed] = session.DecodeRequestHeader(wire.data(), wire.size());
        const auto* rejected = session.AuthenticatedRejectedHeader();
        if (fault == 0) {
            Check(request && request->user && request->user->profile.user_id == 73 &&
                  consumed == wire.size() && !rejected, "valid header lost authenticated identity");
        } else if (fault == 1) {
            Check(!request && rejected && rejected->user->profile.user_id == 73 &&
                  rejected->target.SameEndpoint(TargetAddress("1.1.1.1", 53)) &&
                  rejected->command == vmess::Command::UDP,
                  "authenticated malformed header lost verified identity or parsed target");
        } else {
            Check(!request && !rejected, "unauthenticated header exposed trusted identity");
        }
    }
    UserStore::ClearWorkerView();
}


template <typename Fn>
void CheckNotSupported(Fn&& fn) {
    bool rejected = false;
    try {
        fn();
    } catch (const transport::LinkError& error) {
        rejected = error.code() == ErrorCode::NOT_SUPPORTED;
    }
    Check(rejected, "empty VMess UDP must fail explicitly without encoding EOF");
}

void TestEmptyUdpWrite(vmess::Security security) {
    const uint8_t options = vmess::Option::CHUNK_STREAM | vmess::Option::CHUNK_MASKING |
        vmess::Option::GLOBAL_PADDING | vmess::Option::AUTHENTICATED_LENGTH;
    const auto request = MakeRequest(security, options, vmess::Command::UDP);
    Connection connection;
    vmess::TimedUserValidator validator;
    vmess::encoding::ServerSession session(validator, "empty-udp-test");
    session.SetRequest(request);
    auto writer = session.EncodeResponseBodyWithHeader(connection.stream);
    auto reject = [&](net::awaitable<void> operation) {
        bool completed = false;
        std::exception_ptr failure;
        connection.io.restart();
        net::co_spawn(connection.io, std::move(operation),
            [&](std::exception_ptr error) { failure = error; completed = true; });
        connection.io.run_for(std::chrono::seconds(1));
        Check(completed && failure, "empty VMess UDP write silently succeeded");
        CheckNotSupported([&] { std::rethrow_exception(failure); });
    };
    buf::MultiBuffer empty{MakeBuffer(0, &request.target)};
    reject(writer->WriteMultiBuffer(std::move(empty)));
    reject(writer->WriteBuffers(std::span<const net::const_buffer>{}));
    Check(connection.peer.available() == 0,
          "rejected VMess UDP write emitted an EOF or response header");

    buf::MultiBuffer data{MakeBuffer(17, &request.target, 0x42)};
    WriteReady(connection, *writer, std::move(data));
    buf::MultiBuffer later_empty{MakeBuffer(0, &request.target)};
    reject(writer->WriteMultiBuffer(std::move(later_empty)));
    const size_t available = connection.peer.available();
    memory::ByteVector wire(available);
    Check(net::read(connection.peer, net::buffer(wire)) == wire.size(),
          "VMess UDP response wire was incomplete");
    ResponseDecoder decoder(request);
    size_t offset = 38;
    const auto decoded = decoder.Decode(wire, offset);
    Check(decoded == memory::ByteVector(17, 0x42) && offset == wire.size(),
          "rejected empty VMess UDP consumed framing state or appended EOF");

    const vmess::encoding::BodyKey key{request.body_key, request.body_iv};
    vmess::encoding::BodyEncoder encoder(
        {security, options, vmess::Command::UDP}, key, key);
    buf::MultiBuffer encoded;
    buf::MultiBuffer request_empty{MakeBuffer(0, &request.target)};
    CheckNotSupported([&] { encoder.Encode(request_empty, encoded); });
    CheckNotSupported([&] {
        encoder.Encode(std::span<const net::const_buffer>{}, encoded);
    });
    Check(encoded.empty(), "VMess request encoder emitted a forbidden empty chunk");
    encoder.EncodeEnd(encoded);
    Check(!encoded.empty(), "VMess explicit EOF marker was disabled");
}
}  // namespace

TEST(VmessUdpDatagram, Contract) {
    const TargetAddress target("1.1.1.1", 53);
    const TargetAddress other("8.8.8.8", 53);
    buf::MultiBuffer no_message;
    vmess::ValidateFixedUdpDatagram(no_message, target);
    buf::MultiBuffer empty{MakeBuffer(0, &target)};
    CheckNotSupported([&] { vmess::ValidateFixedUdpDatagram(empty, target); });

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

    TestAuthenticatedHeaderFailure();
    TestEncryptedCancellation();
    TestResponseAuthenticatedLength(vmess::Security::AES_128_GCM);
    TestResponseAuthenticatedLength(vmess::Security::CHACHA20_POLY1305);
    TestEmptyUdpWrite(vmess::Security::AES_128_GCM);
    TestEmptyUdpWrite(vmess::Security::CHACHA20_POLY1305);

}
