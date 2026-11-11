#include <stdexcept>
#include <gtest/gtest.h>

#include "proxy/vmess/vmess_crypto.hpp"
#include "proxy/vmess/encoding/body.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "app/proxyman/inbound/user_store.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <string_view>
#include <tuple>
#include <memory_resource>

namespace {



buf::BufferGuard MakeBuffer(size_t size,
                        const common::TargetAddress* target,
                        uint8_t value) {
    buf::BufferGuard buffer{buf::Buffer::New()};
    if (!buffer) throw std::bad_alloc();
    if (size > buffer->Available()) throw std::length_error("VMess fixture exceeds buffer");
    std::fill_n(buffer->Tail().data(), size, value);
    buffer->Produce(static_cast<uint32_t>(size));
    if (target) {
        buffer->SetUDP(*target);
    }
    return buffer;
}

template <typename Factory>
void ExpectLinkError(Factory&& factory, std::string_view message,
                     common::ErrorCode expected = common::ErrorCode::PROTOCOL_INVALID_ADDRESS) {
    try {
        factory();
        ADD_FAILURE() << message;
    } catch (const transport::LinkError& error) {
        EXPECT_EQ(error.code(), expected) << message;
    }
}

proxy::vmess::VMessRequest MakeRequest(proxy::vmess::Security security, uint8_t options,
                                proxy::vmess::Command command) {
    proxy::vmess::VMessRequest request;
    request.security = security;
    request.options = options;
    request.command = command;
    request.target = common::TargetAddress("127.0.0.1", 5353);
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
    explicit RequestEncoder(const proxy::vmess::VMessRequest& request)
        : cipher_(request.security, request.body_key.data(), request.body_iv.data())
        , padding_((request.options & proxy::vmess::Option::GLOBAL_PADDING) != 0) {
        if ((request.options & proxy::vmess::Option::AUTHENTICATED_LENGTH) != 0) {
            const std::array<std::string_view, 1> path{"auth_len"};
            auto key = proxy::vmess::KDF16(request.body_key.data(), request.body_key.size(), path);
            length_cipher_.emplace(request.security, key.data(), request.body_iv.data());
        }
        if ((request.options & proxy::vmess::Option::CHUNK_MASKING) != 0) {
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
        EXPECT_EQ((cipher_.Encrypt(payload.data(), payload.size(), wire.data() + HeaderSize())), (static_cast<ssize_t>(body_size))) << "VMess test request encryption failed";
        if (length_cipher_) {
            const auto plain_size = static_cast<uint16_t>(total_size - length_cipher_->Overhead());
            const std::array<uint8_t, 2> length{
                static_cast<uint8_t>(plain_size >> 8), static_cast<uint8_t>(plain_size)};
            EXPECT_EQ((length_cipher_->Encrypt(length.data(), length.size(), wire.data())), (static_cast<ssize_t>(HeaderSize()))) << "VMess test authenticated length encryption failed";
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
    proxy::vmess::VMessCipher cipher_;
    std::optional<proxy::vmess::VMessCipher> length_cipher_;
    std::optional<proxy::vmess::ShakeMask> mask_;
    bool padding_;
};

// Response framing as Xray-core decodes it (DecodeResponseBody): payload
// cipher and mask use the response key/IV, the authenticated length always
// uses the request body key and the request body IV.
class ResponseDecoder {
public:
    explicit ResponseDecoder(const proxy::vmess::VMessRequest& request)
        : key_(Sha256(request.body_key))
        , iv_(Sha256(request.body_iv))
        , cipher_(request.security, key_.data(), iv_.data())
        , padding_((request.options & proxy::vmess::Option::GLOBAL_PADDING) != 0) {
        if ((request.options & proxy::vmess::Option::AUTHENTICATED_LENGTH) != 0) {
            const std::array<std::string_view, 1> path{"auth_len"};
            length_key_ = proxy::vmess::KDF16(request.body_key.data(), request.body_key.size(), path);
            length_cipher_.emplace(request.security, length_key_.data(), request.body_iv.data());
        }
        if ((request.options & proxy::vmess::Option::CHUNK_MASKING) != 0) {
            mask_.emplace(iv_.data());
        }
    }

    memory::ByteVector Decode(std::span<const uint8_t> wire, size_t& offset) {
        const size_t padding = padding_ && mask_ ? mask_->NextMask() % 64 : 0;
        const size_t header_size = length_cipher_ ? length_cipher_->Overhead() + 2 : 2;
        if (offset > wire.size() || wire.size() - offset < header_size)
            throw std::runtime_error("VMess response chunk header truncated");
        size_t total_size = 0;
        if (length_cipher_) {
            std::array<uint8_t, 2> length{};
            EXPECT_EQ((length_cipher_->Decrypt(wire.data() + offset, header_size, length.data())), (static_cast<ssize_t>(length.size()))) << "VMess response authenticated length does not decrypt with the request IV";
            total_size = ((size_t{length[0]} << 8) | length[1]) + length_cipher_->Overhead();
        } else {
            auto length = static_cast<uint16_t>((wire[offset] << 8) | wire[offset + 1]);
            if (mask_) {
                length ^= mask_->NextMask();
            }
            total_size = length;
        }
        offset += header_size;
        if (total_size < padding + cipher_.Overhead() || wire.size() - offset < total_size)
            throw std::runtime_error("VMess response chunk body truncated");
        const size_t sealed_size = total_size - padding;
        memory::ByteVector payload(sealed_size - cipher_.Overhead());
        EXPECT_EQ((cipher_.Decrypt(wire.data() + offset, sealed_size, payload.data())), (static_cast<ssize_t>(payload.size()))) << "VMess response chunk payload failed authentication";
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
    proxy::vmess::VMessCipher cipher_;
    std::optional<proxy::vmess::VMessCipher> length_cipher_;
    std::optional<proxy::vmess::ShakeMask> mask_;
    bool padding_;
};

struct Connection {

    net::io_context io;
    tcp::acceptor acceptor{io, {net::ip::address_v4::loopback(), 0}};
    tcp::socket peer{io};
    transport::internet::TcpStream stream{Connect()};

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

void CancelBlockedRead(Connection& connection,
                       net::awaitable<buf::MultiBuffer> operation) {
    net::cancellation_signal cancellation;
    bool completed = false;
    std::exception_ptr failure;
    connection.io.restart();
    net::co_spawn(connection.io, std::move(operation),
        net::bind_cancellation_slot(cancellation.slot(),
            [&](std::exception_ptr error, buf::MultiBuffer result) {
                EXPECT_TRUE((result.empty())) << "cancelled VMess read returned partial plaintext";
                failure = error;
                completed = true;
            }));
    // All prefix bytes are already in the production stream's pending data.
    // Drain ready work: the only remaining read is a real socket wait, with no
    // peer data and no elapsed-time assumption about when cancellation occurs.
    connection.io.poll();
    EXPECT_FALSE((completed)) << "VMess read did not wait for the incomplete record";
    cancellation.emit(net::cancellation_type::terminal);
    connection.io.run_for(std::chrono::seconds(1));
    if (!completed) {
        connection.stream.Close();
        connection.peer.cancel();
        connection.io.run();
    }
    ASSERT_TRUE(completed);
    ASSERT_TRUE(failure) << "VMess cancellation became EOF";
    bool aborted = false;
    try {
        std::rethrow_exception(failure);
    } catch (const IoSystemError& error) {
        aborted = error.code() == io_error::operation_aborted;
    }
    EXPECT_TRUE((aborted)) << "VMess cancellation returned the wrong error";
    EXPECT_TRUE((connection.stream.IsOpen() && connection.peer.is_open())) << "VMess cancellation permanently closed the transport";
}

void CancelBlockedRead(Connection& connection, transport::MultiBufferReader& reader,
                       bool automatic_cancel) {
    CancelBlockedRead(connection, ReadBody(reader, automatic_cancel));
}

buf::MultiBuffer ReadReady(Connection& connection,
                           net::awaitable<buf::MultiBuffer> operation) {
    bool completed = false;
    std::exception_ptr failure;
    buf::MultiBuffer result;
    connection.io.restart();
    net::co_spawn(connection.io, std::move(operation),
        [&](std::exception_ptr error, buf::MultiBuffer value) {
            failure = error;
            result = std::move(value);
            completed = true;
        });
    connection.io.run_for(std::chrono::seconds(1));
    if (!completed) {
        connection.stream.Close();
        connection.peer.cancel();
        connection.io.run();
        throw std::runtime_error("resumed VMess read stalled");
    }
    EXPECT_TRUE((completed)) << "resumed VMess read stalled";
    if (failure) {
        std::rethrow_exception(failure);
    }
    return result;
}

buf::MultiBuffer ReadReady(Connection& connection, transport::MultiBufferReader& reader) {
    return ReadReady(connection, reader.ReadMultiBuffer());
}

void CheckReadFailed(Connection& connection,
                      net::awaitable<buf::MultiBuffer> operation,
                      std::string_view message) {
    bool reset = false;
    try {
        static_cast<void>(ReadReady(connection, std::move(operation)));
    } catch (const IoSystemError& error) {
        reset = error.code() == io_error::connection_reset;
    }
    EXPECT_TRUE((reset)) << message;
}

void CheckPayload(const buf::MultiBuffer& result, std::span<const uint8_t> expected,
                  const proxy::vmess::VMessRequest& request) {
    const buf::ContiguousBufferView actual(result);
    EXPECT_TRUE((actual.Bytes().size() == expected.size() &&
              std::equal(actual.Bytes().begin(), actual.Bytes().end(), expected.begin()))) << "resumed VMess record lost, duplicated, or corrupted payload bytes";
    if (request.command == proxy::vmess::Command::UDP) {
        proxy::vmess::ValidateFixedUdpDatagram(result, request.target);
    }
}

memory::ByteVector MakePayload(size_t size, uint8_t seed) {
    memory::ByteVector payload(size);
    for (size_t i = 0; i < size; ++i) {
        payload[i] = static_cast<uint8_t>(seed + i * 17);
    }
    return payload;
}

void TestCancellationResume(proxy::vmess::Security security, uint8_t options,
                            proxy::vmess::Command command, size_t payload_size) {
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
    proxy::vmess::encoding::ServerSession session("cancellation-test");
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
    EXPECT_TRUE((ReadReady(connection, *reader).empty())) << "VMess EOF marker did not finish the reader";
    EXPECT_TRUE((ReadReady(connection, *reader).empty())) << "VMess EOF marker was not permanent";
}

void TestBatchCancellation(proxy::vmess::Security security, uint8_t options) {
    auto request = MakeRequest(security, options, proxy::vmess::Command::TCP);
    RequestEncoder encoder(request);
    auto expected = MakePayload(113, 0x12);
    const auto second_payload = MakePayload(157, 0x83);
    const auto first_wire = encoder.Encode(expected);
    const auto second_wire = encoder.Encode(second_payload);
    const auto third_payload = MakePayload(81, 0x29);
    const auto third_wire = encoder.Encode(third_payload);
    expected.insert(expected.end(), second_payload.begin(), second_payload.end());

    Connection connection;
    proxy::vmess::encoding::ServerSession session("batch-cancellation-test");
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

void TestTransportEOF(proxy::vmess::Security security, uint8_t options, size_t prefix_size) {
    auto request = MakeRequest(security, options, proxy::vmess::Command::UDP);
    RequestEncoder encoder(request);
    const auto payload = MakePayload(113, 0x57);
    const auto wire = encoder.Encode(payload);
    Connection connection;
    connection.stream.PrependReadData(std::span<const uint8_t>(wire).first(prefix_size));
    proxy::vmess::encoding::ServerSession session("transport-eof-test");
    session.SetRequest(request);
    auto reader = session.DecodeRequestBody(connection.stream);
    CancelBlockedRead(connection, *reader, false);
    connection.peer.shutdown(tcp::socket::shutdown_send);
    if (prefix_size == 0) {
        EXPECT_TRUE((ReadReady(connection, *reader).empty())) << "real VMess TCP EOF became a cancellation error";
        EXPECT_TRUE((ReadReady(connection, *reader).empty())) << "real VMess TCP EOF was not permanent";
    } else {
        // EOF inside a record is truncation, never a clean end of body.
        for (int attempt = 0; attempt != 2; ++attempt) {
            CheckReadFailed(connection, reader->ReadMultiBuffer(),
                            "truncated VMess record ended as a clean EOF");
        }
    }
}

void TestAuthenticationFailure(proxy::vmess::Security security, uint8_t options,
                               bool corrupt_length) {
    auto request = MakeRequest(security, options, proxy::vmess::Command::UDP);
    RequestEncoder encoder(request);
    const auto payload = MakePayload(113, 0x47);
    auto wire = encoder.Encode(payload);
    const size_t corrupt_offset = corrupt_length
        ? encoder.HeaderSize() - 1
        : encoder.HeaderSize() + payload.size();
    wire[corrupt_offset] ^= 0x80;
    Connection connection;
    proxy::vmess::encoding::ServerSession session("authentication-failure-test");
    session.SetRequest(request);
    auto reader = session.DecodeRequestBody(connection.stream);
    connection.stream.PrependReadData(std::span<const uint8_t>(wire).first(1));
    CancelBlockedRead(connection, *reader, false);
    connection.stream.PrependReadData(std::span<const uint8_t>(wire).subspan(1));
    for (int attempt = 0; attempt != 2; ++attempt) {
        CheckReadFailed(connection, reader->ReadMultiBuffer(),
                        "resumed VMess read suppressed an authentication failure");
    }
    // Corrupted EOF chunk authentication tag must be rejected as connection_reset.
    {
        Connection eof_connection;
        proxy::vmess::encoding::ServerSession eof_session("eof-auth-failure-test");
        eof_session.SetRequest(request);
        auto eof_reader = eof_session.DecodeRequestBody(eof_connection.stream);
        RequestEncoder eof_encoder(request);
        auto eof_wire = eof_encoder.Encode({});
        eof_wire[encoder.HeaderSize()] ^= 0x80;
        eof_connection.stream.PrependReadData(eof_wire);
        for (int attempt = 0; attempt != 2; ++attempt) {
            CheckReadFailed(eof_connection, eof_reader->ReadMultiBuffer(),
                            "corrupted VMess EOF chunk authentication tag was accepted");
        }
    }
}
class VmessEncryptedBody : public testing::TestWithParam<
    std::tuple<proxy::vmess::Security, uint8_t>> {};

TEST_P(VmessEncryptedBody, CancellationResumesWithoutNonceOrMaskDrift) {
    const auto [security, options] = GetParam();
    for (const auto command : {proxy::vmess::Command::UDP, proxy::vmess::Command::TCP}) {
        SCOPED_TRACE(static_cast<int>(command));
        TestCancellationResume(security, options, command, 113);
        TestCancellationResume(security, options, command, buf::Buffer::kSize + 37);
    }
}

TEST_P(VmessEncryptedBody, BatchCancellationPreservesCompletedAndPartialRecords) {
    const auto [security, options] = GetParam();
    TestBatchCancellation(security, options);
}

TEST_P(VmessEncryptedBody, BodyAuthenticationFailureIsTerminal) {
    const auto [security, options] = GetParam();
    TestAuthenticationFailure(security, options, false);
}

class VmessLengthAuthentication : public testing::TestWithParam<proxy::vmess::Security> {};

TEST_P(VmessLengthAuthentication, FailureIsTerminal) {
    constexpr uint8_t options = proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING |
        proxy::vmess::Option::GLOBAL_PADDING | proxy::vmess::Option::AUTHENTICATED_LENGTH;
    TestAuthenticationFailure(GetParam(), options, true);
}

INSTANTIATE_TEST_SUITE_P(AeadModes, VmessLengthAuthentication,
    testing::Values(proxy::vmess::Security::AES_128_GCM, proxy::vmess::Security::CHACHA20_POLY1305));

TEST_P(VmessEncryptedBody, TransportEofDistinguishesBoundaryFromTruncation) {
    const auto [security, options] = GetParam();
    for (const size_t prefix : {size_t{0}, size_t{1}, size_t{23}}) {
        SCOPED_TRACE(prefix);
        TestTransportEOF(security, options, prefix);
    }
}

INSTANTIATE_TEST_SUITE_P(SecurityAndFraming, VmessEncryptedBody, testing::Combine(
    testing::Values(proxy::vmess::Security::AES_128_GCM, proxy::vmess::Security::CHACHA20_POLY1305),
    testing::Values(uint8_t{proxy::vmess::Option::CHUNK_STREAM},
        uint8_t{proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING | proxy::vmess::Option::GLOBAL_PADDING},
        uint8_t{proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING |
            proxy::vmess::Option::GLOBAL_PADDING | proxy::vmess::Option::AUTHENTICATED_LENGTH})));

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
    if (!completed) {
        connection.stream.Close();
        connection.peer.cancel();
        connection.io.run();
    }
    ASSERT_TRUE(completed);
    ASSERT_FALSE(failure);
}

// A server response with AUTHENTICATED_LENGTH must decode with Xray-core's
// nonce choice; the production client decoder cannot prove this alone.
void TestResponseAuthenticatedLength(proxy::vmess::Security security) {
    constexpr size_t kResponseHeaderSize = 38;
    const uint8_t options = proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING |
        proxy::vmess::Option::GLOBAL_PADDING | proxy::vmess::Option::AUTHENTICATED_LENGTH;
    const auto request = MakeRequest(security, options, proxy::vmess::Command::TCP);
    Connection connection;
    proxy::vmess::encoding::ServerSession session("response-length-test");
    session.SetRequest(request);
    auto writer = session.EncodeResponseBodyWithHeader(connection.stream);
    ASSERT_TRUE(writer);

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
    EXPECT_TRUE((wire.size() > kResponseHeaderSize)) << "VMess response was not written";

    ResponseDecoder decoder(request);
    size_t offset = kResponseHeaderSize;
    for (const auto& [size, value] : chunks) {
        const auto payload = decoder.Decode(wire, offset);
        EXPECT_TRUE((payload.size() == size &&
                  std::all_of(payload.begin(), payload.end(),
                              [value](uint8_t byte) { return byte == value; }))) << "VMess response chunk payload changed";
    }
    EXPECT_EQ((offset), (wire.size())) << "VMess response carried unexpected trailing bytes";
}

memory::ByteVector MakeClientResponse(Connection& connection,
                                     proxy::vmess::encoding::ClientSession& client,
                                     const proxy::vmess::MemoryAccount& account,
                                     const AES_KEY& auth_id_key,
                                     const common::TargetAddress& target,
                                     proxy::vmess::Command command,
                                     proxy::vmess::VMessRequest* authenticated_request = nullptr) {
    using namespace proxyman::inbound;
    constexpr auto tag = "vmess-client-response";
    PreparedVmessUser user;
    user.uuid_bytes = account.uuid_bytes;
    user.auth_key = account.auth_key;
    user.cmd_key = account.cmd_key;
    auto snapshot = UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{user}});
    auto view = UserStore::PrepareWorkerView(snapshot);
    UserStore::InstallWorkerView(std::move(view));
    struct WorkerViewGuard {
        ~WorkerViewGuard() { UserStore::ClearWorkerView(); }
    } worker_view;

    bool completed = false;
    std::exception_ptr failure;
    connection.io.restart();
    net::co_spawn(connection.io,
        client.EncodeRequestHeader(connection.stream, account, auth_id_key, target, command),
        [&](std::exception_ptr error, proxy::vmess::encoding::VMessHandshakeResult result) {
            failure = error;
            EXPECT_TRUE((result.has_value())) << "VMess client request header failed";
            completed = true;
        });
    connection.io.run_for(std::chrono::seconds(1));
    if (!completed) {
        connection.stream.Close();
        connection.peer.cancel();
        connection.io.run();
        throw std::runtime_error("VMess client request header stalled");
    }
    if (failure) std::rethrow_exception(failure);
    EXPECT_TRUE((completed && !failure)) << "VMess client request header did not complete";
    memory::ByteVector header(connection.peer.available());
    EXPECT_TRUE((!header.empty() && net::read(connection.peer, net::buffer(header)) == header.size())) << "VMess client request header was not written";
    proxy::vmess::encoding::ServerSession server(tag);
    auto [request, consumed] = server.DecodeRequestHeader(header.data(), header.size());
    if (!request || consumed != header.size())
        throw std::runtime_error("VMess server could not authenticate the client request");
    if (authenticated_request) *authenticated_request = *request;
    const auto udp_target = request->target;
    const bool is_udp = request->command == proxy::vmess::Command::UDP;
    server.SetRequest(std::move(*request));
    auto writer = server.EncodeResponseBodyWithHeader(connection.stream);
    if (!writer) throw std::runtime_error("VMess server response writer was not created");
    WriteReady(connection, *writer,
               buf::MultiBuffer{MakeBuffer(113, is_udp ? &udp_target : nullptr, 0x53)});
    memory::ByteVector response(connection.peer.available());
    EXPECT_TRUE((response.size() > 38 &&
              net::read(connection.peer, net::buffer(response)) == response.size())) << "VMess server response was not written";
    return response;
}

net::awaitable<buf::MultiBuffer> ReadClientBody(Connection& connection,
                                               proxy::vmess::encoding::ClientSession& client,
                                               bool automatic_cancel) {
    co_await net::this_coro::throw_if_cancelled(automatic_cancel);
    co_return co_await client.DecodeResponse(connection.stream);
}

void TestClientAuthenticationFailure(size_t corrupt_offset,
                                     proxy::vmess::Command command = proxy::vmess::Command::TCP) {
    auto account = proxy::vmess::MemoryAccount::FromUUID("11111111-1111-4111-8111-111111111111");
    ASSERT_TRUE(account);
    const auto auth_id_key = proxy::vmess::ExpandAuthIDEncryptKey(account->auth_key);
    const common::TargetAddress target("127.0.0.1", 5353);
    Connection connection;
    proxy::vmess::encoding::ClientSession client(proxy::vmess::Security::AES_128_GCM, command);
    const auto response = MakeClientResponse(
        connection, client, *account, auth_id_key, target, command);
    auto corrupted = response;
    corrupted[corrupt_offset] ^= 0x80;
    const size_t prefix_size = corrupt_offset < 18 ? 18
        : corrupt_offset < 38 ? 38 : corrupted.size();
    connection.stream.PrependReadData(
        std::span<const uint8_t>(corrupted).first(prefix_size));
    CheckReadFailed(connection, client.DecodeResponse(connection.stream),
                    "VMess client accepted a corrupt response");
    // A second authentic header and body must not revive the failed response.
    connection.stream.PrependReadData(response);
    CheckReadFailed(connection, client.DecodeResponse(connection.stream),
                    "VMess client revived after response authentication failure");
}

void TestClientTruncation(proxy::vmess::Command command, size_t cut) {
    auto account = proxy::vmess::MemoryAccount::FromUUID("11111111-1111-4111-8111-111111111111");
    ASSERT_TRUE(account);
    const auto auth_id_key = proxy::vmess::ExpandAuthIDEncryptKey(account->auth_key);
    const common::TargetAddress target("127.0.0.1", 5353);
    Connection connection;
    proxy::vmess::encoding::ClientSession client(proxy::vmess::Security::AES_128_GCM, command);
    const auto response = MakeClientResponse(
        connection, client, *account, auth_id_key, target, command);
    connection.stream.PrependReadData(std::span<const uint8_t>(response).first(cut));
    connection.peer.shutdown(tcp::socket::shutdown_send);
    CheckReadFailed(connection, client.DecodeResponse(connection.stream),
                    "VMess client accepted a truncated response");
    connection.stream.PrependReadData(response);
    CheckReadFailed(connection, client.DecodeResponse(connection.stream),
                    "VMess client revived after response truncation");
}

void TestClientHeaderCancellation(proxy::vmess::Security security, proxy::vmess::Command command) {
    auto account = proxy::vmess::MemoryAccount::FromUUID("11111111-1111-4111-8111-111111111111");
    ASSERT_TRUE(account);
    const auto auth_id_key = proxy::vmess::ExpandAuthIDEncryptKey(account->auth_key);
    const common::TargetAddress target("127.0.0.1", 5353);
    Connection connection;
    proxy::vmess::encoding::ClientSession client(security, command);
    const auto response = MakeClientResponse(
        connection, client, *account, auth_id_key, target, command);
    size_t supplied = 0;
    for (const size_t cut : {size_t{0}, size_t{1}, size_t{17}, size_t{18}, size_t{23}, size_t{37}}) {
        connection.stream.PrependReadData(
            std::span<const uint8_t>(response).subspan(supplied, cut - supplied));
        supplied = cut;
        CancelBlockedRead(connection, ReadClientBody(connection, client, cut % 2 == 0));
    }
    connection.stream.PrependReadData(std::span<const uint8_t>(response).subspan(supplied));
    const auto payload = ReadReady(connection, client.DecodeResponse(connection.stream));
    const buf::ContiguousBufferView bytes(payload);
    EXPECT_TRUE((bytes.Bytes().size() == 113 &&
              std::all_of(bytes.Bytes().begin(), bytes.Bytes().end(),
                          [](uint8_t byte) { return byte == 0x53; }))) << "VMess client response header cancellation lost plaintext";
}

class InterruptedBodyReader final : public transport::MultiBufferReader {
public:
    InterruptedBodyReader(std::span<const uint8_t> prefix,
                          std::span<const uint8_t> suffix)
        : prefix_(CopyBytes(prefix)), suffix_(CopyBytes(suffix)) {}

    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        ++reads_;
        if (reads_ == 1) {
            co_return std::move(prefix_);
        }
        if (reads_ == 2) {
            throw IoSystemError(io_error::connection_reset, "VMess test interrupted body read");
        }
        co_return std::move(suffix_);
    }
    buf::MultiBuffer TakeRemaining() noexcept { return std::move(suffix_); }

private:
    static buf::MultiBuffer CopyBytes(std::span<const uint8_t> bytes) {
        auto buffer = MakeBuffer(bytes.size(), nullptr, 0x6d);
        std::copy(bytes.begin(), bytes.end(), buffer->Bytes().begin());
        return buf::MultiBuffer{std::move(buffer)};
    }

    buf::MultiBuffer prefix_;
    buf::MultiBuffer suffix_;
    transport::CancellationSource cancellation_;
    size_t reads_ = 0;
};

void TestBodyReadFailure(proxy::vmess::Command command, size_t cut) {
    const auto request = MakeRequest(
        proxy::vmess::Security::AES_128_GCM,
        proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING |
            proxy::vmess::Option::GLOBAL_PADDING,
        command);
    RequestEncoder encoder(request);
    auto prefix = command == proxy::vmess::Command::TCP
        ? encoder.Encode(MakePayload(37, 0x12)) : memory::ByteVector{};
    const auto wire = encoder.Encode(MakePayload(113, 0x47));
    const proxy::vmess::encoding::BodyKey key{request.body_key, request.body_iv};
    proxy::vmess::encoding::BodyDecoder decoder({request.security, request.options, command}, key, key);
    prefix.insert(prefix.end(), wire.begin(), wire.begin() + cut);
    InterruptedBodyReader source(prefix, std::span<const uint8_t>(wire).subspan(cut));
    Connection connection;
    for (int attempt = 0; attempt != 2; ++attempt) {
        CheckReadFailed(connection, decoder.Read(source),
                        "VMess body reader resumed plaintext after a transport failure");
    }
    auto remaining = source.TakeRemaining();
    const buf::ContiguousBufferView bytes(remaining);
    EXPECT_TRUE((std::equal(bytes.Bytes().begin(), bytes.Bytes().end(),
                     wire.begin() + cut, wire.end()))) << "failed VMess body reader consumed subsequent transport bytes";
}

TEST(VmessUdpDatagram, AuthenticatedHeaderRejectionPreservesOnlyVerifiedIdentity) {
    using namespace proxyman::inbound;
    constexpr auto tag = "vmess-header-classification";
    PreparedVmessUser user;
    user.auth_key.fill(0x19);
    user.cmd_key.fill(0x27);
    user.profile.user_id = 73;
    user.profile.email = "header@example.test";
    auto snapshot = UserStore::PrepareUsers(tag, UserSet{PreparedVmessUsers{user}});
    auto view = UserStore::PrepareWorkerView(snapshot);
    UserStore::InstallWorkerView(std::move(view));
    struct WorkerViewGuard {
        ~WorkerViewGuard() { UserStore::ClearWorkerView(); }
    } worker_view;

    for (int fault = 0; fault != 3; ++fault) {
        std::array<uint8_t, 49> plain{};
        plain[0] = 1;
        plain[35] = static_cast<uint8_t>(proxy::vmess::Security::NONE);
        plain[37] = static_cast<uint8_t>(proxy::vmess::Command::UDP);
        plain[38] = 0;
        plain[39] = 53;
        plain[40] = 1;
        plain[41] = 1; plain[42] = 1; plain[43] = 1; plain[44] = 1;
        const uint32_t checksum = common::Fnv1a32(std::span<const uint8_t>(plain.data(), 45)) ^ (fault == 1 ? 1u : 0u);
        for (size_t i = 0; i != 4; ++i) {
            plain[45 + i] = static_cast<uint8_t>(checksum >> (24 - i * 8));
        }
        std::array<uint8_t, 42 + 49 + 16> wire{};
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        proxy::vmess::GenerateAuthID(proxy::vmess::ExpandAuthIDEncryptKey(user.auth_key), now, wire.data());
        const std::span<const uint8_t, 16> auth_id(wire.data(), 16);
        const std::span<const uint8_t, 8> nonce(wire.data() + 34, 8);
        const auto length_key = proxy::vmess::RequestHeaderLengthKey(user.cmd_key, auth_id, nonce);
        const auto payload_key = proxy::vmess::RequestHeaderPayloadKey(user.cmd_key, auth_id, nonce);
        const std::array<uint8_t, 2> length{0, static_cast<uint8_t>(plain.size())};
        EXPECT_TRUE((proxy::SealScatterOneShotAead(EVP_aead_aes_128_gcm(), {length_key.key.data(), 16}, {length_key.nonce.data(), 12}, {length.data(), length.size()}, {auth_id.data(), auth_id.size()}, wire.data() + 16, {wire.data() + 18, 16}))) << "failed to seal header length";
        EXPECT_TRUE((proxy::SealScatterOneShotAead(EVP_aead_aes_128_gcm(), {payload_key.key.data(), 16}, {payload_key.nonce.data(), 12}, {plain.data(), plain.size()}, {auth_id.data(), auth_id.size()}, wire.data() + 42, {wire.data() + 42 + plain.size(), 16}))) << "failed to seal header";
        if (fault == 2) wire.back() ^= 1;
        proxy::vmess::encoding::ServerSession session(tag);
        auto [request, consumed] = session.DecodeRequestHeader(wire.data(), wire.size());
        const auto* rejected = session.AuthenticatedRejectedHeader();
        if (fault == 0) {
            EXPECT_TRUE((request && request->user && request->user->profile.user_id == 73 &&
                  consumed == wire.size() && !rejected)) << "valid header lost authenticated identity";
        } else if (fault == 1) {
            EXPECT_TRUE((!request && rejected && rejected->user->profile.user_id == 73 &&
                  rejected->target.SameEndpoint(common::TargetAddress("1.1.1.1", 53)) &&
                  rejected->command == proxy::vmess::Command::UDP)) << "authenticated malformed header lost verified identity or parsed target";
        } else {
            EXPECT_TRUE((!request && !rejected)) << "unauthenticated header exposed trusted identity";
        }
    }
    UserStore::ClearWorkerView();
}


template <typename Fn>
void CheckNotSupported(Fn&& fn) {
    ExpectLinkError(std::forward<Fn>(fn),
        "empty VMess UDP must fail explicitly without encoding EOF", common::ErrorCode::NOT_SUPPORTED);
}

void TestEmptyUdpWrite(proxy::vmess::Security security) {
    const uint8_t options = proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING |
        proxy::vmess::Option::GLOBAL_PADDING | proxy::vmess::Option::AUTHENTICATED_LENGTH;
    const auto request = MakeRequest(security, options, proxy::vmess::Command::UDP);
    Connection connection;
    proxy::vmess::encoding::ServerSession session("empty-udp-test");
    session.SetRequest(request);
    auto writer = session.EncodeResponseBodyWithHeader(connection.stream);
    auto reject = [&](net::awaitable<void> operation) {
        bool completed = false;
        std::exception_ptr failure;
        connection.io.restart();
        net::co_spawn(connection.io, std::move(operation),
            [&](std::exception_ptr error) { failure = error; completed = true; });
        connection.io.run();
        ASSERT_TRUE(completed);
        ASSERT_TRUE(failure) << "empty VMess UDP write silently succeeded";
        CheckNotSupported([&] { std::rethrow_exception(failure); });
    };
    buf::MultiBuffer empty{MakeBuffer(0, &request.target, 0x6d)};
    reject(writer->WriteMultiBuffer(std::move(empty)));
    reject(writer->WriteBuffers(std::span<const net::const_buffer>{}));
    EXPECT_EQ((connection.peer.available()), (0)) << "rejected VMess UDP write emitted an EOF or response header";

    buf::MultiBuffer data{MakeBuffer(17, &request.target, 0x42)};
    WriteReady(connection, *writer, std::move(data));
    buf::MultiBuffer later_empty{MakeBuffer(0, &request.target, 0x6d)};
    reject(writer->WriteMultiBuffer(std::move(later_empty)));
    const size_t available = connection.peer.available();
    memory::ByteVector wire(available);
    EXPECT_EQ((net::read(connection.peer, net::buffer(wire))), (wire.size())) << "VMess UDP response wire was incomplete";
    ResponseDecoder decoder(request);
    size_t offset = 38;
    const auto decoded = decoder.Decode(wire, offset);
    EXPECT_TRUE((decoded == memory::ByteVector(17, 0x42) && offset == wire.size())) << "rejected empty VMess UDP consumed framing state or appended EOF";

    const proxy::vmess::encoding::BodyKey key{request.body_key, request.body_iv};
    proxy::vmess::encoding::BodyEncoder encoder({security, options, proxy::vmess::Command::UDP}, key, key);
    buf::MultiBuffer encoded;
    buf::MultiBuffer request_empty{MakeBuffer(0, &request.target, 0x6d)};
    CheckNotSupported([&] { encoder.Encode(request_empty, encoded); });
    CheckNotSupported([&] {
        encoder.Encode(std::span<const net::const_buffer>{}, encoded);
    });
    EXPECT_TRUE((encoded.empty())) << "VMess request encoder emitted a forbidden empty chunk";
    std::array<uint8_t, 128> eof_chunk{};
    EXPECT_TRUE((encoder.EncodeEndTo(eof_chunk) != 0)) << "VMess explicit EOF marker was disabled";
}

// Publish a real TCP prefix before a deterministic transport failure. Later
// writes would succeed unless the VMess direction has retired itself.
class InterruptedWriteStream final : public transport::AsyncStream {
public:
    InterruptedWriteStream(Connection& connection, IoErrorCode error)
        : connection_(connection), error_(error) {}

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        co_return co_await connection_.stream.AsyncRead(buffer);
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        const std::array<net::const_buffer, 1> buffers{buffer};
        co_await WriteBuffers(buffers);
        co_return buffer.size();
    }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        co_return co_await connection_.stream.ReadMultiBuffer();
    }
    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (!interrupted_) {
            interrupted_ = true;
            if (write_closed) throw transport::WriteClosed();
            memory::ByteVector prefix;
            for (const auto buffer : buffers) {
                const auto* bytes = static_cast<const uint8_t*>(buffer.data());
                const size_t size = std::min(buffer.size(), size_t{7} - prefix.size());
                if (size != 0) prefix.insert(prefix.end(), bytes, bytes + size);
                if (prefix.size() == 7) break;
            }
            const std::array<net::const_buffer, 1> first{net::buffer(prefix)};
            co_await connection_.stream.WriteBuffers(first);
            published.resize(prefix.size());
            net::read(connection_.peer, net::buffer(published));
            throw IoSystemError(error_, "deterministic VMess partial write");
        }
        co_await connection_.stream.WriteBuffers(buffers);
    }
    void ShutdownWrite() override { connection_.stream.ShutdownWrite(); }
    void Cancel() noexcept override { connection_.stream.Cancel(); }
    void Close() override { connection_.stream.Close(); }
    int NativeHandle() const override { return connection_.stream.NativeHandle(); }
    bool IsOpen() const override { return connection_.stream.IsOpen(); }

    memory::ByteVector published;
    bool write_closed = false;

private:
    Connection& connection_;
    IoErrorCode error_;
    bool interrupted_ = false;
};

std::exception_ptr CompleteWrite(Connection& connection, net::awaitable<void> operation) {
    std::exception_ptr failure;
    bool completed = false;
    connection.io.restart();
    net::co_spawn(connection.io, std::move(operation), [&](std::exception_ptr error) {
        completed = true;
        failure = error;
    });
    connection.io.run();
    EXPECT_TRUE((completed)) << "VMess deterministic write did not complete";
    return failure;
}

void CheckWriteError(std::exception_ptr failure, IoErrorCode expected) {
    ASSERT_TRUE(failure) << "VMess write unexpectedly succeeded";
    try {
        std::rethrow_exception(failure);
    } catch (const IoSystemError& error) {
        EXPECT_EQ(error.code(), expected);
    }
}

void CheckWriteClosed(std::exception_ptr failure) {
    ASSERT_TRUE(failure) << "VMess write after EOF unexpectedly succeeded";
    EXPECT_THROW(std::rethrow_exception(failure), transport::WriteClosed);
}

proxy::vmess::encoding::VMessHandshakeResult CompleteHeader(
    Connection& connection, proxy::vmess::encoding::ClientSession& client, transport::AsyncStream& stream,
    const proxy::vmess::MemoryAccount& account, const AES_KEY& auth_key,
    const common::TargetAddress& target, proxy::vmess::Command command) {
    proxy::vmess::encoding::VMessHandshakeResult result;
    std::exception_ptr failure;
    connection.io.restart();
    net::co_spawn(connection.io,
        client.EncodeRequestHeader(stream, account, auth_key, target, command),
        [&](std::exception_ptr error, proxy::vmess::encoding::VMessHandshakeResult value) {
            failure = error;
            result = std::move(value);
        });
    connection.io.run();
    if (failure) std::rethrow_exception(failure);
    return result;
}

void TestWriteFailure(bool server_side, bool eof, IoErrorCode error,
                      proxy::vmess::Command command) {
    const auto request = MakeRequest(
        proxy::vmess::Security::AES_128_GCM,
        proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING |
            proxy::vmess::Option::GLOBAL_PADDING | proxy::vmess::Option::AUTHENTICATED_LENGTH,
        command);
    Connection connection;
    InterruptedWriteStream stream(connection, error);
    const std::array<uint8_t, 19> payload{0x41, 0x42, 0x43};
    const std::array<net::const_buffer, 1> buffers{net::buffer(payload)};
    proxy::vmess::encoding::ClientSession client(request.security, command);
    proxy::vmess::encoding::ServerSession server("write-failure");
    server.SetRequest(request);
    auto writer = server.EncodeResponseBodyWithHeader(stream);
    auto write = [&]() -> net::awaitable<void> {
        if (server_side) {
            if (eof) co_await writer->AsyncShutdownWrite();
            else co_await writer->WriteBuffers(buffers);
        } else {
            if (eof) co_await client.EncodeRequestBodyEOF(stream);
            else co_await client.EncodeRequestBody(stream, buffers);
        }
    };
    CheckWriteError(CompleteWrite(connection, write()), error);
    EXPECT_FALSE((stream.published.empty())) << "VMess failure did not publish a TCP prefix";
    CheckWriteError(CompleteWrite(connection, write()), io_error::connection_reset);
    CheckWriteError(CompleteWrite(connection, server_side
        ? writer->WriteMultiBuffer(buf::MultiBuffer{MakeBuffer(
            11, command == proxy::vmess::Command::UDP ? &request.target : nullptr, 0x6d)})
        : client.EncodeRequestBody(stream, buf::MultiBuffer{MakeBuffer(11, nullptr, 0x6d)})),
        io_error::connection_reset);
    if (!server_side) {
        for (int entry = 0; entry != 3; ++entry) {
            Connection healthy;
            auto rejected_write = [&]() -> net::awaitable<void> {
                if (entry == 0) {
                    co_await client.EncodeRequestBody(healthy.stream, buffers);
                } else if (entry == 1) {
                    co_await client.EncodeRequestBody(
                        healthy.stream, buf::MultiBuffer{MakeBuffer(11, nullptr, 0x6d)});
                } else {
                    co_await client.EncodeRequestBodyEOF(healthy.stream);
                }
            };
            CheckWriteError(CompleteWrite(healthy, rejected_write()), io_error::connection_reset);
            EXPECT_TRUE((healthy.stream.IsOpen())) << "failed VMess session closed a newly supplied healthy transport";
        }
    }
}

void TestWriteEnd(bool server_side, proxy::vmess::Command command) {
    const auto request = MakeRequest(proxy::vmess::Security::AES_128_GCM,
        proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING, command);
    Connection connection;
    auto account = proxy::vmess::MemoryAccount::FromUUID("11111111-1111-4111-8111-111111111111");
    const auto auth_key = proxy::vmess::ExpandAuthIDEncryptKey(account->auth_key);
    proxy::vmess::encoding::ClientSession client(request.security, command);
    proxy::vmess::encoding::ServerSession server("write-eof");
    server.SetRequest(request);
    auto writer = server.EncodeResponseBodyWithHeader(connection.stream);
    const auto response = server_side ? memory::ByteVector{}
        : MakeClientResponse(connection, client, *account, auth_key, request.target, command);
    auto finish = [&]() -> net::awaitable<void> {
        if (server_side) co_await writer->AsyncShutdownWrite();
        else co_await client.EncodeRequestBodyEOF(connection.stream);
    };
    EXPECT_FALSE((CompleteWrite(connection, finish()))) << "VMess EOF write failed";
    const size_t eof_size = connection.peer.available();
    EXPECT_TRUE((eof_size != 0)) << "VMess EOF had no wire bytes";
    EXPECT_FALSE((CompleteWrite(connection, finish()))) << "VMess EOF was not idempotent";
    const std::array<uint8_t, 3> data{1, 2, 3};
    const std::array<net::const_buffer, 1> buffers{net::buffer(data)};
    CheckWriteClosed(CompleteWrite(connection, server_side
        ? writer->WriteBuffers(buffers)
        : client.EncodeRequestBody(connection.stream, buffers)));
    CheckWriteClosed(CompleteWrite(connection, server_side
        ? writer->WriteMultiBuffer(buf::MultiBuffer{MakeBuffer(
            11, command == proxy::vmess::Command::UDP ? &request.target : nullptr, 0x6d)})
        : client.EncodeRequestBody(connection.stream, buf::MultiBuffer{MakeBuffer(11, nullptr, 0x6d)})));
    EXPECT_EQ((connection.peer.available()), (eof_size)) << "VMess wrote more bytes after EOF";
    if (server_side) {
        RequestEncoder encoder(request);
        const auto payload = MakePayload(17, 0x81);
        const auto wire = encoder.Encode(payload);
        net::write(connection.peer, net::buffer(wire));
        auto reader = server.DecodeRequestBody(connection.stream);
        CheckPayload(ReadReady(connection, *reader), payload, request);
    } else {
        connection.stream.PrependReadData(response);
        const auto result = ReadReady(connection, client.DecodeResponse(connection.stream));
        const buf::ContiguousBufferView bytes(result);
        EXPECT_TRUE((bytes.Bytes().size() == 113 &&
                  std::all_of(bytes.Bytes().begin(), bytes.Bytes().end(),
                              [](uint8_t byte) { return byte == 0x53; }))) << "VMess request EOF damaged the response direction";
    }
}
}  // namespace

TEST(VmessUdpDatagram, RejectsEmptyMissingMixedAndWrongFixedUdpEndpoints) {
    const common::TargetAddress target("1.1.1.1", 53);
    const common::TargetAddress other("8.8.8.8", 53);
    buf::MultiBuffer empty{MakeBuffer(0, &target, 0x6d)};
    CheckNotSupported([&] { proxy::vmess::ValidateFixedUdpDatagram(empty, target); });



    buf::MultiBuffer mixed;
    mixed.push_back(MakeBuffer(4096, &target, 0x6d));
    mixed.push_back(MakeBuffer(1024, &other, 0x6d));
    ExpectLinkError([&] { proxy::vmess::ValidateFixedUdpDatagram(mixed, target); },
    "mixed VMess UDP endpoint was partially accepted");

    buf::MultiBuffer missing;
    missing.push_back(MakeBuffer(4096, &target, 0x6d));
    missing.push_back(MakeBuffer(1024, nullptr, 0x6d));
    ExpectLinkError([&] { proxy::vmess::ValidateFixedUdpDatagram(missing, target); },
    "missing VMess UDP endpoint was partially accepted");

    buf::MultiBuffer wrong{MakeBuffer(4096, &other, 0x6d)};
    ExpectLinkError([&] { proxy::vmess::ValidateFixedUdpDatagram(wrong, target); },
    "wrong fixed VMess UDP endpoint was accepted");


}

class VmessResponseEncoding : public testing::TestWithParam<proxy::vmess::Security> {};

TEST_P(VmessResponseEncoding, AuthenticatedLengthMatchesXrayNonceChoice) {
    TestResponseAuthenticatedLength(GetParam());
}

TEST_P(VmessResponseEncoding, EmptyUdpRejectionPreservesNextRecordAndExplicitEof) {
    TestEmptyUdpWrite(GetParam());
}

INSTANTIATE_TEST_SUITE_P(AeadModes, VmessResponseEncoding,
    testing::Values(proxy::vmess::Security::AES_128_GCM, proxy::vmess::Security::CHACHA20_POLY1305));

TEST(VmessUdpDatagram, ClientResponseHeaderFailureIsTerminal) {
    TestClientAuthenticationFailure(17);
    TestClientAuthenticationFailure(37);
}

TEST(VmessUdpDatagram, ClientResponseHeaderCancellationResumes) {
    for (const auto security : {proxy::vmess::Security::AES_128_GCM, proxy::vmess::Security::CHACHA20_POLY1305}) {
        for (const auto command : {proxy::vmess::Command::TCP, proxy::vmess::Command::UDP}) {
            TestClientHeaderCancellation(security, command);
        }
    }
}

TEST(VmessUdpDatagram, BodyReadFailureIsTerminal) {
    for (const auto command : {proxy::vmess::Command::TCP, proxy::vmess::Command::UDP}) {
        for (const size_t cut : {size_t{1}, size_t{9}}) {
            TestBodyReadFailure(command, cut);
        }
    }
}

TEST(VmessUdpDatagram, ClientResponseBodyFailureIsTerminal) {
    for (const auto command : {proxy::vmess::Command::TCP, proxy::vmess::Command::UDP}) {
        TestClientAuthenticationFailure(40, command);
        for (const size_t cut : {size_t{0}, size_t{1}, size_t{18}, size_t{37}, size_t{40}}) {
            TestClientTruncation(command, cut);
        }
    }
}

TEST(VmessUdpDatagram, RequestHeaderWriteFailureIsTerminal) {
    for (const IoErrorCode error : {IoErrorCode{io_error::connection_reset},
                                   IoErrorCode{io_error::operation_aborted}}) {
        Connection connection;
        InterruptedWriteStream stream(connection, error);
        auto account = proxy::vmess::MemoryAccount::FromUUID("11111111-1111-4111-8111-111111111111");
        const auto auth_key = proxy::vmess::ExpandAuthIDEncryptKey(account->auth_key);
        const common::TargetAddress target("127.0.0.1", 5353);
        proxy::vmess::encoding::ClientSession client(proxy::vmess::Security::AES_128_GCM, proxy::vmess::Command::TCP);
        const auto first = CompleteHeader(
            connection, client, stream, *account, auth_key, target, proxy::vmess::Command::TCP);
        EXPECT_TRUE((!first && first.error() == common::MapAsioError(error))) << "VMess request header changed the original write error";
        EXPECT_FALSE((stream.published.empty())) << "VMess request header fault had no wire prefix";
        const auto next = CompleteHeader(
            connection, client, stream, *account, auth_key, target, proxy::vmess::Command::TCP);
        EXPECT_FALSE((next)) << "VMess retried a request header after its key was erased";
        CheckWriteError(CompleteWrite(connection, client.EncodeRequestBody(
            stream, buf::MultiBuffer{MakeBuffer(13, nullptr, 0x6d)})), io_error::connection_reset);
        CheckWriteError(CompleteWrite(connection, client.EncodeRequestBodyEOF(stream)),
                        io_error::connection_reset);
    }
}

TEST(VmessUdpDatagram, BodyWriteFailureIsTerminal) {
    for (const bool server_side : {false, true}) {
        for (const bool eof : {false, true}) {
            for (const auto command : {proxy::vmess::Command::TCP, proxy::vmess::Command::UDP}) {
                for (const IoErrorCode error : {IoErrorCode{io_error::connection_reset},
                                               IoErrorCode{io_error::operation_aborted}}) {
                    TestWriteFailure(server_side, eof, error, command);
                }
            }
        }
    }
}

TEST(VmessUdpDatagram, BodyWriteEndPreservesReverseRead) {
    for (const bool server_side : {false, true}) {
        for (const auto command : {proxy::vmess::Command::TCP, proxy::vmess::Command::UDP}) {
            TestWriteEnd(server_side, command);
        }
    }
}

TEST(VmessUdpDatagram, BodyEncoderRejectsAliasBeforeAdvancing) {
    const auto request = MakeRequest(proxy::vmess::Security::AES_128_GCM,
        proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING |
            proxy::vmess::Option::AUTHENTICATED_LENGTH, proxy::vmess::Command::UDP);
    const proxy::vmess::encoding::BodyKey key{request.body_key, request.body_iv};
    proxy::vmess::encoding::BodyEncoder encoder({request.security, request.options, request.command}, key, key);
    buf::MultiBuffer payload{MakeBuffer(19, &request.target, 0x31)};
    ExpectLinkError([&] { encoder.Encode(payload, payload); },
                  "VMess BodyEncoder accepted the same input/output object",
                  common::ErrorCode::INVALID_ARGUMENT);
    const buf::ContiguousBufferView original(payload);
    EXPECT_TRUE((original.Bytes().size() == 19 &&
              std::all_of(original.Bytes().begin(), original.Bytes().end(),
                          [](uint8_t byte) { return byte == 0x31; }))) << "VMess alias rejection modified its input";
    EXPECT_FALSE((encoder.Failed())) << "VMess alias rejection retired the encoder";
    buf::MultiBuffer encoded;
    encoder.Encode(payload, encoded);
    RequestEncoder reference(request);
    const auto expected = reference.Encode(memory::ByteVector(19, 0x31));
    const buf::ContiguousBufferView actual(encoded);
    EXPECT_TRUE((std::equal(actual.Bytes().begin(), actual.Bytes().end(),
                     expected.begin(), expected.end()))) << "VMess alias rejection advanced nonce or mask";
    std::array<uint8_t, 128> eof_chunk{};
    EXPECT_TRUE((encoder.EncodeEndTo(eof_chunk) != 0)) << "VMess EOF marker failed";
    CheckWriteClosed([&]() -> std::exception_ptr {
        try { encoder.Encode(payload, encoded); }
        catch (...) { return std::current_exception(); }
        return {};
    }());
}

TEST(VmessUdpDatagram, RequestHeaderInputRejectionPreservesKeys) {
    Connection connection;
    auto account = proxy::vmess::MemoryAccount::FromUUID("11111111-1111-4111-8111-111111111111");
    const auto auth_key = proxy::vmess::ExpandAuthIDEncryptKey(account->auth_key);
    common::TargetAddress target;
    proxy::vmess::encoding::ClientSession client(proxy::vmess::Security::AES_128_GCM, proxy::vmess::Command::TCP);
    const auto rejected = CompleteHeader(
        connection, client, connection.stream, *account, auth_key, target, proxy::vmess::Command::TCP);
    EXPECT_TRUE((!rejected && rejected.error() == common::ErrorCode::PROTOCOL_INVALID_ADDRESS)) << "VMess invalid request target changed its error";
    EXPECT_EQ((connection.peer.available()), (0)) << "VMess invalid target published header bytes";
    target = common::TargetAddress("127.0.0.1", 5353);
    const auto response = MakeClientResponse(
        connection, client, *account, auth_key, target, proxy::vmess::Command::TCP);
    connection.stream.PrependReadData(response);
    const auto decoded = ReadReady(connection, client.DecodeResponse(connection.stream));
    const buf::ContiguousBufferView bytes(decoded);
    EXPECT_TRUE((bytes.Bytes().size() == 113 &&
              std::all_of(bytes.Bytes().begin(), bytes.Bytes().end(),
                          [](uint8_t byte) { return byte == 0x53; }))) << "VMess input rejection erased the keys needed by the next legal request";
}

TEST(VmessUdpDatagram, BodyInputRejectionPreservesNextRecord) {
    const auto request = MakeRequest(proxy::vmess::Security::AES_128_GCM,
        proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING |
            proxy::vmess::Option::AUTHENTICATED_LENGTH, proxy::vmess::Command::UDP);
    const proxy::vmess::encoding::BodyKey key{request.body_key, request.body_iv};
    proxy::vmess::encoding::BodyEncoder encoder({request.security, request.options, request.command}, key, key);
    buf::MultiBuffer encoded;
    CheckNotSupported([&] {
        encoder.Encode(std::span<const net::const_buffer>{}, encoded);
    });
    const auto oversized = MakePayload(proxy::vmess::MAX_CHUNK_SIZE + 1, 0x21);
    const std::array<net::const_buffer, 1> large{net::buffer(oversized)};
    ExpectLinkError([&] { encoder.Encode(large, encoded); },
                  "VMess accepted an oversized UDP record",
                  common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    const auto one_over = MakePayload(
        proxy::vmess::MAX_CHUNK_SIZE - proxy::vmess::GCM_TAG_SIZE + 1, 0x19);
    const std::array<net::const_buffer, 1> one_over_buffers{net::buffer(one_over)};
    ExpectLinkError([&] { encoder.Encode(one_over_buffers, encoded); },
                  "VMess accepted one byte beyond its authenticated payload limit",
                  common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    buf::MultiBuffer large_packet;
    EXPECT_TRUE((buf::AppendSpanToMultiBuffer(oversized, large_packet))) << "VMess oversized test packet allocation failed";
    ExpectLinkError([&] { encoder.Encode(large_packet, encoded); },
                  "VMess accepted oversized multi-buffer UDP",
                  common::ErrorCode::PROTOCOL_ENCODE_FAILED);
    const std::array<net::const_buffer, 1> null_input{
        net::const_buffer(nullptr, 1)};
    ExpectLinkError([&] { encoder.Encode(null_input, encoded); },
                  "VMess accepted non-empty null input", common::ErrorCode::INVALID_ARGUMENT);
    EXPECT_TRUE((encoded.empty() && !encoder.Failed())) << "VMess input rejection published bytes or retired the encoder";
    const auto payload = MakePayload(113, 0x47);
    const std::array<net::const_buffer, 1> legal{net::buffer(payload)};
    encoder.Encode(legal, encoded);
    RequestEncoder reference(request);
    const auto expected = reference.Encode(payload);
    const buf::ContiguousBufferView actual(encoded);
    EXPECT_TRUE((std::equal(actual.Bytes().begin(), actual.Bytes().end(),
                     expected.begin(), expected.end()))) << "VMess input rejection advanced the next record's framing state";
    encoded.clear();
    const auto maximum = MakePayload(proxy::vmess::MAX_CHUNK_SIZE - proxy::vmess::GCM_TAG_SIZE, 0x61);
    const std::array<net::const_buffer, 2> maximum_buffers{
        net::buffer(maximum.data(), 17),
        net::buffer(maximum.data() + 17, maximum.size() - 17)};
    encoder.Encode(maximum_buffers, encoded);
    const auto expected_maximum = reference.Encode(maximum);
    const buf::ContiguousBufferView actual_maximum(encoded);
    EXPECT_TRUE((std::equal(actual_maximum.Bytes().begin(), actual_maximum.Bytes().end(),
                     expected_maximum.begin(), expected_maximum.end()))) << "VMess maximum UDP payload damaged the next authenticated record";
}

TEST(VmessUdpDatagram, LowerWriteClosedPreservesReverseRead) {
    for (const bool server_side : {false, true}) {
        const auto request = MakeRequest(proxy::vmess::Security::AES_128_GCM,
            proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING,
            proxy::vmess::Command::TCP);
        Connection connection;
        InterruptedWriteStream stream(connection, io_error::connection_reset);
        stream.write_closed = true;
        auto account = proxy::vmess::MemoryAccount::FromUUID("11111111-1111-4111-8111-111111111111");
        const auto auth_key = proxy::vmess::ExpandAuthIDEncryptKey(account->auth_key);
        proxy::vmess::encoding::ClientSession client(request.security, request.command);
        const auto response = server_side ? memory::ByteVector{}
            : MakeClientResponse(
                  connection, client, *account, auth_key, request.target, request.command);
        proxy::vmess::encoding::ServerSession server("lower-write-closed");
        server.SetRequest(request);
        auto writer = server.EncodeResponseBodyWithHeader(stream);
        const auto payload = MakePayload(17, 0x31);
        const std::array<net::const_buffer, 1> buffers{net::buffer(payload)};
        for (int attempt = 0; attempt != 2; ++attempt) {
            CheckWriteClosed(CompleteWrite(connection, server_side
                ? writer->WriteBuffers(buffers) : client.EncodeRequestBody(stream, buffers)));
        }
        EXPECT_EQ((connection.peer.available()), (0)) << "VMess resumed publication after a clean lower write close";
        if (server_side) {
            RequestEncoder encoder(request);
            const auto wire = encoder.Encode(payload);
            net::write(connection.peer, net::buffer(wire));
            auto reader = server.DecodeRequestBody(stream);
            CheckPayload(ReadReady(connection, *reader), payload, request);
        } else {
            connection.stream.PrependReadData(response);
            const auto decoded = ReadReady(connection, client.DecodeResponse(stream));
            const buf::ContiguousBufferView bytes(decoded);
            EXPECT_TRUE((bytes.Bytes().size() == 113 &&
                      std::all_of(bytes.Bytes().begin(), bytes.Bytes().end(),
                                  [](uint8_t byte) { return byte == 0x53; }))) << "VMess clean lower write close discarded the response direction";
        }
    }
}

TEST(VmessUdpDatagram, PreCancelledWritePreservesNextRecord) {
    // Entry: MultiBuffer, buffer sequence, EOF, and client request header.
    for (const bool server_side : {false, true}) {
        for (const auto command : {proxy::vmess::Command::TCP, proxy::vmess::Command::UDP}) {
            for (int entry = 0; entry != (server_side ? 3 : 4); ++entry) {
                Connection connection;
                auto request = MakeRequest(proxy::vmess::Security::AES_128_GCM,
                    proxy::vmess::Option::CHUNK_STREAM | proxy::vmess::Option::CHUNK_MASKING |
                        proxy::vmess::Option::GLOBAL_PADDING |
                        proxy::vmess::Option::AUTHENTICATED_LENGTH, command);
                auto account = proxy::vmess::MemoryAccount::FromUUID(
                    "11111111-1111-4111-8111-111111111111");
                const auto auth_key = proxy::vmess::ExpandAuthIDEncryptKey(account->auth_key);
                proxy::vmess::encoding::ClientSession client(request.security, command);
                memory::ByteVector response;
                if (!server_side && entry != 3) {
                    response = MakeClientResponse(
                        connection, client, *account, auth_key, request.target, command, &request);
                }
                proxy::vmess::encoding::ServerSession server("pre-cancel-write");
                server.SetRequest(request);
                auto writer = server.EncodeResponseBodyWithHeader(connection.stream);
                const memory::ByteVector payload(19, 0x63);
                const std::array<net::const_buffer, 1> buffers{net::buffer(payload)};
                auto write_payload = [&]() -> net::awaitable<void> {
                    if (entry == 0) {
                        buf::MultiBuffer mb{MakeBuffer(
                            payload.size(), command == proxy::vmess::Command::UDP
                                ? &request.target : nullptr, 0x63)};
                        if (server_side) co_await writer->WriteMultiBuffer(std::move(mb));
                        else co_await client.EncodeRequestBody(connection.stream, std::move(mb));
                    } else {
                        if (server_side) co_await writer->WriteBuffers(buffers);
                        else co_await client.EncodeRequestBody(connection.stream, buffers);
                    }
                };
                net::cancellation_signal cancellation;
                std::exception_ptr failure;
                auto cancel_before_entry = [&]() -> net::awaitable<void> {
                    co_await net::this_coro::throw_if_cancelled(false);
                    cancellation.emit(net::cancellation_type::terminal);
                    bool cancelled = false;
                    try {
                        if (entry == 3) {
                            const auto result = co_await client.EncodeRequestHeader(
                                connection.stream, *account, auth_key, request.target, command);
                            cancelled = !result &&
                                result.error() == common::MapAsioError(io_error::operation_aborted);
                        } else if (entry == 2) {
                            if (server_side) co_await writer->AsyncShutdownWrite();
                            else co_await client.EncodeRequestBodyEOF(connection.stream);
                        } else {
                            co_await write_payload();
                        }
                    } catch (const IoSystemError& error) {
                        cancelled = error.code() == io_error::operation_aborted;
                    }
                    co_await net::this_coro::reset_cancellation_state();
                    EXPECT_EQ((connection.peer.available()), (0)) << "pre-cancelled VMess write published wire bytes";
                    EXPECT_TRUE((cancelled)) << "pre-cancelled VMess write did not report cancellation";
                };
                connection.io.restart();
                net::co_spawn(connection.io, cancel_before_entry(),
                    net::bind_cancellation_slot(cancellation.slot(),
                        [&](std::exception_ptr error) { failure = error; }));
                connection.io.run();
                if (failure) std::rethrow_exception(failure);

                if (!server_side && entry == 3) {
                    response = MakeClientResponse(
                        connection, client, *account, auth_key, request.target, command, &request);
                }
                auto resume = [&]() -> net::awaitable<void> {
                    co_await write_payload();
                    if (server_side) co_await writer->AsyncShutdownWrite();
                    else co_await client.EncodeRequestBodyEOF(connection.stream);
                };
                if (const auto error = CompleteWrite(connection, resume())) {
                    std::rethrow_exception(error);
                }
                if (server_side) {
                    memory::ByteVector wire(connection.peer.available());
                    net::read(connection.peer, net::buffer(wire));
                    ResponseDecoder decoder(request);
                    size_t offset = 38;
                    EXPECT_EQ((decoder.Decode(wire, offset)), (payload)) << "pre-cancelled VMess response advanced its next record";
                    EXPECT_TRUE((decoder.Decode(wire, offset).empty() && offset == wire.size())) << "pre-cancelled VMess response damaged EOF framing";
                } else {
                    connection.stream.PrependReadData(response);
                    const auto decoded = ReadReady(connection, client.DecodeResponse(connection.stream));
                    const buf::ContiguousBufferView bytes(decoded);
                    EXPECT_TRUE((bytes.Bytes().size() == 113 &&
                              std::all_of(bytes.Bytes().begin(), bytes.Bytes().end(),
                                          [](uint8_t byte) { return byte == 0x53; }))) << "pre-cancelled VMess request damaged response keys";
                    transport::internet::TcpStream peer_stream(std::move(connection.peer));
                    proxy::vmess::encoding::ServerSession peer("pre-cancel-request-peer");
                    peer.SetRequest(request);
                    auto reader = peer.DecodeRequestBody(peer_stream);
                    CheckPayload(ReadReady(connection, *reader), payload, request);
                    EXPECT_TRUE((ReadReady(connection, *reader).empty())) << "pre-cancelled VMess request damaged EOF framing";
                }
            }
        }
    }
}
