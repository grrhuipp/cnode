#pragma once

#include "common/target_address.hpp"
#include "shadowsocks_protocol.hpp"
#include "stream_crypto.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <tl/expected.hpp>
#include <memory>
#include <span>
#include <vector>

namespace ss {

class RequestBodyWriter final
    : public memory::ThreadAllocated
    , public transport::MultiBufferWriter {
public:
    RequestBodyWriter(SsAeadCipher write_cipher,
                      uint64_t write_nonce,
                      AsyncStream& stream)
        : write_cipher_(std::move(write_cipher))
        , write_nonce_(write_nonce)
        , stream_(&stream) {}

    RequestBodyWriter(const RequestBodyWriter&) = delete;
    RequestBodyWriter& operator=(const RequestBodyWriter&) = delete;
    RequestBodyWriter(RequestBodyWriter&&) noexcept = default;
    RequestBodyWriter& operator=(RequestBodyWriter&&) noexcept = default;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;
    bool WriteShutdownClosesLink() const noexcept override {
        return stream_ && stream_->WriteShutdownClosesLink();
    }

private:
    void Finish() {
        write_finished_ = true;
        write_cipher_.reset();
    }

    void Retire() {
        auto* stream = std::exchange(stream_, nullptr);
        write_cipher_.reset();
        if (stream) stream->CloseAbortive();
    }

    std::optional<SsAeadCipher> write_cipher_;
    uint64_t write_nonce_ = 0;
    bool write_finished_ = false;
    AsyncStream* stream_ = nullptr;
};

struct WriteTCPRequestResult {
    RequestBodyWriter request_writer;
    KeyBytes request_salt;
};

// xray-core proxy/shadowsocks/client.go 对应的客户端握手与 reader/writer 入口。
[[nodiscard]] net::awaitable<tl::expected<WriteTCPRequestResult, ErrorCode>>
WriteTCPRequest(const TargetAddress& target,
                const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                std::span<const KeyBytes> psk_chain,
                AsyncStream& stream,
                ForwardedMetadataView forwarded = {});

[[nodiscard]] net::awaitable<tl::expected<detail::BodyReader, ErrorCode>>
ReadTCPResponse(const SsCipherInfo& cipher_info,
                const KeyBytes& master_key,
                const KeyBytes& request_salt,
                AsyncStream& stream);

}  // namespace ss
