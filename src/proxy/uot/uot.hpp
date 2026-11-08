#pragma once

#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"
#include "common/target_address.hpp"
#include "common/address_codec.hpp"
#include "transport/async_stream.hpp"
#include "transport/link.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <tl/expected.hpp>
#include <optional>
#include <span>
#include <string_view>

namespace proxy::uot {

inline constexpr std::string_view kMagicAddress = "sp.v2.udp-over-tcp.arpa";
inline constexpr std::string_view kV1MagicAddress = "sp.udp-over-tcp.arpa";
inline constexpr size_t kMaxAddressSize = kMaxEncodedAddressSize;
inline constexpr size_t kMaxRequestSize = 1 + kMaxAddressSize;

enum class Version : uint8_t {
    V1 = 1,
    V2 = 2,
};

struct Request {
    bool is_connect = false;
    TargetAddress destination;
    std::optional<ForwardedMetadata> forwarded;
};
struct EncodedRequest {
    std::array<uint8_t, kMaxRequestSize> bytes{};
    size_t size = 0;

    [[nodiscard]] std::span<const uint8_t> span() const noexcept {
        return {bytes.data(), size};
    }
};

[[nodiscard]] std::optional<Version> VersionFromMagicAddress(
    const TargetAddress& target) noexcept;

[[nodiscard]] tl::expected<EncodedRequest, ErrorCode> EncodeRequest(
    bool is_connect,
    const TargetAddress& destination,
    ForwardedMetadataView forwarded = {});

[[nodiscard]] net::awaitable<tl::expected<Request, ErrorCode>> ReadRequest(
    transport::MultiBufferReader& reader,
    buf::MultiBuffer& pending);


struct PreparedRequest {
    bool is_connect = false;
    TargetAddress destination;
    std::optional<ForwardedMetadata> forwarded;
    buf::MultiBuffer pending;
    buf::MultiBuffer initial_decoded;
};

[[nodiscard]] net::awaitable<tl::expected<PreparedRequest, ErrorCode>>
ReadUotRequestHeader(
    Version version,
    transport::MultiBufferReader& reader,
    buf::MultiBuffer pending = {},
    ErrorCode v1_eof_error = ErrorCode::PROTOCOL_DECODE_FAILED);
class PacketReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return reader_.Cancellation(); }
    // A UDP association has no write-half-close to propagate to its peer.
    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::CloseLink;
    }

    PacketReader(transport::MultiBufferReader& reader,
                 bool is_connect,
                 TargetAddress destination,
                 buf::MultiBuffer pending = {});

    PacketReader(transport::MultiBufferReader& reader,
                 PreparedRequest prepared);

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;

    [[nodiscard]] buf::MultiBuffer TakePending() noexcept;
private:
    transport::MultiBufferReader& reader_;
    bool is_connect_ = false;
    // 非 connect 仅使用帧内地址，请求目标已由会话上下文拥有。
    TargetAddress destination_;
    buf::MultiBuffer pending_;
    buf::MultiBuffer initial_decoded_;
};

class PacketWriter final : public transport::MultiBufferWriter {
public:
    PacketWriter(transport::MultiBufferWriter& writer,
                 bool is_connect,
                 TargetAddress destination);

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;
    bool WriteShutdownClosesLink() const noexcept override { return writer_.WriteShutdownClosesLink(); }

private:
    net::awaitable<void> WritePacket(
        const TargetAddress& destination,
        std::span<const net::const_buffer> payload);

    transport::MultiBufferWriter& writer_;
    bool is_connect_ = false;
    TargetAddress destination_;
};

template <typename Underlying>
class FramedEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    FramedEndpoint(Underlying& underlying,
                   bool is_connect,
                   TargetAddress destination,
                   buf::MultiBuffer pending = {})
        : underlying_(underlying)
        , reader_(underlying, is_connect, is_connect ? destination : TargetAddress{}, std::move(pending))
        , writer_(underlying, is_connect, std::move(destination)) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        return reader_.ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        return writer_.WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        return writer_.WriteBuffers(buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return writer_.AsyncShutdownWrite();
    }

    transport::CancellationSource& Cancellation() noexcept override { return underlying_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return reader_.ReadEofAction(); }
    bool WriteShutdownClosesLink() const noexcept override { return writer_.WriteShutdownClosesLink(); }

    void Cancel() noexcept {
        if constexpr (requires(Underlying& endpoint) { endpoint.Cancel(); }) {
            underlying_.Cancel();
        }
    }

    void Close() {
        if constexpr (requires(Underlying& endpoint) { endpoint.Close(); }) {
            underlying_.Close();
        }
    }

    void CloseAbortive() {
        if constexpr (requires(Underlying& endpoint) { endpoint.CloseAbortive(); }) {
            underlying_.CloseAbortive();
        }
    }

    void SetIdleTimeout(std::chrono::seconds timeout) {
        if constexpr (requires(Underlying& endpoint) { endpoint.SetIdleTimeout(timeout); }) {
            underlying_.SetIdleTimeout(timeout);
        }
    }

    void SetReadTimeout(std::chrono::seconds timeout) {
        if constexpr (requires(Underlying& endpoint) { endpoint.SetReadTimeout(timeout); }) {
            underlying_.SetReadTimeout(timeout);
        }
    }

    void SetWriteTimeout(std::chrono::seconds timeout) {
        if constexpr (requires(Underlying& endpoint) { endpoint.SetWriteTimeout(timeout); }) {
            underlying_.SetWriteTimeout(timeout);
        }
    }

    [[nodiscard]] bool ConsumeIdleTimeout() noexcept {
        if constexpr (requires(Underlying& endpoint) { endpoint.ConsumeIdleTimeout(); }) {
            return underlying_.ConsumeIdleTimeout();
        } else {
            return false;
        }
    }

    [[nodiscard]] bool ConsumeReadTimeout() noexcept {
        if constexpr (requires(Underlying& endpoint) { endpoint.ConsumeReadTimeout(); }) {
            return underlying_.ConsumeReadTimeout();
        } else {
            return false;
        }
    }

    [[nodiscard]] bool ConsumeWriteTimeout() noexcept {
        if constexpr (requires(Underlying& endpoint) { endpoint.ConsumeWriteTimeout(); }) {
            return underlying_.ConsumeWriteTimeout();
        } else {
            return false;
        }
    }

    void ClearPhaseDeadline() {
        if constexpr (requires(Underlying& endpoint) { endpoint.ClearPhaseDeadline(); }) {
            underlying_.ClearPhaseDeadline();
        }
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        if constexpr (requires(Underlying& endpoint) {
                endpoint.StartPhaseDeadline(timeout);
            }) {
            return underlying_.StartPhaseDeadline(timeout);
        } else {
            return {};
        }
    }

    [[nodiscard]] bool ConsumePhaseDeadline() noexcept {
        if constexpr (requires(Underlying& endpoint) {
                endpoint.ConsumePhaseDeadline();
            }) {
            return underlying_.ConsumePhaseDeadline();
        } else {
            return false;
        }
    }

private:
    Underlying& underlying_;
    PacketReader reader_;
    PacketWriter writer_;
};

}  // namespace proxy::uot
