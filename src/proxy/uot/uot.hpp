#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/link.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string_view>

namespace acpp::proxy::uot {

inline constexpr std::string_view kMagicAddress = "sp.v2.udp-over-tcp.arpa";
inline constexpr std::string_view kV1MagicAddress = "sp.udp-over-tcp.arpa";
inline constexpr size_t kMaxAddressSize = 1 + 1 + 255 + 2;
inline constexpr size_t kMaxRequestSize = 1 + kMaxAddressSize;

enum class Version : uint8_t {
    V1 = 1,
    V2 = 2,
};

struct Request {
    bool is_connect = false;
    TargetAddress destination;
    size_t consumed = 0;
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

[[nodiscard]] std::expected<EncodedRequest, ErrorCode> EncodeRequest(
    bool is_connect,
    const TargetAddress& destination);

[[nodiscard]] net::awaitable<std::expected<Request, ErrorCode>> ReadRequest(
    transport::MultiBufferReader& reader,
    buf::MultiBuffer& pending);

class PacketReader final : public transport::MultiBufferReader {
public:
    PacketReader(transport::MultiBufferReader& reader,
                 bool is_connect,
                 TargetAddress destination,
                 buf::MultiBuffer pending = {});

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;

    void SetInitialDecoded(buf::MultiBuffer packet) noexcept;

private:
    transport::MultiBufferReader& reader_;
    bool is_connect_ = false;
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
        , reader_(underlying, is_connect, destination, std::move(pending))
        , writer_(underlying, is_connect, std::move(destination)) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        co_return co_await reader_.ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        co_await writer_.WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        co_await writer_.WriteBuffers(buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        co_await writer_.AsyncShutdownWrite();
    }

    void Cancel() noexcept {
        if constexpr (requires(Underlying& endpoint) { endpoint.Cancel(); }) {
            underlying_.Cancel();
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

    [[nodiscard]] bool ForwardHalfCloseOnPeerEof() const noexcept {
        if constexpr (requires(const Underlying& endpoint) {
                endpoint.ForwardHalfCloseOnPeerEof();
            }) {
            return underlying_.ForwardHalfCloseOnPeerEof();
        } else {
            return false;
        }
    }

private:
    Underlying& underlying_;
    PacketReader reader_;
    PacketWriter writer_;
};

}  // namespace acpp::proxy::uot
