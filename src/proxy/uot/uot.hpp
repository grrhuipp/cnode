#pragma once
#include "proxy/uot_version.hpp"

#include "common/asio_types.hpp"
#include "app/relay.hpp"
#include "common/multi_buffer.hpp"
#include "common/error.hpp"
#include "common/target_address.hpp"
#include "common/address_codec.hpp"
#include "routing/dispatcher.hpp"
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

namespace proxy {

inline constexpr std::string_view kMagicAddress = "sp.v2.udp-over-tcp.arpa";
inline constexpr std::string_view kV1MagicAddress = "sp.udp-over-tcp.arpa";
inline constexpr size_t kMaxAddressSize = common::kMaxEncodedAddressSize;
inline constexpr size_t kMaxRequestSize = 1 + kMaxAddressSize;


[[nodiscard]] constexpr std::string_view MagicAddress(UotVersion version) noexcept {
    return version == UotVersion::V1 ? kV1MagicAddress : kMagicAddress;
}

struct EncodedRequest {
    std::array<uint8_t, kMaxRequestSize> bytes{};
    size_t size = 0;

    [[nodiscard]] std::span<const uint8_t> span() const noexcept {
        return {bytes.data(), size};
    }
};

[[nodiscard]] std::optional<UotVersion> VersionFromMagicAddress(
    const common::TargetAddress& target) noexcept;

[[nodiscard]] tl::expected<EncodedRequest, common::ErrorCode> EncodeUotRequest(
    bool is_connect,
    const common::TargetAddress& destination,
    common::ForwardedMetadataView forwarded = {});

// One UoT request header: the V2 request or, for V1, the first packet's
// target with that packet already decoded.
struct PreparedRequest {
    bool is_connect = false;
    common::TargetAddress destination;
    std::optional<common::ForwardedMetadata> forwarded;
    common::MultiBuffer pending;
    common::MultiBuffer initial_decoded;
};

// EOF before the first UoT byte is the peer's normal close → SOCKET_EOF;
// EOF or malformed bytes after it → PROTOCOL_DECODE_FAILED.
[[nodiscard]] net::awaitable<tl::expected<PreparedRequest, common::ErrorCode>>
ReadUotRequestHeader(
    UotVersion version,
    transport::MultiBufferReader& reader,
    common::MultiBuffer pending);

[[nodiscard]] net::awaitable<app::RelayResult> DispatchPreparedUotRequest(
    PreparedRequest prepared,
    std::unique_ptr<transport::AsyncStream> stream,
    transport::MultiBufferReader& request_reader,
    transport::MultiBufferWriter& response_writer,
    routing::Dispatcher& dispatcher,
    const routing::DispatchPolicy& dispatch_policy,
    net::io_context& io_context,
    common::Context& ctx,
    app::StatsShard& stats,
    const infra::TimeoutsConfig& timeouts);
class UotPacketReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return reader_.Cancellation(); }
    // A UDP association has no write-half-close to propagate to its peer.
    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::CloseLink;
    }

    UotPacketReader(transport::MultiBufferReader& reader,
                 bool is_connect,
                 common::TargetAddress destination,
                 common::MultiBuffer pending = {});

    UotPacketReader(transport::MultiBufferReader& reader,
                 PreparedRequest prepared);

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override;

    [[nodiscard]] common::MultiBuffer TakePending() noexcept;
private:
    transport::MultiBufferReader& reader_;
    bool is_connect_ = false;
    // 非 connect 仅使用帧内地址，请求目标已由会话上下文拥有。
    common::TargetAddress destination_;
    common::MultiBuffer pending_;
};

class UotPacketWriter final : public transport::MultiBufferWriter {
public:
    UotPacketWriter(transport::MultiBufferWriter& writer,
                 bool is_connect,
                 common::TargetAddress destination);

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;
    bool WriteShutdownClosesLink() const noexcept override { return writer_.WriteShutdownClosesLink(); }

private:
    transport::MultiBufferWriter& writer_;
    bool is_connect_ = false;
    common::TargetAddress destination_;
    std::array<uint8_t, common::kMaxBaseEncodedAddressSize + 2> header_{};
};

template <typename Underlying>
class UotFramedEndpoint final
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    UotFramedEndpoint(Underlying& underlying,
                   bool is_connect,
                   common::TargetAddress destination,
                   common::MultiBuffer pending = {})
        : underlying_(underlying)
        , reader_(underlying, is_connect, is_connect ? destination : common::TargetAddress{},
                  std::move(pending))
        , writer_(underlying, is_connect, std::move(destination)) {}

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        return reader_.ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
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

    Underlying& RelayControl() noexcept { return underlying_; }
    const Underlying& RelayControl() const noexcept { return underlying_; }

    void Cancel() noexcept {
        if constexpr (requires(Underlying& endpoint) { endpoint.Cancel(); }) {
            underlying_.Cancel();
        } else if constexpr (requires(Underlying& endpoint) { endpoint.RelayControl().Cancel(); }) {
            underlying_.RelayControl().Cancel();
        }
    }

private:
    Underlying& underlying_;
    UotPacketReader reader_;
    UotPacketWriter writer_;
};

}  // namespace proxy
