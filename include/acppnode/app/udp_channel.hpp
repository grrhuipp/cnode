#pragma once
#include "acppnode/transport/cancellation.hpp"

#include "acppnode/transport/link.hpp"

#include <chrono>
#include <memory>

namespace acpp {

class UDPSession;
class PhaseDeadlineHandle;

// One request's datagram endpoint on a Worker-local, possibly shared socket.
// Cancellation retires this registration and joins its send, never the socket.
class UDPChannel final : public transport::MultiBufferReader,
                         public transport::MultiBufferWriter {
public:
    UDPChannel(net::io_context& io_context, std::shared_ptr<UDPSession> session);
    ~UDPChannel() noexcept override;
    UDPChannel(const UDPChannel&) = delete;
    UDPChannel& operator=(const UDPChannel&) = delete;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override;
    net::awaitable<void> AsyncShutdownWrite() override;
    bool ForwardHalfCloseOnPeerEof() const noexcept { return true; }
    void Cancel() noexcept;
    transport::CancellationSource& Cancellation() noexcept override;

    void SetIdleTimeout(std::chrono::seconds timeout);
    void SetReadTimeout(std::chrono::seconds timeout);
    void SetWriteTimeout(std::chrono::seconds timeout);
    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout);
    void ClearPhaseDeadline() noexcept;
    bool ConsumeIdleTimeout() noexcept;
    bool ConsumeReadTimeout() noexcept;
    bool ConsumeWriteTimeout() noexcept;
    bool ConsumePhaseDeadline() noexcept;

private:
    struct State;
    std::shared_ptr<State> state_;
};

}  // namespace acpp
