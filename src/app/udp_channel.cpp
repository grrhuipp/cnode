#include "acppnode/app/udp_channel.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <exception>
#include <optional>
#include <stdexcept>
#include <variant>

namespace acpp {

namespace {
[[noreturn]] void ThrowChannelError(ErrorCode error) {
    throw transport::LinkError(error);
}
}  // namespace

struct UDPChannel::State : std::enable_shared_from_this<State> {
    using Clock = std::chrono::steady_clock;
    enum Kind : size_t { Idle, Read, Write, Phase, Count };
    static constexpr size_t kMaxPackets = 256;
    static constexpr size_t kMaxBytes = 512 * 1024;

    State(net::io_context& io_context, std::shared_ptr<UDPSession> session)
        : session(std::move(session)), reply_signal(io_context, 1),
          cancel_send(io_context, 1), timer(io_context) {
        if (!this->session) throw std::invalid_argument("UDP channel requires a session");
    }
    ~State() noexcept { Stop(ErrorCode::CANCELLED); }

    const std::shared_ptr<UDPSession> session;
    uint64_t callback_id = 0;
    net::experimental::channel<void(IoErrorCode)> reply_signal;
    net::experimental::channel<void(IoErrorCode)> cancel_send;
    memory::ThreadLocalDeque<buf::MultiBuffer> replies;
    size_t queued_bytes = 0;
    bool closed = false;
    transport::CancellationSource cancellation;
    bool write_closed = false;
    ErrorCode error = ErrorCode::OK;
    std::array<bool, Count> pending{};
    std::array<std::chrono::seconds, Count> durations{};
    std::array<std::optional<Clock::time_point>, Count> deadlines{};
    uint8_t expired = 0;
    uint32_t phase_generation = 0;
    net::steady_timer timer;
    std::optional<Clock::time_point> armed_deadline;
    uint64_t timer_generation = 0;

    static std::optional<Clock::time_point> Deadline(std::chrono::seconds timeout) {
        if (timeout <= std::chrono::seconds::zero()) return std::nullopt;
        const auto now = Clock::now();
        const auto remaining = Clock::time_point::max() - now;
        if (timeout >= std::chrono::duration_cast<std::chrono::seconds>(remaining)) {
            return Clock::time_point::max();
        }
        return now + timeout;
    }

    void CancelTimer() noexcept {
        ++timer_generation;
        armed_deadline.reset();
        IoErrorCode ignored;
        timer.cancel(ignored);
    }

    void Schedule() {
        std::optional<Clock::time_point> first;
        for (const auto& deadline : deadlines) {
            if (deadline && (!first || *deadline < *first)) first = deadline;
        }
        if (!first || closed) {
            CancelTimer();
            return;
        }
        // Activity usually moves idle expiry later. Keep the existing wake and
        // inspect authoritative deadlines there, instead of allocating a new
        // asynchronous wait for every datagram.
        if (armed_deadline && *armed_deadline <= *first) return;
        CancelTimer();
        timer.expires_at(*first);
        const auto generation = timer_generation;
        timer.async_wait([weak = weak_from_this(), generation](const IoErrorCode& ec) {
            auto self = weak.lock();
            if (!self || self->closed || generation != self->timer_generation) return;
            self->armed_deadline.reset();
            if (ec) {
                self->Stop(ErrorCode::INTERNAL);
                return;
            }
            const auto now = Clock::now();
            for (size_t i = 0; i < Count; ++i) {
                if (self->deadlines[i] && *self->deadlines[i] <= now) {
                    self->expired |= static_cast<uint8_t>(1u << i);
                }
            }
            if (self->expired != 0) {
                self->Stop(ErrorCode::CANCELLED);
                return;
            }
            try { self->Schedule(); }
            catch (...) { self->Stop(ErrorCode::INTERNAL); }
        });
        armed_deadline = first;
    }

    void Stop(ErrorCode terminal) noexcept {
        if (closed) return;
        closed = true;
        error = terminal;
        cancellation.Stop(terminal);
        CancelTimer();
        deadlines.fill(std::nullopt);
        if (callback_id != 0) {
            session->UnregisterCallback(std::exchange(callback_id, 0));
        }
        reply_signal.close();
        cancel_send.close();
        replies.clear();
        queued_bytes = 0;
    }

    void CheckOpen() const {
        if (closed) ThrowChannelError(error);
    }

    void Touch() {
        if (closed) return;
        deadlines[Idle] = Deadline(durations[Idle]);
        Schedule();
    }

    void SetTimeout(Kind kind, std::chrono::seconds timeout) {
        if (closed) return;
        durations[kind] = timeout;
        expired &= static_cast<uint8_t>(~(1u << kind));
        deadlines[kind] = kind == Idle || kind == Phase || pending[kind]
            ? Deadline(timeout) : std::nullopt;
        Schedule();
    }

    bool Consume(Kind kind) noexcept {
        const auto mask = static_cast<uint8_t>(1u << kind);
        const bool result = (expired & mask) != 0;
        expired &= static_cast<uint8_t>(~mask);
        return result;
    }

    void Begin(Kind kind) {
        CheckOpen();
        if (kind == Write && write_closed) ThrowChannelError(ErrorCode::CANCELLED);
        if (pending[kind]) throw std::logic_error("UDP channel permits one reader and one writer");
        pending[kind] = true;
        try {
            deadlines[kind] = Deadline(durations[kind]);
            Schedule();
        } catch (...) {
            Finish(kind);
            throw;
        }
    }

    void Finish(Kind kind) noexcept {
        pending[kind] = false;
        deadlines[kind].reset();
        if (std::none_of(deadlines.begin(), deadlines.end(), [](const auto& value) { return value.has_value(); })) {
            CancelTimer();
        }
    }

    struct Operation {
        State& owner;
        Kind kind;
        Operation(State& owner, Kind kind) : owner(owner), kind(kind) { owner.Begin(kind); }
        ~Operation() noexcept { owner.Finish(kind); }
        Operation(const Operation&) = delete;
        Operation& operator=(const Operation&) = delete;
    };

    bool Receive(UDPPacketView packet) noexcept {
        if (closed || packet.data.empty()) return false;
        try {
            if (replies.size() >= kMaxPackets || packet.data.size() > kMaxBytes - queued_bytes) {
                Stop(ErrorCode::RESOURCE_EXHAUSTED);
                return false;
            }
            buf::MultiBuffer payload;
            if (!buf::AppendSpanToMultiBuffer(packet.data, payload)) {
                Stop(ErrorCode::RESOURCE_EXHAUSTED);
                return false;
            }
            for (auto* buffer : payload) buffer->SetUDP(packet.target);
            replies.push_back(std::move(payload));
            queued_bytes += packet.data.size();
            Touch();
            (void)reply_signal.try_send(IoErrorCode{});
            return true;
        } catch (...) {
            Stop(ErrorCode::RESOURCE_EXHAUSTED);
            return false;
        }
    }

    // Always return a value: the other race participant must be cancelled and
    // joined even when DNS, buffer setup, or socket initiation throws.
    static net::awaitable<std::expected<ErrorCode, std::exception_ptr>> Send(
        std::shared_ptr<State> self, TargetAddress target, buf::MultiBuffer payload) {
        try {
            self->CheckOpen();
            const auto callback_id = self->callback_id;
            co_return co_await self->session->SendTo(target, std::move(payload), callback_id);
        } catch (...) {
            co_return std::unexpected(std::current_exception());
        }
    }
};

UDPChannel::UDPChannel(net::io_context& io_context, std::shared_ptr<UDPSession> session)
    : state_(std::make_shared<State>(io_context, std::move(session))) {
    state_->callback_id = state_->session->RegisterCallback(
        [weak = std::weak_ptr<State>(state_)](UDPPacketView packet) {
            if (auto state = weak.lock()) return state->Receive(packet);
            return false;
        });
    if (state_->callback_id == 0) {
        ThrowChannelError(ErrorCode::RESOURCE_EXHAUSTED);
    }
}

UDPChannel::~UDPChannel() noexcept { Cancel(); }

net::awaitable<buf::MultiBuffer> UDPChannel::ReadMultiBuffer() {
    auto state = state_;
    State::Operation reading(*state, State::Read);
    while (true) {
        if (!state->replies.empty()) {
            auto payload = std::move(state->replies.front());
            state->replies.pop_front();
            state->queued_bytes -= buf::TotalLen(payload);
            co_return payload;
        }
        if (state->closed) {
            ThrowChannelError(state->error);
        }
        auto [ec] = co_await state->reply_signal.async_receive(net::as_tuple(net::use_awaitable));
        if (ec && !state->closed) state->Stop(ErrorCode::CANCELLED);
    }
}

net::awaitable<void> UDPChannel::WriteMultiBuffer(buf::MultiBuffer payload) {
    using namespace net::experimental::awaitable_operators;
    auto state = state_;
    state->CheckOpen();
    const auto datagram = buf::InspectUdpDatagram(payload);
    if (datagram.status == buf::UdpDatagramStatus::Empty) co_return;
    if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid()) {
        ThrowChannelError(ErrorCode::INVALID_ARGUMENT);
    }
    TargetAddress target = *datagram.target;
    State::Operation writing(*state, State::Write);
    auto result = co_await (
        State::Send(state, std::move(target), std::move(payload)) ||
        state->cancel_send.async_receive(net::as_tuple(net::use_awaitable)));
    state->CheckOpen();
    if (result.index() != 0) ThrowChannelError(ErrorCode::CANCELLED);
    const auto& sent = std::get<0>(result);
    if (!sent) std::rethrow_exception(sent.error());
    if (*sent != ErrorCode::OK) ThrowChannelError(*sent);
    state->Touch();
}

net::awaitable<void> UDPChannel::AsyncShutdownWrite() {
    // UDP has no wire FIN. Stop accepting new writes, but retain the callback
    // so replies to sent datagrams can arrive during relay's half-close budget.
    state_->write_closed = true;
    state_->cancel_send.close();
    co_return;
}

void UDPChannel::Cancel() noexcept { state_->Stop(ErrorCode::CANCELLED); }
transport::CancellationSource& UDPChannel::Cancellation() noexcept { return state_->cancellation; }
void UDPChannel::SetIdleTimeout(std::chrono::seconds timeout) { state_->SetTimeout(State::Idle, timeout); }
void UDPChannel::SetReadTimeout(std::chrono::seconds timeout) { state_->SetTimeout(State::Read, timeout); }
void UDPChannel::SetWriteTimeout(std::chrono::seconds timeout) { state_->SetTimeout(State::Write, timeout); }
PhaseDeadlineHandle UDPChannel::StartPhaseDeadline(std::chrono::seconds timeout) {
    ClearPhaseDeadline();
    if (state_->closed || timeout <= std::chrono::seconds::zero()) return {};
    state_->SetTimeout(State::Phase, timeout);
    return PhaseDeadlineHandle(&state_->expired, 1u << State::Phase,
                               &state_->phase_generation, state_->phase_generation);
}
void UDPChannel::ClearPhaseDeadline() noexcept {
    ++state_->phase_generation;
    state_->expired &= static_cast<uint8_t>(~(1u << State::Phase));
    state_->Finish(State::Phase);
}
bool UDPChannel::ConsumeIdleTimeout() noexcept { return state_->Consume(State::Idle); }
bool UDPChannel::ConsumeReadTimeout() noexcept { return state_->Consume(State::Read); }
bool UDPChannel::ConsumeWriteTimeout() noexcept { return state_->Consume(State::Write); }
bool UDPChannel::ConsumePhaseDeadline() noexcept { return state_->Consume(State::Phase); }

}  // namespace acpp
