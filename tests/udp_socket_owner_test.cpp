#include "acppnode/app/proxyman/inbound/udp_worker.hpp"
#include "udp_receive_buffer.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace {

class DummyUdpHandler final : public acpp::proxyman::inbound::UdpHandler {
public:
    explicit DummyUdpHandler(
        std::shared_ptr<int> adopted_state = {})
        : adopted_state_(std::move(adopted_state)) {}

    void AdoptWorkerStateFrom(
        acpp::proxyman::inbound::UdpHandler& previous) noexcept override {
        const auto* old = dynamic_cast<const DummyUdpHandler*>(&previous);
        if (!old) {
            return;
        }
        worker_state_ = old->worker_state_;
        if (adopted_state_) {
            *adopted_state_ = worker_state_;
        }
    }

    std::optional<acpp::proxyman::inbound::UdpDecodeResult> DecodeUdp(
        std::string_view,
        std::string_view,
        const uint8_t*,
        size_t) override {
        return std::nullopt;
    }

private:
    std::shared_ptr<int> adopted_state_;
    int worker_state_ = 73;
};

class CountingUdpResponseContext final
    : public acpp::proxyman::inbound::UdpResponseContext {
public:
    acpp::buf::MultiBuffer Encode(acpp::UDPPacketView packet) override {
        ++calls;
        last_size = packet.data.size();
        return {};
    }

    size_t calls = 0;
    size_t last_size = 0;
};

static_assert(noexcept(
    std::declval<acpp::proxyman::inbound::UdpWorker&>().Close()));
static_assert(noexcept(
    std::declval<acpp::proxyman::inbound::UdpWorker&>().ReplaceHandler(
        std::declval<std::unique_ptr<acpp::proxyman::inbound::UdpHandler>>())));
static_assert(noexcept(
    std::declval<acpp::proxyman::inbound::UdpWorker&>().CleanupAllClientSessions()));
static_assert(noexcept(
    std::declval<acpp::proxyman::inbound::UdpWorker&>().CloseSocket(
        std::declval<const std::string&>())));
static_assert(noexcept(
    std::declval<acpp::proxyman::inbound::UdpWorker&>().CloseAllSockets()));

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

}  // namespace

int main() {
    acpp::TargetAddress callback_source;
    callback_source.type = acpp::AddressType::IPv4;
    callback_source.resolved_addr = acpp::net::ip::address_v4::loopback();
    callback_source.port = 5353;
    std::array<uint8_t, 1> callback_payload{0x5a};
    acpp::UDPPacketView callback_packet{callback_source, callback_payload};

    acpp::PacketCallback empty_callback;
    if (empty_callback(callback_packet)) {
        Fail("empty UDP callback reported successful delivery");
    }

    acpp::PacketCallback throwing_callback{
        [](acpp::UDPPacketView) { throw 7; }};
    if (throwing_callback(callback_packet)) {
        Fail("throwing UDP callback reported successful delivery");
    }

    bool callback_invoked = false;
    acpp::PacketCallback valid_callback{
        [&](acpp::UDPPacketView packet) {
            callback_invoked = packet.data.size() == 1 && packet.data[0] == 0x5a;
        }};
    if (!valid_callback(callback_packet) || !callback_invoked) {
        Fail("valid UDP callback was not delivered");
    }

    acpp::net::io_context io_context;
    acpp::IoErrorCode ec;
    const acpp::udp::endpoint reply_endpoint_a(
        acpp::net::ip::address_v4::loopback(), 10001);
    const acpp::udp::endpoint reply_endpoint_b(
        acpp::net::ip::address_v4::loopback(), 10002);
    const acpp::proxyman::inbound::UdpSessionOwner default_owner;

    acpp::proxyman::inbound::UdpWorker::ClientSession failing_reply_session(
        io_context,
        acpp::RoutedPacketCallback{
            [](acpp::UDPPacketView, const acpp::udp::endpoint&) { throw 9; }},
        reply_endpoint_a,
        default_owner);
    acpp::buf::BufferGuard reply_buffer{acpp::buf::Buffer::New()};
    if (!reply_buffer) Fail("failed to allocate UDP callback test buffer");
    reply_buffer->Tail()[0] = 0x33;
    reply_buffer->Produce(1);
    reply_buffer->SetUDP(callback_source);
    acpp::buf::MultiBuffer reply_payload{reply_buffer.release()};
    bool reply_failure_reported = false;
    acpp::net::co_spawn(
        io_context,
        failing_reply_session.WriteMultiBuffer(std::move(reply_payload)),
        [&](std::exception_ptr error) {
            reply_failure_reported = error != nullptr;
        });
    io_context.run();
    if (!reply_failure_reported) {
        Fail("UDP client reply callback failure was silently ignored");
    }
    io_context.restart();

    std::vector<uint8_t> callback_large_payload(
        acpp::buf::Buffer::kSize + 257, 0x6d);
    acpp::buf::MultiBuffer callback_large_buffers;
    if (!acpp::buf::AppendSpanToMultiBuffer(
            callback_large_payload, callback_large_buffers)) {
        Fail("failed to allocate large UDP callback payload");
    }
    for (acpp::buf::Buffer* buffer : callback_large_buffers) {
        if (buffer && !buffer->IsEmpty()) {
            buffer->SetUDP(callback_source);
        }
    }

    size_t large_callback_count = 0;
    bool large_callback_matches = false;
    acpp::udp::endpoint observed_reply_endpoint;
    acpp::proxyman::inbound::UdpWorker::ClientSession large_reply_session(
        io_context,
        acpp::RoutedPacketCallback{[&](
            acpp::UDPPacketView packet,
            const acpp::udp::endpoint& reply_endpoint) {
            ++large_callback_count;
            observed_reply_endpoint = reply_endpoint;
            large_callback_matches =
                packet.data.size() == callback_large_payload.size() &&
                std::equal(packet.data.begin(), packet.data.end(),
                           callback_large_payload.begin());
        }},
        reply_endpoint_a,
        default_owner);
    bool large_reply_failed = false;
    acpp::net::co_spawn(
        io_context,
        large_reply_session.WriteMultiBuffer(std::move(callback_large_buffers)),
        [&](std::exception_ptr error) {
            large_reply_failed = error != nullptr;
        });
    io_context.run();
    if (large_reply_failed || large_callback_count != 1 ||
        !large_callback_matches || observed_reply_endpoint != reply_endpoint_a) {
        std::cerr << "large_reply_failed=" << large_reply_failed
                  << " callback_count=" << large_callback_count
                  << " callback_matches=" << large_callback_matches << '\n';
        Fail("multi-buffer UDP reply was split into multiple datagrams");
    }
    io_context.restart();

    acpp::buf::MultiBuffer migrated_reply_buffers;
    if (!acpp::buf::AppendSpanToMultiBuffer(
            callback_large_payload, migrated_reply_buffers)) {
        Fail("failed to allocate migrated UDP reply payload");
    }
    for (acpp::buf::Buffer* buffer : migrated_reply_buffers) {
        if (buffer && !buffer->IsEmpty()) {
            buffer->SetUDP(callback_source);
        }
    }
    large_reply_session.UpdateReplyEndpoint(reply_endpoint_b);
    acpp::net::co_spawn(
        io_context,
        large_reply_session.WriteMultiBuffer(std::move(migrated_reply_buffers)),
        [&](std::exception_ptr error) {
            large_reply_failed = error != nullptr;
        });
    io_context.run();
    if (large_reply_failed || large_callback_count != 2 ||
        !large_callback_matches || observed_reply_endpoint != reply_endpoint_b) {
        Fail("UDP client session kept replying to its stale endpoint");
    }
    io_context.restart();

    auto first = acpp::proxyman::inbound::UdpWorker::MakeSocket(io_context);
    first->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open first UDP socket");
    first->bind(acpp::udp::endpoint(acpp::net::ip::address_v4::loopback(), 0), ec);
    if (ec) Fail("failed to bind first UDP socket");
    const auto endpoint = first->local_endpoint(ec);
    if (ec || endpoint.port() == 0) Fail("failed to resolve first UDP endpoint");

    std::array<uint8_t, 1> receive_buffer{};
    acpp::udp::endpoint peer;
    bool receive_cancelled = false;
    first->async_receive_from(
        acpp::net::buffer(receive_buffer),
        peer,
        [&](acpp::IoErrorCode receive_ec, size_t) {
            receive_cancelled = receive_ec == acpp::io_error::operation_aborted;
        });
    first.reset();
    io_context.run();
    if (!receive_cancelled) {
        Fail("destroyed UDP socket did not cancel its pending receive");
    }
    io_context.restart();

    acpp::udp::socket large_receiver(io_context, acpp::udp::v4());
    large_receiver.bind(
        acpp::udp::endpoint(acpp::net::ip::address_v4::loopback(), 0), ec);
    if (ec) Fail("failed to bind large UDP receiver");
    acpp::udp::socket large_sender(io_context, acpp::udp::v4());
    const auto large_endpoint = large_receiver.local_endpoint(ec);
    if (ec) Fail("failed to query large UDP receiver endpoint");

    std::vector<uint8_t> large_payload(acpp::buf::Buffer::kSize + 257, 0x6d);
    bool large_received = false;
    acpp::net::co_spawn(
        io_context,
        [&]() -> acpp::net::awaitable<void> {
            auto [wait_ec] = co_await large_receiver.async_wait(
                acpp::udp::socket::wait_read,
                acpp::net::as_tuple(acpp::net::use_awaitable));
            if (wait_ec) co_return;

            acpp::IoErrorCode available_ec;
            const size_t available = large_receiver.available(available_ec);
            if (available_ec) co_return;
            acpp::detail::UdpReceiveBuffer receive_buffer;
            const auto storage = receive_buffer.Prepare(available);
            acpp::udp::endpoint sender_endpoint;
            auto [receive_ec, bytes] = co_await large_receiver.async_receive_from(
                storage,
                sender_endpoint,
                acpp::net::as_tuple(acpp::net::use_awaitable));
            if (receive_ec) co_return;
            const auto received = receive_buffer.Data(bytes);
            large_received = received.size() == large_payload.size() &&
                std::equal(received.begin(), received.end(), large_payload.begin());
        },
        acpp::net::detached);
    large_sender.send_to(acpp::net::buffer(large_payload), large_endpoint, 0, ec);
    if (ec) Fail("failed to send large UDP datagram");
    io_context.run();
    if (!large_received) {
        Fail("UDP receive path truncated a datagram larger than one Buffer");
    }
    io_context.restart();

    auto second = acpp::proxyman::inbound::UdpWorker::MakeSocket(io_context);
    second->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open second UDP socket");
    second->bind(endpoint, ec);
    if (ec) Fail("owned UDP socket did not release its bound port");

    acpp::proxyman::inbound::UdpWorker worker(
        "test-inbound", std::make_unique<DummyUdpHandler>());

    acpp::proxyman::inbound::UdpSessionOwner owner_a;
    acpp::proxyman::inbound::UdpSessionOwner owner_b;
    std::array<uint8_t, 16> owner_a_bytes{};
    std::array<uint8_t, 16> owner_b_bytes{};
    owner_a_bytes.fill(0x11);
    owner_b_bytes.fill(0x22);
    if (!owner_a.Assign(owner_a_bytes) || !owner_b.Assign(owner_b_bytes)) {
        Fail("failed to initialize UDP session owners");
    }
    const std::string owner_a_session_key =
        owner_a.ScopeSessionKey("shared-session-id");
    const std::string owner_b_session_key =
        owner_b.ScopeSessionKey("shared-session-id");
    if (owner_a_session_key.empty() || owner_b_session_key.empty() ||
        owner_a_session_key == owner_b_session_key) {
        Fail("UDP protocol session key was not scoped by authenticated owner");
    }
    const auto owner_session = worker.CreateClientSession(
        "owner-socket",
        owner_a_session_key,
        io_context,
        acpp::RoutedPacketCallback{
            [](acpp::UDPPacketView, const acpp::udp::endpoint&) {}},
        reply_endpoint_a,
        owner_a,
        std::chrono::steady_clock::now());
    auto make_owner_payload = [&]() {
        acpp::buf::BufferGuard buffer{acpp::buf::Buffer::New()};
        if (!buffer) Fail("failed to allocate UDP owner payload");
        buffer->Tail()[0] = 0x44;
        buffer->Produce(1);
        return acpp::buf::MultiBuffer{buffer.release()};
    };
    if (worker.PushClientPayload(
            "owner-socket",
            owner_a_session_key,
            callback_source,
            reply_endpoint_b,
            owner_b,
            make_owner_payload(),
            std::chrono::steady_clock::now())) {
        Fail("UDP session key collision crossed authenticated owners");
    }
    if (!worker.PushClientPayload(
            "owner-socket",
            owner_a_session_key,
            callback_source,
            reply_endpoint_b,
            owner_a,
            make_owner_payload(),
            std::chrono::steady_clock::now())) {
        Fail("UDP session rejected its authenticated owner");
    }
    const auto second_owner_session = worker.CreateClientSession(
        "owner-socket",
        owner_b_session_key,
        io_context,
        acpp::RoutedPacketCallback{
            [](acpp::UDPPacketView, const acpp::udp::endpoint&) {}},
        reply_endpoint_a,
        owner_b,
        std::chrono::steady_clock::now());
    if (!second_owner_session || second_owner_session == owner_session ||
        !worker.PushClientPayload(
            "owner-socket",
            owner_b_session_key,
            callback_source,
            reply_endpoint_b,
            owner_b,
            make_owner_payload(),
            std::chrono::steady_clock::now())) {
        Fail("UDP session ID collision blocked a different authenticated owner");
    }
    auto* attached = worker.AttachSocket("stable-socket", std::move(second));
    if (!attached || worker.FindSocket("stable-socket") != attached ||
        !attached->is_open()) {
        Fail("failed to attach initial UDP socket");
    }

    auto duplicate = acpp::proxyman::inbound::UdpWorker::MakeSocket(io_context);
    duplicate->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open duplicate UDP socket");
    if (worker.AttachSocket("stable-socket", std::move(duplicate)) != nullptr) {
        Fail("duplicate UDP socket attachment was accepted");
    }
    if (worker.FindSocket("stable-socket") != attached || !attached->is_open()) {
        Fail("duplicate attachment replaced the live UDP socket");
    }

    auto response_context = std::make_shared<CountingUdpResponseContext>();
    acpp::proxyman::inbound::UdpWorker::ClientSession snapshot_reply_session(
        io_context,
        acpp::RoutedPacketCallback{
            [response_context](
                acpp::UDPPacketView packet,
                const acpp::udp::endpoint&) {
                auto encoded = response_context->Encode(packet);
                encoded.clear();
            }},
        reply_endpoint_a,
        default_owner);
    auto adopted_worker_state = std::make_shared<int>(-1);
    if (!worker.ReplaceHandler(
            std::make_unique<DummyUdpHandler>(adopted_worker_state))) {
        Fail("valid UDP handler replacement was rejected");
    }
    if (*adopted_worker_state != 73) {
        Fail("UDP handler replacement discarded Worker-local protocol state");
    }
    if (owner_session->Closed()) {
        Fail("UDP handler replacement closed a live client session");
    }
    acpp::buf::BufferGuard snapshot_reply{acpp::buf::Buffer::New()};
    if (!snapshot_reply) Fail("failed to allocate snapshot UDP reply");
    snapshot_reply->Tail()[0] = 0x55;
    snapshot_reply->Produce(1);
    snapshot_reply->SetUDP(callback_source);
    bool snapshot_reply_failed = false;
    acpp::net::co_spawn(
        io_context,
        snapshot_reply_session.WriteMultiBuffer(
            acpp::buf::MultiBuffer{snapshot_reply.release()}),
        [&](std::exception_ptr error) {
            snapshot_reply_failed = error != nullptr;
        });
    io_context.run();
    if (snapshot_reply_failed || response_context->calls != 1 ||
        response_context->last_size != 1) {
        Fail("UDP handler replacement changed a live response context");
    }
    io_context.restart();
    if (worker.FindSocket("stable-socket") != attached || !attached->is_open()) {
        Fail("UDP handler replacement disturbed the live socket");
    }
    if (worker.ReplaceHandler(nullptr)) {
        Fail("null UDP handler replacement was accepted");
    }
    if (worker.FindSocket("stable-socket") != attached || !attached->is_open()) {
        Fail("rejected UDP handler replacement disturbed the live socket");
    }

    owner_session->Close();

    worker.CloseSocket("stable-socket");
    if (worker.FindSocket("stable-socket") != nullptr) {
        Fail("closed UDP socket remained registered");
    }

    return 0;
}
