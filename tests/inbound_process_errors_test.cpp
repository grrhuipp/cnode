#include "acppnode/app/proxyman/inbound/handler.hpp"
#include "acppnode/app/request_load_state.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"
#include "acppnode/transport/link_error.hpp"
#include "anytls_codec.hpp"

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <array>
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace {
using namespace acpp;
struct State { int fault = 0; int active = 0; bool destroyed = false; };

void Raise(int fault) {
    switch (fault) {
        case 1: throw std::bad_alloc();
        case 2: throw transport::LinkError(ErrorCode::BLOCKED);
        case 3: throw IoSystemError(io_error::operation_aborted);
        case 4: throw IoSystemError(io_error::timed_out);
        case 5: throw IoSystemError(io_error::connection_reset);
        case 6: throw std::runtime_error("original-inbound-error");
        case 7: throw 42;
    }
}

class Stream final : public AsyncStream {
public:
    explicit Stream(State& state) : state_(state) {}
    ~Stream() override { if (state_.active != 0) std::terminate(); state_.destroyed = true; }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        ++state_.active;
        co_await net::post(net::use_awaitable);
        --state_.active;
        Raise(state_.fault);
        std::memset(buffer.data(), 0, buffer.size());
        co_return buffer.size();
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override { co_return buffer.size(); }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override { co_return buf::MultiBuffer{}; }
    void ShutdownWrite() override {}
    void Cancel() noexcept override { NotifyCancellation(); }
    void Close() override { NotifyClosed(); }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return true; }
private:
    State& state_;
};

class Proxy final : public Inbound {
public:
    Proxy(int fault, bool codec) : fault_(fault), codec_(codec) {}
    net::awaitable<RelayResult> Process(std::unique_ptr<AsyncStream> stream,
        routing::Dispatcher&, const proxyman::inbound::ReceiverSettings&, net::io_context&,
        session::Context&, const TimeoutsConfig&, uint32_t) override {
        RelayResult result;
        if (codec_) {
            auto text = co_await anytls::ReadFrameText(*stream, 19);
            if (!text) result.error = text.error();
        } else {
            co_await net::post(net::use_awaitable);
            Raise(fault_);
        }
        co_return result;
    }
private:
    int fault_;
    bool codec_;
};

class Dispatcher final : public routing::Dispatcher {
    net::awaitable<RelayResult> Dispatch(net::io_context&, const routing::DispatchPolicy&,
        std::unique_ptr<AsyncStream>, transport::Link, InitialPayload, session::Context&,
        StatsShard&, const TimeoutsConfig&) override { throw std::logic_error("unexpected dispatch"); co_return RelayResult{}; }
};
}

// Replace the external transport builder and reporting sink; execute the
// production accepted-TCP and logical-transport ownership/error boundaries.
namespace acpp {
net::awaitable<TransportBuildResult> BuildInboundTransport(net::io_context&,
    std::unique_ptr<AsyncStream> raw, const StreamSettings&, std::string*, uint64_t,
    std::shared_ptr<InboundTransportStreamHandler> streams, InboundTransportMetadata*) {
    if (streams) { streams->OnInboundTransportStream(std::move(raw)); co_return std::unique_ptr<AsyncStream>{}; }
    co_return std::move(raw);
}
net::awaitable<ProxyProtocolReadResult> ReadInboundProxyProtocol(AsyncStream&, std::chrono::seconds) {
    throw std::logic_error("unexpected proxy protocol"); co_return ProxyProtocolReadResult{};
}
}
int main() {
    size_t passed = 0, total = 0;
    for (bool logical : {false, true}) for (bool codec : {false, true}) for (int fault = 0; fault < 8; ++fault) {
        net::io_context io;
        State state{.fault = fault};
        proxyman::inbound::ReceiverSettings receiver{.dispatch_policy = {{}, routing::ForceOutbound{"direct"}}};
        receiver.inbound_tag = "test";
        receiver.protocol = "fixture";
        receiver.proxy_protocol = ProxyProtocolMode::Off;
        receiver.stream_settings.network = logical ? "grpc" : "tcp";
        auto handler = std::make_shared<proxyman::inbound::Handler>(std::move(receiver), std::make_unique<Proxy>(fault, codec));
        Dispatcher dispatcher;
        StatsShard stats;
        app::RequestLoadState load(100, 0);
        TimeoutsConfig timeouts;
        session::Context context;
        context.conn_id = 1;
        context.inbound.tag = "test";
        bool returned = false;
        std::exception_ptr failure;
        net::co_spawn(io, handler->ProcessAcceptedTCP(io, dispatcher, stats, load, timeouts,
            std::make_unique<Stream>(state), context), [&](std::exception_ptr error) { failure = error; returned = true; });
        io.run();
        if (failure) {
            try { std::rethrow_exception(failure); }
            catch (const std::exception& error) { std::printf("fixture parent failure: %s\n", error.what()); }
            catch (...) { std::printf("fixture parent failure: unknown\n"); }
        }
        const bool ok = returned && !failure && state.destroyed;
        ++total;
        passed += ok;
        std::printf("inbound logical=%d codec=%d fault=%d released=%d returned=%d: %s\n",
            logical, codec, fault, state.destroyed, returned, ok ? "PASS" : "FAIL");
    }
    std::printf("inbound cases=%zu passed=%zu failed=%zu\n", total, passed, total - passed);
    return passed == total ? 0 : 1;
}
