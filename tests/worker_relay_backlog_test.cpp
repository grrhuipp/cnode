#include "app/udp_session_relay.hpp"
#include "common/error.hpp"
#include "proxy/mux/xudp.hpp"

#include <gtest/gtest.h>
#include <mimalloc.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <optional>

namespace {

using namespace std::chrono_literals;

// Two Workers' io_contexts driven on the test thread. The second one is
// not polled while a test floods it: its rings fill, so every further
// message waits in the first Worker's backlog toward it.
template <class Subsystem>
struct WorkerPair {
    net::io_context first;
    net::io_context second;

    WorkerPair() {
        const std::array<net::io_context*, 2> workers{&first, &second};
        common::InstallWorkerMesh<Subsystem>(workers);
    }
    ~WorkerPair() {
        common::StopWorkerMesh<Subsystem>(first);
        common::StopWorkerMesh<Subsystem>(second);
        Poll();
    }
    Subsystem& First() { return *common::FindWorkerMesh<Subsystem>(first); }
    void Poll() {
        for (auto* io : {&first, &second}) {
            if (io->stopped()) io->restart();
            io->poll();
        }
    }
};

size_t CommittedBytes() {
    size_t elapsed = 0, user = 0, system = 0, rss = 0, peak_rss = 0;
    size_t commit = 0, peak_commit = 0, faults = 0;
    mi_process_info(&elapsed, &user, &system, &rss, &peak_rss, &commit, &peak_commit, &faults);
    return commit;
}

// Far beyond any bounded backlog, small next to one held message per call.
constexpr size_t kFlood = 1'000'000;
constexpr size_t kBoundedGrowth = 16u << 20;

// A Gone answers every datagram of an unknown session; a Worker that does
// not drain must not make its peer hold one per datagram.
TEST(WorkerRelayBacklog, UdpGoneTowardStalledWorkerStaysBounded) {
    WorkerPair<app::UdpSessionRelay> workers;
    auto& relay = workers.First();
    const size_t before = CommittedBytes();
    for (size_t token = 1; token <= kFlood; ++token) relay.SendGone(1, token);
    const size_t after = CommittedBytes();
    const size_t growth = after > before ? after - before : 0;
    EXPECT_LT(growth, kBoundedGrowth) << "Gone backlog grew with every message";
    workers.Poll();
}

struct IdleClient final : proxy::XudpClient {};

// Rapid XUDP sub-session open/close toward a Worker that does not drain:
// attachments wait for that Worker's acknowledgement, so the slots, not the
// open/close rate, bound what is held; once it drains, the slots return.
TEST(WorkerRelayBacklog, XudpAttachChurnTowardStalledWorkerStaysBounded) {
    WorkerPair<proxy::XudpRelay> workers;
    auto& relay = workers.First();
    IdleClient client;
    const size_t before = CommittedBytes();
    bool refused = false;
    for (size_t cycle = 0; cycle < kFlood / 4; ++cycle) {
        try {
            const auto attachment = relay.Open(1, 7, client);
            relay.Close(attachment);
        } catch (const IoSystemError&) {
            refused = true;
            break;
        }
    }
    const size_t after = CommittedBytes();
    const size_t growth = after > before ? after - before : 0;
    EXPECT_TRUE(refused) << "unacknowledged attachments were never bounded";
    EXPECT_LT(growth, kBoundedGrowth) << "attach/detach backlog grew with every cycle";

    // The stalled Worker refuses every attachment of its unknown flow; each
    // refusal frees one slot.
    std::optional<proxy::XudpRelay::Attachment> recovered;
    for (int round = 0; round < 10000 && !recovered; ++round) {
        workers.Poll();
        try {
            recovered = relay.Open(1, 7, client);
        } catch (const IoSystemError&) {
        }
    }
    ASSERT_TRUE(recovered) << "acknowledged attachments did not return their slots";
    relay.Close(*recovered);
    workers.Poll();
}

}  // namespace
