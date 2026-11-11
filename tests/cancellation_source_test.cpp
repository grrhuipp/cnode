#include <gtest/gtest.h>

#include "allocation_hook.hpp"
#include "transport/link.hpp"

#include <array>
#include <optional>


constinit allocation_hook::Hooks allocation_hook::hooks{};
using ::ErrorCode;
using ::transport::CancellationSource;
using ::transport::Cancellation;
using ::transport::CancellationSubscription;

namespace {
struct Counter {
    int calls = 0;
    ErrorCode reason = ErrorCode::OK;
    bool terminal = false;
    void Record(Cancellation cancellation) noexcept {
        ++calls;
        reason = cancellation.reason;
        terminal = cancellation.terminal;
    }
};

struct RecordingListener final : CancellationSubscription {
    explicit RecordingListener(Counter& counter) noexcept : counter(counter) {}
    Counter& counter;
private:
    void OnCancellation(Cancellation cancellation) noexcept override {
        counter.Record(cancellation);
    }
};

TEST(CancellationSource, ScopedListenersUnsubscribeBeforeSourceDestruction) {
    Counter retained, removed, orphaned;
    std::optional<RecordingListener> orphan;
    {
        CancellationSource source;
        RecordingListener first(retained);
        first.Resubscribe(source);
        {
            RecordingListener second(removed);
            second.Resubscribe(source);
        }
        source.CancelPending(ErrorCode::RESOURCE_EXHAUSTED);
        source.CancelPending();
        orphan.emplace(orphaned);
        orphan->Resubscribe(source);
    }
    orphan.reset();
    EXPECT_EQ(retained.calls, 1);
    EXPECT_EQ(retained.reason, ErrorCode::RESOURCE_EXHAUSTED);
    EXPECT_EQ(removed.calls, 0);
    EXPECT_EQ(orphaned.calls, 0);
}

class CancellationMutation : public testing::TestWithParam<bool> {};
TEST_P(CancellationMutation, AllowsListenerRemovalAdditionAndReentrantDelivery) {
    const bool reentrant = GetParam();
    CancellationSource source;
    Counter victim, fresh, mutator;
    struct Mutation {
        struct Listener final : CancellationSubscription {
            explicit Listener(Mutation& owner) noexcept : owner(owner) {}
            Mutation& owner;
        private:
            void OnCancellation(Cancellation cancellation) noexcept override {
                auto& mutation = owner;
                mutation.mutator.Record(cancellation);
                mutation.victim.reset();
                mutation.self.reset();
                mutation.added.emplace(mutation.fresh);
                mutation.added->Resubscribe(mutation.source);
                if (mutation.reentrant) mutation.source.CancelPending(ErrorCode::RELAY_TIMEOUT);
            }
        };
        CancellationSource& source;
        Counter& fresh;
        Counter& mutator;
        bool reentrant;
        std::optional<RecordingListener> victim;
        std::optional<Listener> self;
        std::optional<RecordingListener> added;
    } mutation{source, fresh, mutator, reentrant, {}, {}, {}};
    mutation.victim.emplace(victim);
    mutation.victim->Resubscribe(source);
    mutation.self.emplace(mutation);
    mutation.self->Resubscribe(source);
    source.CancelPending(ErrorCode::RESOURCE_EXHAUSTED);
    EXPECT_EQ(mutator.calls, 1);
    EXPECT_EQ(victim.calls, 0);
    EXPECT_EQ(fresh.calls, reentrant ? 1 : 0);
    source.CancelPending(ErrorCode::RELAY_TIMEOUT);
    source.CancelPending();
    EXPECT_EQ(fresh.calls, 1);
    EXPECT_EQ(fresh.reason, ErrorCode::RELAY_TIMEOUT);
}

INSTANTIATE_TEST_SUITE_P(Delivery, CancellationMutation, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "Reentrant" : "Deferred";
    });

TEST(CancellationSource, DeliversOnlyToRemainingListenersAfterBulkRemoval) {
    CancellationSource source;
    std::array<Counter, 128> counters;
    std::array<std::optional<RecordingListener>, 128> subscriptions;
    for (size_t i = 0; i < counters.size(); ++i) {
        subscriptions[i].emplace(counters[i]);
        subscriptions[i]->Resubscribe(source);
    }
    for (size_t i = 0; i < counters.size(); i += 3) subscriptions[i].reset();
    source.CancelPending();
    for (size_t i = 0; i < counters.size(); ++i)
        EXPECT_EQ(counters[i].calls, i % 3 == 0 ? 0 : 1) << i;
}

TEST(CancellationSource, TerminalStopIsStickyForCurrentAndLateListeners) {
    CancellationSource source;
    source.CancelPending();
    Counter current, late;
    RecordingListener first(current);
    first.Resubscribe(source);
    EXPECT_EQ(current.calls, 0);
    source.Stop(ErrorCode::RESOURCE_EXHAUSTED);
    source.Stop();
    source.CancelPending();
    RecordingListener second(late);
    second.Resubscribe(source);
    EXPECT_EQ(current.calls, 1);
    EXPECT_TRUE(current.terminal);
    EXPECT_EQ(current.reason, ErrorCode::RESOURCE_EXHAUSTED);
    EXPECT_EQ(late.calls, 1);
    EXPECT_TRUE(late.terminal);
    EXPECT_EQ(late.reason, ErrorCode::RESOURCE_EXHAUSTED);
}

struct Forwarding final : CancellationSubscription {
    CancellationSource& source;
    CancellationSource& destination;

    Forwarding(CancellationSource& from, CancellationSource& to) noexcept
        : source(from), destination(to) {
        Resubscribe(source);
    }

private:
    void OnCancellation(Cancellation cancellation) noexcept override {
        if (cancellation.terminal) destination.Stop(cancellation.reason);
        else {
            Resubscribe(source);
            destination.CancelPending(cancellation.reason);
        }
    }
};

class CancellationForwarding : public testing::TestWithParam<bool> {};
TEST_P(CancellationForwarding, PropagatesPendingAndTerminalCancellation) {
    const bool stopped_before_construction = GetParam();
    CancellationSource upstream, downstream;
    if (stopped_before_construction) upstream.Stop(ErrorCode::RESOURCE_EXHAUSTED);
    Forwarding forward(upstream, downstream);
    if (!stopped_before_construction) {
        for (int i = 0; i < 4; ++i) {
            Counter current;
            RecordingListener subscription(current);
            subscription.Resubscribe(downstream);
            EXPECT_EQ(current.calls, 0);
            upstream.CancelPending();
            EXPECT_EQ(current.calls, 1);
            EXPECT_FALSE(current.terminal);
        }
        upstream.Stop(ErrorCode::RESOURCE_EXHAUSTED);
    }
    Counter late;
    RecordingListener subscription(late);
    subscription.Resubscribe(downstream);
    EXPECT_EQ(late.calls, 1);
    EXPECT_TRUE(late.terminal);
    EXPECT_EQ(late.reason, ErrorCode::RESOURCE_EXHAUSTED);
}

INSTANTIATE_TEST_SUITE_P(UpstreamState, CancellationForwarding, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "AlreadyStopped" : "Live";
    });

TEST(CancellationSource, UnsubscribeAndRebindLeaveOnlyCurrentSourceActive) {
    CancellationSource first, second;
    Counter counter;
    RecordingListener subscription(counter);
    subscription.Resubscribe(first);
    subscription.Unsubscribe();
    subscription.Unsubscribe();
    first.CancelPending();
    EXPECT_EQ(counter.calls, 0);
    subscription.Resubscribe(first);
    subscription.Resubscribe(second);
    first.Stop();
    EXPECT_EQ(counter.calls, 0);
    second.CancelPending(ErrorCode::RELAY_TIMEOUT);
    EXPECT_EQ(counter.calls, 1);
    EXPECT_FALSE(counter.terminal);
    EXPECT_EQ(counter.reason, ErrorCode::RELAY_TIMEOUT);
}

TEST(CancellationSource, SourceCanBeDestroyedDuringDelivery) {
    std::optional<CancellationSource> source(std::in_place);
    Counter delivered;
    RecordingListener follower(delivered);
    follower.Resubscribe(*source);
    struct DestroySource final : CancellationSubscription {
        explicit DestroySource(std::optional<CancellationSource>& source) noexcept : source(source) {}
        std::optional<CancellationSource>& source;
        bool called = false;
    private:
        void OnCancellation(Cancellation) noexcept override {
            called = true;
            source.reset();
        }
    } destroy(source);
    destroy.Resubscribe(*source);
    source->CancelPending(ErrorCode::RESOURCE_EXHAUSTED);
    EXPECT_TRUE(destroy.called);
    EXPECT_FALSE(source);
    EXPECT_EQ(delivered.calls, 1);
    EXPECT_EQ(delivered.reason, ErrorCode::RESOURCE_EXHAUSTED);
}
}  // namespace


TEST(CancellationBridge, MergesSignalsAndUnsubscribesAtScopeEnd) {
    net::cancellation_signal parent;
    CancellationSource source;
    size_t deliveries = 0;
    {
        transport::CancellationBridge bridge(parent.slot(), source);
        bridge.Slot().assign([&](net::cancellation_type) { ++deliveries; });
        bridge.Interrupt();
        EXPECT_EQ(deliveries, 1);
        EXPECT_FALSE(bridge.Cancelled());
        parent.emit(net::cancellation_type::terminal);
        EXPECT_TRUE(bridge.Cancelled());
        EXPECT_EQ(deliveries, 2);
        source.Stop(ErrorCode::TIMEOUT);
        EXPECT_EQ(deliveries, 3);
    }
    parent.emit(net::cancellation_type::all);
    source.Stop();
    EXPECT_EQ(deliveries, 3);
}

TEST(CancellationBridge, ObservesSourceStoppedBeforeConstruction) {
    CancellationSource source;
    source.Stop(ErrorCode::TIMEOUT);
    transport::CancellationBridge stopped({}, source);
    EXPECT_TRUE(stopped.Cancelled());
}

TEST(CancellationBridge, ScopeExitUnsubscribesFromLiveSource) {
    size_t deliveries = 0;
    CancellationSource live;
    {
        transport::CancellationBridge removed({}, live);
        removed.Slot().assign([&](net::cancellation_type) { ++deliveries; });
    }
    live.CancelPending();
    EXPECT_EQ(deliveries, 0u);
}
