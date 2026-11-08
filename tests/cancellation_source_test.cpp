#include <gtest/gtest.h>

#include "transport/cancellation.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <optional>
#include <type_traits>

namespace { bool reject_allocations = false; }
void* operator new(std::size_t size) {
    if (reject_allocations) throw std::bad_alloc();
    if (void* value = std::malloc(size ? size : 1)) return value;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }

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

bool TestLifetimes() {
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
    return retained.calls == 1 && retained.reason == ErrorCode::RESOURCE_EXHAUSTED &&
        removed.calls == 0 && orphaned.calls == 0;
}

bool TestMutation(bool reentrant) {
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
    const bool first = mutator.calls == 1 && victim.calls == 0 &&
        fresh.calls == (reentrant ? 1 : 0);
    source.CancelPending(ErrorCode::RELAY_TIMEOUT);
    source.CancelPending();
    return first && fresh.calls == 1 && fresh.reason == ErrorCode::RELAY_TIMEOUT;
}

bool TestManyListeners() {
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
        if (counters[i].calls != (i % 3 == 0 ? 0 : 1)) return false;
    return true;
}

bool TestTerminalState() {
    CancellationSource source;
    source.CancelPending();
    Counter current, late;
    RecordingListener first(current);
    first.Resubscribe(source);
    if (current.calls != 0) return false;
    source.Stop(ErrorCode::RESOURCE_EXHAUSTED);
    source.Stop();
    source.CancelPending();
    RecordingListener second(late);
    second.Resubscribe(source);
    return current.calls == 1 && current.terminal && current.reason == ErrorCode::RESOURCE_EXHAUSTED &&
        late.calls == 1 && late.terminal && late.reason == ErrorCode::RESOURCE_EXHAUSTED;
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

bool TestForwarding(bool stopped_before_construction) {
    CancellationSource upstream, downstream;
    if (stopped_before_construction) upstream.Stop(ErrorCode::RESOURCE_EXHAUSTED);
    Forwarding forward(upstream, downstream);
    if (!stopped_before_construction) {
        for (int i = 0; i < 4; ++i) {
            Counter current;
            RecordingListener subscription(current);
            subscription.Resubscribe(downstream);
            if (current.calls != 0) return false;
            upstream.CancelPending();
            if (current.calls != 1 || current.terminal) return false;
        }
        upstream.Stop(ErrorCode::RESOURCE_EXHAUSTED);
    }
    Counter late;
    RecordingListener subscription(late);
    subscription.Resubscribe(downstream);
    return late.calls == 1 && late.terminal && late.reason == ErrorCode::RESOURCE_EXHAUSTED;
}

bool TestUnsubscribeAndRebind() {
    CancellationSource first, second;
    Counter counter;
    RecordingListener subscription(counter);
    subscription.Resubscribe(first);
    subscription.Unsubscribe();
    subscription.Unsubscribe();
    first.CancelPending();
    if (counter.calls != 0) return false;
    subscription.Resubscribe(first);
    subscription.Resubscribe(second);
    first.Stop();
    if (counter.calls != 0) return false;
    second.CancelPending(ErrorCode::RELAY_TIMEOUT);
    return counter.calls == 1 && !counter.terminal && counter.reason == ErrorCode::RELAY_TIMEOUT;
}

bool TestSourceDestroyedDuringDelivery() {
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
    return destroy.called && !source && delivered.calls == 1 &&
        delivered.reason == ErrorCode::RESOURCE_EXHAUSTED;
}
}  // namespace

TEST(CancellationSource, Contract) {
    reject_allocations = true;
    const bool passed = TestLifetimes() && TestMutation(false) && TestMutation(true) && TestManyListeners() &&
        TestTerminalState() && TestForwarding(false) && TestForwarding(true) &&
        TestUnsubscribeAndRebind() && TestSourceDestroyedDuringDelivery();
    reject_allocations = false;
    std::printf("cancellation source: scoped delivery, terminal state, late subscription, forwarding, reentrancy and no allocations: %s\n",
        passed ? "PASS" : "FAIL");
    { ASSERT_TRUE(passed); return; }
}
