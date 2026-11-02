#include "acppnode/transport/cancellation.hpp"

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

using acpp::ErrorCode;
using acpp::transport::CancellationSource;
using acpp::transport::Cancellation;
using acpp::transport::CancellationSubscription;

namespace {
struct Counter {
    int calls = 0;
    ErrorCode reason = ErrorCode::OK;
    bool terminal = false;
    static void Record(void* raw, Cancellation cancellation) noexcept {
        auto& counter = *static_cast<Counter*>(raw);
        ++counter.calls;
        counter.reason = cancellation.reason;
        counter.terminal = cancellation.terminal;
    }
};

bool TestLifetimes() {
    Counter retained, removed, orphaned;
    std::optional<CancellationSubscription> orphan;
    {
        CancellationSource source;
        CancellationSubscription first(source, Counter::Record, &retained);
        {
            CancellationSubscription second(source, Counter::Record, &removed);
        }
        source.CancelPending(ErrorCode::RESOURCE_EXHAUSTED);
        source.CancelPending();
        orphan.emplace(source, Counter::Record, &orphaned);
    }
    orphan.reset();
    return retained.calls == 1 && retained.reason == ErrorCode::RESOURCE_EXHAUSTED &&
        removed.calls == 0 && orphaned.calls == 0;
}

bool TestMutation(bool reentrant) {
    CancellationSource source;
    Counter victim, fresh, mutator;
    std::optional<CancellationSubscription> victim_subscription, self, added;
    struct Context {
        CancellationSource& source;
        std::optional<CancellationSubscription>& victim;
        std::optional<CancellationSubscription>& self;
        std::optional<CancellationSubscription>& added;
        Counter& fresh;
        Counter& mutator;
        bool reentrant;
    } context{source, victim_subscription, self, added, fresh, mutator, reentrant};
    victim_subscription.emplace(source, Counter::Record, &victim);
    self.emplace(source, [](void* raw, Cancellation cancellation) noexcept {
        auto& ctx = *static_cast<Context*>(raw);
        Counter::Record(&ctx.mutator, cancellation);
        ctx.victim.reset();
        ctx.self.reset();
        ctx.added.emplace(ctx.source, Counter::Record, &ctx.fresh);
        if (ctx.reentrant) ctx.source.CancelPending(ErrorCode::RELAY_TIMEOUT);
    }, &context);
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
    std::array<std::optional<CancellationSubscription>, 128> subscriptions;
    for (size_t i = 0; i < counters.size(); ++i)
        subscriptions[i].emplace(source, Counter::Record, &counters[i]);
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
    CancellationSubscription first(source, Counter::Record, &current);
    if (current.calls != 0) return false;
    source.Stop(ErrorCode::RESOURCE_EXHAUSTED);
    source.Stop();
    source.CancelPending();
    CancellationSubscription second(source, Counter::Record, &late);
    return current.calls == 1 && current.terminal && current.reason == ErrorCode::RESOURCE_EXHAUSTED &&
        late.calls == 1 && late.terminal && late.reason == ErrorCode::RESOURCE_EXHAUSTED;
}

struct Forwarding {
    CancellationSource& source;
    CancellationSource& destination;
    CancellationSubscription subscription;

    Forwarding(CancellationSource& from, CancellationSource& to)
        : source(from), destination(to), subscription(from, [](void* raw, Cancellation cancellation) noexcept {
            auto& self = *static_cast<Forwarding*>(raw);
            if (cancellation.terminal) self.destination.Stop(cancellation.reason);
            else {
                self.subscription.Resubscribe(self.source);
                self.destination.CancelPending(cancellation.reason);
            }
        }, this) {}
};

bool TestForwarding(bool stopped_before_construction) {
    CancellationSource upstream, downstream;
    if (stopped_before_construction) upstream.Stop(ErrorCode::RESOURCE_EXHAUSTED);
    Forwarding forward(upstream, downstream);
    if (!stopped_before_construction) {
        for (int i = 0; i < 4; ++i) {
            Counter current;
            CancellationSubscription subscription(downstream, Counter::Record, &current);
            if (current.calls != 0) return false;
            upstream.CancelPending();
            if (current.calls != 1 || current.terminal) return false;
        }
        upstream.Stop(ErrorCode::RESOURCE_EXHAUSTED);
    }
    Counter late;
    CancellationSubscription subscription(downstream, Counter::Record, &late);
    return late.calls == 1 && late.terminal && late.reason == ErrorCode::RESOURCE_EXHAUSTED;
}
}  // namespace

int main() {
    static_assert(!std::is_move_constructible_v<CancellationSource>);
    static_assert(!std::is_move_constructible_v<CancellationSubscription>);
    reject_allocations = true;
    const bool passed = TestLifetimes() && TestMutation(false) && TestMutation(true) && TestManyListeners() &&
        TestTerminalState() && TestForwarding(false) && TestForwarding(true);
    reject_allocations = false;
    std::printf("cancellation source: scoped delivery, terminal state, late subscription, forwarding, reentrancy and no allocations: %s\n",
        passed ? "PASS" : "FAIL");
    return passed ? 0 : 1;
}
