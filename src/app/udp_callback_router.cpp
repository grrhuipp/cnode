#include "udp_callback_router.hpp"

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/defaults.hpp"

#include <algorithm>

namespace acpp::detail {

namespace {

struct CallbackIdList {
    uint64_t first = 0;
    memory::ThreadLocalVector<uint64_t> overflow;

    void Push(uint64_t callback_id) {
        if (first == 0) {
            first = callback_id;
            return;
        }
        overflow.push_back(callback_id);
    }

    [[nodiscard]] bool Remove(uint64_t callback_id) noexcept {
        if (first == callback_id) {
            if (!overflow.empty()) {
                first = overflow.back();
                overflow.pop_back();
            } else {
                first = 0;
            }
            return true;
        }

        auto it = std::find(overflow.begin(), overflow.end(), callback_id);
        if (it == overflow.end()) {
            return false;
        }
        *it = overflow.back();
        overflow.pop_back();
        return true;
    }

    [[nodiscard]] bool Empty() const noexcept { return first == 0; }
};

struct TargetState {
    steady_clock::time_point last_active;
    uint64_t generation = 0;
    size_t pending_sends = 0;
    bool established = false;
};

struct CallbackEntry {
    PacketCallback callback;
    memory::ThreadLocalUnorderedMap<
        UdpEndpointKey,
        TargetState,
        UdpEndpointKeyHash> sent_targets;
    bool pending_removal = false;
};

}  // namespace

struct UdpCallbackRouter::Impl {
    static constexpr auto kTargetMappingTtl =
        std::chrono::seconds(defaults::kUdpTargetMappingTtl);
    static constexpr auto kTargetPruneInterval =
        std::chrono::seconds(defaults::kUdpTargetPruneInterval);

    [[nodiscard]] uint64_t NextCallbackId() noexcept {
        while (true) {
            const uint64_t candidate = next_callback_id++;
            if (next_callback_id == 0) {
                next_callback_id = 1;
            }
            if (candidate != 0 && !registered_callbacks.contains(candidate)) {
                return candidate;
            }
        }
    }

    [[nodiscard]] uint64_t NextGeneration() noexcept {
        const uint64_t generation = next_generation++;
        if (next_generation == 0) {
            next_generation = 1;
        }
        return generation == 0 ? NextGeneration() : generation;
    }

    [[nodiscard]] bool EraseCallback(uint64_t callback_id) noexcept {
        auto it = registered_callbacks.find(callback_id);
        if (it == registered_callbacks.end()) {
            return false;
        }

        bool removed_reverse_key = false;
        for (const auto& [target, state] : it->second.sent_targets) {
            (void)state;
            auto reverse_it = target_to_callbacks.find(target);
            if (reverse_it == target_to_callbacks.end()) {
                continue;
            }
            auto& callbacks = reverse_it->second;
            if (callbacks.Remove(callback_id) && callbacks.Empty()) {
                target_to_callbacks.erase(reverse_it);
                removed_reverse_key = true;
            }
        }
        target_mapping_count -= std::min(
            target_mapping_count, it->second.sent_targets.size());
        registered_callbacks.erase(it);
        MaybeShrinkHashContainer(registered_callbacks, 16);
        if (removed_reverse_key) {
            MaybeShrinkHashContainer(target_to_callbacks, 16);
        }
        return true;
    }

    void ClearNow() noexcept {
        registered_callbacks.clear();
        target_to_callbacks.clear();
        deferred_unregistrations.clear();
        target_mapping_count = 0;
        clear_pending = false;
        MaybeShrinkHashContainer(registered_callbacks, 16);
        MaybeShrinkHashContainer(target_to_callbacks, 16);
        TryShrinkSequence(deferred_unregistrations);
    }

    void FlushDeferredMutations() noexcept {
        if (dispatch_depth != 0) {
            return;
        }
        if (clear_pending) {
            ClearNow();
            return;
        }
        for (uint64_t callback_id : deferred_unregistrations) {
            (void)EraseCallback(callback_id);
        }
        deferred_unregistrations.clear();
    }

    void RefreshTarget(
        const UdpEndpointKey& target,
        uint64_t callback_id,
        steady_clock::time_point now) noexcept {
        auto callback_it = registered_callbacks.find(callback_id);
        if (callback_it == registered_callbacks.end()) {
            return;
        }
        auto target_it = callback_it->second.sent_targets.find(target);
        if (target_it == callback_it->second.sent_targets.end()) {
            return;
        }
        target_it->second.last_active = now;
    }

    memory::ThreadLocalUnorderedMap<uint64_t, CallbackEntry> registered_callbacks;
    memory::ThreadLocalUnorderedMap<
        UdpEndpointKey,
        CallbackIdList,
        UdpEndpointKeyHash> target_to_callbacks;
    memory::ThreadLocalVector<uint64_t> deferred_unregistrations;
    size_t target_mapping_count = 0;
    uint64_t next_callback_id = 1;
    uint64_t next_generation = 1;
    size_t dispatch_depth = 0;
    bool clear_pending = false;
    steady_clock::time_point next_target_prune_at =
        steady_clock::now() + kTargetPruneInterval;
};

UdpCallbackRouter::UdpCallbackRouter()
    : impl_(std::make_unique<Impl>()) {}

UdpCallbackRouter::~UdpCallbackRouter() noexcept = default;

uint64_t UdpCallbackRouter::Register(PacketCallback callback) {
    if (!callback || impl_->clear_pending ||
        impl_->registered_callbacks.size() >= kMaxCallbacks) {
        return 0;
    }

    const uint64_t callback_id = impl_->NextCallbackId();
    impl_->registered_callbacks.emplace(
        callback_id,
        CallbackEntry{.callback = std::move(callback)});
    return callback_id;
}

bool UdpCallbackRouter::Unregister(uint64_t callback_id) {
    auto it = impl_->registered_callbacks.find(callback_id);
    if (it == impl_->registered_callbacks.end()) {
        return false;
    }
    if (impl_->dispatch_depth == 0) {
        return impl_->EraseCallback(callback_id);
    }
    if (it->second.pending_removal) {
        return true;
    }

    impl_->deferred_unregistrations.push_back(callback_id);
    it->second.pending_removal = true;
    return true;
}

std::pair<ErrorCode, UdpCallbackRouter::MappingToken>
UdpCallbackRouter::TrackTarget(
    const UdpEndpointKey& target,
    uint64_t callback_id,
    steady_clock::time_point now) {
    Prune(now);

    auto callback_it = impl_->registered_callbacks.find(callback_id);
    if (callback_it == impl_->registered_callbacks.end() ||
        callback_it->second.pending_removal || impl_->clear_pending) {
        return {ErrorCode::INVALID_ARGUMENT, {}};
    }

    auto& sent_targets = callback_it->second.sent_targets;
    auto existing = sent_targets.find(target);
    if (existing != sent_targets.end()) {
        existing->second.last_active = now;
        ++existing->second.pending_sends;
        return {ErrorCode::OK, MappingToken{
            .target = target,
            .callback_id = callback_id,
            .generation = existing->second.generation,
            .inserted = false,
        }};
    }
    if (sent_targets.size() >= kMaxTargetsPerCallback ||
        impl_->target_mapping_count >= kMaxTargetMappings) {
        return {ErrorCode::RESOURCE_EXHAUSTED, {}};
    }

    const uint64_t generation = impl_->NextGeneration();
    sent_targets.emplace(target, TargetState{
        .last_active = now,
        .generation = generation,
        .pending_sends = 1,
        .established = false,
    });
    try {
        impl_->target_to_callbacks[target].Push(callback_id);
    } catch (...) {
        sent_targets.erase(target);
        auto reverse_it = impl_->target_to_callbacks.find(target);
        if (reverse_it != impl_->target_to_callbacks.end() &&
            reverse_it->second.Empty()) {
            impl_->target_to_callbacks.erase(reverse_it);
        }
        throw;
    }
    ++impl_->target_mapping_count;
    return {ErrorCode::OK, MappingToken{
        .target = target,
        .callback_id = callback_id,
        .generation = generation,
        .inserted = true,
    }};
}

void UdpCallbackRouter::CommitTarget(const MappingToken& token) noexcept {
    if (!token) {
        return;
    }
    auto callback_it = impl_->registered_callbacks.find(token.callback_id);
    if (callback_it == impl_->registered_callbacks.end()) {
        return;
    }
    auto target_it = callback_it->second.sent_targets.find(token.target);
    if (target_it == callback_it->second.sent_targets.end() ||
        target_it->second.generation != token.generation) {
        return;
    }
    target_it->second.pending_sends -=
        std::min<size_t>(target_it->second.pending_sends, 1);
    target_it->second.established = true;
}

void UdpCallbackRouter::RollbackTarget(const MappingToken& token) noexcept {
    if (!token) {
        return;
    }
    auto callback_it = impl_->registered_callbacks.find(token.callback_id);
    if (callback_it == impl_->registered_callbacks.end()) {
        return;
    }
    auto target_it = callback_it->second.sent_targets.find(token.target);
    if (target_it == callback_it->second.sent_targets.end() ||
        target_it->second.generation != token.generation) {
        return;
    }

    auto& target_state = target_it->second;
    target_state.pending_sends -=
        std::min<size_t>(target_state.pending_sends, 1);
    if (target_state.pending_sends != 0 || target_state.established) {
        return;
    }
    callback_it->second.sent_targets.erase(target_it);
    impl_->target_mapping_count -=
        std::min<size_t>(impl_->target_mapping_count, 1);
    auto reverse_it = impl_->target_to_callbacks.find(token.target);
    if (reverse_it == impl_->target_to_callbacks.end()) {
        return;
    }
    auto& callbacks = reverse_it->second;
    if (callbacks.Remove(token.callback_id) && callbacks.Empty()) {
        impl_->target_to_callbacks.erase(reverse_it);
    }
}

void UdpCallbackRouter::Prune(steady_clock::time_point now) {
    if (now < impl_->next_target_prune_at || impl_->dispatch_depth != 0) {
        return;
    }
    impl_->next_target_prune_at = now + Impl::kTargetPruneInterval;
    const auto cutoff = now - Impl::kTargetMappingTtl;

    bool removed_reverse_key = false;
    for (auto& [callback_id, entry] : impl_->registered_callbacks) {
        bool pruned_entry_targets = false;
        for (auto it = entry.sent_targets.begin();
             it != entry.sent_targets.end();) {
            if (it->second.pending_sends != 0 ||
                it->second.last_active >= cutoff) {
                ++it;
                continue;
            }
            auto reverse_it = impl_->target_to_callbacks.find(it->first);
            if (reverse_it != impl_->target_to_callbacks.end()) {
                auto& callbacks = reverse_it->second;
                if (callbacks.Remove(callback_id) && callbacks.Empty()) {
                    impl_->target_to_callbacks.erase(reverse_it);
                    removed_reverse_key = true;
                }
            }
            it = entry.sent_targets.erase(it);
            impl_->target_mapping_count -=
                std::min<size_t>(impl_->target_mapping_count, 1);
            pruned_entry_targets = true;
        }
        if (pruned_entry_targets) {
            MaybeShrinkHashContainer(entry.sent_targets, 16);
        }
    }
    if (removed_reverse_key) {
        MaybeShrinkHashContainer(impl_->target_to_callbacks, 16);
    }
}

bool UdpCallbackRouter::Dispatch(
    const UdpEndpointKey& sender,
    UDPPacketView packet,
    steady_clock::time_point now) {
    uint64_t first_callback = 0;
    memory::ThreadLocalVector<uint64_t> overflow_snapshot;

    auto target_it = impl_->target_to_callbacks.find(sender);
    if (target_it != impl_->target_to_callbacks.end()) {
        first_callback = target_it->second.first;
        if (!target_it->second.overflow.empty()) {
            overflow_snapshot.assign(
                target_it->second.overflow.begin(),
                target_it->second.overflow.end());
        }
    } else if (impl_->registered_callbacks.size() == 1) {
        first_callback = impl_->registered_callbacks.begin()->first;
    } else {
        return false;
    }

    struct DispatchScope {
        explicit DispatchScope(Impl& impl) noexcept : impl(impl) {
            ++impl.dispatch_depth;
        }
        ~DispatchScope() noexcept {
            --impl.dispatch_depth;
            impl.FlushDeferredMutations();
        }
        Impl& impl;
    } dispatch_scope(*impl_);

    bool delivered = false;
    const auto deliver = [&](uint64_t callback_id) {
        if (callback_id == 0 || impl_->clear_pending) {
            return;
        }
        auto callback_it = impl_->registered_callbacks.find(callback_id);
        if (callback_it == impl_->registered_callbacks.end() ||
            callback_it->second.pending_removal) {
            return;
        }
        impl_->RefreshTarget(sender, callback_id, now);
        if (callback_it->second.callback(packet)) {
            delivered = true;
        }
    };

    deliver(first_callback);
    for (uint64_t callback_id : overflow_snapshot) {
        deliver(callback_id);
    }
    return delivered;
}

void UdpCallbackRouter::Clear() noexcept {
    if (impl_->dispatch_depth != 0) {
        impl_->clear_pending = true;
        return;
    }
    impl_->ClearNow();
}

size_t UdpCallbackRouter::RegisteredCount() const noexcept {
    return impl_->registered_callbacks.size();
}

size_t UdpCallbackRouter::TargetMappingCount() const noexcept {
    return impl_->target_mapping_count;
}

}  // namespace acpp::detail
